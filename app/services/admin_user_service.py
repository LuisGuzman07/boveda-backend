import math
import uuid
from datetime import datetime, timezone
from typing import Iterable, Optional

from fastapi import Depends, HTTPException, status
from sqlalchemy import func, or_, select, update
from sqlalchemy.orm import Session, selectinload

from app.models.auth import EventoAuditoria, Permiso, Rol, Sesion, SesionBoveda, Usuario
from app.schemas.admin import AdminUserActionResponse, AdminUserListResponse
from app.schemas.auth import UsuarioRead
from app.services.auth_service import get_current_auth_context


SEEDED_ROLE_NAMES = {"Administrador", "Miembro", "Auditor", "Invitado"}
ADMINISTRATOR_ROLE_NAME = "Administrador"


def user_permission_codes(user: Usuario) -> set[str]:
    return {permission.codigo for role in user.roles for permission in role.permisos}


def require_permission(permission: str):
    def dependency(context=Depends(get_current_auth_context)):
        if permission not in user_permission_codes(context.user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="No cuenta con el permiso requerido para esta operación.",
            )
        return context

    return dependency


class AdminUserService:
    def __init__(self, db: Session):
        self.db = db

    def list_users(self, page: int, page_size: int, query: Optional[str], estado: Optional[str]) -> AdminUserListResponse:
        statement = select(Usuario).options(selectinload(Usuario.roles).selectinload(Rol.permisos))
        if query:
            value = f"%{query.strip()}%"
            statement = statement.where(or_(Usuario.nombre.ilike(value), Usuario.correo.ilike(value)))
        if estado:
            statement = statement.where(Usuario.estado == estado)
        total = self.db.scalar(select(func.count()).select_from(statement.subquery())) or 0
        users = self.db.scalars(statement.order_by(Usuario.correo).offset((page - 1) * page_size).limit(page_size)).all()
        return AdminUserListResponse(
            total=total,
            page=page,
            page_size=page_size,
            total_pages=math.ceil(total / page_size) if total else 1,
            items=[UsuarioRead.model_validate(user) for user in users],
        )

    def catalog_roles(self) -> list[Rol]:
        return list(self.db.scalars(
            select(Rol).where(Rol.nombre.in_(SEEDED_ROLE_NAMES)).options(selectinload(Rol.permisos)).order_by(Rol.nombre)
        ).all())

    def catalog_permissions(self) -> list[Permiso]:
        return list(self.db.scalars(select(Permiso).order_by(Permiso.codigo)).all())

    def update_status(self, actor: Usuario, target_id: uuid.UUID, new_status: str, reason: str) -> AdminUserActionResponse:
        target = self._target(actor, target_id)
        before_roles = self._role_ids(target.roles)
        if target.estado == new_status:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="El usuario ya tiene ese estado.")
        if new_status == "INACTIVO" and self._is_administrator(target) and self._active_administrator_count() <= 1:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No se puede desactivar al último administrador activo.")
        before_status = target.estado
        target.estado = new_status
        self._invalidate_user_sessions(target.id_usuario, "CAMBIO_ADMINISTRATIVO_AUTORIZACION")
        self._audit(actor, target, "USUARIO_ESTADO_ACTUALIZADO", before_roles, before_roles, before_status, new_status, reason)
        self.db.commit()
        self.db.refresh(target)
        return AdminUserActionResponse(message="Estado de usuario actualizado y sesiones invalidadas.", usuario=UsuarioRead.model_validate(target))

    def assign_role(self, actor: Usuario, target_id: uuid.UUID, role_id: uuid.UUID, reason: str) -> AdminUserActionResponse:
        target = self._target(actor, target_id)
        role = self._seeded_role(role_id)
        self._assert_assignable(actor, role)
        if any(existing.id_rol == role.id_rol for existing in target.roles):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="El usuario ya tiene ese rol asignado.")
        before_roles = self._role_ids(target.roles)
        target.roles.append(role)
        after_roles = self._role_ids(target.roles)
        self._invalidate_user_sessions(target.id_usuario, "CAMBIO_ADMINISTRATIVO_AUTORIZACION")
        self._audit(actor, target, "ROL_ASIGNADO", before_roles, after_roles, target.estado, target.estado, reason)
        self.db.commit()
        self.db.refresh(target)
        return AdminUserActionResponse(message="Rol asignado y sesiones invalidadas.", usuario=UsuarioRead.model_validate(target))

    def remove_role(self, actor: Usuario, target_id: uuid.UUID, role_id: uuid.UUID, reason: str) -> AdminUserActionResponse:
        target = self._target(actor, target_id)
        role = self._seeded_role(role_id)
        self._assert_assignable(actor, role)
        if not any(existing.id_rol == role.id_rol for existing in target.roles):
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="El usuario no tiene ese rol asignado.")
        if role.nombre == ADMINISTRATOR_ROLE_NAME and target.estado == "ACTIVO" and self._active_administrator_count() <= 1:
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="No se puede retirar el último rol de administrador activo.")
        before_roles = self._role_ids(target.roles)
        target.roles.remove(role)
        after_roles = self._role_ids(target.roles)
        self._invalidate_user_sessions(target.id_usuario, "CAMBIO_ADMINISTRATIVO_AUTORIZACION")
        self._audit(actor, target, "ROL_RETIRADO", before_roles, after_roles, target.estado, target.estado, reason)
        self.db.commit()
        self.db.refresh(target)
        return AdminUserActionResponse(message="Rol retirado y sesiones invalidadas.", usuario=UsuarioRead.model_validate(target))

    def _target(self, actor: Usuario, target_id: uuid.UUID) -> Usuario:
        if actor.id_usuario == target_id:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No puede modificar su propio estado o roles administrativos.")
        target = self.db.scalar(select(Usuario).where(Usuario.id_usuario == target_id).options(selectinload(Usuario.roles).selectinload(Rol.permisos)))
        if not target:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Usuario no encontrado.")
        return target

    def _seeded_role(self, role_id: uuid.UUID) -> Rol:
        role = self.db.scalar(select(Rol).where(Rol.id_rol == role_id).options(selectinload(Rol.permisos)))
        if not role or role.nombre not in SEEDED_ROLE_NAMES:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="El rol solicitado no pertenece al catálogo administrable.")
        return role

    def _assert_assignable(self, actor: Usuario, role: Rol) -> None:
        actor_permissions = user_permission_codes(actor)
        role_permissions = {permission.codigo for permission in role.permisos}
        if not role_permissions.issubset(actor_permissions):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No puede asignar ni retirar un rol con privilegios superiores a los propios.")

    def _active_administrator_count(self) -> int:
        return self.db.scalar(
            select(func.count(func.distinct(Usuario.id_usuario)))
            .join(Usuario.roles)
            .where(Usuario.estado == "ACTIVO", Rol.nombre == ADMINISTRATOR_ROLE_NAME)
        ) or 0

    @staticmethod
    def _role_ids(roles: Iterable[Rol]) -> list[str]:
        return sorted(str(role.id_rol) for role in roles)

    @staticmethod
    def _is_administrator(user: Usuario) -> bool:
        return any(role.nombre == ADMINISTRATOR_ROLE_NAME for role in user.roles)

    def _invalidate_user_sessions(self, user_id: uuid.UUID, reason: str) -> None:
        session_ids = select(Sesion.id_sesion).where(Sesion.id_usuario == user_id, Sesion.revocada.is_(False))
        self.db.execute(update(SesionBoveda).where(SesionBoveda.id_sesion.in_(session_ids), SesionBoveda.revocada.is_(False)).values(revocada=True, motivo_revocacion=reason))
        self.db.execute(update(Sesion).where(Sesion.id_usuario == user_id, Sesion.revocada.is_(False)).values(revocada=True, motivo_revocacion=reason, ultima_actividad=datetime.now(timezone.utc)))

    def _audit(self, actor: Usuario, target: Usuario, action: str, before_roles: list[str], after_roles: list[str], before_status: str, after_status: str, reason: str) -> None:
        self.db.add(EventoAuditoria(
            id_usuario=actor.id_usuario,
            accion=action,
            tipo_evento="ADMINISTRACION_USUARIOS",
            resultado="EXITO",
            recurso_id=str(target.id_usuario),
            recurso_tipo="USUARIO",
            detalles={
                "actor_user_id": str(actor.id_usuario),
                "target_user_id": str(target.id_usuario),
                "before_role_ids": before_roles,
                "after_role_ids": after_roles,
                "before_status": before_status,
                "after_status": after_status,
                "reason": reason,
            },
        ))
