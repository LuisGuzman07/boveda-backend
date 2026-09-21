from dataclasses import dataclass
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Iterable

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.models.policy import PoliticaSeguridad
from app.repositories.auth_repository import AuthRepository
from app.repositories.policy_repository import PolicyRepository
from app.schemas.policy import (
    PoliticaSeguridadBatchItem,
    PoliticaSeguridadRead,
    PoliticaSeguridadUpdateRequest,
)
from app.services.device_identity_service import DeviceIdentityService

if TYPE_CHECKING:
    from app.services.auth_service import AuthenticatedSession


@dataclass(frozen=True)
class PolicyDefinition:
    default: int
    minimum: int
    maximum: int
    description: str
    applied: bool


# Values are deliberately bounded in code. A malformed database value must never
# silently weaken authentication or vault-session controls.
POLICY_DEFINITIONS: dict[str, PolicyDefinition] = {
    "INACTIVITY_TIMEOUT_MINUTES": PolicyDefinition(
        default=15,
        minimum=1,
        maximum=1440,
        description="Minutos máximos de inactividad para sesiones web.",
        applied=True,
    ),
    "MAX_FAILED_LOGIN_ATTEMPTS": PolicyDefinition(
        default=5,
        minimum=3,
        maximum=20,
        description="Intentos fallidos antes de bloquear temporalmente una cuenta.",
        applied=True,
    ),
    "LOCKOUT_DURATION_MINUTES": PolicyDefinition(
        default=15,
        minimum=1,
        maximum=1440,
        description="Duración del bloqueo temporal por intentos fallidos.",
        applied=True,
    ),
    # Preserve CU08's five-minute capability default instead of adopting Maikol's
    # weaker fifteen-minute value.
    "VAULT_SESSION_DURATION_MINUTES": PolicyDefinition(
        default=5,
        minimum=1,
        maximum=60,
        description="Duración máxima de capacidades de sesión de bóveda.",
        applied=True,
    ),
    "PASSWORD_MIN_LENGTH": PolicyDefinition(
        default=12,
        minimum=8,
        maximum=128,
        description="Longitud mínima para contraseñas nuevas o restablecidas.",
        applied=True,
    ),
    "AUDIT_RETENTION_DAYS": PolicyDefinition(
        default=90,
        minimum=30,
        maximum=3650,
        description=(
            "Objetivo de conservación de auditoría. Requiere una política de archivo y "
            "retención legal antes de activar eliminación automática."
        ),
        applied=False,
    ),
}


class PolicyService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = PolicyRepository(db)
        self.auth_repo = AuthRepository(db)

    @staticmethod
    def _definition(codigo: str) -> PolicyDefinition:
        definition = POLICY_DEFINITIONS.get(codigo)
        if not definition:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="La política de seguridad solicitada no existe.",
            )
        return definition

    @classmethod
    def _validate_value(cls, codigo: str, valor: int) -> PolicyDefinition:
        definition = cls._definition(codigo)
        if isinstance(valor, bool) or not isinstance(valor, int):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="El valor de la política debe ser un entero.",
            )
        if not definition.minimum <= valor <= definition.maximum:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=(
                    f"El valor para {codigo} debe estar entre "
                    f"{definition.minimum} y {definition.maximum}."
                ),
            )
        return definition

    @classmethod
    def _serialize(cls, policy: PoliticaSeguridad) -> PoliticaSeguridadRead:
        definition = cls._validate_value(policy.codigo, policy.valor_entero)
        if policy.tipo_valor != "INTEGER":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="La configuración de seguridad contiene un tipo de política no compatible.",
            )
        return PoliticaSeguridadRead(
            codigo=policy.codigo,
            tipo_valor="INTEGER",
            valor=policy.valor_entero,
            minimo=definition.minimum,
            maximo=definition.maximum,
            activa=policy.activa,
            version=policy.version,
            descripcion=definition.description,
            aplicada=definition.applied,
        )

    def get_effective_value(self, codigo: str) -> int:
        definition = self._definition(codigo)
        policy = self.repo.get_by_code(codigo)
        if not policy or not policy.activa:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"La política de seguridad {codigo} no está disponible.",
            )
        self._validate_value(codigo, policy.valor_entero)
        if policy.tipo_valor != "INTEGER":
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail=f"La política de seguridad {codigo} tiene un tipo inválido.",
            )
        if not definition.applied:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"La política {codigo} está configurada pero aún no tiene aplicación operativa.",
            )
        return policy.valor_entero

    def validate_password_length(self, password: str) -> int:
        minimum = self.get_effective_value("PASSWORD_MIN_LENGTH")
        if len(password) < minimum:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail=f"La contraseña debe tener al menos {minimum} caracteres.",
            )
        return minimum

    def _refresh_permissions(self, user) -> set[str]:
        self.db.expire(user, ["roles"])
        roles = list(user.roles)
        for role in roles:
            self.db.expire(role, ["permisos"])
        return {permission.codigo for role in roles for permission in role.permisos}

    def _authorize(
        self,
        context: "AuthenticatedSession",
        permission: str | None = None,
        *,
        require_recent_mfa: bool = False,
    ):
        user, device, session = self.auth_repo.lock_authenticated_session(
            context.user.id_usuario,
            context.device.id_dispositivo,
            context.session.id_sesion,
        )
        permissions = self._refresh_permissions(user)
        if permission and permission not in permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Se requiere el permiso {permission} para esta operación.",
            )
        if require_recent_mfa:
            DeviceIdentityService.require_recent_mfa(session)
        return user, device, session

    def list_policies(self, context: "AuthenticatedSession") -> list[PoliticaSeguridadRead]:
        self._authorize(context, "policies:read")
        return [self._serialize(policy) for policy in self.repo.list_all()]

    def effective_policies(self, context: "AuthenticatedSession") -> tuple[list[PoliticaSeguridadRead], dict[str, int]]:
        self._authorize(context)
        policies_by_code = {policy.codigo: policy for policy in self.repo.list_all()}
        missing = set(POLICY_DEFINITIONS) - set(policies_by_code)
        if missing:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Faltan políticas de seguridad requeridas en la base de datos.",
            )
        items = [self._serialize(policies_by_code[codigo]) for codigo in sorted(POLICY_DEFINITIONS)]
        values: dict[str, int] = {}
        for policy in items:
            if policy.aplicada:
                values[policy.codigo] = self.get_effective_value(policy.codigo)
        return items, values

    def update_policy(
        self,
        context: "AuthenticatedSession",
        codigo: str,
        request: PoliticaSeguridadUpdateRequest,
        *,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> PoliticaSeguridadRead:
        update = PoliticaSeguridadBatchItem(
            codigo=codigo.strip().upper(), valor=request.valor, version=request.version
        )
        return self._update_many(context, [update], client_ip=client_ip, user_agent=user_agent)[0]

    def batch_update_policies(
        self,
        context: "AuthenticatedSession",
        updates: Iterable[PoliticaSeguridadBatchItem],
        *,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> list[PoliticaSeguridadRead]:
        return self._update_many(context, list(updates), client_ip=client_ip, user_agent=user_agent)

    def _update_many(
        self,
        context: "AuthenticatedSession",
        updates: list[PoliticaSeguridadBatchItem],
        *,
        client_ip: str | None,
        user_agent: str | None,
    ) -> list[PoliticaSeguridadRead]:
        if not updates:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="Debe incluir al menos una actualización de política.",
            )
        codes = [update.codigo.strip().upper() for update in updates]
        if len(codes) != len(set(codes)):
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="No se puede actualizar una política más de una vez en el mismo lote.",
            )
        for update, codigo in zip(updates, codes):
            self._validate_value(codigo, update.valor)

        actor, device, _ = self._authorize(
            context, "policies:write", require_recent_mfa=True
        )
        policies = self.repo.get_by_codes_for_update(codes)
        policies_by_code = {policy.codigo: policy for policy in policies}
        if set(codes) != set(policies_by_code):
            missing = sorted(set(codes) - set(policies_by_code))
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"No se encontraron las políticas: {', '.join(missing)}.",
            )

        for update, codigo in zip(updates, codes):
            policy = policies_by_code[codigo]
            if policy.version != update.version:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=(
                        f"La política {codigo} cambió en otra sesión. Actualiza la lista antes de guardar."
                    ),
                )
            if policy.tipo_valor != "INTEGER" or not policy.activa:
                raise HTTPException(
                    status_code=status.HTTP_409_CONFLICT,
                    detail=f"La política {codigo} no está disponible para actualización.",
                )

        changes = []
        now = datetime.now(timezone.utc)
        for update, codigo in zip(updates, codes):
            policy = policies_by_code[codigo]
            if policy.valor_entero == update.valor:
                continue
            changes.append(
                {
                    "codigo": codigo,
                    "anterior": policy.valor_entero,
                    "nuevo": update.valor,
                    "version_anterior": policy.version,
                }
            )
            policy.valor_entero = update.valor
            policy.version += 1
            policy.id_modificada_por = actor.id_usuario
            policy.fecha_actualizacion = now

        if not changes:
            return [self._serialize(policies_by_code[codigo]) for codigo in codes]

        try:
            self.db.flush()
            self.auth_repo.add_audit_event(
                accion=(
                    "POLITICA_SEGURIDAD_ACTUALIZADA"
                    if len(changes) == 1
                    else "POLITICAS_SEGURIDAD_ACTUALIZADAS"
                ),
                tipo_evento="SEGURIDAD",
                resultado="EXITO",
                user_id=actor.id_usuario,
                device_id=device.id_dispositivo,
                resource_type="POLITICA_SEGURIDAD",
                ip=client_ip,
                user_agent=user_agent,
                detalles={"cambios": changes},
            )
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

        for policy in policies:
            self.db.refresh(policy)
        return [self._serialize(policies_by_code[codigo]) for codigo in codes]
