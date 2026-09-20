from typing import List, Optional
import uuid
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.models.auth import Dispositivo, Sesion, Usuario
from app.repositories.auth_repository import AuthRepository
from app.repositories.device_repository import DeviceRepository
from app.services.auth_service import AuthenticatedSession
from app.services.device_identity_service import DeviceIdentityService
from app.schemas.device import (
    DeviceActionResponse,
    DeviceAuthorizeRequest,
    DeviceListResponse,
    DeviceRead,
    DeviceRegisterRequest,
)


class DeviceService:
    def __init__(self, db: Session):
        self.db = db
        self.device_repo = DeviceRepository(db)
        self.auth_repo = AuthRepository(db)

    def _refresh_authorization(self, user: Usuario) -> tuple[set[str], set[str]]:
        self.db.expire(user, ["roles"])
        roles = list(user.roles)
        for role in roles:
            self.db.expire(role, ["permisos"])
        return (
            {role.nombre for role in roles},
            {permission.codigo for role in roles for permission in role.permisos},
        )

    def _lock_admin_session(self, context: AuthenticatedSession) -> Usuario:
        admin_user, _, _ = self.auth_repo.lock_authenticated_session(
            context.user.id_usuario,
            context.device.id_dispositivo,
            context.session.id_sesion,
        )
        roles, _ = self._refresh_authorization(admin_user)
        if "Administrador" not in roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Acceso restringido: se requieren privilegios de Administrador.",
            )
        return admin_user

    def list_devices(
        self,
        user: Usuario,
        current_device_id: Optional[uuid.UUID] = None,
    ) -> DeviceListResponse:
        """CU-04: Lista todos los dispositivos vinculados al usuario, señalando el actual."""
        devices = self.device_repo.get_user_devices(user.id_usuario)

        device_reads: List[DeviceRead] = []
        active_device_id = current_device_id

        for d in devices:
            is_current = d.id_dispositivo == active_device_id

            read_item = DeviceRead(
                id_dispositivo=d.id_dispositivo,
                id_usuario=d.id_usuario,
                nombre=d.nombre,
                tipo=d.tipo,
                sistema_operativo=d.sistema_operativo,
                identificador_seguro=d.identificador_seguro,
                huella_clave_publica=d.huella_clave_publica,
                es_confiable=d.es_confiable,
                estado=d.estado,
                identidad_verificada_en=d.identidad_verificada_en,
                confianza_otorgada_en=d.confianza_otorgada_en,
                confianza_otorgada_por=d.confianza_otorgada_por,
                fecha_registro=d.fecha_registro,
                ultimo_acceso=d.ultimo_acceso,
                es_dispositivo_actual=is_current,
            )
            device_reads.append(read_item)

        return DeviceListResponse(
            total=len(device_reads),
            dispositivos=device_reads,
            dispositivo_actual_id=active_device_id,
        )

    def register_device(
        self,
        user: Usuario,
        current_device: Dispositivo,
        session: Sesion,
        request: DeviceRegisterRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> DeviceActionResponse:
        """Updates only the device bound to the current authenticated session."""
        if request.identificador_seguro != current_device.identificador_seguro:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="La identidad de instalación debe registrarse durante el inicio de sesión.",
            )
        from app.schemas.auth import DispositivoInfo

        device = self.auth_repo.get_or_create_device(
            user.id_usuario,
            DispositivoInfo(
                nombre=request.nombre or current_device.nombre,
                tipo=request.tipo or current_device.tipo,
                sistema_operativo=request.sistema_operativo or current_device.sistema_operativo,
                identificador_seguro=request.identificador_seguro,
                public_key=request.public_key,
                vault_public_key=request.vault_public_key,
            ),
            expected_security_version=session.version_seguridad,
        )
        self.auth_repo.create_audit_event(
            accion="REGISTRO_IDENTIDAD_DISPOSITIVO",
            tipo_evento="DISPOSITIVO",
            resultado="EXITO",
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            ip=client_ip,
            user_agent=user_agent,
            detalles={
                "nombre": device.nombre,
                "tipo": device.tipo,
                "sistema_operativo": device.sistema_operativo,
                "estado": device.estado,
            },
        )

        read_item = DeviceRead.model_validate(device)
        read_item.es_dispositivo_actual = True

        return DeviceActionResponse(
            status="ok",
            message="Identidad registrada como PENDING. Completa la prueba de posesión y espera aprobación administrativa.",
            dispositivo=read_item,
        )

    def revoke_device(
        self,
        device_id: uuid.UUID,
        user: Usuario,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> DeviceActionResponse:
        """CU-04 / CU-05: Desvincula el dispositivo y revoca todas las sesiones activas en él."""
        device = self.device_repo.get_device_by_id(device_id, user.id_usuario)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Dispositivo no encontrado o no pertenece a la cuenta.",
            )

        self.device_repo.revoke_and_delete_device(device, revocado_por=user.id_usuario)

        self.auth_repo.create_audit_event(
            accion="REVOCAR_DISPOSITIVO",
            tipo_evento="DISPOSITIVO",
            resultado="EXITO",
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            ip=client_ip,
            user_agent=user_agent,
            detalles={
                "nombre": device.nombre,
                "motivo": "DESVINCULACION_POR_USUARIO",
            },
        )

        read_item = DeviceRead.model_validate(device)
        return DeviceActionResponse(
            status="ok",
            message=f"Dispositivo '{device.nombre}' desvinculado y sesiones revocadas.",
            dispositivo=read_item,
        )

    # --- CU-05: Lógica de Negocio y Auditoría Administrativa ---

    def list_all_devices_admin(
        self,
        query: Optional[str] = None,
        solo_confiables: Optional[bool] = None,
        estado: Optional[str] = None,
    ):
        """CU-05: Lista todos los dispositivos de la plataforma con datos de usuario y sesiones."""
        from app.schemas.device import AdminDeviceListResponse, AdminDeviceRead

        raw_list = self.device_repo.get_all_devices_admin(
            query=query,
            solo_confiables=solo_confiables,
            estado=estado,
        )

        items = []
        for row in raw_list:
            d = row["device"]
            item = AdminDeviceRead(
                id_dispositivo=d.id_dispositivo,
                id_usuario=d.id_usuario,
                usuario_nombre=row["usuario_nombre"],
                usuario_correo=row["usuario_correo"],
                nombre=d.nombre,
                tipo=d.tipo,
                sistema_operativo=d.sistema_operativo,
                identificador_seguro=d.identificador_seguro,
                es_confiable=d.es_confiable,
                estado=d.estado,
                fecha_registro=d.fecha_registro,
                ultimo_acceso=d.ultimo_acceso,
                fecha_revocacion=d.fecha_revocacion,
                revocado_por=d.revocado_por,
                identidad_verificada_en=d.identidad_verificada_en,
                confianza_otorgada_en=d.confianza_otorgada_en,
                confianza_otorgada_por=d.confianza_otorgada_por,
                sesiones_activas=row["sesiones_activas"],
            )
            items.append(item)

        return AdminDeviceListResponse(
            total=len(items),
            dispositivos=items,
        )

    def approve_device_admin(
        self,
        device_id: uuid.UUID,
        context: AuthenticatedSession,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> DeviceActionResponse:
        """Approves a separate user's possession-verified pending device."""
        admin_user, _, admin_session = self.auth_repo.lock_authenticated_session(
            context.user.id_usuario,
            context.device.id_dispositivo,
            context.session.id_sesion,
        )
        roles, permissions = self._refresh_authorization(admin_user)
        if "Administrador" not in roles and "devices:approve" not in permissions:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Se requiere el permiso devices:approve para aprobar un dispositivo.",
            )
        DeviceIdentityService.require_recent_mfa(admin_session)
        try:
            device = self.device_repo.approve_pending_device(device_id, admin_user.id_usuario)
        except PermissionError as error:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Un usuario no puede aprobar su propio dispositivo.",
            ) from error
        except ValueError as error:
            details = {
                "DEVICE_NOT_FOUND": (status.HTTP_404_NOT_FOUND, "Dispositivo no encontrado en el sistema."),
                "DEVICE_REVOKED": (status.HTTP_403_FORBIDDEN, "El dispositivo fue revocado."),
                "POSSESSION_PROOF_REQUIRED": (
                    status.HTTP_409_CONFLICT,
                    "El dispositivo debe demostrar posesión antes de ser aprobado.",
                ),
                "DEVICE_NOT_PENDING": (
                    status.HTTP_409_CONFLICT,
                    "El dispositivo ya no está pendiente de aprobación.",
                ),
                "DEVICE_APPROVAL_RACE": (
                    status.HTTP_409_CONFLICT,
                    "La aprobación no pudo completarse por un cambio concurrente.",
                ),
            }
            status_code, detail = details.get(
                str(error),
                (status.HTTP_409_CONFLICT, "No se pudo aprobar el dispositivo."),
            )
            raise HTTPException(status_code=status_code, detail=detail) from error

        self.auth_repo.add_audit_event(
            accion="APROBACION_DISPOSITIVO_ADMIN",
            tipo_evento="SEGURIDAD",
            resultado="EXITO",
            user_id=device.id_usuario,
            device_id=device.id_dispositivo,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"aprobado_por": str(admin_user.id_usuario)},
        )
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise
        self.db.refresh(device)
        return DeviceActionResponse(
            status="ok",
            message="Dispositivo aprobado como TRUSTED por administración.",
            dispositivo=DeviceRead.model_validate(device),
        )

    def revoke_device_admin(
        self,
        device_id: uuid.UUID,
        context: AuthenticatedSession,
        motivo: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> DeviceActionResponse:
        """CU-05: Invalida el dispositivo de cualquier usuario y cierra todas sus sesiones activas."""
        admin_user = self._lock_admin_session(context)
        device = self.device_repo.get_device_by_id_global(device_id)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Dispositivo no encontrado en el sistema.",
            )

        self.device_repo.revoke_device_by_admin(
            device=device,
            admin_id=admin_user.id_usuario,
            motivo=motivo,
        )

        self.auth_repo.create_audit_event(
            accion="REVOCACION_DISPOSITIVO_ADMIN",
            tipo_evento="SEGURIDAD",
            resultado="EXITO",
            user_id=device.id_usuario,
            device_id=device.id_dispositivo,
            ip=client_ip,
            user_agent=user_agent,
            detalles={
                "admin_id": str(admin_user.id_usuario),
                "admin_correo": admin_user.correo,
                "nombre_dispositivo": device.nombre,
                "motivo": motivo,
                "accion": "INVALIDACION_INMEDIATA_TERMINAL",
            },
        )

        read_item = DeviceRead.model_validate(device)
        return DeviceActionResponse(
            status="ok",
            message=f"Dispositivo '{device.nombre}' revocado exitosamente por administración. Todas las sesiones activas han sido cerradas.",
            dispositivo=read_item,
        )

    def revoke_all_user_devices_admin(
        self,
        target_user_id: uuid.UUID,
        context: AuthenticatedSession,
        motivo: str,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> dict:
        """CU-05: Expulsa todos los dispositivos y sesiones activas de un usuario por seguridad."""
        admin_user = self._lock_admin_session(context)
        target_user = self.auth_repo.get_user_by_id(target_user_id)
        if not target_user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario objetivo no encontrado.",
            )

        count = self.device_repo.revoke_all_devices_for_user(
            user_id=target_user_id,
            admin_id=admin_user.id_usuario,
            motivo=motivo,
        )

        self.auth_repo.create_audit_event(
            accion="REVOCACION_TOTAL_DISPOSITIVOS_ADMIN",
            tipo_evento="SEGURIDAD",
            resultado="EXITO",
            user_id=target_user.id_usuario,
            ip=client_ip,
            user_agent=user_agent,
            detalles={
                "admin_id": str(admin_user.id_usuario),
                "admin_correo": admin_user.correo,
                "usuario_afectado": target_user.correo,
                "dispositivos_revocados": count,
                "motivo": motivo,
            },
        )

        return {
            "status": "ok",
            "message": f"Se han revocado {count} dispositivos y todas las sesiones activas del usuario {target_user.correo}.",
            "dispositivos_revocados": count,
        }
