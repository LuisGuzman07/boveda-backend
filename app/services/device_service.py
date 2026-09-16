from typing import List, Optional
import uuid
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.models.auth import Dispositivo, Usuario
from app.repositories.auth_repository import AuthRepository
from app.repositories.device_repository import DeviceRepository
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

    def list_devices(
        self,
        user: Usuario,
        current_device_identifier: Optional[str] = None,
    ) -> DeviceListResponse:
        """CU-04: Lista todos los dispositivos vinculados al usuario, señalando el actual."""
        devices = self.device_repo.get_user_devices(user.id_usuario)

        device_reads: List[DeviceRead] = []
        current_device_id: Optional[uuid.UUID] = None

        for d in devices:
            is_current = bool(
                current_device_identifier
                and d.identificador_seguro == current_device_identifier
            )
            if is_current:
                current_device_id = d.id_dispositivo

            read_item = DeviceRead(
                id_dispositivo=d.id_dispositivo,
                id_usuario=d.id_usuario,
                nombre=d.nombre,
                tipo=d.tipo,
                sistema_operativo=d.sistema_operativo,
                identificador_seguro=d.identificador_seguro,
                public_key=d.public_key,
                es_confiable=d.es_confiable,
                estado=d.estado,
                fecha_registro=d.fecha_registro,
                ultimo_acceso=d.ultimo_acceso,
                es_dispositivo_actual=is_current,
            )
            device_reads.append(read_item)

        return DeviceListResponse(
            total=len(device_reads),
            dispositivos=device_reads,
            dispositivo_actual_id=current_device_id,
        )

    def register_device(
        self,
        user: Usuario,
        request: DeviceRegisterRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> DeviceActionResponse:
        """CU-04: Registra o actualiza el hardware/navegador local como terminal del usuario."""
        device = self.device_repo.create_or_update_device(user.id_usuario, request)

        accion = (
            "REGISTRO_DISPOSITIVO_CONFIANZA"
            if device.es_confiable
            else "REGISTRO_DISPOSITIVO"
        )
        self.auth_repo.create_audit_event(
            accion=accion,
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
                "es_confiable": device.es_confiable,
                "identificador_seguro": device.identificador_seguro[:8] + "...",
            },
        )

        read_item = DeviceRead.model_validate(device)
        read_item.es_dispositivo_actual = True

        msg = (
            "Dispositivo registrado y marcado como de confianza exitosamente."
            if device.es_confiable
            else "Dispositivo registrado exitosamente en la bóveda."
        )
        return DeviceActionResponse(
            status="ok",
            message=msg,
            dispositivo=read_item,
        )

    def authorize_device(
        self,
        device_id: uuid.UUID,
        user: Usuario,
        request: DeviceAuthorizeRequest,
        current_device_identifier: Optional[str] = None,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> DeviceActionResponse:
        """CU-04: Autoriza o revoca el estado de confianza de un dispositivo."""
        device = self.device_repo.get_device_by_id(device_id, user.id_usuario)
        if not device:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Dispositivo no encontrado o no pertenece a la cuenta.",
            )

        device = self.device_repo.set_device_trust(
            device=device,
            es_confiable=request.es_confiable,
            nombre=request.nombre,
        )

        accion = (
            "AUTORIZAR_DISPOSITIVO_CONFIANZA"
            if request.es_confiable
            else "REVOCAR_DISPOSITIVO_CONFIANZA"
        )
        self.auth_repo.create_audit_event(
            accion=accion,
            tipo_evento="DISPOSITIVO",
            resultado="EXITO",
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            ip=client_ip,
            user_agent=user_agent,
            detalles={
                "nombre": device.nombre,
                "es_confiable": device.es_confiable,
                "accion": "MODIFICAR_CONFIANZA",
            },
        )

        is_current = bool(
            current_device_identifier
            and device.identificador_seguro == current_device_identifier
        )
        read_item = DeviceRead.model_validate(device)
        read_item.es_dispositivo_actual = is_current

        msg = (
            f"El dispositivo '{device.nombre}' ha sido autorizado como Dispositivo de Confianza."
            if request.es_confiable
            else f"Se ha revocado la confianza del dispositivo '{device.nombre}'."
        )
        return DeviceActionResponse(
            status="ok",
            message=msg,
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
