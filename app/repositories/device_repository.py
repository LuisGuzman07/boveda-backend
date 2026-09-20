from datetime import datetime, timezone
from typing import List, Optional
import uuid
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from app.models.auth import DesafioDispositivo, Dispositivo, Sesion, SesionBoveda, Usuario
from app.repositories.auth_repository import AuthRepository
from app.schemas.device import DeviceRegisterRequest


class DeviceRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_user_devices(self, user_id: uuid.UUID) -> List[Dispositivo]:
        """Retorna todos los dispositivos asociados al usuario ordenados por último acceso."""
        stmt = (
            select(Dispositivo)
            .where(
                Dispositivo.id_usuario == user_id,
            )
            .order_by(Dispositivo.ultimo_acceso.desc())
        )
        return list(self.db.scalars(stmt).all())

    def get_device_by_id(self, device_id: uuid.UUID, user_id: uuid.UUID) -> Optional[Dispositivo]:
        """Obtiene un dispositivo por su ID asegurando que pertenezca al usuario especificado."""
        stmt = select(Dispositivo).where(
            Dispositivo.id_dispositivo == device_id,
            Dispositivo.id_usuario == user_id,
        )
        return self.db.scalars(stmt).first()

    def get_device_by_secure_id(self, user_id: uuid.UUID, secure_id: str) -> Optional[Dispositivo]:
        """Busca un dispositivo por su identificador seguro persistente."""
        stmt = select(Dispositivo).where(
            Dispositivo.id_usuario == user_id,
            Dispositivo.identificador_seguro == secure_id,
        )
        return self.db.scalars(stmt).first()

    def create_or_update_device(
        self,
        user_id: uuid.UUID,
        data: DeviceRegisterRequest,
    ) -> Dispositivo:
        """Registra un nuevo dispositivo o actualiza su última conexión y metadatos."""
        now = datetime.now(timezone.utc)
        device = self.get_device_by_secure_id(user_id, data.identificador_seguro)

        if device:
            device.ultimo_acceso = now
            if data.nombre:
                device.nombre = data.nombre
            if data.tipo:
                device.tipo = data.tipo
            if data.sistema_operativo:
                device.sistema_operativo = data.sistema_operativo
            if device.estado == "REVOKED":
                raise ValueError("A revoked device cannot be re-registered.")
        else:
            device = Dispositivo(
                id_usuario=user_id,
                nombre=data.nombre or "Dispositivo Desconocido",
                tipo=data.tipo or "WEB",
                sistema_operativo=data.sistema_operativo or "Desconocido",
                identificador_seguro=data.identificador_seguro,
                public_key=data.public_key,
                es_confiable=False,
                estado="PENDING",
                fecha_registro=now,
                ultimo_acceso=now,
            )
            self.db.add(device)

        self.db.commit()
        self.db.refresh(device)
        return device

    def revoke_and_delete_device(
        self,
        device: Dispositivo,
        revocado_por: uuid.UUID,
    ) -> None:
        """Preserva la identidad revocada como tombstone e invalida sus capacidades."""
        self._revoke_devices(
            [device.id_dispositivo],
            revocado_por,
            motivo="DISPOSITIVO_DESVINCULADO",
        )
        self.db.refresh(device)

    def _revoke_devices(
        self,
        device_ids: List[uuid.UUID],
        revocado_por: uuid.UUID,
        motivo: str,
        *,
        commit: bool = True,
    ) -> int:
        """Make revocation terminal before invalidating dependent capabilities."""
        if not device_ids:
            return 0
        now = datetime.now(timezone.utc)
        # This conditional update obtains the device row lock in PostgreSQL. Any stale
        # proof or approval must re-evaluate its state after this transaction commits.
        revoked = self.db.execute(
            update(Dispositivo)
            .where(
                Dispositivo.id_dispositivo.in_(device_ids),
                Dispositivo.estado != "REVOKED",
            )
            .values(
                estado="REVOKED",
                es_confiable=False,
                fecha_revocacion=now,
                revocado_por=revocado_por,
            )
            .execution_options(synchronize_session=False)
        )
        session_ids = select(Sesion.id_sesion).where(Sesion.id_dispositivo.in_(device_ids))
        self.db.execute(
            update(DesafioDispositivo)
            .where(
                DesafioDispositivo.id_dispositivo.in_(device_ids),
                DesafioDispositivo.consumido_en.is_(None),
            )
            .values(consumido_en=now, intentos=DesafioDispositivo.intentos + 1)
        )
        self.db.execute(
            update(SesionBoveda)
            .where(
                SesionBoveda.id_sesion.in_(session_ids),
                SesionBoveda.revocada.is_(False),
            )
            .values(revocada=True, motivo_revocacion="DISPOSITIVO_REVOCADO")
        )
        self.db.execute(
            update(Sesion)
            .where(Sesion.id_dispositivo.in_(device_ids), Sesion.revocada.is_(False))
            .values(
                revocada=True,
                motivo_revocacion=motivo,
                ultima_actividad=now,
            )
        )
        if commit:
            self.db.commit()
        return revoked.rowcount or 0

    # --- CU-05: Métodos de Gestión y Revocación Administrativa ---

    def get_device_by_id_global(self, device_id: uuid.UUID) -> Optional[Dispositivo]:
        """Obtiene un dispositivo por su ID sin filtrar por usuario (para uso administrativo)."""
        stmt = select(Dispositivo).where(Dispositivo.id_dispositivo == device_id)
        return self.db.scalars(stmt).first()

    def approve_pending_device(
        self,
        device_id: uuid.UUID,
        approver_id: uuid.UUID,
    ) -> Dispositivo:
        """Promotes only a possession-verified pending identity under a row lock."""
        device = self.db.scalars(
            select(Dispositivo)
            .where(Dispositivo.id_dispositivo == device_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()
        if not device:
            raise ValueError("DEVICE_NOT_FOUND")
        if device.id_usuario == approver_id:
            raise PermissionError("SELF_APPROVAL_FORBIDDEN")
        if device.estado == "REVOKED":
            raise ValueError("DEVICE_REVOKED")
        if not device.public_key or not device.identidad_verificada_en:
            raise ValueError("POSSESSION_PROOF_REQUIRED")
        if device.estado != "PENDING":
            raise ValueError("DEVICE_NOT_PENDING")

        now = datetime.now(timezone.utc)
        approved = self.db.execute(
            update(Dispositivo)
            .where(
                Dispositivo.id_dispositivo == device_id,
                Dispositivo.estado == "PENDING",
                Dispositivo.identidad_verificada_en.is_not(None),
            )
            .values(
                estado="TRUSTED",
                es_confiable=True,
                confianza_otorgada_en=now,
                confianza_otorgada_por=approver_id,
                ultimo_acceso=now,
            )
            .execution_options(synchronize_session=False)
        )
        if approved.rowcount != 1:
            self.db.rollback()
            raise ValueError("DEVICE_APPROVAL_RACE")
        self.db.flush()
        self.db.refresh(device)
        return device

    def get_all_devices_admin(
        self,
        query: Optional[str] = None,
        solo_confiables: Optional[bool] = None,
        estado: Optional[str] = None,
    ) -> List[dict]:
        """Retorna todos los dispositivos del sistema con datos del usuario y conteo de sesiones activas."""
        from sqlalchemy import func, or_
        from app.models.auth import Usuario

        # Subquery para contar sesiones activas por dispositivo
        sesiones_subquery = (
            select(
                Sesion.id_dispositivo,
                func.count(Sesion.id_sesion).label("activas_count"),
            )
            .where(Sesion.revocada == False)
            .group_by(Sesion.id_dispositivo)
            .subquery()
        )

        stmt = (
            select(
                Dispositivo,
                Usuario.nombre.label("user_nombre"),
                Usuario.correo.label("user_correo"),
                func.coalesce(sesiones_subquery.c.activas_count, 0).label("sesiones_activas"),
            )
            .join(Usuario, Dispositivo.id_usuario == Usuario.id_usuario)
            .outerjoin(
                sesiones_subquery,
                Dispositivo.id_dispositivo == sesiones_subquery.c.id_dispositivo,
            )
        )

        if solo_confiables is not None:
            stmt = stmt.where(Dispositivo.es_confiable == solo_confiables)

        if estado:
            stmt = stmt.where(Dispositivo.estado == estado)

        if query:
            search_pattern = f"%{query.strip()}%"
            stmt = stmt.where(
                or_(
                    Usuario.nombre.ilike(search_pattern),
                    Usuario.correo.ilike(search_pattern),
                    Dispositivo.nombre.ilike(search_pattern),
                    Dispositivo.sistema_operativo.ilike(search_pattern),
                    Dispositivo.identificador_seguro.ilike(search_pattern),
                )
            )

        stmt = stmt.order_by(Dispositivo.ultimo_acceso.desc())
        results = self.db.execute(stmt).all()

        device_list = []
        for dev, user_nombre, user_correo, sesiones_activas in results:
            device_list.append(
                {
                    "device": dev,
                    "usuario_nombre": user_nombre,
                    "usuario_correo": user_correo,
                    "sesiones_activas": sesiones_activas,
                }
            )
        return device_list

    def revoke_device_by_admin(
        self,
        device: Dispositivo,
        admin_id: uuid.UUID,
        motivo: str = "Revocación administrativa de seguridad",
    ) -> None:
        """CU-05: Invalida el dispositivo y revoca inmediatamente todas las sesiones activas vinculadas."""
        self._revoke_devices(
            [device.id_dispositivo],
            admin_id,
            motivo=f"REVOCADO_POR_ADMINISTRADOR: {motivo}",
        )
        self.db.refresh(device)

    def revoke_all_devices_for_user(
        self,
        user_id: uuid.UUID,
        admin_id: uuid.UUID,
        motivo: str = "Revocación masiva de terminales por seguridad",
    ) -> int:
        """CU-05: Revoca todos los dispositivos y todas las sesiones de una cuenta."""
        target_user = self.db.scalars(
            select(Usuario)
            .where(Usuario.id_usuario == user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()
        if not target_user:
            return 0
        device_ids = list(
            self.db.scalars(
                select(Dispositivo.id_dispositivo)
                .where(Dispositivo.id_usuario == user_id)
                .with_for_update()
            ).all()
        )
        revoked = self._revoke_devices(
            device_ids,
            admin_id,
            motivo=f"REVOCACION_MASIVA_ADMIN: {motivo}",
            commit=False,
        )
        AuthRepository(self.db).revoke_user_security_state(
            user_id,
            "REVOCACION_MASIVA_ADMIN",
            commit=False,
        )
        self.db.commit()
        return revoked
