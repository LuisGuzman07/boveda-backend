from datetime import datetime, timezone
from typing import List, Optional
import uuid
from fastapi import HTTPException, status
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from app.core.device_crypto import DeviceCryptoError, normalize_ed25519_public_key
from app.models.auth import Dispositivo, EventoAuditoria, Rol, Sesion, SesionBoveda, Usuario
from app.schemas.auth import DispositivoInfo


class AuthRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_user_by_email(self, email: str) -> Optional[Usuario]:
        """Obtiene un usuario por su correo electrónico."""
        stmt = select(Usuario).where(Usuario.correo == email.lower().strip())
        return self.db.scalars(stmt).first()

    def get_user_by_id(self, user_id: uuid.UUID) -> Optional[Usuario]:
        """Obtiene un usuario por su ID primario."""
        stmt = select(Usuario).where(Usuario.id_usuario == user_id)
        return self.db.scalars(stmt).first()

    def get_role_by_name(self, name: str) -> Optional[Rol]:
        """Obtiene un rol por su nombre."""
        stmt = select(Rol).where(Rol.nombre == name)
        return self.db.scalars(stmt).first()

    def create_user(
        self,
        nombre: str,
        correo: str,
        password_hash: str,
        roles: Optional[List[Rol]] = None,
    ) -> Usuario:
        """Crea y persiste un nuevo usuario con sus roles asignados."""
        user = Usuario(
            id_usuario=uuid.uuid4(),
            nombre=nombre.strip(),
            correo=correo.lower().strip(),
            password_hash=password_hash,
            correo_verificado=False,
            estado="ACTIVO",
            intentos_fallidos=0,
            roles=roles or [],
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def update_user(self, user: Usuario) -> Usuario:
        """Actualiza y persiste el estado de un usuario."""
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def get_or_create_device(
        self, user_id: uuid.UUID, info: DispositivoInfo
    ) -> Dispositivo:
        """Registers a pending device identity without granting trust from client input."""
        stmt = select(Dispositivo).where(
            Dispositivo.id_usuario == user_id,
            Dispositivo.identificador_seguro == info.identificador_seguro,
        )
        device = self.db.scalars(stmt).first()

        if device:
            if device.estado == "REVOKED":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="El dispositivo fue revocado y no puede reactivarse.",
                )
            device.ultimo_acceso = datetime.now(timezone.utc)
            if info.nombre:
                device.nombre = info.nombre
            if info.sistema_operativo:
                device.sistema_operativo = info.sistema_operativo
            if info.public_key:
                public_key, fingerprint = self._normalize_device_key(info.public_key)
                if device.public_key and device.public_key != public_key:
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="El identificador de instalacion ya pertenece a otra identidad criptografica.",
                    )
                if not device.public_key:
                    device.public_key = public_key
                    device.algoritmo_clave = "Ed25519"
                    device.huella_clave_publica = fingerprint
                    device.estado = "PENDING"
                    device.es_confiable = False
                    device.identidad_verificada_en = None
                    device.confianza_otorgada_en = None
            if info.vault_public_key:
                vault_public_key, _ = self._normalize_device_key(info.vault_public_key)
                if (
                    device.clave_firma_boveda
                    and device.clave_firma_boveda != vault_public_key
                ):
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="La clave de firma CU06 no coincide con la registrada para este dispositivo.",
                    )
                device.clave_firma_boveda = vault_public_key
            elif not device.clave_firma_boveda and device.public_key:
                device.clave_firma_boveda = device.public_key
        else:
            public_key = None
            fingerprint = None
            vault_public_key = None
            if info.public_key:
                public_key, fingerprint = self._normalize_device_key(info.public_key)
            if info.vault_public_key:
                vault_public_key, _ = self._normalize_device_key(info.vault_public_key)
            else:
                vault_public_key = public_key
            device = Dispositivo(
                id_usuario=user_id,
                nombre=info.nombre,
                tipo=info.tipo,
                sistema_operativo=info.sistema_operativo,
                identificador_seguro=info.identificador_seguro or str(uuid.uuid4()),
                public_key=public_key,
                clave_firma_boveda=vault_public_key,
                algoritmo_clave="Ed25519" if public_key else None,
                huella_clave_publica=fingerprint,
                es_confiable=False,
                estado="PENDING",
            )
            self.db.add(device)

        self.db.commit()
        self.db.refresh(device)
        return device

    @staticmethod
    def _normalize_device_key(value: str) -> tuple[str, str]:
        try:
            return normalize_ed25519_public_key(value)
        except DeviceCryptoError as error:
            raise HTTPException(
                status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
                detail="La clave publica Ed25519 no es valida.",
            ) from error

    def create_session(
        self,
        user_id: uuid.UUID,
        device_id: Optional[uuid.UUID],
        refresh_token_hash: str,
        expires_at: datetime,
        session_id: Optional[uuid.UUID] = None,
        family_id: Optional[uuid.UUID] = None,
        refresh_jti: Optional[str] = None,
        client_type: str = "NATIVE",
        csrf_hash: Optional[str] = None,
        mfa_verified_at: Optional[datetime] = None,
    ) -> Sesion:
        """Registra una nueva sesión en la base de datos."""
        session = Sesion(
            id_sesion=session_id or uuid.uuid4(),
            id_usuario=user_id,
            id_dispositivo=device_id,
            refresh_token_hash=refresh_token_hash,
            familia_refresh_id=family_id or uuid.uuid4(),
            refresh_jti=refresh_jti,
            tipo_cliente=client_type,
            csrf_hash=csrf_hash,
            mfa_verificado_en=mfa_verified_at,
            revocada=False,
            fecha_expiracion=expires_at,
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    def get_session_by_token_hash(self, token_hash: str) -> Optional[Sesion]:
        """Busca una sesión activa por el hash del refresh token."""
        stmt = select(Sesion).where(
            Sesion.refresh_token_hash == token_hash,
            Sesion.revocada == False,
        )
        return self.db.scalars(stmt).first()

    def get_session_by_id(self, session_id: uuid.UUID) -> Optional[Sesion]:
        return self.db.get(Sesion, session_id)

    def get_device_by_id(self, device_id: uuid.UUID) -> Optional[Dispositivo]:
        return self.db.get(Dispositivo, device_id)

    def rotate_refresh_token(
        self,
        session: Sesion,
        expected_jti: str,
        expected_hash: str,
        new_jti: str,
        new_hash: str,
        csrf_hash: Optional[str],
        now: datetime,
    ) -> bool:
        result = self.db.execute(
            update(Sesion)
            .where(
                Sesion.id_sesion == session.id_sesion,
                Sesion.revocada.is_(False),
                Sesion.refresh_jti == expected_jti,
                Sesion.refresh_token_hash == expected_hash,
            )
            .values(
                refresh_jti=new_jti,
                refresh_token_hash=new_hash,
                csrf_hash=csrf_hash,
                refresh_consumido_en=now,
                ultima_actividad=now,
            )
        )
        self.db.commit()
        return result.rowcount == 1

    def revoke_refresh_family(self, family_id: uuid.UUID, motivo: str) -> int:
        now = datetime.now(timezone.utc)
        session_ids = select(Sesion.id_sesion).where(Sesion.familia_refresh_id == family_id)
        self.db.execute(
            update(SesionBoveda)
            .where(SesionBoveda.id_sesion.in_(session_ids), SesionBoveda.revocada.is_(False))
            .values(revocada=True, motivo_revocacion=motivo)
        )
        result = self.db.execute(
            update(Sesion)
            .where(Sesion.familia_refresh_id == family_id, Sesion.revocada.is_(False))
            .values(revocada=True, motivo_revocacion=motivo, ultima_actividad=now)
        )
        self.db.commit()
        return result.rowcount or 0

    def revoke_session(self, session: Sesion, motivo: str = "LOGOUT") -> Sesion:
        """Marca una sesión como revocada."""
        session.revocada = True
        session.motivo_revocacion = motivo
        session.ultima_actividad = datetime.now(timezone.utc)
        self.db.execute(
            update(SesionBoveda)
            .where(SesionBoveda.id_sesion == session.id_sesion, SesionBoveda.revocada.is_(False))
            .values(revocada=True, motivo_revocacion=motivo)
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    def create_audit_event(
        self,
        accion: str,
        tipo_evento: str,
        resultado: str,
        user_id: Optional[uuid.UUID] = None,
        device_id: Optional[uuid.UUID] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        detalles: Optional[dict] = None,
    ) -> EventoAuditoria:
        """Crea un registro inmutable en la tabla EVENTO_AUDITORIA."""
        event = EventoAuditoria(
            id_usuario=user_id,
            id_dispositivo=device_id,
            accion=accion,
            tipo_evento=tipo_evento,
            resultado=resultado,
            direccion_ip=ip,
            user_agent=user_agent,
            detalles=detalles,
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event
