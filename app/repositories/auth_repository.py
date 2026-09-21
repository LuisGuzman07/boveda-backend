from datetime import datetime, timezone
import hashlib
from typing import List, Optional
import uuid
from fastapi import HTTPException, status
from sqlalchemy import and_, or_, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session
from app.core.device_crypto import DeviceCryptoError, normalize_ed25519_public_key
from app.models.auth import (
    DesafioDispositivo,
    Dispositivo,
    EventoAuditoria,
    IdentidadDispositivo,
    Rol,
    Sesion,
    SesionBoveda,
    Usuario,
)
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

    def lock_user(self, user_id: uuid.UUID) -> Optional[Usuario]:
        """Serializes changes that can invalidate every session of one user."""
        return self.db.scalars(
            select(Usuario)
            .where(Usuario.id_usuario == user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()

    def get_active_session_for_update(
        self,
        session_id: uuid.UUID,
        user_id: uuid.UUID,
        security_version: int,
    ) -> Sesion:
        session = self.db.scalars(
            select(Sesion)
            .where(
                Sesion.id_sesion == session_id,
                Sesion.id_usuario == user_id,
                Sesion.revocada.is_(False),
                Sesion.version_seguridad == security_version,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()
        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sesión expirada o revocada.",
            )
        return session

    def lock_authenticated_session(
        self,
        user_id: uuid.UUID,
        device_id: uuid.UUID,
        session_id: uuid.UUID,
    ) -> tuple[Usuario, Dispositivo, Sesion]:
        """Re-checks an actor's server session at the mutation lock boundary."""
        user = self.lock_user(user_id)
        device = self.db.scalars(
            select(Dispositivo)
            .where(Dispositivo.id_dispositivo == device_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()
        session = self.db.scalars(
            select(Sesion)
            .where(Sesion.id_sesion == session_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()
        expires_at = session.fecha_expiracion if session else None
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if (
            not user
            or user.estado != "ACTIVO"
            or not device
            or device.id_usuario != user_id
            or device.estado == "REVOKED"
            or not session
            or session.revocada
            or not expires_at
            or expires_at <= datetime.now(timezone.utc)
            or session.id_usuario != user_id
            or session.id_dispositivo != device_id
            or session.version_seguridad != user.version_seguridad
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sesión expirada o revocada.",
            )
        return user, device, session

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
        self,
        user_id: uuid.UUID,
        info: DispositivoInfo,
        *,
        expected_security_version: Optional[int] = None,
    ) -> Dispositivo:
        """Registers a pending identity while retaining its global terminal claim."""
        user = self.lock_user(user_id)
        if not user or user.estado != "ACTIVO":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario no válido o inactivo.",
            )
        if (
            expected_security_version is not None
            and user.version_seguridad != expected_security_version
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="El estado de seguridad cambió. Inicia sesión nuevamente.",
            )

        secure_id = info.identificador_seguro or str(uuid.uuid4())
        public_key = None
        fingerprint = None
        vault_public_key = None
        if info.public_key:
            public_key, fingerprint = self._normalize_device_key(info.public_key)
        if info.vault_public_key:
            vault_public_key, _ = self._normalize_device_key(info.vault_public_key)

        device = self.db.scalars(
            select(Dispositivo)
            .where(
                Dispositivo.id_usuario == user_id,
                Dispositivo.identificador_seguro == secure_id,
            )
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()

        if device:
            if device.estado == "REVOKED":
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="La identidad de instalación fue revocada y no puede registrarse de nuevo.",
                )
            device.ultimo_acceso = datetime.now(timezone.utc)
            if info.nombre:
                device.nombre = info.nombre
            if info.sistema_operativo:
                device.sistema_operativo = info.sistema_operativo
            if public_key:
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
                    device.confianza_otorgada_por = None
            if vault_public_key:
                if (
                    device.clave_firma_boveda
                    and device.clave_firma_boveda != vault_public_key
                ):
                    raise HTTPException(
                        status_code=status.HTTP_409_CONFLICT,
                        detail="La clave de firma CU06 no coincide con la registrada para este dispositivo.",
                    )
                device.clave_firma_boveda = vault_public_key
        else:
            device = Dispositivo(
                id_usuario=user_id,
                nombre=info.nombre,
                tipo=info.tipo,
                sistema_operativo=info.sistema_operativo,
                identificador_seguro=secure_id,
                public_key=public_key,
                clave_firma_boveda=vault_public_key,
                algoritmo_clave="Ed25519" if public_key else None,
                huella_clave_publica=fingerprint,
                es_confiable=False,
                estado="PENDING",
            )
            self.db.add(device)

        try:
            self.db.flush()
            self._claim_device_identities(device, secure_id, fingerprint)
            self.db.commit()
        except IntegrityError as error:
            self.db.rollback()
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="La identidad de instalación ya fue registrada y no puede reutilizarse.",
            ) from error
        self.db.refresh(device)
        return device

    def _claim_device_identities(
        self,
        device: Dispositivo,
        secure_id: str,
        public_key_fingerprint: Optional[str],
    ) -> None:
        claims = [
            ("INSTALLATION_ID", hashlib.sha256(secure_id.encode("utf-8")).hexdigest())
        ]
        if public_key_fingerprint:
            claims.append(("DEVICE_KEY", public_key_fingerprint))
        conditions = [
            and_(IdentidadDispositivo.tipo == kind, IdentidadDispositivo.huella == fingerprint)
            for kind, fingerprint in claims
        ]
        existing = self.db.scalars(
            select(IdentidadDispositivo).where(or_(*conditions)).with_for_update()
        ).all()
        existing_by_identity = {(claim.tipo, claim.huella): claim for claim in existing}
        for kind, fingerprint in claims:
            claim = existing_by_identity.get((kind, fingerprint))
            if claim and claim.id_dispositivo != device.id_dispositivo:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="La identidad de instalación fue revocada o ya pertenece a otro dispositivo.",
                )
            if not claim:
                self.db.add(
                    IdentidadDispositivo(
                        id_identidad=uuid.uuid4(),
                        id_dispositivo=device.id_dispositivo,
                        tipo=kind,
                        huella=fingerprint,
                    )
                )

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
        expected_security_version: Optional[int] = None,
    ) -> Sesion:
        """Registra una nueva sesión en la base de datos."""
        user = self.lock_user(user_id)
        if not user or user.estado != "ACTIVO":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario no válido o inactivo.",
            )
        if (
            expected_security_version is not None
            and user.version_seguridad != expected_security_version
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="El estado de seguridad cambió. Inicia sesión nuevamente.",
            )
        if device_id:
            active_device = self.db.scalars(
                select(Dispositivo)
                .where(
                    Dispositivo.id_dispositivo == device_id,
                    Dispositivo.id_usuario == user_id,
                    Dispositivo.estado != "REVOKED",
                )
                .with_for_update()
                .execution_options(populate_existing=True)
            ).first()
            if not active_device:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="El dispositivo asociado fue revocado.",
                )
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
            version_seguridad=user.version_seguridad,
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
                Sesion.version_seguridad
                == select(Usuario.version_seguridad)
                .where(Usuario.id_usuario == Sesion.id_usuario)
                .scalar_subquery(),
                Sesion.id_dispositivo.in_(
                    select(Dispositivo.id_dispositivo).where(
                        Dispositivo.estado != "REVOKED"
                    )
                ),
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

    def revoke_session_capabilities(self, session: Sesion, motivo: str) -> bool:
        """Revokes one refresh-backed session and its vault capabilities without committing."""
        now = datetime.now(timezone.utc)
        revoked = self.db.execute(
            update(Sesion)
            .where(Sesion.id_sesion == session.id_sesion, Sesion.revocada.is_(False))
            .values(revocada=True, motivo_revocacion=motivo, ultima_actividad=now)
        )
        if revoked.rowcount != 1:
            return False
        self.db.execute(
            update(SesionBoveda)
            .where(SesionBoveda.id_sesion == session.id_sesion, SesionBoveda.revocada.is_(False))
            .values(revocada=True, motivo_revocacion=motivo)
        )
        return True

    def touch_web_session(self, session: Sesion, security_version: int) -> bool:
        """Records activity only while the server-side web session remains current."""
        touched = self.db.execute(
            update(Sesion)
            .where(
                Sesion.id_sesion == session.id_sesion,
                Sesion.revocada.is_(False),
                Sesion.version_seguridad == security_version,
            )
            .values(ultima_actividad=datetime.now(timezone.utc))
        )
        return touched.rowcount == 1

    def revoke_user_security_state(
        self,
        user_id: uuid.UUID,
        motivo: str,
        *,
        commit: bool = True,
    ) -> int:
        """Invalidate every server-side capability that depends on a user session."""
        user = self.lock_user(user_id)
        if not user:
            return 0
        now = datetime.now(timezone.utc)
        user.version_seguridad += 1
        session_ids = select(Sesion.id_sesion).where(Sesion.id_usuario == user_id)
        self.db.execute(
            update(SesionBoveda)
            .where(SesionBoveda.id_usuario == user_id, SesionBoveda.revocada.is_(False))
            .values(revocada=True, motivo_revocacion=motivo)
        )
        result = self.db.execute(
            update(Sesion)
            .where(Sesion.id_usuario == user_id, Sesion.revocada.is_(False))
            .values(revocada=True, motivo_revocacion=motivo, ultima_actividad=now)
        )
        self.db.execute(
            update(DesafioDispositivo)
            .where(
                DesafioDispositivo.id_usuario == user_id,
                DesafioDispositivo.consumido_en.is_(None),
                DesafioDispositivo.id_sesion.in_(session_ids),
            )
            .values(consumido_en=now, intentos=DesafioDispositivo.intentos + 1)
        )
        if commit:
            self.db.commit()
        return result.rowcount or 0

    def add_audit_event(
        self,
        accion: str,
        tipo_evento: str,
        resultado: str,
        user_id: Optional[uuid.UUID] = None,
        device_id: Optional[uuid.UUID] = None,
        resource_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        detalles: Optional[dict] = None,
    ) -> EventoAuditoria:
        event = EventoAuditoria(
            id_usuario=user_id,
            id_dispositivo=device_id,
            accion=accion,
            tipo_evento=tipo_evento,
            resultado=resultado,
            recurso_id=resource_id,
            recurso_tipo=resource_type,
            direccion_ip=ip,
            user_agent=user_agent,
            detalles=detalles,
        )
        self.db.add(event)
        return event

    def create_audit_event(
        self,
        accion: str,
        tipo_evento: str,
        resultado: str,
        user_id: Optional[uuid.UUID] = None,
        device_id: Optional[uuid.UUID] = None,
        resource_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        detalles: Optional[dict] = None,
    ) -> EventoAuditoria:
        """Crea un registro inmutable en la tabla EVENTO_AUDITORIA."""
        event = self.add_audit_event(
            accion=accion,
            tipo_evento=tipo_evento,
            resultado=resultado,
            user_id=user_id,
            device_id=device_id,
            resource_id=resource_id,
            resource_type=resource_type,
            ip=ip,
            user_agent=user_agent,
            detalles=detalles,
        )
        self.db.commit()
        self.db.refresh(event)
        return event
