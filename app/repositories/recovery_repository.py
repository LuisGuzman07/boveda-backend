from datetime import datetime, timedelta, timezone
import hashlib
from typing import Optional
import uuid
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.auth import Sesion, Usuario
from app.models.mfa import RecuperacionCuenta


class RecoveryRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_user_by_email(self, email: str) -> Optional[Usuario]:
        stmt = select(Usuario).where(Usuario.correo == email.lower().strip())
        return self.db.scalars(stmt).first()

    def find_user_by_id(self, user_id: uuid.UUID) -> Optional[Usuario]:
        stmt = select(Usuario).where(Usuario.id_usuario == user_id)
        return self.db.scalars(stmt).first()

    def create_recovery_token(
        self, user_id: uuid.UUID, raw_token: str, expires_in_minutes: int = 15
    ) -> RecuperacionCuenta:
        """Invalida tokens previos y crea un nuevo token de recuperación con expiración."""
        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(minutes=expires_in_minutes)

        # Invalidar tokens previos de reseteo para este usuario
        old_stmt = select(RecuperacionCuenta).where(
            RecuperacionCuenta.id_usuario == user_id,
            RecuperacionCuenta.tipo == "RESET_TOKEN",
            RecuperacionCuenta.utilizado == False,
        )
        for old in self.db.scalars(old_stmt).all():
            old.utilizado = True
            old.fecha_utilizacion = now
            self.db.add(old)

        token_hash = hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()
        token_record = RecuperacionCuenta(
            id_recuperacion=uuid.uuid4(),
            id_usuario=user_id,
            codigo=f"RST-{raw_token[:6].upper()}",
            token_hash=token_hash,
            tipo="RESET_TOKEN",
            utilizado=False,
            fecha_creacion=now,
            fecha_expiracion=expires_at,
        )
        self.db.add(token_record)
        self.db.commit()
        self.db.refresh(token_record)
        return token_record

    def get_valid_token_record(self, raw_token: str) -> Optional[RecuperacionCuenta]:
        """Obtiene el registro del token si existe, no ha sido usado y no ha expirado."""
        token_hash = hashlib.sha256(raw_token.strip().encode("utf-8")).hexdigest()
        stmt = select(RecuperacionCuenta).where(
            RecuperacionCuenta.token_hash == token_hash,
            RecuperacionCuenta.tipo == "RESET_TOKEN",
            RecuperacionCuenta.utilizado == False,
        )
        record = self.db.scalars(stmt).first()
        if not record:
            return None

        now = datetime.now(timezone.utc)
        if record.fecha_expiracion and record.fecha_expiracion < now:
            return None

        return record

    def consume_token(self, token_record: RecuperacionCuenta) -> None:
        """Marca el token como utilizado."""
        token_record.utilizado = True
        token_record.fecha_utilizacion = datetime.now(timezone.utc)
        self.db.add(token_record)
        self.db.commit()

    def update_user_password(self, user: Usuario, new_password_hash: str) -> None:
        """Actualiza la contraseña y restablece bloqueos por intentos fallidos."""
        now = datetime.now(timezone.utc)
        user.password_hash = new_password_hash
        user.intentos_fallidos = 0
        user.bloqueado_hasta = None
        user.fecha_actualizacion = now
        self.db.add(user)
        self.db.commit()

    def revoke_all_user_sessions(
        self, user_id: uuid.UUID, motivo: str = "RESTABLECIMIENTO_CONTRASENA"
    ) -> int:
        """Revoca todas las sesiones activas del usuario."""
        now = datetime.now(timezone.utc)
        stmt = select(Sesion).where(
            Sesion.id_usuario == user_id,
            Sesion.revocada == False,
        )
        active_sessions = self.db.scalars(stmt).all()
        count = len(active_sessions)
        for s in active_sessions:
            s.revocada = True
            s.motivo_revocacion = motivo
            s.ultima_actividad = now
            self.db.add(s)

        self.db.commit()
        return count
