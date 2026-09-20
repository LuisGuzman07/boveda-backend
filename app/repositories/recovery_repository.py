from datetime import datetime, timedelta, timezone
from typing import Optional
import uuid
from sqlalchemy import or_, select, update
from sqlalchemy.orm import Session
from app.core.security import hash_token
from app.models.auth import DesafioDispositivo, Sesion, SesionBoveda, Usuario
from app.models.mfa import AutenticadorMfa, RecuperacionCuenta


class RecoveryRepository:
    def __init__(self, db: Session):
        self.db = db

    def find_user_by_email(self, email: str) -> Optional[Usuario]:
        stmt = select(Usuario).where(Usuario.correo == email.lower().strip())
        return self.db.scalars(stmt).first()

    def find_user_by_id(self, user_id: uuid.UUID) -> Optional[Usuario]:
        stmt = select(Usuario).where(Usuario.id_usuario == user_id)
        return self.db.scalars(stmt).first()

    def find_user_by_id_for_update(self, user_id: uuid.UUID) -> Optional[Usuario]:
        return self.db.scalars(
            select(Usuario)
            .where(Usuario.id_usuario == user_id)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).first()

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

        token_record = RecuperacionCuenta(
            id_recuperacion=uuid.uuid4(),
            id_usuario=user_id,
            codigo=f"REC-{uuid.uuid4().hex[:12].upper()}",
            token_hash=hash_token(raw_token.strip()),
            tipo="RESET_TOKEN",
            utilizado=False,
            fecha_creacion=now,
            fecha_expiracion=expires_at,
        )
        self.db.add(token_record)
        self.db.flush()
        return token_record

    def get_valid_token_record(self, raw_token: str) -> Optional[RecuperacionCuenta]:
        """Obtiene el registro del token si existe, no ha sido usado y no ha expirado."""
        token_hash = hash_token(raw_token.strip())
        stmt = select(RecuperacionCuenta).where(
            RecuperacionCuenta.token_hash == token_hash,
            RecuperacionCuenta.tipo == "RESET_TOKEN",
            RecuperacionCuenta.utilizado == False,
        )
        record = self.db.scalars(stmt).first()
        if not record:
            return None

        now = datetime.now(timezone.utc)
        expires_at = record.fecha_expiracion
        if expires_at and expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)
        if expires_at and expires_at < now:
            return None

        return record

    def consume_token_if_valid(self, token_record: RecuperacionCuenta, raw_token: str) -> bool:
        """Claims a token only if it is still unused and unexpired."""
        now = datetime.now(timezone.utc)
        statement = (
            update(RecuperacionCuenta)
            .where(
                RecuperacionCuenta.id_recuperacion == token_record.id_recuperacion,
                RecuperacionCuenta.token_hash == hash_token(raw_token.strip()),
                RecuperacionCuenta.tipo == "RESET_TOKEN",
                RecuperacionCuenta.utilizado.is_(False),
                or_(
                    RecuperacionCuenta.fecha_expiracion.is_(None),
                    RecuperacionCuenta.fecha_expiracion > now,
                ),
            )
            .values(utilizado=True, fecha_utilizacion=now)
            .execution_options(synchronize_session=False)
        )
        result = self.db.execute(statement)
        return result.rowcount == 1

    def invalidate_token(self, token_record: RecuperacionCuenta) -> None:
        """Makes a token unusable when email delivery did not complete."""
        token_record.utilizado = True
        token_record.fecha_utilizacion = datetime.now(timezone.utc)
        self.db.add(token_record)

    def update_user_password(self, user: Usuario, new_password_hash: str) -> None:
        """Stages a password change for the surrounding recovery transaction."""
        now = datetime.now(timezone.utc)
        user.password_hash = new_password_hash
        user.intentos_fallidos = 0
        user.bloqueado_hasta = None
        user.fecha_actualizacion = now
        self.db.add(user)

    def revoke_all_user_sessions(
        self, user_id: uuid.UUID, motivo: str = "RESTABLECIMIENTO_CONTRASENA"
    ) -> int:
        """Revoca todas las sesiones activas del usuario."""
        user = self.find_user_by_id_for_update(user_id)
        if not user:
            return 0
        now = datetime.now(timezone.utc)
        user.version_seguridad += 1
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

        self.db.execute(
            update(SesionBoveda)
            .where(SesionBoveda.id_usuario == user_id, SesionBoveda.revocada.is_(False))
            .values(revocada=True, motivo_revocacion=motivo)
        )
        self.db.execute(
            update(DesafioDispositivo)
            .where(
                DesafioDispositivo.id_usuario == user_id,
                DesafioDispositivo.consumido_en.is_(None),
            )
            .values(consumido_en=now, intentos=DesafioDispositivo.intentos + 1)
        )

        return count

    def revoke_mfa_and_backup_codes(self, user_id: uuid.UUID) -> None:
        """Recovery removes every remaining MFA capability before committing reset."""
        now = datetime.now(timezone.utc)
        self.db.execute(
            update(AutenticadorMfa)
            .where(
                AutenticadorMfa.id_usuario == user_id,
                AutenticadorMfa.estado.in_(["PENDIENTE", "ACTIVO"]),
            )
            .values(estado="REVOCADO")
        )
        self.db.execute(
            update(RecuperacionCuenta)
            .where(
                RecuperacionCuenta.id_usuario == user_id,
                RecuperacionCuenta.tipo.in_(["BACKUP_CODE", "PENDING_BACKUP_CODE"]),
                RecuperacionCuenta.utilizado.is_(False),
            )
            .values(utilizado=True, fecha_utilizacion=now)
        )
