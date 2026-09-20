from datetime import datetime, timezone
import hashlib
from typing import List, Optional
import uuid
from sqlalchemy import case, select, update
from sqlalchemy.orm import Session
from app.models.mfa import AutenticadorMfa, RecuperacionCuenta


class MfaRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_active_mfa(
        self, user_id: uuid.UUID, *, lock: bool = False
    ) -> Optional[AutenticadorMfa]:
        """Obtiene el autenticador MFA activo del usuario."""
        stmt = select(AutenticadorMfa).where(
            AutenticadorMfa.id_usuario == user_id,
            AutenticadorMfa.estado == "ACTIVO",
        )
        if lock:
            stmt = stmt.with_for_update().execution_options(populate_existing=True)
        return self.db.scalars(stmt).first()

    def get_pending_mfa(
        self, user_id: uuid.UUID, *, lock: bool = False
    ) -> Optional[AutenticadorMfa]:
        stmt = select(AutenticadorMfa).where(
            AutenticadorMfa.id_usuario == user_id,
            AutenticadorMfa.estado == "PENDIENTE",
        ).order_by(AutenticadorMfa.fecha_registro.desc())
        if lock:
            stmt = stmt.with_for_update().execution_options(populate_existing=True)
        return self.db.scalars(stmt).first()

    def get_pending_or_active_mfa(self, user_id: uuid.UUID) -> Optional[AutenticadorMfa]:
        """Obtiene el autenticador en configuración pendiente o activo."""
        stmt = select(AutenticadorMfa).where(
            AutenticadorMfa.id_usuario == user_id,
            AutenticadorMfa.estado.in_(["PENDIENTE", "ACTIVO"]),
        ).order_by(
            case((AutenticadorMfa.estado == "PENDIENTE", 0), else_=1),
            AutenticadorMfa.fecha_registro.desc(),
        )
        return self.db.scalars(stmt).first()

    def save_mfa(self, mfa: AutenticadorMfa, *, commit: bool = True) -> AutenticadorMfa:
        """Guarda o actualiza el registro de autenticador MFA."""
        self.db.add(mfa)
        if commit:
            self.db.commit()
            self.db.refresh(mfa)
        return mfa

    def revoke_mfa(self, user_id: uuid.UUID, *, commit: bool = True) -> None:
        """Revoca autenticadores y códigos de respaldo en la misma security boundary."""
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
        if commit:
            self.db.commit()

    def revoke_other_active_mfa(
        self,
        user_id: uuid.UUID,
        retained_id: uuid.UUID,
        *,
        commit: bool = True,
    ) -> int:
        """Retires the old authenticator only after a replacement is verified."""
        result = self.db.execute(
            update(AutenticadorMfa)
            .where(
                AutenticadorMfa.id_usuario == user_id,
                AutenticadorMfa.id_autenticador != retained_id,
                AutenticadorMfa.estado == "ACTIVO",
            )
            .values(estado="REVOCADO")
        )
        if commit:
            self.db.commit()
        return result.rowcount or 0

    def save_pending_recovery_codes(
        self,
        user_id: uuid.UUID,
        raw_codes: List[str],
        *,
        commit: bool = True,
    ) -> List[RecuperacionCuenta]:
        """Stores setup codes in a state that cannot complete an MFA login yet."""
        now = datetime.now(timezone.utc)
        old_stmt = select(RecuperacionCuenta).where(
            RecuperacionCuenta.id_usuario == user_id,
            RecuperacionCuenta.tipo == "PENDING_BACKUP_CODE",
            RecuperacionCuenta.utilizado == False,
        )
        for old in self.db.scalars(old_stmt).all():
            old.utilizado = True
            old.fecha_utilizacion = now
            self.db.add(old)

        created = []
        for code in raw_codes:
            code_hash = hashlib.sha256(code.strip().encode("utf-8")).hexdigest()
            item = RecuperacionCuenta(
                id_recuperacion=uuid.uuid4(),
                id_usuario=user_id,
                codigo=f"****-{code[-4:]}",
                token_hash=code_hash,
                tipo="PENDING_BACKUP_CODE",
                utilizado=False,
            )
            self.db.add(item)
            created.append(item)

        if commit:
            self.db.commit()
        return created

    def activate_pending_recovery_codes(
        self, user_id: uuid.UUID, *, commit: bool = True
    ) -> int:
        """Activates only codes linked to a successfully verified pending setup."""
        now = datetime.now(timezone.utc)
        self.db.execute(
            update(RecuperacionCuenta)
            .where(
                RecuperacionCuenta.id_usuario == user_id,
                RecuperacionCuenta.tipo == "BACKUP_CODE",
                RecuperacionCuenta.utilizado.is_(False),
            )
            .values(utilizado=True, fecha_utilizacion=now)
        )
        activated = self.db.execute(
            update(RecuperacionCuenta)
            .where(
                RecuperacionCuenta.id_usuario == user_id,
                RecuperacionCuenta.tipo == "PENDING_BACKUP_CODE",
                RecuperacionCuenta.utilizado.is_(False),
            )
            .values(tipo="BACKUP_CODE")
        )
        if commit:
            self.db.commit()
        return activated.rowcount or 0

    def verify_and_consume_recovery_code(
        self, user_id: uuid.UUID, raw_code: str, *, commit: bool = True
    ) -> bool:
        """Verifica y consume un código de recuperación."""
        code_hash = hashlib.sha256(raw_code.strip().encode("utf-8")).hexdigest()
        result = self.db.execute(
            update(RecuperacionCuenta)
            .where(
                RecuperacionCuenta.id_usuario == user_id,
                RecuperacionCuenta.token_hash == code_hash,
                RecuperacionCuenta.tipo == "BACKUP_CODE",
                RecuperacionCuenta.utilizado.is_(False),
            )
            .values(
                utilizado=True,
                fecha_utilizacion=datetime.now(timezone.utc),
            )
        )
        if commit:
            self.db.commit()
        return result.rowcount == 1
