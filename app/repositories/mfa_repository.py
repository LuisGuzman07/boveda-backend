from datetime import datetime, timezone
import hashlib
from typing import List, Optional
import uuid
from sqlalchemy import select, update
from sqlalchemy.orm import Session
from app.models.mfa import AutenticadorMfa, RecuperacionCuenta


class MfaRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_active_mfa(self, user_id: uuid.UUID) -> Optional[AutenticadorMfa]:
        """Obtiene el autenticador MFA activo del usuario."""
        stmt = select(AutenticadorMfa).where(
            AutenticadorMfa.id_usuario == user_id,
            AutenticadorMfa.estado == "ACTIVO",
        )
        return self.db.scalars(stmt).first()

    def get_pending_or_active_mfa(self, user_id: uuid.UUID) -> Optional[AutenticadorMfa]:
        """Obtiene el autenticador en configuración pendiente o activo."""
        stmt = select(AutenticadorMfa).where(
            AutenticadorMfa.id_usuario == user_id,
            AutenticadorMfa.estado.in_(["PENDIENTE", "ACTIVO"]),
        ).order_by(AutenticadorMfa.fecha_registro.desc())
        return self.db.scalars(stmt).first()

    def save_mfa(self, mfa: AutenticadorMfa) -> AutenticadorMfa:
        """Guarda o actualiza el registro de autenticador MFA."""
        self.db.add(mfa)
        self.db.commit()
        self.db.refresh(mfa)
        return mfa

    def revoke_mfa(self, user_id: uuid.UUID) -> None:
        """Revoca todos los autenticadores MFA del usuario."""
        stmt = select(AutenticadorMfa).where(
            AutenticadorMfa.id_usuario == user_id,
            AutenticadorMfa.estado == "ACTIVO",
        )
        for item in self.db.scalars(stmt).all():
            item.estado = "REVOCADO"
            self.db.add(item)
        self.db.commit()

    def save_recovery_codes(self, user_id: uuid.UUID, raw_codes: List[str]) -> List[RecuperacionCuenta]:
        """Guarda códigos de recuperación de emergencia con su respectivo hash."""
        # Invalidar códigos anteriores no utilizados
        old_stmt = select(RecuperacionCuenta).where(
            RecuperacionCuenta.id_usuario == user_id,
            RecuperacionCuenta.tipo == "BACKUP_CODE",
            RecuperacionCuenta.utilizado == False,
        )
        for old in self.db.scalars(old_stmt).all():
            old.utilizado = True
            self.db.add(old)

        created = []
        for code in raw_codes:
            code_hash = hashlib.sha256(code.strip().encode("utf-8")).hexdigest()
            item = RecuperacionCuenta(
                id_recuperacion=uuid.uuid4(),
                id_usuario=user_id,
                codigo=f"****-{code[-4:]}",
                token_hash=code_hash,
                tipo="BACKUP_CODE",
                utilizado=False,
            )
            self.db.add(item)
            created.append(item)

        self.db.commit()
        return created

    def verify_and_consume_recovery_code(self, user_id: uuid.UUID, raw_code: str) -> bool:
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
        self.db.commit()
        return result.rowcount == 1
