from datetime import datetime, timezone
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.vault import KitEmergencia


class EmergencyKitRepository:
    def __init__(self, db: Session):
        self.db = db

    def active_for_vault(self, vault_id: uuid.UUID, user_id: uuid.UUID) -> KitEmergencia | None:
        kit = self.db.scalars(
            select(KitEmergencia).where(
                KitEmergencia.id_boveda == vault_id,
                KitEmergencia.id_usuario == user_id,
                KitEmergencia.estado == "ACTIVO",
            ).order_by(KitEmergencia.version_kit.desc())
        ).first()
        if not kit:
            return None
        expires = kit.fecha_expiracion
        if expires and (expires.replace(tzinfo=timezone.utc) if expires.tzinfo is None else expires) <= datetime.now(timezone.utc):
            return None
        return kit

    def valid(self, kit_id: uuid.UUID, vault_id: uuid.UUID, user_id: uuid.UUID) -> KitEmergencia | None:
        kit = self.db.get(KitEmergencia, kit_id)
        if not kit or kit.id_boveda != vault_id or kit.id_usuario != user_id or kit.estado != "ACTIVO":
            return None
        expires = kit.fecha_expiracion
        if expires and (expires.replace(tzinfo=timezone.utc) if expires.tzinfo is None else expires) <= datetime.now(timezone.utc):
            return None
        return kit

    def revoke_active(self, vault_id: uuid.UUID, user_id: uuid.UUID) -> None:
        now = datetime.now(timezone.utc)
        for kit in self.db.scalars(select(KitEmergencia).where(
            KitEmergencia.id_boveda == vault_id,
            KitEmergencia.id_usuario == user_id,
            KitEmergencia.estado == "ACTIVO",
        )).all():
            kit.estado = "REVOCADO"
            kit.fecha_revocacion = now
