from datetime import datetime, timezone
from typing import Dict, List, Optional
import uuid
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.policy import PoliticaSeguridad


class PolicyRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_all(self) -> List[PoliticaSeguridad]:
        stmt = select(PoliticaSeguridad).order_by(PoliticaSeguridad.codigo.asc())
        return list(self.db.scalars(stmt).all())

    def get_by_code(self, code: str) -> Optional[PoliticaSeguridad]:
        stmt = select(PoliticaSeguridad).where(PoliticaSeguridad.codigo == code.upper())
        return self.db.scalars(stmt).first()

    def update(
        self,
        policy: PoliticaSeguridad,
        valor: str,
        activa: Optional[bool],
        admin_id: uuid.UUID,
    ) -> PoliticaSeguridad:
        policy.valor = valor
        if activa is not None:
            policy.activa = activa
        policy.modificada_por = admin_id
        policy.fecha_actualizacion = datetime.now(timezone.utc)
        self.db.add(policy)
        self.db.commit()
        self.db.refresh(policy)
        return policy

    def get_effective_dict(self) -> Dict[str, str]:
        stmt = select(PoliticaSeguridad).where(PoliticaSeguridad.activa == True)
        policies = self.db.scalars(stmt).all()
        return {p.codigo: p.valor for p in policies}
