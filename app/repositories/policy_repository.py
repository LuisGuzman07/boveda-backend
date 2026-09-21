from collections.abc import Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models.policy import PoliticaSeguridad


class PolicyRepository:
    """Persistence helpers only; transaction boundaries remain in the service."""

    def __init__(self, db: Session):
        self.db = db

    def get_by_code(self, codigo: str) -> PoliticaSeguridad | None:
        return self.db.scalars(
            select(PoliticaSeguridad).where(PoliticaSeguridad.codigo == codigo)
        ).first()

    def list_all(self) -> list[PoliticaSeguridad]:
        return list(
            self.db.scalars(
                select(PoliticaSeguridad).order_by(PoliticaSeguridad.codigo)
            ).all()
        )

    def get_by_codes_for_update(self, codigos: Iterable[str]) -> list[PoliticaSeguridad]:
        return list(
            self.db.scalars(
                select(PoliticaSeguridad)
                .where(PoliticaSeguridad.codigo.in_(set(codigos)))
                .order_by(PoliticaSeguridad.codigo)
                .with_for_update()
                .execution_options(populate_existing=True)
            ).all()
        )
