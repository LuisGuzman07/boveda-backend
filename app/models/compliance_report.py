import uuid
from datetime import datetime

from sqlalchemy import DateTime, ForeignKey, JSON, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ReporteCumplimiento(Base):
    __tablename__ = "reporte_cumplimiento"

    id_reporte: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    id_solicitante: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("usuario.id_usuario"), nullable=False, index=True)
    version: Mapped[str] = mapped_column(String(30), nullable=False)
    filtros: Mapped[dict] = mapped_column(JSON, nullable=False)
    resumen: Mapped[dict] = mapped_column(JSON, nullable=False)
    fecha_generacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
