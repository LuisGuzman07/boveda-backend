import uuid
from datetime import datetime
from typing import List, Optional

from sqlalchemy import DateTime, Float, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.core.database import Base


class AnalisisAnomalia(Base):
    __tablename__ = "analisis_anomalia"

    id_analisis: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    id_solicitante: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("usuario.id_usuario"), nullable=False)
    estado: Mapped[str] = mapped_column(String(20), nullable=False, default="COMPLETADO")
    model_version: Mapped[str] = mapped_column(String(50), nullable=False)
    random_state: Mapped[int] = mapped_column(Integer, nullable=False)
    feature_schema_version: Mapped[str] = mapped_column(String(50), nullable=False)
    configuracion: Mapped[dict] = mapped_column(JSON, nullable=False)
    secuencia_inicio: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    secuencia_fin: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    total_eventos: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    estado_integridad: Mapped[str] = mapped_column(String(20), nullable=False)
    motivo: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    hallazgos: Mapped[List["HallazgoAnomalia"]] = relationship(back_populates="analisis", cascade="all, delete-orphan")


class HallazgoAnomalia(Base):
    __tablename__ = "hallazgo_anomalia"

    id_hallazgo: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    id_analisis: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("analisis_anomalia.id_analisis", ondelete="CASCADE"), nullable=False, index=True)
    id_evento: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("evento_auditoria.id_evento"), nullable=False, index=True)
    secuencia_evento: Mapped[int] = mapped_column(Integer, nullable=False)
    decision_score: Mapped[float] = mapped_column(Float, nullable=False)
    etiqueta: Mapped[str] = mapped_column(String(20), nullable=False)
    explicacion: Mapped[str] = mapped_column(Text, nullable=False)
    analisis: Mapped[AnalisisAnomalia] = relationship(back_populates="hallazgos")
