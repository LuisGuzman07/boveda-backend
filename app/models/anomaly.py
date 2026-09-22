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

    @property
    def conteo_anomalias(self) -> int:
        return sum(1 for h in self.hallazgos if h.etiqueta == "ANOMALIA")

    @property
    def conteo_critico(self) -> int:
        return sum(1 for h in self.hallazgos if h.nivel_riesgo == "CRITICO")

    @property
    def conteo_alto(self) -> int:
        return sum(1 for h in self.hallazgos if h.nivel_riesgo == "ALTO")

    @property
    def conteo_medio(self) -> int:
        return sum(1 for h in self.hallazgos if h.nivel_riesgo == "MEDIO")


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
    evento: Mapped[Optional["EventoAuditoria"]] = relationship("EventoAuditoria")

    @property
    def nivel_riesgo(self) -> str:
        if self.decision_score < -0.10:
            return "CRITICO"
        if self.decision_score < -0.05:
            return "ALTO"
        if self.decision_score < 0.00:
            return "MEDIO"
        return "NORMAL"

    @property
    def accion(self) -> Optional[str]:
        return self.evento.accion if self.evento else None

    @property
    def tipo_evento(self) -> Optional[str]:
        return self.evento.tipo_evento if self.evento else None

    @property
    def resultado(self) -> Optional[str]:
        return self.evento.resultado if self.evento else None

    @property
    def fecha_evento(self) -> Optional[datetime]:
        return self.evento.fecha_evento if self.evento else None

    @property
    def usuario_correo(self) -> Optional[str]:
        return self.evento.usuario.correo if self.evento and self.evento.usuario else None

    @property
    def usuario_nombre(self) -> Optional[str]:
        return self.evento.usuario.nombre if self.evento and self.evento.usuario else None

    @property
    def direccion_ip(self) -> Optional[str]:
        return self.evento.direccion_ip if self.evento else None
