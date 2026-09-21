import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, CheckConstraint, DateTime, ForeignKey, Integer, String, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class PoliticaSeguridad(Base):
    __tablename__ = "politica_seguridad"
    __table_args__ = (
        CheckConstraint("tipo_valor = 'INTEGER'", name="ck_politica_seguridad_tipo_valor"),
        CheckConstraint("valor_entero >= 0", name="ck_politica_seguridad_valor_no_negativo"),
        CheckConstraint("version >= 1", name="ck_politica_seguridad_version_positiva"),
    )

    id_politica: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    codigo: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    tipo_valor: Mapped[str] = mapped_column(String(20), default="INTEGER", nullable=False)
    valor_entero: Mapped[int] = mapped_column(Integer, nullable=False)
    activa: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    id_modificada_por: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("usuario.id_usuario", ondelete="SET NULL"),
        nullable=True,
    )
    fecha_creacion: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    fecha_actualizacion: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False
    )
