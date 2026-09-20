from datetime import datetime
from typing import Optional
import uuid
from sqlalchemy import Boolean, DateTime, ForeignKey, Integer, String, Text, func
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


class AutenticadorMfa(Base):
    __tablename__ = "autenticador_mfa"

    id_autenticador: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    id_usuario: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("usuario.id_usuario", ondelete="CASCADE"), nullable=False
    )
    tipo: Mapped[str] = mapped_column(String(50), default="TOTP", nullable=False)
    # Retained only for legacy rows until the controlled encryption backfill is verified.
    secreto_cifrado: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    secreto_cifrado_v2: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    version_criptografica: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    public_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    credential_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    contador: Mapped[int] = mapped_column(Integer, default=0)
    estado: Mapped[str] = mapped_column(String(50), default="PENDIENTE")  # PENDIENTE, ACTIVO, REVOCADO
    fecha_registro: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    ultimo_uso: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    usuario = relationship("Usuario", backref="autenticadores_mfa")


class RecuperacionCuenta(Base):
    __tablename__ = "recuperacion_cuenta"

    id_recuperacion: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    id_usuario: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("usuario.id_usuario", ondelete="CASCADE"), nullable=False
    )
    codigo: Mapped[str] = mapped_column(String(50), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    tipo: Mapped[str] = mapped_column(String(50), default="BACKUP_CODE", nullable=False)
    utilizado: Mapped[bool] = mapped_column(Boolean, default=False)
    fecha_creacion: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    fecha_expiracion: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    fecha_utilizacion: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    usuario = relationship("Usuario", backref="codigos_recuperacion")
