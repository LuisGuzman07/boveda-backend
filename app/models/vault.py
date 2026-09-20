import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, String, UniqueConstraint, Uuid, func
from sqlalchemy.orm import Mapped, mapped_column
from app.core.database import Base


class Boveda(Base):
    __tablename__ = "boveda"
    __table_args__ = (
        UniqueConstraint("id_propietario", "idempotency_key", name="uq_boveda_reintento"),
        CheckConstraint("estado IN ('ACTIVA', 'ELIMINADA')", name="ck_boveda_estado"),
    )
    id_boveda: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    id_propietario: Mapped[uuid.UUID] = mapped_column(ForeignKey("usuario.id_usuario"), index=True)
    nombre_cifrado: Mapped[dict] = mapped_column(JSON)
    descripcion_cifrada: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    version_criptografica: Mapped[int]
    kdf_salt: Mapped[str] = mapped_column(String(64))
    kdf_parametros: Mapped[dict] = mapped_column(JSON)
    estado: Mapped[str] = mapped_column(String(20), default="ACTIVA")
    idempotency_key: Mapped[str] = mapped_column(String(100))
    solicitud_hash: Mapped[str] = mapped_column(String(64))
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    fecha_actualizacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())


class MembresiaBoveda(Base):
    __tablename__ = "membresia_boveda"
    __table_args__ = (
        CheckConstraint("estado IN ('ACTIVA', 'REVOCADA')", name="ck_membresia_estado"),
    )
    id_boveda: Mapped[uuid.UUID] = mapped_column(ForeignKey("boveda.id_boveda"), primary_key=True)
    id_usuario: Mapped[uuid.UUID] = mapped_column(ForeignKey("usuario.id_usuario"), primary_key=True)
    rol_boveda: Mapped[str] = mapped_column(String(30), default="PROPIETARIO")
    estado: Mapped[str] = mapped_column(String(20), default="ACTIVA")
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ClaveEnvuelta(Base):
    __tablename__ = "clave_envuelta"
    __table_args__ = (
        UniqueConstraint("id_boveda", "id_usuario", "id_dispositivo", "version_clave", name="uq_clave_destinatario"),
        CheckConstraint("estado IN ('ACTIVA', 'REVOCADA')", name="ck_clave_estado"),
    )
    id_clave_envuelta: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    id_boveda: Mapped[uuid.UUID] = mapped_column(ForeignKey("boveda.id_boveda"))
    id_usuario: Mapped[uuid.UUID] = mapped_column(ForeignKey("usuario.id_usuario"))
    id_dispositivo: Mapped[uuid.UUID] = mapped_column(ForeignKey("dispositivo.id_dispositivo"))
    algoritmo: Mapped[str] = mapped_column(String(100))
    ciphertext: Mapped[str] = mapped_column(String(2048))
    nonce: Mapped[str] = mapped_column(String(32))
    tag: Mapped[str] = mapped_column(String(32))
    version_clave: Mapped[int]
    estado: Mapped[str] = mapped_column(String(20), default="ACTIVA")
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
