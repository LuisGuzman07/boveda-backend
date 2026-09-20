import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import (
    JSON,
    CheckConstraint,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    UniqueConstraint,
    Uuid,
    func,
)
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


class Archivo(Base):
    """Opaque logical file record. User-visible metadata stays client-encrypted."""

    __tablename__ = "archivo"
    __table_args__ = (
        CheckConstraint(
            "estado IN ('PENDING', 'UPLOADING', 'AVAILABLE', 'FAILED', 'ABORTED')",
            name="ck_archivo_estado",
        ),
        Index("ix_archivo_boveda_estado", "id_boveda", "estado"),
    )

    id_archivo: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    id_boveda: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("boveda.id_boveda", ondelete="RESTRICT"), index=True
    )
    id_creado_por: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("usuario.id_usuario", ondelete="RESTRICT"), index=True
    )
    estado: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False)
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    fecha_actualizacion: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ArchivoVersion(Base):
    """One client-encrypted version and its upload intent state."""

    __tablename__ = "archivo_version"
    __table_args__ = (
        UniqueConstraint("id_archivo", "numero_version", name="uq_archivo_version_numero"),
        UniqueConstraint(
            "id_boveda",
            "id_usuario_origen",
            "idempotency_key",
            name="uq_archivo_version_reintento",
        ),
        CheckConstraint(
            "estado IN ('PENDING', 'UPLOADING', 'AVAILABLE', 'FAILED', 'ABORTED')",
            name="ck_archivo_version_estado",
        ),
        CheckConstraint(
            "tamano_ciphertext_esperado >= 0",
            name="ck_archivo_version_tamano_esperado",
        ),
        CheckConstraint(
            "tamano_ciphertext IS NULL OR tamano_ciphertext >= 0",
            name="ck_archivo_version_tamano_final",
        ),
        CheckConstraint(
            "estado <> 'AVAILABLE' OR (tamano_ciphertext IS NOT NULL "
            "AND checksum_ciphertext_sha256 IS NOT NULL "
            "AND contenido_cifrado IS NOT NULL "
            "AND clave_archivo_envuelta IS NOT NULL "
            "AND metadata_cifrada IS NOT NULL)",
            name="ck_archivo_version_material_disponible",
        ),
        Index("ix_archivo_version_expiracion", "estado", "fecha_expiracion"),
    )

    id_version: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    id_archivo: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("archivo.id_archivo", ondelete="RESTRICT"), index=True
    )
    id_boveda: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("boveda.id_boveda", ondelete="RESTRICT"), index=True
    )
    numero_version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    id_usuario_origen: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("usuario.id_usuario", ondelete="RESTRICT"), index=True
    )
    id_dispositivo_origen: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("dispositivo.id_dispositivo", ondelete="RESTRICT"), index=True
    )
    id_sesion_boveda_origen: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("sesion_boveda.id_sesion_boveda", ondelete="RESTRICT"), index=True
    )
    estado: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False)
    version_criptografica: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    tamano_ciphertext_esperado: Mapped[int] = mapped_column(Integer, nullable=False)
    tamano_ciphertext: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    checksum_ciphertext_sha256: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    contenido_cifrado: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    clave_archivo_envuelta: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    metadata_cifrada: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    idempotency_key: Mapped[str] = mapped_column(String(100), nullable=False)
    solicitud_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    complete_idempotency_key: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    complete_solicitud_hash: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    abort_idempotency_key: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    fecha_expiracion: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    fecha_completado: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    fecha_actualizacion: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )


class ReplicaArchivo(Base):
    """Storage location for one encrypted version; never contains a plaintext name."""

    __tablename__ = "replica_archivo"
    __table_args__ = (
        UniqueConstraint("id_version", "proveedor", name="uq_replica_archivo_proveedor"),
        UniqueConstraint("bucket", "object_key", name="uq_replica_archivo_objeto"),
        UniqueConstraint("bucket", "staging_object_key", name="uq_replica_archivo_staging"),
        CheckConstraint("proveedor IN ('MINIO', 'S3')", name="ck_replica_archivo_proveedor"),
        CheckConstraint(
            "estado IN ('PENDING', 'UPLOADING', 'AVAILABLE', 'FAILED', 'ABORTED')",
            name="ck_replica_archivo_estado",
        ),
    )

    id_replica: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    id_version: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("archivo_version.id_version", ondelete="RESTRICT"), index=True
    )
    proveedor: Mapped[str] = mapped_column(String(20), default="MINIO", nullable=False)
    bucket: Mapped[str] = mapped_column(String(63), nullable=False)
    object_key: Mapped[str] = mapped_column(String(128), nullable=False)
    staging_object_key: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    etag: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    estado: Mapped[str] = mapped_column(String(20), default="PENDING", nullable=False)
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    fecha_actualizacion: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
