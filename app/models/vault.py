import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import JSON, CheckConstraint, DateTime, ForeignKey, Integer, String, UniqueConstraint, Uuid, func
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
        UniqueConstraint("id_boveda", "id_usuario", name="uq_membresia_boveda_usuario"),
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
        UniqueConstraint("id_version_archivo", "id_usuario", "id_dispositivo", "version_clave", name="uq_clave_archivo_destinatario"),
        CheckConstraint("estado IN ('ACTIVA', 'REVOCADA')", name="ck_clave_estado"),
    )
    id_clave_envuelta: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    id_boveda: Mapped[uuid.UUID] = mapped_column(ForeignKey("boveda.id_boveda"))
    id_version_archivo: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("version_archivo.id_version_archivo"), nullable=True)
    id_usuario: Mapped[uuid.UUID] = mapped_column(ForeignKey("usuario.id_usuario"))
    id_dispositivo: Mapped[uuid.UUID] = mapped_column(ForeignKey("dispositivo.id_dispositivo"))
    algoritmo: Mapped[str] = mapped_column(String(100))
    ciphertext: Mapped[str] = mapped_column(String(2048))
    nonce: Mapped[str] = mapped_column(String(32))
    tag: Mapped[str] = mapped_column(String(32))
    version_clave: Mapped[int]
    estado: Mapped[str] = mapped_column(String(20), default="ACTIVA")
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class AccesoCompartido(Base):
    __tablename__ = "acceso_compartido"
    __table_args__ = (
        UniqueConstraint("id_otorgante", "idempotency_key", name="uq_acceso_compartido_reintento"),
        CheckConstraint("(id_boveda IS NOT NULL AND id_archivo IS NULL) OR (id_boveda IS NULL AND id_archivo IS NOT NULL)", name="ck_acceso_compartido_un_alcance"),
        CheckConstraint("permiso IN ('LECTURA')", name="ck_acceso_compartido_permiso"),
        CheckConstraint("estado IN ('ACTIVO', 'REVOCADO')", name="ck_acceso_compartido_estado"),
    )

    id_acceso_compartido: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    id_boveda: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("boveda.id_boveda"), nullable=True, index=True)
    id_archivo: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("archivo.id_archivo"), nullable=True, index=True)
    id_destinatario: Mapped[uuid.UUID] = mapped_column(ForeignKey("usuario.id_usuario"), index=True)
    id_otorgante: Mapped[uuid.UUID] = mapped_column(ForeignKey("usuario.id_usuario"), index=True)
    permiso: Mapped[str] = mapped_column(String(20), default="LECTURA")
    inicia_en: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    expira_en: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    estado: Mapped[str] = mapped_column(String(20), default="ACTIVO")
    revocado_en: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revocado_por: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("usuario.id_usuario"), nullable=True)
    motivo_revocacion: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    epoca_clave: Mapped[int] = mapped_column(Integer, default=1)
    version_clave: Mapped[int] = mapped_column(Integer, default=1)
    idempotency_key: Mapped[str] = mapped_column(String(100))
    solicitud_hash: Mapped[str] = mapped_column(String(64))
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class SobreAccesoCompartido(Base):
    __tablename__ = "sobre_acceso_compartido"
    __table_args__ = (
        UniqueConstraint("id_acceso_compartido", "id_dispositivo_destinatario", name="uq_sobre_acceso_dispositivo"),
        CheckConstraint("estado IN ('ACTIVO', 'REVOCADO')", name="ck_sobre_acceso_estado"),
    )

    id_sobre_acceso: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    id_acceso_compartido: Mapped[uuid.UUID] = mapped_column(ForeignKey("acceso_compartido.id_acceso_compartido", ondelete="CASCADE"), index=True)
    id_dispositivo_destinatario: Mapped[uuid.UUID] = mapped_column(ForeignKey("dispositivo.id_dispositivo"), index=True)
    algoritmo: Mapped[str] = mapped_column(String(100))
    ciphertext: Mapped[str] = mapped_column(String(4096))
    nonce: Mapped[str] = mapped_column(String(64))
    tag: Mapped[str] = mapped_column(String(64))
    huella_identidad_destinatario: Mapped[str] = mapped_column(String(64))
    epoca_clave: Mapped[int] = mapped_column(Integer, default=1)
    version_clave: Mapped[int] = mapped_column(Integer, default=1)
    estado: Mapped[str] = mapped_column(String(20), default="ACTIVO")
    revocado_en: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class KitEmergencia(Base):
    __tablename__ = "kit_emergencia"
    __table_args__ = (
        UniqueConstraint("id_boveda", "version_kit", name="uq_kit_emergencia_version"),
        CheckConstraint("estado IN ('ACTIVO', 'REVOCADO')", name="ck_kit_emergencia_estado"),
    )

    id_kit: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    id_boveda: Mapped[uuid.UUID] = mapped_column(ForeignKey("boveda.id_boveda", ondelete="CASCADE"), index=True)
    id_usuario: Mapped[uuid.UUID] = mapped_column(ForeignKey("usuario.id_usuario", ondelete="CASCADE"), index=True)
    version_kit: Mapped[int] = mapped_column(Integer, default=1)
    version_criptografica: Mapped[int] = mapped_column(Integer, default=1)
    algoritmo_kdf: Mapped[str] = mapped_column(String(32), default="Argon2id")
    kdf_salt: Mapped[str] = mapped_column(String(64))
    kdf_salt_boveda: Mapped[str] = mapped_column(String(64))
    kdf_parametros: Mapped[dict] = mapped_column(JSON)
    sobre_cifrado: Mapped[dict] = mapped_column(JSON)
    huella_kit: Mapped[str] = mapped_column(String(64), index=True)
    estado: Mapped[str] = mapped_column(String(20), default="ACTIVO")
    fecha_expiracion: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    fecha_revocacion: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class Archivo(Base):
    __tablename__ = "archivo"
    __table_args__ = (
        UniqueConstraint("id_boveda", "idempotency_key", name="uq_archivo_reintento"),
        CheckConstraint("estado IN ('ACTIVO', 'ELIMINADO')", name="ck_archivo_estado"),
    )

    id_archivo: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    id_boveda: Mapped[uuid.UUID] = mapped_column(ForeignKey("boveda.id_boveda"), index=True)
    nombre_cifrado: Mapped[dict] = mapped_column(JSON)
    estado: Mapped[str] = mapped_column(String(20), default="ACTIVO")
    idempotency_key: Mapped[str] = mapped_column(String(100))
    fecha_eliminacion: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    eliminado_por: Mapped[Optional[uuid.UUID]] = mapped_column(ForeignKey("usuario.id_usuario", ondelete="SET NULL"), nullable=True)
    motivo_eliminacion: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    solicitud_eliminacion_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    estado_limpieza: Mapped[str] = mapped_column(String(30), default="RETENCION", nullable=False)
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class VersionArchivo(Base):
    __tablename__ = "version_archivo"
    __table_args__ = (
        UniqueConstraint("id_archivo", "numero_version", name="uq_archivo_version"),
        UniqueConstraint("id_boveda", "idempotency_key", name="uq_version_archivo_reintento"),
    )

    id_version_archivo: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True)
    id_archivo: Mapped[uuid.UUID] = mapped_column(ForeignKey("archivo.id_archivo"), index=True)
    id_boveda: Mapped[uuid.UUID] = mapped_column(ForeignKey("boveda.id_boveda"), index=True)
    numero_version: Mapped[int] = mapped_column(Integer)
    tamano_cifrado: Mapped[int] = mapped_column(Integer)
    hash_cifrado: Mapped[str] = mapped_column(String(64))
    nonce_iv: Mapped[str] = mapped_column(String(32))
    auth_tag: Mapped[str] = mapped_column(String(32))
    algoritmo: Mapped[str] = mapped_column(String(100))
    idempotency_key: Mapped[str] = mapped_column(String(100))
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())


class ReplicaAlmacenamiento(Base):
    __tablename__ = "replica_almacenamiento"
    __table_args__ = (
        UniqueConstraint("proveedor", "clave_objeto", name="uq_replica_proveedor_objeto"),
        UniqueConstraint("id_version_archivo", "proveedor", name="uq_replica_version_proveedor"),
        CheckConstraint("proveedor IN ('MINIO', 'S3')", name="ck_replica_proveedor"),
        CheckConstraint("estado IN ('PENDING', 'COPYING', 'VERIFIED', 'RETRYABLE', 'FAILED', 'MISSING', 'HASH_MISMATCH', 'SIZE_MISMATCH', 'UNAVAILABLE')", name="ck_replica_estado"),
    )

    id_replica: Mapped[uuid.UUID] = mapped_column(Uuid, primary_key=True, default=uuid.uuid4)
    id_version_archivo: Mapped[uuid.UUID] = mapped_column(ForeignKey("version_archivo.id_version_archivo"), index=True)
    proveedor: Mapped[str] = mapped_column(String(30), default="MINIO")
    clave_objeto: Mapped[str] = mapped_column(String(255))
    version_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    estado: Mapped[str] = mapped_column(String(30), default="PENDING")
    etag: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    hash_cifrado: Mapped[str] = mapped_column(String(64))
    tamano_esperado: Mapped[int] = mapped_column(Integer)
    intentos: Mapped[int] = mapped_column(Integer, default=0)
    ultimo_error: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    fecha_verificacion: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    fecha_creacion: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
