import uuid
from datetime import datetime
from typing import List, Optional
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Table,
    Text,
    func,
)
from sqlalchemy.dialects.postgresql import JSON, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.core.database import Base


# Tabla intermedia ROL_PERMISO
rol_permiso = Table(
    "rol_permiso",
    Base.metadata,
    Column("id_rol", UUID(as_uuid=True), ForeignKey("rol.id_rol", ondelete="CASCADE"), primary_key=True),
    Column("id_permiso", UUID(as_uuid=True), ForeignKey("permiso.id_permiso", ondelete="CASCADE"), primary_key=True),
)


# Tabla intermedia USUARIO_ROL
class UsuarioRol(Base):
    __tablename__ = "usuario_rol"

    id_usuario: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("usuario.id_usuario", ondelete="CASCADE"), primary_key=True
    )
    id_rol: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("rol.id_rol", ondelete="CASCADE"), primary_key=True
    )
    fecha_creacion: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )


class Permiso(Base):
    __tablename__ = "permiso"

    id_permiso: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    codigo: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    nombre: Mapped[str] = mapped_column(String(150), nullable=False)
    descripcion: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    roles: Mapped[List["Rol"]] = relationship(
        "Rol", secondary=rol_permiso, back_populates="permisos"
    )


class Rol(Base):
    __tablename__ = "rol"

    id_rol: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    nombre: Mapped[str] = mapped_column(String(100), unique=True, index=True, nullable=False)
    descripcion: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    permisos: Mapped[List[Permiso]] = relationship(
        "Permiso", secondary=rol_permiso, back_populates="roles", lazy="selectin"
    )
    usuarios: Mapped[List["Usuario"]] = relationship(
        "Usuario", secondary="usuario_rol", back_populates="roles"
    )


class Usuario(Base):
    __tablename__ = "usuario"

    id_usuario: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    nombre: Mapped[str] = mapped_column(String(255), nullable=False)
    correo: Mapped[str] = mapped_column(String(255), unique=True, index=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    correo_verificado: Mapped[bool] = mapped_column(Boolean, default=False)
    estado: Mapped[str] = mapped_column(String(50), default="ACTIVO")
    bloqueado_hasta: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    intentos_fallidos: Mapped[int] = mapped_column(Integer, default=0)
    ultimo_acceso: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    fecha_creacion: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    fecha_actualizacion: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    roles: Mapped[List[Rol]] = relationship(
        "Rol", secondary="usuario_rol", back_populates="usuarios", lazy="selectin"
    )
    dispositivos: Mapped[List["Dispositivo"]] = relationship(
        "Dispositivo", back_populates="usuario", cascade="all, delete-orphan", foreign_keys="[Dispositivo.id_usuario]"
    )
    sesiones: Mapped[List["Sesion"]] = relationship(
        "Sesion", back_populates="usuario", cascade="all, delete-orphan"
    )


class Dispositivo(Base):
    __tablename__ = "dispositivo"

    id_dispositivo: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    id_usuario: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("usuario.id_usuario", ondelete="CASCADE"), nullable=False
    )
    nombre: Mapped[Optional[str]] = mapped_column(String(150), nullable=True)
    tipo: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    sistema_operativo: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    identificador_seguro: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    public_key: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    es_confiable: Mapped[bool] = mapped_column(Boolean, default=False)
    estado: Mapped[str] = mapped_column(String(50), default="ACTIVO")
    fecha_registro: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    ultimo_acceso: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )
    fecha_revocacion: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    revocado_por: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("usuario.id_usuario", ondelete="SET NULL"), nullable=True
    )

    usuario: Mapped[Usuario] = relationship("Usuario", foreign_keys=[id_usuario], back_populates="dispositivos")
    sesiones: Mapped[List["Sesion"]] = relationship("Sesion", back_populates="dispositivo")


class Sesion(Base):
    __tablename__ = "sesion"

    id_sesion: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    id_usuario: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), ForeignKey("usuario.id_usuario", ondelete="CASCADE"), nullable=False
    )
    id_dispositivo: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("dispositivo.id_dispositivo", ondelete="SET NULL"), nullable=True
    )
    refresh_token_hash: Mapped[str] = mapped_column(String(255), index=True, nullable=False)
    revocada: Mapped[bool] = mapped_column(Boolean, default=False)
    motivo_revocacion: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    fecha_inicio: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
    fecha_expiracion: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    ultima_actividad: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), onupdate=func.now()
    )

    usuario: Mapped[Usuario] = relationship("Usuario", back_populates="sesiones")
    dispositivo: Mapped[Optional[Dispositivo]] = relationship("Dispositivo", back_populates="sesiones")


class EventoAuditoria(Base):
    __tablename__ = "evento_auditoria"

    id_evento: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    id_usuario: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("usuario.id_usuario", ondelete="SET NULL"), nullable=True
    )
    id_dispositivo: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True), ForeignKey("dispositivo.id_dispositivo", ondelete="SET NULL"), nullable=True
    )
    accion: Mapped[str] = mapped_column(String(100), nullable=False)
    tipo_evento: Mapped[str] = mapped_column(String(100), nullable=False)
    resultado: Mapped[str] = mapped_column(String(50), nullable=False)
    recurso_id: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    recurso_tipo: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    direccion_ip: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    detalles: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    fecha_evento: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now()
    )
