from datetime import datetime
import re
from typing import List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator


# Schemas para Permisos y Roles
class PermisoRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_permiso: uuid.UUID
    codigo: str
    nombre: str
    descripcion: Optional[str] = None


class RolRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_rol: uuid.UUID
    nombre: str
    descripcion: Optional[str] = None
    permisos: List[PermisoRead] = []


# Schemas para Dispositivo
class DispositivoInfo(BaseModel):
    nombre: Optional[str] = "Navegador Web"
    tipo: Optional[str] = "WEB"
    sistema_operativo: Optional[str] = "Desconocido"
    identificador_seguro: Optional[str] = Field(default_factory=lambda: str(uuid.uuid4()))


class DispositivoRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_dispositivo: uuid.UUID
    nombre: Optional[str]
    tipo: Optional[str]
    sistema_operativo: Optional[str]
    identificador_seguro: str
    es_confiable: bool
    estado: str
    ultimo_acceso: datetime


# Schemas para Usuario
class UsuarioRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_usuario: uuid.UUID
    nombre: str
    correo: EmailStr
    correo_verificado: bool
    estado: str
    intentos_fallidos: int
    ultimo_acceso: Optional[datetime] = None
    fecha_creacion: datetime
    roles: List[RolRead] = []


# Schemas para CU-01: Registro de Usuario
class RegistroUsuarioRequest(BaseModel):
    nombre: str = Field(..., min_length=2, max_length=255, description="Nombre completo del usuario")
    correo: EmailStr = Field(..., description="Correo electrónico único")
    password: str = Field(..., min_length=8, max_length=128, description="Contraseña segura")

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("La contraseña debe contener al menos una letra mayúscula.")
        if not re.search(r"[a-z]", v):
            raise ValueError("La contraseña debe contener al menos una letra minúscula.")
        if not re.search(r"\d", v):
            raise ValueError("La contraseña debe contener al menos un número.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("La contraseña debe contener al menos un carácter especial (!@#$%^&*...).")
        return v


# Schemas para Sesión y Autenticación (con soporte para MFA)
class LoginRequest(BaseModel):
    correo: EmailStr
    password: str
    dispositivo: Optional[DispositivoInfo] = Field(default_factory=DispositivoInfo)


class RefreshTokenRequest(BaseModel):
    refresh_token: str


class LoginResponse(BaseModel):
    mfa_required: bool = False
    mfa_token: Optional[str] = None
    access_token: Optional[str] = None
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: Optional[int] = None
    usuario: Optional[UsuarioRead] = None
    roles: List[str] = []
    permisos: List[str] = []


class SesionRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_sesion: uuid.UUID
    id_usuario: uuid.UUID
    id_dispositivo: Optional[uuid.UUID]
    revocada: bool
    motivo_revocacion: Optional[str]
    fecha_inicio: datetime
    fecha_expiracion: datetime
    ultima_actividad: datetime


class LogoutResponse(BaseModel):
    status: str = "ok"
    message: str = "Sesión cerrada exitosamente"
