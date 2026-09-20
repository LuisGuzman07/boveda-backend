from datetime import datetime
from typing import List, Literal, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class DeviceRegisterRequest(BaseModel):
    nombre: Optional[str] = Field(None, max_length=150, description="Nombre descriptivo del dispositivo (ej: 'Chrome en Windows')")
    tipo: Optional[str] = Field("WEB", max_length=50, description="Tipo de dispositivo: WEB, DESKTOP, MOVIL")
    sistema_operativo: Optional[str] = Field(None, max_length=100, description="Sistema operativo detectado")
    identificador_seguro: str = Field(..., min_length=10, max_length=255, description="Huella digital persistente o UUID del cliente local")
    public_key: Optional[str] = Field(None, max_length=256, description="Clave pública Ed25519 codificada en base64")
    vault_public_key: Optional[str] = Field(None, max_length=256, description="Clave pública CU06 por cuenta codificada en base64")


class DeviceAuthorizeRequest(BaseModel):
    nombre: Optional[str] = Field(None, max_length=150, description="Nombre personalizado opcional para el dispositivo")


class DeviceChallengeRequest(BaseModel):
    proposito: Literal["DEVICE_ENROLLMENT", "VAULT_SESSION"]


class DeviceChallengeResponse(BaseModel):
    id_desafio: uuid.UUID
    nonce: str
    proposito: str
    fecha_expiracion: datetime


class DeviceChallengeProofRequest(BaseModel):
    id_desafio: uuid.UUID
    nonce: str = Field(min_length=32, max_length=512)
    firma: str = Field(min_length=32, max_length=256)


class DeviceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_dispositivo: uuid.UUID
    id_usuario: uuid.UUID
    nombre: Optional[str] = None
    tipo: Optional[str] = None
    sistema_operativo: Optional[str] = None
    identificador_seguro: str
    huella_clave_publica: Optional[str] = None
    es_confiable: bool
    estado: str
    identidad_verificada_en: Optional[datetime] = None
    confianza_otorgada_en: Optional[datetime] = None
    confianza_otorgada_por: Optional[uuid.UUID] = None
    fecha_registro: datetime
    ultimo_acceso: datetime
    es_dispositivo_actual: bool = False


class DeviceListResponse(BaseModel):
    total: int
    dispositivos: List[DeviceRead]
    dispositivo_actual_id: Optional[uuid.UUID] = None


class DeviceActionResponse(BaseModel):
    status: str = "ok"
    message: str
    dispositivo: DeviceRead


# --- CU-05: Schemas Administrativos para Revocación y Control Global ---

class AdminDeviceRevokeRequest(BaseModel):
    motivo: str = Field(
        "Revocación de seguridad por el administrador",
        min_length=3,
        max_length=255,
        description="Motivo registrado en auditoría para revocar el dispositivo y sus sesiones asociadas",
    )


class AdminDeviceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_dispositivo: uuid.UUID
    id_usuario: uuid.UUID
    usuario_nombre: str
    usuario_correo: str
    nombre: Optional[str] = None
    tipo: Optional[str] = None
    sistema_operativo: Optional[str] = None
    identificador_seguro: str
    es_confiable: bool
    estado: str
    fecha_registro: datetime
    ultimo_acceso: datetime
    fecha_revocacion: Optional[datetime] = None
    revocado_por: Optional[uuid.UUID] = None
    identidad_verificada_en: Optional[datetime] = None
    confianza_otorgada_en: Optional[datetime] = None
    confianza_otorgada_por: Optional[uuid.UUID] = None
    sesiones_activas: int = 0


class AdminDeviceListResponse(BaseModel):
    total: int
    dispositivos: List[AdminDeviceRead]
