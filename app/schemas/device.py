from datetime import datetime
from typing import List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class DeviceRegisterRequest(BaseModel):
    nombre: Optional[str] = Field(None, max_length=150, description="Nombre descriptivo del dispositivo (ej: 'Chrome en Windows')")
    tipo: Optional[str] = Field("WEB", max_length=50, description="Tipo de dispositivo: WEB, DESKTOP, MOVIL")
    sistema_operativo: Optional[str] = Field(None, max_length=100, description="Sistema operativo detectado")
    identificador_seguro: str = Field(..., min_length=10, max_length=255, description="Huella digital persistente o UUID del cliente local")
    public_key: Optional[str] = Field(None, description="Clave pública opcional para enlace criptográfico de hardware")
    confiar_dispositivo: bool = Field(False, description="Si es True, solicita marcar este dispositivo como de confianza")


class DeviceAuthorizeRequest(BaseModel):
    es_confiable: bool = Field(True, description="True para autorizar como de confianza, False para revocar confianza")
    nombre: Optional[str] = Field(None, max_length=150, description="Nombre personalizado opcional para el dispositivo")


class DeviceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_dispositivo: uuid.UUID
    id_usuario: uuid.UUID
    nombre: Optional[str] = None
    tipo: Optional[str] = None
    sistema_operativo: Optional[str] = None
    identificador_seguro: str
    public_key: Optional[str] = None
    es_confiable: bool
    estado: str
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
