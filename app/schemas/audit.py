from datetime import datetime
from typing import Any, Dict, List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class UsuarioAuditBrief(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_usuario: uuid.UUID
    nombre: str
    correo: str


class DispositivoAuditBrief(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_dispositivo: uuid.UUID
    nombre: str
    tipo: str
    sistema_operativo: Optional[str] = None


class EventoAuditoriaRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_evento: uuid.UUID
    id_usuario: uuid.UUID
    id_dispositivo: Optional[uuid.UUID] = None
    accion: str
    tipo_evento: str
    resultado: str
    recurso_id: Optional[str] = None
    recurso_tipo: Optional[str] = None
    direccion_ip: Optional[str] = None
    user_agent: Optional[str] = None
    detalles: Optional[Dict[str, Any]] = None
    fecha_evento: datetime
    chain_sequence: int
    previous_hash: str
    event_hash: str
    schema_version: int
    usuario: Optional[UsuarioAuditBrief] = None
    dispositivo: Optional[DispositivoAuditBrief] = None


class AuditListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: List[EventoAuditoriaRead]


class AuditStatsResponse(BaseModel):
    total_eventos: int
    eventos_exitosos: int
    eventos_fallidos: int
    eventos_denegados: int
    por_tipo: Dict[str, int]
    por_accion: Dict[str, int]


class LogAuditPayload(BaseModel):
    user_id: uuid.UUID
    device_id: Optional[uuid.UUID] = None
    accion: str = Field(..., max_length=100)
    tipo_evento: str = Field(..., max_length=50)
    resultado: str = Field(..., max_length=20)
    recurso_id: Optional[str] = Field(None, max_length=100)
    recurso_tipo: Optional[str] = Field(None, max_length=50)
    ip: Optional[str] = Field(None, max_length=45)
    user_agent: Optional[str] = Field(None, max_length=255)
    detalles: Optional[Dict[str, Any]] = None
