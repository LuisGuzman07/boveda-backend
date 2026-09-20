from datetime import datetime
from typing import List, Optional
import uuid
from pydantic import BaseModel, ConfigDict, Field


class PolicyRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_politica: uuid.UUID
    codigo: str
    nombre: str
    valor: str
    descripcion: Optional[str] = None
    activa: bool
    modificada_por: Optional[uuid.UUID] = None
    modificada_por_nombre: Optional[str] = None
    fecha_actualizacion: datetime


class PolicyUpdateRequest(BaseModel):
    valor: str = Field(..., min_length=1, max_length=255, description="Nuevo valor para el parámetro de seguridad")
    activa: Optional[bool] = Field(None, description="Estado de activación de la política")


class PolicyBatchItem(BaseModel):
    codigo: str = Field(..., min_length=2, max_length=50)
    valor: str = Field(..., min_length=1, max_length=255)
    activa: Optional[bool] = None


class PolicyBatchUpdateRequest(BaseModel):
    politicas: List[PolicyBatchItem]


class EffectivePoliciesResponse(BaseModel):
    inactivity_timeout_minutes: int = 15
    max_failed_login_attempts: int = 5
    lockout_duration_minutes: int = 15
    vault_session_duration_minutes: int = 15
    audit_retention_days: int = 90
    password_min_length: int = 12


class InactivityLockRequest(BaseModel):
    motivo: Optional[str] = Field(
        "Bloqueo automático de terminal por inactividad prolongada (CU-12)",
        max_length=255
    )
