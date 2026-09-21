from datetime import datetime
from typing import Any, Optional
import uuid
from pydantic import BaseModel, ConfigDict


class AnomalyFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id_evento: uuid.UUID
    secuencia_evento: int
    decision_score: float
    etiqueta: str
    explicacion: str


class AnomalyRunRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id_analisis: uuid.UUID
    estado: str
    model_version: str
    random_state: int
    feature_schema_version: str
    configuracion: dict[str, Any]
    secuencia_inicio: Optional[int]
    secuencia_fin: Optional[int]
    total_eventos: int
    estado_integridad: str
    motivo: Optional[str]
    fecha_creacion: datetime
    hallazgos: list[AnomalyFindingRead] = []


class ChainVerificationRead(BaseModel):
    status: str
    checked_events: int
    first_invalid_sequence: Optional[int]
