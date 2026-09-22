from datetime import datetime
from typing import Any, Optional
import uuid
from pydantic import BaseModel, ConfigDict


class AnomalyFindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    id_hallazgo: Optional[uuid.UUID] = None
    id_evento: uuid.UUID
    secuencia_evento: int
    decision_score: float
    etiqueta: str
    nivel_riesgo: str = "NORMAL"
    explicacion: str

    # Metadatos contextuales del evento asociado
    accion: Optional[str] = None
    tipo_evento: Optional[str] = None
    resultado: Optional[str] = None
    fecha_evento: Optional[datetime] = None
    usuario_correo: Optional[str] = None
    usuario_nombre: Optional[str] = None
    direccion_ip: Optional[str] = None


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
    conteo_anomalias: int = 0
    conteo_critico: int = 0
    conteo_alto: int = 0
    conteo_medio: int = 0
    hallazgos: list[AnomalyFindingRead] = []


class AnomalyStatsRead(BaseModel):
    total_analisis: int
    ultimo_analisis_fecha: Optional[datetime] = None
    ultimo_analisis_estado: Optional[str] = None
    total_anomalias_detectadas: int
    anomalias_criticas: int
    anomalias_altas: int
    anomalias_medias: int
    cadena_integridad: str
    eventos_auditados: int


class ChainVerificationRead(BaseModel):
    status: str
    checked_events: int
    first_invalid_sequence: Optional[int]
