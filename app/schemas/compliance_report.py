import uuid
from datetime import datetime
from typing import Literal, Optional

from pydantic import BaseModel, ConfigDict, Field, model_validator


class ComplianceReportCreate(BaseModel):
    fecha_inicio: datetime
    fecha_fin: datetime
    tipo_evento: Optional[str] = Field(None, max_length=100)
    resultado: Optional[str] = Field(None, max_length=50)
    formato: Literal["json", "csv"] = "json"

    @model_validator(mode="after")
    def validate_period(self):
        if self.fecha_inicio >= self.fecha_fin:
            raise ValueError("fecha_inicio must be earlier than fecha_fin")
        if (self.fecha_fin - self.fecha_inicio).days > 366:
            raise ValueError("report period cannot exceed 366 days")
        return self


class ComplianceReportRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id_reporte: uuid.UUID
    version: str
    filtros: dict
    resumen: dict
    fecha_generacion: datetime
