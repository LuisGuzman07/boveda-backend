from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, field_validator, model_validator


class PoliticaSeguridadRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    codigo: str
    tipo_valor: Literal["INTEGER"]
    valor: StrictInt
    minimo: StrictInt
    maximo: StrictInt
    activa: bool
    version: StrictInt
    descripcion: str
    aplicada: bool


class PoliticaSeguridadListResponse(BaseModel):
    items: list[PoliticaSeguridadRead]


class PoliticaSeguridadEffectiveResponse(BaseModel):
    items: list[PoliticaSeguridadRead]
    policies: dict[str, StrictInt]


class PoliticaSeguridadUpdateRequest(BaseModel):
    valor: StrictInt
    version: StrictInt = Field(ge=1)


class PoliticaSeguridadBatchItem(PoliticaSeguridadUpdateRequest):
    codigo: str = Field(min_length=3, max_length=100)

    @field_validator("codigo")
    @classmethod
    def normalize_code(cls, value: str) -> str:
        return value.strip().upper()


class PoliticaSeguridadBatchUpdateRequest(BaseModel):
    actualizaciones: list[PoliticaSeguridadBatchItem] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def reject_duplicate_codes(self):
        codes = [item.codigo for item in self.actualizaciones]
        if len(codes) != len(set(codes)):
            raise ValueError("No se puede actualizar una política más de una vez en el mismo lote.")
        return self
