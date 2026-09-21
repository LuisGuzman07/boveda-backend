import base64
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class ShareEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id_dispositivo_destinatario: uuid.UUID
    algoritmo: str = Field(min_length=3, max_length=100)
    ciphertext: str = Field(min_length=4, max_length=4096)
    nonce: str = Field(min_length=4, max_length=64)
    tag: str = Field(min_length=4, max_length=64)

    @field_validator("ciphertext", "nonce", "tag")
    @classmethod
    def base64_only(cls, value: str):
        try:
            base64.b64decode(value, validate=True)
        except Exception as error:
            raise ValueError("El sobre debe contener Base64 válido.") from error
        return value


class ShareCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    correo_destinatario: str = Field(min_length=3, max_length=255)
    id_boveda: uuid.UUID | None = None
    id_archivo: uuid.UUID | None = None
    permiso: Literal["LECTURA"] = "LECTURA"
    inicia_en: datetime | None = None
    expira_en: datetime | None = None
    epoca_clave: int = Field(default=1, ge=1)
    version_clave: int = Field(default=1, ge=1)
    sobres: list[ShareEnvelope] = Field(min_length=1, max_length=20)

    @model_validator(mode="after")
    def one_scope_and_valid_window(self):
        if (self.id_boveda is None) == (self.id_archivo is None):
            raise ValueError("El acceso debe corresponder a una única bóveda o a un único archivo.")
        if self.expira_en and self.inicia_en and self.expira_en <= self.inicia_en:
            raise ValueError("La expiración debe ser posterior al inicio.")
        if len({envelope.id_dispositivo_destinatario for envelope in self.sobres}) != len(self.sobres):
            raise ValueError("Cada dispositivo destinatario puede tener un único sobre.")
        return self


class ShareRevokeRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    motivo: str | None = Field(default=None, min_length=1, max_length=255)


class ShareRead(BaseModel):
    id_acceso_compartido: uuid.UUID
    id_boveda: uuid.UUID | None
    id_archivo: uuid.UUID | None
    id_destinatario: uuid.UUID
    permiso: str
    inicia_en: datetime
    expira_en: datetime | None
    estado: str
    epoca_clave: int
    version_clave: int
    sobres: list[ShareEnvelope] = []
