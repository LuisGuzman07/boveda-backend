import base64
import binascii
import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field, field_validator


class EncryptedFileEnvelope(BaseModel):
    model_config = ConfigDict(extra="forbid")

    algoritmo: str = Field(default="AES-256-GCM", pattern="^AES-256-GCM$")
    ciphertext: str = Field(min_length=24)
    nonce: str = Field(min_length=16, max_length=32)
    tag: str = Field(min_length=20, max_length=32)

    @field_validator("ciphertext", "nonce", "tag")
    @classmethod
    def validate_base64(cls, value: str, info):
        try:
            decoded = base64.b64decode(value, validate=True)
        except (binascii.Error, ValueError) as error:
            raise ValueError("El material criptográfico debe ser Base64 válido.") from error
        expected = {"nonce": 12, "tag": 16}.get(info.field_name)
        if expected is not None and len(decoded) != expected:
            raise ValueError("Tamaño criptográfico inválido.")
        return value


class FileUploadRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id_archivo: uuid.UUID
    id_version_archivo: uuid.UUID
    nombre_cifrado: EncryptedFileEnvelope
    contenido_cifrado: EncryptedFileEnvelope
    clave_archivo_envuelta: EncryptedFileEnvelope
    tamano_cifrado: int = Field(gt=16, le=100 * 1024 * 1024)
    hash_cifrado: str = Field(min_length=64, max_length=64, pattern="^[0-9a-fA-F]{64}$")

    @field_validator("contenido_cifrado")
    @classmethod
    def validate_ciphertext_size(cls, value: EncryptedFileEnvelope):
        if len(base64.b64decode(value.ciphertext)) < 1:
            raise ValueError("El ciphertext no puede estar vacío.")
        return value

    @field_validator("hash_cifrado")
    @classmethod
    def normalize_hash(cls, value: str):
        return value.lower()


class FileUploadResponse(BaseModel):
    id_archivo: uuid.UUID
    id_version_archivo: uuid.UUID
    numero_version: int
    tamano_cifrado: int
    hash_cifrado: str
    proveedor: str
    estado: str


class FileMetadataResponse(BaseModel):
    id_archivo: uuid.UUID
    id_version_archivo: uuid.UUID
    numero_version: int
    nombre_cifrado: EncryptedFileEnvelope
    tamano_cifrado: int
    hash_cifrado: str
    nonce_iv: str
    auth_tag: str
    algoritmo: str
    fecha_creacion: datetime
    proveedor: str | None = None
    estado_replica: str | None = None
    fecha_verificacion_replica: datetime | None = None


class FileMetadataListResponse(BaseModel):
    items: list[FileMetadataResponse]
    page: int
    page_size: int
    total: int
    has_next: bool


class FileDownloadResponse(BaseModel):
    id_archivo: uuid.UUID
    id_version_archivo: uuid.UUID
    numero_version: int
    tamano_cifrado: int
    hash_cifrado: str
    algoritmo: str
    nonce_iv: str
    auth_tag: str
    ciphertext: str
    clave_archivo_envuelta: EncryptedFileEnvelope


class FileDeleteRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    motivo: str | None = Field(default=None, min_length=1, max_length=255)


class FileDeleteResponse(BaseModel):
    id_archivo: uuid.UUID
    estado: str
    estado_limpieza: str
    idempotente: bool
