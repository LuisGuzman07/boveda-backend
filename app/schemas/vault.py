import base64
import re
import uuid
from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class VaultSchema(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EncryptedEnvelope(VaultSchema):
    algoritmo: Literal["AES-256-GCM"] = "AES-256-GCM"
    ciphertext: str = Field(min_length=4, max_length=2048)
    nonce: str = Field(max_length=32)
    tag: str = Field(max_length=32)

    @field_validator("ciphertext", "nonce", "tag")
    @classmethod
    def validate_base64(cls, value, info):
        try:
            decoded = base64.b64decode(value, validate=True)
        except Exception as error:
            raise ValueError("Base64 inválido") from error
        expected = {"nonce": 12, "tag": 16}.get(info.field_name)
        if expected and len(decoded) != expected:
            raise ValueError("Tamaño criptográfico inválido")
        return value


class WrappedVaultKey(EncryptedEnvelope):
    id_dispositivo: uuid.UUID
    version_clave: Literal[1] = 1


class KdfParameters(VaultSchema):
    algoritmo: Literal["Argon2id"] = "Argon2id"
    memoria_kib: Literal[65536] = 65536
    iteraciones: Literal[3] = 3
    paralelismo: Literal[1] = 1
    longitud: Literal[32] = 32


class VaultCreateRequest(VaultSchema):
    id_boveda: uuid.UUID
    nombre_cifrado: EncryptedEnvelope
    descripcion_cifrada: Optional[EncryptedEnvelope] = None
    version_criptografica: Literal[1] = 1
    kdf_salt: str = Field(max_length=64)
    kdf_parametros: KdfParameters
    clave_envuelta: WrappedVaultKey

    @field_validator("kdf_salt")
    @classmethod
    def validate_salt(cls, value):
        try:
            if len(base64.b64decode(value, validate=True)) != 16:
                raise ValueError("La sal debe tener 16 bytes")
        except Exception as error:
            raise ValueError("Sal Argon2id inválida") from error
        return value


class VaultSessionRequest(VaultSchema):
    id_desafio: uuid.UUID
    nonce: str = Field(min_length=32, max_length=512)
    firma: str = Field(min_length=32, max_length=256)


class FileCiphertextInfo(VaultSchema):
    """Nonce and tag for the raw ciphertext sent directly to object storage."""

    algoritmo: Literal["AES-256-GCM"] = "AES-256-GCM"
    nonce: str = Field(min_length=16, max_length=32)
    tag: str = Field(min_length=20, max_length=32)

    @field_validator("nonce", "tag")
    @classmethod
    def validate_binary_material(cls, value: str, info):
        try:
            decoded = base64.b64decode(value, validate=True)
        except Exception as error:
            raise ValueError("Base64 inválido") from error
        expected = 12 if info.field_name == "nonce" else 16
        if len(decoded) != expected:
            raise ValueError("Tamaño criptográfico inválido")
        return value


class FileEncryptedEnvelope(FileCiphertextInfo):
    ciphertext: str = Field(min_length=4, max_length=16384)

    @field_validator("ciphertext")
    @classmethod
    def validate_ciphertext(cls, value: str):
        try:
            decoded = base64.b64decode(value, validate=True)
        except Exception as error:
            raise ValueError("Base64 inválido") from error
        if not decoded:
            raise ValueError("El ciphertext no puede estar vacío")
        return value


class WrappedFileKey(FileEncryptedEnvelope):
    @field_validator("ciphertext")
    @classmethod
    def validate_wrapped_file_key(cls, value: str):
        try:
            decoded = base64.b64decode(value, validate=True)
        except Exception as error:
            raise ValueError("Base64 inválido") from error
        if len(decoded) != 32:
            raise ValueError("La clave de archivo envuelta debe cifrar 32 bytes")
        return value


class FileUploadIntentRequest(VaultSchema):
    tamano_ciphertext_esperado: int = Field(ge=0)
    version_criptografica: Literal[1] = 1


class FileUploadCompleteRequest(VaultSchema):
    tamano_ciphertext: int = Field(ge=0)
    checksum_ciphertext_sha256: str = Field(min_length=64, max_length=64)
    contenido_cifrado: FileCiphertextInfo
    clave_archivo_envuelta: WrappedFileKey
    metadata_cifrada: FileEncryptedEnvelope
    version_criptografica: Literal[1] = 1

    @field_validator("checksum_ciphertext_sha256")
    @classmethod
    def validate_ciphertext_checksum(cls, value: str):
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError("Checksum ciphertext SHA-256 inválido")
        return value

    @model_validator(mode="after")
    def require_distinct_nonces(self):
        nonces = {
            self.contenido_cifrado.nonce,
            self.clave_archivo_envuelta.nonce,
            self.metadata_cifrada.nonce,
        }
        if len(nonces) != 3:
            raise ValueError("Cada material cifrado debe usar un nonce distinto")
        return self


class FileUploadIntentResponse(VaultSchema):
    id_archivo: uuid.UUID
    id_version: uuid.UUID
    estado: Literal["PENDING", "UPLOADING", "AVAILABLE", "FAILED", "ABORTED"]
    upload_url: Optional[str] = None
    expira_en: Optional[datetime] = None
    content_type: Optional[Literal["application/octet-stream"]] = None


class FileUploadOperationResponse(VaultSchema):
    id_archivo: uuid.UUID
    id_version: uuid.UUID
    estado: Literal["PENDING", "UPLOADING", "AVAILABLE", "FAILED", "ABORTED"]
