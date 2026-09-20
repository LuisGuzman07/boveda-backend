import base64
import uuid
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field, field_validator


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
