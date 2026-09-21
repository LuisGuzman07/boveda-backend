import uuid
from datetime import datetime

from pydantic import BaseModel, ConfigDict


class ReplicaVerificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    proveedor: str
    estado: str
    hash_esperado: str
    tamano_esperado: int
    fecha_verificacion: datetime | None = None


class FileReplicaVerificationResponse(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id_version_archivo: uuid.UUID
    replicas: list[ReplicaVerificationResponse]
