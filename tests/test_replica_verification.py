import hashlib
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.services.replica_verification_service import ReplicaVerificationService


CONTENT = b"encrypted-bytes"
CONTENT_HASH = hashlib.sha256(CONTENT).hexdigest()


class FakeStorage:
    def __init__(self, content=CONTENT, metadata=True, error=None):
        self.content = content
        self.metadata = metadata
        self.error = error

    def get_ciphertext_metadata(self, _key):
        if self.error:
            raise self.error
        if not self.metadata:
            return {}
        return {"size": len(self.content), "hash": hashlib.sha256(self.content).hexdigest()}

    def get_ciphertext(self, _key):
        if self.error:
            raise self.error
        return self.content


class FakeDb:
    def __init__(self):
        self.added = []
        self.commits = 0

    def add(self, value):
        self.added.append(value)

    def commit(self):
        self.commits += 1


def _service(storage, state="PENDING", permission="files:read"):
    replica = SimpleNamespace(
        proveedor="MINIO",
        clave_objeto="opaque-key",
        hash_cifrado=CONTENT_HASH,
        tamano_esperado=len(CONTENT),
        estado=state,
        fecha_verificacion=None,
        ultimo_error=None,
    )
    version = SimpleNamespace(id_version_archivo="version-1", hash_cifrado=CONTENT_HASH)
    db = FakeDb()
    service = ReplicaVerificationService(db, {"MINIO": storage})
    service.repo.get_active_membership = lambda *_: True
    service.repo.get_replication = lambda *_: [(version, replica)]
    user = SimpleNamespace(
        id_usuario="user",
        roles=[SimpleNamespace(permisos=[SimpleNamespace(codigo=permission)])],
    )
    device = SimpleNamespace(id_dispositivo="device")
    return service, db, user, device, replica


def test_equal_copy_is_verified_and_idempotent():
    service, db, user, device, replica = _service(FakeStorage())

    first = service.verify(user, device, "vault", "version-1")
    second = service.verify(user, device, "vault", "version-1")

    assert first["id_version_archivo"] == second["id_version_archivo"]
    assert first["replicas"][0]["estado"] == second["replicas"][0]["estado"] == "VERIFIED"
    assert replica.fecha_verificacion is not None
    assert db.commits == 2


def test_equal_minio_and_s3_copies_are_verified_independently():
    service, _, user, device, minio_replica = _service(FakeStorage())
    s3_replica = SimpleNamespace(
        proveedor="S3",
        clave_objeto="opaque-key-s3",
        hash_cifrado=CONTENT_HASH,
        tamano_esperado=len(CONTENT),
        estado="PENDING",
        fecha_verificacion=None,
        ultimo_error=None,
    )
    version = service.repo.get_replication("vault", "version-1")[0][0]
    service.repo.get_replication = lambda *_: [(version, minio_replica), (version, s3_replica)]
    service.storages["S3"] = FakeStorage()

    result = service.verify(user, device, "vault", "version-1")

    assert [item["estado"] for item in result["replicas"]] == ["VERIFIED", "VERIFIED"]


@pytest.mark.parametrize(
    ("storage", "expected"),
    [
        (FakeStorage(error=FileNotFoundError()), "MISSING"),
        (FakeStorage(content=b"changed-content"), "HASH_MISMATCH"),
        (FakeStorage(content=CONTENT + b"!"), "SIZE_MISMATCH"),
        (FakeStorage(error=TimeoutError()), "RETRYABLE"),
    ],
)
def test_replica_failures_are_classified_without_provider_error(storage, expected):
    service, _, user, device, _ = _service(storage)

    result = service.verify(user, device, "vault", "version-1")

    assert result["replicas"][0]["estado"] == expected
    assert "opaque-key" not in str(result)


def test_provider_without_adapter_is_unavailable():
    service, _, user, device, replica = _service(FakeStorage())
    service.storages = {}

    result = service.verify(user, device, "vault", "version-1")

    assert result["replicas"][0]["estado"] == "UNAVAILABLE"
    assert replica.fecha_verificacion is None


def test_missing_read_permission_is_rejected_before_storage_access():
    service, _, user, device, _ = _service(FakeStorage(), permission="files:upload")

    with pytest.raises(HTTPException) as error:
        service.verify(user, device, "vault", "version-1")

    assert error.value.status_code == 403
