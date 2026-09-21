import hashlib
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from app.models.vault import ReplicaAlmacenamiento
from app.services.replication_service import ReplicationService
from app.services.file_service import FileService


class MemoryStorage:
    def __init__(self, content=b"encrypted-bytes"):
        self.content = content
        self.puts = 0

    def get_ciphertext(self, _key):
        return self.content

    def put_ciphertext(self, _key, content, content_hash):
        assert hashlib.sha256(content).hexdigest() == content_hash
        self.content = content
        self.puts += 1
        return {"etag": "etag", "version_id": "v1"}


class FailingStorage(MemoryStorage):
    def put_ciphertext(self, _key, _content, _content_hash):
        raise TimeoutError("temporary backend failure")


class MissingStorage(MemoryStorage):
    def get_ciphertext(self, _key):
        raise FileNotFoundError("missing")


class FakeDb:
    def __init__(self):
        self.added = []

    def add(self, value):
        self.added.append(value)

    def flush(self):
        return None

    def commit(self):
        return None


def _service(destination):
    content = b"encrypted-bytes"
    version = SimpleNamespace(
        id_version_archivo="version-1",
        hash_cifrado=hashlib.sha256(content).hexdigest(),
    )
    local = SimpleNamespace(
        proveedor="MINIO",
        clave_objeto="vaults/v/version-1.blob",
        hash_cifrado=version.hash_cifrado,
        tamano_esperado=len(content),
    )
    db = FakeDb()
    service = ReplicationService(db, MemoryStorage(content), destination)
    service.repo.get_active_membership = lambda *_: True
    service.repo.get_replication = lambda *_: [(version, local)] + [
        (version, item) for item in db.added if isinstance(item, ReplicaAlmacenamiento)
    ]
    return service, db, version


def test_replication_is_idempotent_and_copies_only_ciphertext():
    destination = MemoryStorage()
    service, _, version = _service(destination)
    actor = SimpleNamespace(id_usuario="user")
    device = SimpleNamespace(id_dispositivo="device")

    first = service.replicate(actor, device, "vault", version.id_version_archivo)
    second = service.replicate(actor, device, "vault", version.id_version_archivo)

    assert first["estado"] == second["estado"] == "VERIFIED"
    assert destination.puts == 1
    assert destination.content == b"encrypted-bytes"


def test_transient_replication_failure_is_retryable():
    service, db, version = _service(FailingStorage())
    with pytest.raises(HTTPException) as error:
        service.replicate(SimpleNamespace(id_usuario="u"), SimpleNamespace(id_dispositivo="d"), "v", version.id_version_archivo)
    assert error.value.status_code == 503
    replica = db.added[0]
    assert replica.estado == "RETRYABLE"
    assert replica.intentos == 1


def test_corrupt_replica_is_rejected_before_verification():
    with pytest.raises(ValueError):
        ReplicationService._validate(b"not-the-blob", "0" * 64, 99)


def test_restore_prefers_local_and_falls_back_to_verified_s3_without_plaintext():
    content = b"encrypted-bytes"
    content_hash = hashlib.sha256(content).hexdigest()
    version = SimpleNamespace(hash_cifrado=content_hash)
    local = SimpleNamespace(proveedor="MINIO", clave_objeto="local", hash_cifrado=content_hash, tamano_esperado=len(content))
    s3 = SimpleNamespace(proveedor="S3", clave_objeto="replica", hash_cifrado=content_hash, tamano_esperado=len(content))
    rows = [(version, None, local, None), (version, None, s3, None)]

    restored, source = FileService._read_verified_replica(rows, MemoryStorage(content), MemoryStorage(content), content_hash)
    assert restored == content
    assert source == "MINIO"

    restored, source = FileService._read_verified_replica(rows, MissingStorage(), MemoryStorage(content), content_hash)
    assert restored == content
    assert source == "S3"


def test_verified_state_is_accepted_by_the_model_postgresql_compatible_check():
    constraint = next(
        item for item in ReplicaAlmacenamiento.__table__.constraints
        if item.name == "ck_replica_estado"
    )

    assert "VERIFIED" in str(constraint.sqltext)
    assert "VERIFICADA" not in str(constraint.sqltext)
