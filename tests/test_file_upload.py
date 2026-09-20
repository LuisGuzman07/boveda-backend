import base64
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import HTTPException
from sqlalchemy import func, select

from app.core.database import SessionLocal
from app.models.auth import EventoAuditoria, Usuario
from app.models.vault import Archivo, ArchivoVersion, ReplicaArchivo
from app.services.file_upload_service import FileUploadService
from app.services.object_storage import (
    ObjectStorageIntegrityError,
    ObjectStorageObjectMissing,
    StoredCiphertext,
    get_object_storage,
)
from tests.helpers.device_identity import new_device_identity
from tests.test_vault import _creation, _signed_request, _vault_session, client


class FakeObjectStorage:
    def __init__(self):
        self.objects: dict[str, bytes] = {}
        self.issued_keys: list[str] = []
        self.issued_sizes: list[int] = []
        self.finalized_keys: list[str] = []
        self.deleted_keys: list[str] = []

    def create_upload_url(self, staging_object_key, expected_size, expires_in):
        self.issued_keys.append(staging_object_key)
        self.issued_sizes.append(expected_size)
        return f"https://storage.example.test/ciphertext/{staging_object_key}?temporary-capability"

    def _verify(self, object_key, expected_size, expected_sha256):
        ciphertext = self.objects.get(object_key)
        if ciphertext is None:
            raise ObjectStorageObjectMissing("missing")
        actual_checksum = hashlib.sha256(ciphertext).hexdigest()
        if len(ciphertext) != expected_size or actual_checksum != expected_sha256:
            raise ObjectStorageIntegrityError("mismatch")
        return StoredCiphertext(
            size=len(ciphertext),
            sha256=actual_checksum,
            etag="ciphertext-etag",
        )

    def finalize_ciphertext(
        self,
        staging_object_key,
        final_object_key,
        expected_size,
        expected_sha256,
    ):
        self._verify(staging_object_key, expected_size, expected_sha256)
        self.objects[final_object_key] = self.objects[staging_object_key]
        self.finalized_keys.append(final_object_key)
        return self._verify(final_object_key, expected_size, expected_sha256)

    def delete_object(self, object_key):
        self.deleted_keys.append(object_key)
        self.objects.pop(object_key, None)


@pytest.fixture
def storage():
    from app.main import app

    fake = FakeObjectStorage()
    app.dependency_overrides[get_object_storage] = lambda: fake
    try:
        yield fake
    finally:
        app.dependency_overrides.pop(get_object_storage, None)


def _ciphertext_info(offset=0):
    return {
        "algoritmo": "AES-256-GCM",
        "nonce": base64.b64encode(
            bytes((index + offset) % 256 for index in range(12))
        ).decode("ascii"),
        "tag": base64.b64encode(
            bytes((index + offset) % 256 for index in range(16))
        ).decode("ascii"),
    }


def _encrypted_envelope(ciphertext: bytes, offset: int):
    return {
        **_ciphertext_info(offset),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def _complete_body(ciphertext: bytes):
    return {
        "tamano_ciphertext": len(ciphertext),
        "checksum_ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
        "contenido_cifrado": _ciphertext_info(0),
        "clave_archivo_envuelta": _encrypted_envelope(bytes(range(32)), 32),
        "metadata_cifrada": _encrypted_envelope(b"encrypted-local-metadata", 64),
        "version_criptografica": 1,
    }


def test_disabled_object_storage_fails_closed_with_a_safe_http_status():
    with pytest.raises(HTTPException) as error:
        get_object_storage()
    assert error.value.status_code == 503
    assert "configured" not in error.value.detail.lower()


def _create_authorized_vault():
    device_identity = new_device_identity()
    vault, _, device, signing_key = _vault_session(device_identity)
    creation = _creation(device)
    created = _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        "/api/v1/vaults",
        creation,
        retry_key="file-create-vault-0001",
    )
    assert created.status_code == 201, created.text
    return vault, device, signing_key, creation["id_boveda"]


def _create_intent(vault, signing_key, vault_id, ciphertext_size, retry_key="file-intent-retry-0001"):
    return _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        f"/api/v1/vaults/{vault_id}/files/upload-intents",
        {"tamano_ciphertext_esperado": ciphertext_size, "version_criptografica": 1},
        retry_key=retry_key,
    )


def test_upload_intent_and_complete_store_only_ciphertext_metadata(storage):
    vault, device, signing_key, vault_id = _create_authorized_vault()
    ciphertext = b"ciphertext-only-payload-with-gcm-tag"

    intent = _create_intent(vault, signing_key, vault_id, len(ciphertext))
    assert intent.status_code == 201, intent.text
    payload = intent.json()
    assert payload["estado"] == "UPLOADING"
    assert payload["content_type"] == "application/octet-stream"
    assert "object_key" not in payload
    assert "nombre" not in payload
    assert "upload_url" in payload
    assert len(storage.issued_keys) == 1
    assert storage.issued_sizes == [len(ciphertext)]
    object_key = storage.issued_keys[0]
    # A presigned PUT necessarily embeds its opaque random path, but the API
    # never returns it as a reusable storage identifier.
    assert "object_key" not in payload
    storage.objects[object_key] = ciphertext

    retried_intent = _create_intent(vault, signing_key, vault_id, len(ciphertext))
    assert retried_intent.status_code == 201
    assert retried_intent.json()["id_archivo"] == payload["id_archivo"]
    assert retried_intent.json()["id_version"] == payload["id_version"]

    complete = _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        f"/api/v1/vaults/{vault_id}/files/{payload['id_archivo']}/versions/{payload['id_version']}/complete",
        _complete_body(ciphertext),
        retry_key="file-complete-retry-0001",
    )
    assert complete.status_code == 200, complete.text
    assert complete.json() == {
        "id_archivo": payload["id_archivo"],
        "id_version": payload["id_version"],
        "estado": "AVAILABLE",
    }
    retried_complete = _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        f"/api/v1/vaults/{vault_id}/files/{payload['id_archivo']}/versions/{payload['id_version']}/complete",
        _complete_body(ciphertext),
        retry_key="file-complete-retry-0002",
    )
    assert retried_complete.status_code == 200
    assert retried_complete.json() == complete.json()

    db = SessionLocal()
    try:
        file = db.get(Archivo, uuid.UUID(payload["id_archivo"]))
        version = db.get(ArchivoVersion, uuid.UUID(payload["id_version"]))
        replica = db.scalars(
            select(ReplicaArchivo).where(ReplicaArchivo.id_version == version.id_version)
        ).one()
        assert file is not None and version is not None
        assert file.id_creado_por == uuid.UUID(device["id_usuario"])
        assert version.estado == replica.estado == "AVAILABLE"
        assert version.tamano_ciphertext == len(ciphertext)
        assert version.checksum_ciphertext_sha256 == hashlib.sha256(ciphertext).hexdigest()
        assert version.metadata_cifrada is not None
        assert "filename" not in str(version.metadata_cifrada).lower()
        assert replica.object_key in storage.finalized_keys
        assert replica.object_key != object_key
        assert replica.staging_object_key == object_key
        assert storage.objects[replica.object_key] == ciphertext
        assert object_key not in storage.objects
        audits = db.scalars(
            select(EventoAuditoria)
            .where(EventoAuditoria.recurso_id == payload["id_version"])
            .order_by(EventoAuditoria.fecha_evento)
        ).all()
        assert [event.accion for event in audits] == [
            "INICIAR_CARGA_ARCHIVO",
            "COMPLETAR_CARGA_ARCHIVO",
        ]
        assert all(object_key not in str(event.detalles) for event in audits)
        assert all("temporary-capability" not in str(event.detalles) for event in audits)
    finally:
        db.close()


def test_available_replica_is_not_mutable_through_the_staging_capability(storage):
    vault, _, signing_key, vault_id = _create_authorized_vault()
    ciphertext = b"ciphertext-that-must-become-immutable"
    intent = _create_intent(vault, signing_key, vault_id, len(ciphertext))
    assert intent.status_code == 201
    payload = intent.json()
    staging_key = storage.issued_keys[-1]
    storage.objects[staging_key] = ciphertext

    completed = _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        f"/api/v1/vaults/{vault_id}/files/{payload['id_archivo']}/versions/{payload['id_version']}/complete",
        _complete_body(ciphertext),
        retry_key="file-finalization-retry-0001",
    )
    assert completed.status_code == 200, completed.text

    db = SessionLocal()
    try:
        replica = db.scalars(
            select(ReplicaArchivo).where(
                ReplicaArchivo.id_version == uuid.UUID(payload["id_version"])
            )
        ).one()
        final_key = replica.object_key
    finally:
        db.close()

    # A leaked PUT capability can only recreate the staging object. The replica
    # already points at a server-owned final key that the capability cannot address.
    storage.objects[staging_key] = b"replacement-through-old-capability"
    assert storage.objects[final_key] == ciphertext


def test_reconciler_removes_recreated_staging_only_after_its_capability_expires(storage):
    vault, _, signing_key, vault_id = _create_authorized_vault()
    ciphertext = b"ciphertext-that-must-clean-up-after-capability-expiry"
    intent = _create_intent(vault, signing_key, vault_id, len(ciphertext))
    assert intent.status_code == 201
    payload = intent.json()
    staging_key = storage.issued_keys[-1]
    storage.objects[staging_key] = ciphertext
    completed = _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        f"/api/v1/vaults/{vault_id}/files/{payload['id_archivo']}/versions/{payload['id_version']}/complete",
        _complete_body(ciphertext),
        retry_key="file-reconcile-staging-retry-0001",
    )
    assert completed.status_code == 200, completed.text

    # The still-valid capability can recreate staging, so retain its key until expiry.
    storage.objects[staging_key] = b"recreated-before-capability-expiry"
    db = SessionLocal()
    try:
        service = FileUploadService(db, storage)
        assert service.reconcile_terminal_objects() == 0
        assert staging_key in storage.objects

        version = db.get(ArchivoVersion, uuid.UUID(payload["id_version"]))
        assert version is not None
        version.fecha_expiracion = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()

        assert service.reconcile_terminal_objects() == 1
        replica = db.scalars(
            select(ReplicaArchivo).where(ReplicaArchivo.id_version == version.id_version)
        ).one()
        assert replica.staging_object_key is None
        assert staging_key not in storage.objects
    finally:
        db.close()


def test_file_upload_rejects_plaintext_fields_and_rechecks_vault_write(storage):
    vault, device, signing_key, vault_id = _create_authorized_vault()
    rejected = _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        f"/api/v1/vaults/{vault_id}/files/upload-intents",
        {
            "tamano_ciphertext_esperado": 32,
            "version_criptografica": 1,
            "nombre_original": "tesis.pdf",
        },
        retry_key="file-plaintext-field-0001",
    )
    assert rejected.status_code == 422

    db = SessionLocal()
    try:
        user = db.get(Usuario, uuid.UUID(device["id_usuario"]))
        assert user is not None
        user.roles = []
        db.commit()
    finally:
        db.close()
    denied = _create_intent(
        vault,
        signing_key,
        vault_id,
        32,
        retry_key="file-permission-denied-0001",
    )
    assert denied.status_code == 403


def test_integrity_failure_marks_terminal_state_and_compensates(storage):
    vault, _, signing_key, vault_id = _create_authorized_vault()
    expected_ciphertext = b"expected-ciphertext-with-authentication-tag"
    intent = _create_intent(vault, signing_key, vault_id, len(expected_ciphertext))
    assert intent.status_code == 201
    payload = intent.json()
    object_key = storage.issued_keys[-1]
    storage.objects[object_key] = b"altered-ciphertext-with-authentication-tag"

    completed = _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        f"/api/v1/vaults/{vault_id}/files/{payload['id_archivo']}/versions/{payload['id_version']}/complete",
        _complete_body(expected_ciphertext),
        retry_key="file-integrity-failure-0001",
    )
    assert completed.status_code == 409
    assert object_key in storage.deleted_keys

    db = SessionLocal()
    try:
        version = db.get(ArchivoVersion, uuid.UUID(payload["id_version"]))
        replica = db.scalars(
            select(ReplicaArchivo).where(ReplicaArchivo.id_version == version.id_version)
        ).one()
        assert version is not None
        assert version.estado == replica.estado == "FAILED"
        event = db.scalars(
            select(EventoAuditoria).where(
                EventoAuditoria.accion == "FALLO_CARGA_ARCHIVO",
                EventoAuditoria.recurso_id == payload["id_version"],
            )
        ).one()
        assert event.detalles == {"motivo": "CIPHERTEXT_VERIFICATION_FAILED"}
    finally:
        db.close()


def test_abort_is_idempotent_and_removes_the_issued_ciphertext(storage):
    vault, _, signing_key, vault_id = _create_authorized_vault()
    ciphertext = b"ciphertext-waiting-for-abort-tag"
    intent = _create_intent(vault, signing_key, vault_id, len(ciphertext))
    assert intent.status_code == 201
    payload = intent.json()
    object_key = storage.issued_keys[-1]
    storage.objects[object_key] = ciphertext
    path = f"/api/v1/vaults/{vault_id}/files/{payload['id_archivo']}/versions/{payload['id_version']}/abort"
    aborted = _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        path,
        retry_key="file-abort-retry-0001",
    )
    repeated = _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        path,
        retry_key="file-abort-retry-0002",
    )
    assert aborted.status_code == repeated.status_code == 200
    assert aborted.json()["estado"] == repeated.json()["estado"] == "ABORTED"
    assert object_key in storage.deleted_keys
    assert object_key not in storage.objects
    db = SessionLocal()
    try:
        assert (
            db.scalar(
                select(func.count())
                .select_from(EventoAuditoria)
                .where(
                    EventoAuditoria.accion == "ABORTAR_CARGA_ARCHIVO",
                    EventoAuditoria.recurso_id == payload["id_version"],
                )
            )
            == 1
        )
    finally:
        db.close()


def test_expired_intent_is_aborted_before_a_presigned_retry(storage):
    vault, _, signing_key, vault_id = _create_authorized_vault()
    ciphertext = b"ciphertext-expired-before-complete-tag"
    intent = _create_intent(vault, signing_key, vault_id, len(ciphertext))
    assert intent.status_code == 201
    payload = intent.json()
    object_key = storage.issued_keys[-1]
    storage.objects[object_key] = ciphertext

    db = SessionLocal()
    try:
        version = db.get(ArchivoVersion, uuid.UUID(payload["id_version"]))
        assert version is not None
        version.fecha_expiracion = datetime.now(timezone.utc) - timedelta(seconds=1)
        db.commit()
    finally:
        db.close()

    retry = _create_intent(vault, signing_key, vault_id, len(ciphertext))
    assert retry.status_code == 409
    assert object_key in storage.deleted_keys
    db = SessionLocal()
    try:
        version = db.get(ArchivoVersion, uuid.UUID(payload["id_version"]))
        assert version is not None
        assert version.estado == "ABORTED"
    finally:
        db.close()
