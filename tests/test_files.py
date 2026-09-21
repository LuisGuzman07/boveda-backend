import base64
import hashlib
import uuid

from sqlalchemy import select

from app.core.database import SessionLocal
from app.models.auth import EventoAuditoria, Permiso, Usuario
from app.models.vault import Archivo, ReplicaAlmacenamiento, VersionArchivo
from app.services import file_service
from app.services.file_service import FileService
from app.services.replica_verification_service import ReplicaVerificationService
from tests.test_vault import _creation, _signed_request, _vault_session, client
from tests.helpers.device_identity import new_device_identity


class MemoryMinio:
    objects = {}

    def put_ciphertext(self, object_key, content, content_hash):
        self.objects[object_key] = (content, content_hash)
        return {"etag": "memory-etag"}

    def delete(self, object_key):
        self.objects.pop(object_key, None)

    def get_ciphertext(self, object_key):
        return self.objects[object_key][0]


class FailingCleanupStorage:
    def delete(self, _object_key):
        raise TimeoutError("temporary cleanup failure")


def _file_envelope(data):
    return {
        "algoritmo": "AES-256-GCM",
        "ciphertext": base64.b64encode(data).decode("ascii"),
        "nonce": base64.b64encode(b"n" * 12).decode("ascii"),
        "tag": base64.b64encode(b"t" * 16).decode("ascii"),
    }


def _file_body():
    ciphertext = b"ciphertext-only-content"
    return {
        "id_archivo": str(uuid.uuid4()),
        "id_version_archivo": str(uuid.uuid4()),
        "nombre_cifrado": _file_envelope(b"encrypted-name-envelope"),
        "contenido_cifrado": _file_envelope(ciphertext),
        "clave_archivo_envuelta": _file_envelope(b"wrapped-file-key-32-bytes-000000"),
        "tamano_cifrado": len(ciphertext) + 16,
        "hash_cifrado": hashlib.sha256(ciphertext).hexdigest(),
    }


def test_upload_persists_only_ciphertext_metadata_and_minio_object(monkeypatch):
    monkeypatch.setattr(file_service, "MinioStorage", MemoryMinio)
    MemoryMinio.objects.clear()
    identity = new_device_identity()
    vault, _, device, signing_key = _vault_session(identity)
    created = _signed_request(signing_key, vault["access_token"], "POST", "/api/v1/vaults", _creation(device))
    assert created.status_code == 201, created.text

    body = _file_body()
    response = _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        f"/api/v1/vaults/{created.json()['id_boveda']}/files",
        body,
        retry_key="file-upload-retry-0001",
    )
    assert response.status_code == 201, response.text
    assert response.json()["proveedor"] == "MINIO"
    assert len(MemoryMinio.objects) == 1

    db = SessionLocal()
    try:
        archivo = db.scalar(select(Archivo))
        version = db.scalar(select(VersionArchivo))
        replica = db.scalar(select(ReplicaAlmacenamiento))
        assert archivo.nombre_cifrado["ciphertext"] != "encrypted-name"
        assert version.hash_cifrado == body["hash_cifrado"]
        assert replica.clave_objeto.startswith("vaults/")
        assert "ciphertext-only-content" not in replica.clave_objeto
    finally:
        db.close()


def test_upload_rejects_unauthorized_plaintext_and_tampered_hash(monkeypatch):
    monkeypatch.setattr(file_service, "MinioStorage", MemoryMinio)
    MemoryMinio.objects.clear()
    identity = new_device_identity()
    vault, _, device, signing_key = _vault_session(identity)
    created = _signed_request(signing_key, vault["access_token"], "POST", "/api/v1/vaults", _creation(device), retry_key="file-test-vault-0001")
    assert created.status_code == 201, created.text
    vault_id = created.json()["id_boveda"]
    body = _file_body()
    body["content"] = "plaintext must not be accepted"
    denied = _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        f"/api/v1/vaults/{vault_id}/files",
        body,
        retry_key="file-invalid-extra-0001",
    )
    assert denied.status_code == 422

    unauthorized = _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        f"/api/v1/vaults/{uuid.uuid4()}/files",
        _file_body(),
        retry_key="file-unauthorized-0001",
    )
    assert unauthorized.status_code == 403

    body = _file_body()
    body["hash_cifrado"] = "0" * 64
    tampered = _signed_request(
        signing_key,
        vault["access_token"],
        "POST",
        f"/api/v1/vaults/{vault_id}/files",
        body,
        retry_key="file-invalid-hash-0001",
    )
    assert tampered.status_code == 422


def _create_file(signing_key, token, vault_id, retry_key):
    body = _file_body()
    response = _signed_request(
        signing_key,
        token,
        "POST",
        f"/api/v1/vaults/{vault_id}/files",
        body,
        retry_key=retry_key,
    )
    assert response.status_code == 201, response.text
    return body


def test_list_files_requires_bound_device_signature_and_membership(monkeypatch):
    monkeypatch.setattr(file_service, "MinioStorage", MemoryMinio)
    identity = new_device_identity()
    vault, _, device, signing_key = _vault_session(identity)
    created = _signed_request(signing_key, vault["access_token"], "POST", "/api/v1/vaults", _creation(device))
    vault_id = created.json()["id_boveda"]

    wrong_device = new_device_identity()
    denied_signature = _signed_request(
        wrong_device.private_key,
        vault["access_token"],
        "GET",
        f"/api/v1/vaults/{vault_id}/files",
    )
    assert denied_signature.status_code == 401

    other_vault = uuid.uuid4()
    denied_membership = _signed_request(
        signing_key,
        vault["access_token"],
        "GET",
        f"/api/v1/vaults/{other_vault}/files",
    )
    assert denied_membership.status_code == 403


def test_list_files_returns_empty_page_without_reading_storage(monkeypatch):
    monkeypatch.setattr(file_service, "MinioStorage", MemoryMinio)
    MemoryMinio.objects.clear()
    identity = new_device_identity()
    vault, _, device, signing_key = _vault_session(identity)
    created = _signed_request(signing_key, vault["access_token"], "POST", "/api/v1/vaults", _creation(device))
    response = _signed_request(
        signing_key,
        vault["access_token"],
        "GET",
        f"/api/v1/vaults/{created.json()['id_boveda']}/files?page=1&page_size=2",
    )
    assert response.status_code == 200, response.text
    assert response.json() == {"items": [], "page": 1, "page_size": 2, "total": 0, "has_next": False}
    assert MemoryMinio.objects == {}


def test_list_files_is_paginated_ordered_and_excludes_deleted_files(monkeypatch):
    monkeypatch.setattr(file_service, "MinioStorage", MemoryMinio)
    MemoryMinio.objects.clear()
    identity = new_device_identity()
    vault, _, device, signing_key = _vault_session(identity)
    created = _signed_request(signing_key, vault["access_token"], "POST", "/api/v1/vaults", _creation(device))
    vault_id = created.json()["id_boveda"]
    bodies = [
        _create_file(signing_key, vault["access_token"], vault_id, f"file-list-retry-{index:04d}")
        for index in range(3)
    ]

    first_page = _signed_request(
        signing_key,
        vault["access_token"],
        "GET",
        f"/api/v1/vaults/{vault_id}/files?page=1&page_size=2",
    )
    assert first_page.status_code == 200, first_page.text
    first_data = first_page.json()
    assert first_data["total"] == 3
    assert first_data["has_next"] is True
    assert len(first_data["items"]) == 2
    assert [item["id_archivo"] for item in first_data["items"]] == sorted(
        [body["id_archivo"] for body in bodies]
    )[:2]

    deleted_id = uuid.UUID(bodies[1]["id_archivo"])
    db = SessionLocal()
    try:
        deleted = db.get(Archivo, deleted_id)
        deleted.estado = "ELIMINADO"
        db.commit()
    finally:
        db.close()

    remaining = _signed_request(
        signing_key,
        vault["access_token"],
        "GET",
        f"/api/v1/vaults/{vault_id}/files?page=1&page_size=10",
    )
    assert remaining.status_code == 200, remaining.text
    data = remaining.json()
    assert data["total"] == 2
    assert all(item["id_archivo"] != str(deleted_id) for item in data["items"])
    assert "encrypted-name" not in remaining.text
    assert "wrapped-file-key" not in remaining.text
    assert "ciphertext-only-content" not in remaining.text
    assert all("clave" not in item and "contenido" not in item for item in data["items"])


def test_download_returns_ciphertext_and_encrypted_key_after_integrity_check(monkeypatch):
    monkeypatch.setattr(file_service, "MinioStorage", MemoryMinio)
    MemoryMinio.objects.clear()
    identity = new_device_identity()
    vault, _, device, signing_key = _vault_session(identity)
    created = _signed_request(signing_key, vault["access_token"], "POST", "/api/v1/vaults", _creation(device), retry_key="download-vault-0001")
    vault_id = created.json()["id_boveda"]
    body = _create_file(signing_key, vault["access_token"], vault_id, "download-file-0001")

    response = _signed_request(
        signing_key,
        vault["access_token"],
        "GET",
        f"/api/v1/vaults/{vault_id}/files/{body['id_version_archivo']}/download",
    )
    assert response.status_code == 200, response.text
    data = response.json()
    assert data["ciphertext"] == base64.b64encode(b"ciphertext-only-content").decode()
    assert "wrapped-file-key" not in response.text
    assert "ciphertext-only-content" not in response.text
    assert data["clave_archivo_envuelta"]["ciphertext"] == body["clave_archivo_envuelta"]["ciphertext"]


def test_download_rejects_missing_or_corrupt_object_and_audits_failure(monkeypatch):
    monkeypatch.setattr(file_service, "MinioStorage", MemoryMinio)
    MemoryMinio.objects.clear()
    identity = new_device_identity()
    vault, _, device, signing_key = _vault_session(identity)
    created = _signed_request(signing_key, vault["access_token"], "POST", "/api/v1/vaults", _creation(device), retry_key="download-vault-0002")
    vault_id = created.json()["id_boveda"]
    body = _create_file(signing_key, vault["access_token"], vault_id, "download-file-0002")
    object_key = next(iter(MemoryMinio.objects))
    MemoryMinio.objects[object_key] = (b"tampered", body["hash_cifrado"])

    tampered = _signed_request(
        signing_key, vault["access_token"], "GET",
        f"/api/v1/vaults/{vault_id}/files/{body['id_version_archivo']}/download",
    )
    assert tampered.status_code == 409
    missing = _signed_request(
        signing_key, vault["access_token"], "GET",
        f"/api/v1/vaults/{vault_id}/files/{uuid.uuid4()}/download",
    )
    assert missing.status_code == 404


def test_verify_then_download_uses_verified_replica_under_model_constraint(monkeypatch):
    monkeypatch.setattr(file_service, "MinioStorage", MemoryMinio)
    MemoryMinio.objects.clear()
    identity = new_device_identity()
    vault, _, device, signing_key = _vault_session(identity)
    created = _signed_request(signing_key, vault["access_token"], "POST", "/api/v1/vaults", _creation(device))
    vault_id = created.json()["id_boveda"]
    body = _create_file(signing_key, vault["access_token"], vault_id, "verify-download-file-0001")

    db = SessionLocal()
    try:
        version = db.get(VersionArchivo, uuid.UUID(body["id_version_archivo"]))
        replica = db.scalar(select(ReplicaAlmacenamiento))
        replica.estado = "PENDING"
        ReplicaVerificationService(db, {"MINIO": MemoryMinio()})._verify_replica(replica, version.hash_cifrado)
        db.commit()
        assert replica.estado == "VERIFIED"
    finally:
        db.close()

    downloaded = _signed_request(
        signing_key, vault["access_token"], "GET",
        f"/api/v1/vaults/{vault_id}/files/{body['id_version_archivo']}/download",
    )
    assert downloaded.status_code == 200, downloaded.text


def test_logical_delete_is_authorized_idempotent_and_retains_ciphertext(monkeypatch):
    monkeypatch.setattr(file_service, "MinioStorage", MemoryMinio)
    MemoryMinio.objects.clear()
    identity = new_device_identity()
    vault, _, device, signing_key = _vault_session(identity)
    created = _signed_request(signing_key, vault["access_token"], "POST", "/api/v1/vaults", _creation(device))
    vault_id = created.json()["id_boveda"]
    body = _create_file(signing_key, vault["access_token"], vault_id, "delete-file-0001")
    path = f"/api/v1/vaults/{vault_id}/files/{body['id_archivo']}"

    deleted = _signed_request(signing_key, vault["access_token"], "DELETE", path, {"motivo": "user request"}, retry_key="delete-file-request-0001")
    repeated = _signed_request(signing_key, vault["access_token"], "DELETE", path, {}, retry_key="delete-file-request-0002")
    assert deleted.status_code == repeated.status_code == 200
    assert deleted.json()["estado_limpieza"] == "RETENCION"
    assert repeated.json()["idempotente"] is True
    assert len(MemoryMinio.objects) == 1

    listed = _signed_request(signing_key, vault["access_token"], "GET", f"/api/v1/vaults/{vault_id}/files")
    downloaded = _signed_request(signing_key, vault["access_token"], "GET", f"/api/v1/vaults/{vault_id}/files/{body['id_version_archivo']}/download")
    assert listed.json()["items"] == []
    assert downloaded.status_code == 404

    db = SessionLocal()
    try:
        archivo = db.get(Archivo, uuid.UUID(body["id_archivo"]))
        assert archivo.fecha_eliminacion is not None
        assert archivo.eliminado_por is not None
        assert archivo.motivo_eliminacion == "user request"
        assert archivo.solicitud_eliminacion_id == "delete-file-request-0001"
        audit = db.scalars(select(EventoAuditoria).where(EventoAuditoria.accion == "ELIMINAR_ARCHIVO_CIFRADO")).one()
        assert "ciphertext" not in str(audit.detalles).lower()
        assert "wrapped" not in str(audit.detalles).lower()
    finally:
        db.close()


def test_delete_denial_and_cleanup_failure_are_audited_without_secrets(monkeypatch):
    monkeypatch.setattr(file_service, "MinioStorage", MemoryMinio)
    MemoryMinio.objects.clear()
    identity = new_device_identity()
    vault, _, device, signing_key = _vault_session(identity)
    created = _signed_request(signing_key, vault["access_token"], "POST", "/api/v1/vaults", _creation(device))
    vault_id = created.json()["id_boveda"]
    body = _create_file(signing_key, vault["access_token"], vault_id, "delete-file-0002")

    db = SessionLocal()
    try:
        user = db.scalars(select(Usuario).where(Usuario.correo == "admin@boveda.com")).one()
        permission = db.scalars(select(Permiso).where(Permiso.codigo == "files:delete")).one()
        for role in user.roles:
            if permission in role.permisos:
                role.permisos.remove(permission)
        db.commit()
    finally:
        db.close()

    path = f"/api/v1/vaults/{vault_id}/files/{body['id_archivo']}"
    denied = _signed_request(signing_key, vault["access_token"], "DELETE", path, {}, retry_key="delete-file-request-0003")
    assert denied.status_code == 403

    db = SessionLocal()
    try:
        archivo = db.get(Archivo, uuid.UUID(body["id_archivo"]))
        archivo.estado = "ELIMINADO"
        archivo.estado_limpieza = "RETENCION"
        db.commit()
        status = FileService(db).attempt_retained_cleanup(archivo.id_archivo, {"MINIO": FailingCleanupStorage()})
        assert status == "REINTENTO_LIMPIEZA"
        events = db.scalars(select(EventoAuditoria).where(EventoAuditoria.accion.in_([
            "FALLO_AUTORIZACION_ELIMINAR_ARCHIVO", "FALLO_LIMPIEZA_ARCHIVO_CIFRADO",
        ]))).all()
        assert len(events) == 2
        assert all("ciphertext-only-content" not in str(event.detalles) for event in events)
    finally:
        db.close()
