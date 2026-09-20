"""Verify CU08 against disposable PostgreSQL, FastAPI, MinIO and Flutter.

The runner creates all credentials, tokens and test data in memory. Its temporary
Flutter configuration is deleted after use and neither the runner nor its helpers
print credentials, presigned capabilities, plaintext or ciphertext.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import tempfile
import time
import uuid

import httpx
from minio import Minio
from minio.error import S3Error
import psycopg

from verify_cu06_e2e import (
    Account,
    DeviceIdentity,
    POSTGRES_IMAGE,
    ROOT,
    VerificationError,
    _approve,
    _authenticate,
    _enroll,
    _free_port,
    _open_vault_session,
    _quiet,
    _random_password,
    _run,
    _server_environment,
    _wait_for_database,
    _wait_for_health,
)


MOBILE_ROOT = ROOT.parent / "boveda-mobile"
TEMPORARY_DATABASE = "boveda_lote2b_tmp_cu08_e2e"
MINIO_IMAGE = "quay.io/minio/minio:RELEASE.2025-04-22T22-12-26Z"
MINIO_MC_IMAGE = "quay.io/minio/mc:RELEASE.2025-04-16T18-13-26Z"
MINIO_REGION = "us-east-1"


def _run_flutter_contract(config_path: Path) -> None:
    flutter = shutil.which("flutter")
    if not flutter:
        raise VerificationError("Flutter is required for the CU08 contract runner.")
    _run(
        [
            flutter,
            "test",
            "test/cu08_http_e2e_test.dart",
            f"--dart-define=CU08_E2E_CONFIG={config_path.as_posix()}",
            "--reporter",
            "expanded",
        ],
        cwd=MOBILE_ROOT,
        environment=os.environ.copy(),
        name="Flutter CU08 contract runner",
    )


def _wait_for_minio(endpoint: str, timeout_seconds: float = 30) -> None:
    deadline = time.monotonic() + timeout_seconds
    with httpx.Client(timeout=2) as client:
        while time.monotonic() < deadline:
            try:
                if client.get(f"http://{endpoint}/minio/health/live").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
    raise VerificationError("Temporary MinIO did not become ready.")


def _storage_client(endpoint: str, access_key: str, secret_key: str) -> Minio:
    return Minio(
        endpoint,
        access_key=access_key,
        secret_key=secret_key,
        secure=False,
        region=MINIO_REGION,
    )


def _provision_runtime_user(
    *,
    container: str,
    root_access_key: str,
    root_secret_key: str,
    runtime_access_key: str,
    runtime_secret_key: str,
    bucket: str,
    environment: dict[str, str],
) -> None:
    """Run the same private-bucket runtime policy used by the compose overlay."""

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": [
                    "s3:GetBucketLocation",
                    "s3:PutObject",
                    "s3:GetObject",
                    "s3:DeleteObject",
                ],
                "Resource": [
                    f"arn:aws:s3:::{bucket}",
                    f"arn:aws:s3:::{bucket}/*",
                ],
            }
        ],
    }
    policy_base64 = base64.b64encode(
        json.dumps(policy, separators=(",", ":")).encode("utf-8")
    ).decode("ascii")
    setup = """
        mc alias set local http://localhost:9000 "$MINIO_ROOT_USER" "$MINIO_ROOT_PASSWORD" >/dev/null;
        mc mb --ignore-existing "local/$MINIO_BUCKET" >/dev/null;
        mc anonymous set none "local/$MINIO_BUCKET" >/dev/null;
        mc admin user add local "$OBJECT_STORE_ACCESS_KEY" "$OBJECT_STORE_SECRET_KEY" >/dev/null;
        printf "%s" "$POLICY_B64" | base64 -d > /tmp/runtime-policy.json;
        mc admin policy create local boveda-ciphertext-runtime /tmp/runtime-policy.json >/dev/null 2>&1 || mc admin policy update local boveda-ciphertext-runtime /tmp/runtime-policy.json >/dev/null;
        mc admin policy attach local boveda-ciphertext-runtime --user "$OBJECT_STORE_ACCESS_KEY" >/dev/null;
        rm -f /tmp/runtime-policy.json
    """
    _run(
        [
            "docker",
            "run",
            "--rm",
            "--network",
            f"container:{container}",
            "--entrypoint",
            "/bin/sh",
            "--env",
            f"MINIO_ROOT_USER={root_access_key}",
            "--env",
            f"MINIO_ROOT_PASSWORD={root_secret_key}",
            "--env",
            f"MINIO_BUCKET={bucket}",
            "--env",
            f"OBJECT_STORE_ACCESS_KEY={runtime_access_key}",
            "--env",
            f"OBJECT_STORE_SECRET_KEY={runtime_secret_key}",
            "--env",
            f"POLICY_B64={policy_base64}",
            MINIO_MC_IMAGE,
            "-ec",
            setup,
        ],
        cwd=ROOT,
        environment=environment,
        name="MinIO runtime policy provisioning",
    )


def _object_digest(storage: Minio, bucket: str, object_key: str) -> tuple[int, str]:
    response = None
    digest = hashlib.sha256()
    size = 0
    try:
        response = storage.get_object(bucket, object_key)
        while chunk := response.read(64 * 1024):
            size += len(chunk)
            digest.update(chunk)
    finally:
        if response is not None:
            response.close()
            response.release_conn()
    return size, digest.hexdigest()


def _assert_cu08_persistence(
    database_url: str,
    contract: dict,
    storage: Minio,
    bucket: str,
) -> tuple[str, str]:
    vault_id = contract.get("vault_id")
    file_id = contract.get("file_id")
    version_id = contract.get("version_id")
    expected_size = contract.get("ciphertext_size")
    expected_digest = contract.get("ciphertext_sha256")
    marker = contract.get("plaintext_marker")
    if not all(isinstance(value, str) and value for value in (vault_id, file_id, version_id, expected_digest, marker)):
        raise VerificationError("Flutter did not return a valid CU08 upload contract.")
    if not isinstance(expected_size, int) or expected_size < 0:
        raise VerificationError("Flutter returned an invalid ciphertext size.")

    driver_url = database_url.replace("postgresql+psycopg://", "postgresql://", 1)
    with psycopg.connect(driver_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT a.estado, av.estado, av.tamano_ciphertext,
                       av.checksum_ciphertext_sha256, av.contenido_cifrado,
                       av.clave_archivo_envuelta, av.metadata_cifrada,
                       r.estado, r.bucket, r.object_key, r.staging_object_key
                FROM archivo AS a
                JOIN archivo_version AS av ON av.id_archivo = a.id_archivo
                JOIN replica_archivo AS r ON r.id_version = av.id_version
                WHERE a.id_boveda = %s AND a.id_archivo = %s AND av.id_version = %s
                """,
                (vault_id, file_id, version_id),
            )
            row = cursor.fetchone()
            if row is None:
                raise VerificationError("CU08 upload persistence is missing.")
            (
                file_state,
                version_state,
                ciphertext_size,
                checksum,
                content,
                wrapped_key,
                metadata,
                replica_state,
                stored_bucket,
                final_key,
                staging_key,
            ) = row
            if (
                file_state != "AVAILABLE"
                or version_state != "AVAILABLE"
                or replica_state != "AVAILABLE"
                or ciphertext_size != expected_size
                or checksum != expected_digest
                or stored_bucket != bucket
                or not isinstance(final_key, str)
                or not final_key.startswith("files/")
                or not isinstance(staging_key, str)
                or not staging_key.startswith("uploads/")
            ):
                raise VerificationError("CU08 persistence recorded an invalid available replica.")
            if not all(isinstance(value, dict) for value in (content, wrapped_key, metadata)):
                raise VerificationError("CU08 persistence omitted encrypted upload material.")
            serialized = json.dumps(
                {"content": content, "wrapped_key": wrapped_key, "metadata": metadata},
                sort_keys=True,
            )
            if marker in serialized or "upload_url" in serialized:
                raise VerificationError("CU08 persistence retained plaintext or a storage capability.")

            cursor.execute(
                """
                SELECT accion, detalles
                FROM evento_auditoria
                WHERE recurso_id = %s
                ORDER BY fecha_evento
                """,
                (version_id,),
            )
            audits = cursor.fetchall()
            if [action for action, _ in audits] != [
                "INICIAR_CARGA_ARCHIVO",
                "COMPLETAR_CARGA_ARCHIVO",
            ]:
                raise VerificationError("CU08 upload audit trail is incomplete.")
            if any("upload_url" in json.dumps(details, sort_keys=True) for _, details in audits):
                raise VerificationError("CU08 audit persisted a storage capability.")

            aborted_version_id = contract.get("oversized_version_id")
            if not isinstance(aborted_version_id, str) or not aborted_version_id:
                raise VerificationError("Flutter did not abort the rejected oversized intent.")
            cursor.execute(
                "SELECT estado FROM archivo_version WHERE id_version = %s",
                (aborted_version_id,),
            )
            if cursor.fetchone() != ("ABORTED",):
                raise VerificationError("The rejected oversized intent was not aborted.")

    stored_size, stored_digest = _object_digest(storage, bucket, final_key)
    if stored_size != expected_size or stored_digest != expected_digest:
        raise VerificationError("The immutable MinIO final object does not match Flutter ciphertext.")
    try:
        storage.stat_object(bucket, staging_key)
    except S3Error as error:
        raise VerificationError("The test did not recreate the still-valid staging capability.") from error
    return final_key, staging_key


def _expire_upload_capability(database_url: str, version_id: str) -> None:
    driver_url = database_url.replace("postgresql+psycopg://", "postgresql://", 1)
    with psycopg.connect(driver_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                UPDATE archivo_version
                SET fecha_expiracion = NOW() - INTERVAL '1 second'
                WHERE id_version = %s
                """,
                (version_id,),
            )
        connection.commit()


def _assert_staging_reconciled(
    database_url: str,
    version_id: str,
    storage: Minio,
    bucket: str,
    staging_key: str,
    final_key: str,
    expected_size: int,
    expected_digest: str,
) -> None:
    driver_url = database_url.replace("postgresql+psycopg://", "postgresql://", 1)
    with psycopg.connect(driver_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                "SELECT staging_object_key FROM replica_archivo WHERE id_version = %s",
                (version_id,),
            )
            if cursor.fetchone() != (None,):
                raise VerificationError("Expired staging capability was not cleared from persistence.")
    try:
        storage.stat_object(bucket, staging_key)
    except S3Error as error:
        if error.code not in {"NoSuchKey", "NoSuchObject"}:
            raise VerificationError("MinIO could not verify staging cleanup.") from error
    else:
        raise VerificationError("Expired staging ciphertext was not removed from MinIO.")
    if _object_digest(storage, bucket, final_key) != (expected_size, expected_digest):
        raise VerificationError("Staging reconciliation modified the immutable final ciphertext.")


def verify() -> None:
    if not shutil.which("docker"):
        raise VerificationError("Docker is required for the CU08 E2E verification.")
    suffix = uuid.uuid4().hex[:12]
    admin = Account(f"cu08-admin-{suffix}@boveda.com", _random_password())
    owner = Account(f"cu08-owner-{suffix}@boveda.com", _random_password())
    database_user = f"cu08_{suffix[:8]}"
    database_password = secrets.token_urlsafe(32)
    database_port = _free_port()
    minio_port = _free_port()
    database_url = (
        f"postgresql+psycopg://{database_user}:{database_password}"
        f"@127.0.0.1:{database_port}/{TEMPORARY_DATABASE}"
    )
    minio_endpoint = f"127.0.0.1:{minio_port}"
    minio_root_access_key = f"cu08root{suffix}"
    minio_root_secret_key = secrets.token_urlsafe(32)
    minio_runtime_access_key = f"cu08run{suffix}"
    minio_runtime_secret_key = secrets.token_urlsafe(32)
    bucket = f"cu08-{suffix}"
    environment = _server_environment(database_url, admin, owner)
    environment.update(
        {
            "OBJECT_STORAGE_ENABLED": "true",
            "MINIO_INTERNAL_ENDPOINT": minio_endpoint,
            "MINIO_PUBLIC_ENDPOINT": f"http://{minio_endpoint}",
            "MINIO_ACCESS_KEY": minio_runtime_access_key,
            "MINIO_SECRET_KEY": minio_runtime_secret_key,
            "MINIO_BUCKET": bucket,
            "MINIO_REGION": MINIO_REGION,
            "MINIO_SECURE": "false",
            "MINIO_PRESIGNED_TTL_SECONDS": "300",
            "FILE_UPLOAD_MAX_BYTES": str(20 * 1024 * 1024),
        }
    )
    postgres_container = f"boveda-cu08-e2e-postgres-{suffix}"
    minio_container = f"boveda-cu08-e2e-minio-{suffix}"
    server: subprocess.Popen[bytes] | None = None
    started_postgres = False
    started_minio = False

    try:
        _run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                postgres_container,
                "--publish",
                f"127.0.0.1:{database_port}:5432",
                "--env",
                f"POSTGRES_DB={TEMPORARY_DATABASE}",
                "--env",
                f"POSTGRES_USER={database_user}",
                "--env",
                f"POSTGRES_PASSWORD={database_password}",
                POSTGRES_IMAGE,
            ],
            cwd=ROOT,
            environment=environment,
            name="Temporary PostgreSQL startup",
        )
        started_postgres = True
        _run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                minio_container,
                "--publish",
                f"127.0.0.1:{minio_port}:9000",
                "--env",
                f"MINIO_ROOT_USER={minio_root_access_key}",
                "--env",
                f"MINIO_ROOT_PASSWORD={minio_root_secret_key}",
                MINIO_IMAGE,
                "server",
                "/data",
            ],
            cwd=ROOT,
            environment=environment,
            name="Temporary MinIO startup",
        )
        started_minio = True
        _wait_for_database(database_url)
        _wait_for_minio(minio_endpoint)
        _provision_runtime_user(
            container=minio_container,
            root_access_key=minio_root_access_key,
            root_secret_key=minio_root_secret_key,
            runtime_access_key=minio_runtime_access_key,
            runtime_secret_key=minio_runtime_secret_key,
            bucket=bucket,
            environment=environment,
        )
        storage = _storage_client(
            minio_endpoint,
            minio_root_access_key,
            minio_root_secret_key,
        )

        _run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=ROOT,
            environment=environment,
            name="Alembic CU08 migration",
        )
        _run(
            [sys.executable, "-m", "alembic", "check"],
            cwd=ROOT,
            environment=environment,
            name="Alembic CU08 check",
        )
        _run(
            [sys.executable, "-c", "from app.core.seed import seed_database; seed_database()"],
            cwd=ROOT,
            environment=environment,
            name="Temporary database seed",
        )

        api_port = _free_port()
        base_url = f"http://127.0.0.1:{api_port}/api/v1"
        server = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "uvicorn",
                "app.main:app",
                "--host",
                "127.0.0.1",
                "--port",
                str(api_port),
                "--log-level",
                "warning",
            ],
            cwd=ROOT,
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        _wait_for_health(base_url, server)

        with httpx.Client(base_url=base_url, timeout=20) as client:
            owner_identity = DeviceIdentity.create()
            owner_native = _authenticate(client, owner, owner_identity)
            owner_device = _enroll(client, owner_identity, owner_native)

            admin_identity = DeviceIdentity.create()
            admin_native = _authenticate(client, admin, admin_identity)
            _enroll(client, admin_identity, admin_native)
            _approve(client, admin_native, owner_device)
            owner_vault_token = _open_vault_session(client, owner_identity, owner_native)

            with tempfile.TemporaryDirectory(prefix="boveda-cu08-e2e-") as temp_dir:
                config_path = Path(temp_dir) / "flutter-contract.json"
                config_path.write_text(
                    json.dumps(
                        {
                            "base_url": base_url,
                            "vault_token": owner_vault_token,
                            "device_id": owner_native.device_id,
                            "vault_signing_seed": owner_identity.vault_seed(),
                            "device_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                            "master_password": secrets.token_urlsafe(24),
                            "vault_name": f"cu08-{suffix}",
                            "vault_description": f"upload-{suffix}",
                            "plaintext_marker": f"cu08-plaintext-{suffix}",
                        }
                    ),
                    encoding="utf-8",
                )
                _run_flutter_contract(config_path)
                contract = json.loads(config_path.read_text(encoding="utf-8"))
                if contract.get("cu08_flutter_complete") is not True:
                    raise VerificationError("Flutter did not complete the CU08 contract.")

        final_key, staging_key = _assert_cu08_persistence(
            database_url,
            contract,
            storage,
            bucket,
        )
        version_id = contract["version_id"]
        expected_size = contract["ciphertext_size"]
        expected_digest = contract["ciphertext_sha256"]
        _expire_upload_capability(database_url, version_id)
        _run(
            [sys.executable, "scripts/reconcile_file_uploads.py"],
            cwd=ROOT,
            environment=environment,
            name="CU08 staging reconciliation",
        )
        _assert_staging_reconciled(
            database_url,
            version_id,
            storage,
            bucket,
            staging_key,
            final_key,
            expected_size,
            expected_digest,
        )
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)
        if started_minio:
            _quiet(["docker", "stop", minio_container])
            _quiet(["docker", "rm", minio_container])
        if started_postgres:
            _quiet(["docker", "stop", postgres_container])
            _quiet(["docker", "rm", postgres_container])


def main() -> int:
    try:
        verify()
    except VerificationError as error:
        print(f"CU08 E2E verification failed: {error}", file=sys.stderr)
        return 1
    except Exception:
        print("CU08 E2E verification failed; temporary resources were cleaned.", file=sys.stderr)
        return 1
    print("CU08 HTTP, MinIO, Flutter and PostgreSQL verification succeeded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
