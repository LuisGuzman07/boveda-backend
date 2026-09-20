"""Verify CU07 against a disposable PostgreSQL, FastAPI and Flutter runtime.

The temporary Flutter configuration contains generated test credentials only inside
TemporaryDirectory and this runner never prints their values or encrypted payloads.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import uuid

import httpx
import psycopg
from cryptography.hazmat.primitives import serialization

from verify_cu06_e2e import (
    Account,
    DeviceIdentity,
    POSTGRES_IMAGE,
    ROOT,
    VerificationError,
    _approve,
    _assert_e2e_persistence,
    _authenticate,
    _enroll,
    _free_port,
    _open_vault_session,
    _quiet,
    _random_password,
    _require,
    _run,
    _server_environment,
    _vault_request,
    _wait_for_database,
    _wait_for_health,
)


MOBILE_ROOT = ROOT.parent / "boveda-mobile"
TEMPORARY_DATABASE = "boveda_lote2b_tmp_cu07_e2e"


def _private_seed(identity: DeviceIdentity, *, vault_key: bool) -> str:
    key = identity.vault_key if vault_key else identity.installation_key
    return base64.b64encode(
        key.private_bytes(
            serialization.Encoding.Raw,
            serialization.PrivateFormat.Raw,
            serialization.NoEncryption(),
        )
    ).decode("ascii")


def _run_flutter_contract(config_path: Path) -> None:
    flutter = shutil.which("flutter")
    if not flutter:
        raise VerificationError("Flutter is required for the CU07 contract runner.")
    _run(
        [
            flutter,
            "test",
            "test/cu07_http_e2e_test.dart",
            f"--dart-define=CU07_E2E_CONFIG={config_path.as_posix()}",
            "--reporter",
            "expanded",
        ],
        cwd=MOBILE_ROOT,
        environment=os.environ.copy(),
        name="Flutter CU07 contract runner",
    )


def _assert_cu07_persistence(database_url: str, vault_id: str) -> None:
    driver_url = database_url.replace("postgresql+psycopg://", "postgresql://", 1)
    with psycopg.connect(driver_url) as connection:
        with connection.cursor() as cursor:
            cursor.execute(
                """
                SELECT detalles
                FROM evento_auditoria
                WHERE accion = 'ENTREGAR_SOBRE_BOVEDA' AND recurso_id = %s
                """,
                (vault_id,),
            )
            rows = cursor.fetchall()
            if len(rows) != 1:
                raise VerificationError("Authorized envelope delivery was not audited exactly once.")
            details = rows[0][0]
            if details != {"version_criptografica": 1, "version_clave": 1}:
                raise VerificationError("Envelope audit persisted unexpected cryptographic material.")
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM information_schema.columns
                WHERE table_schema = 'public'
                  AND table_name IN ('boveda', 'clave_envuelta', 'sesion_boveda')
                  AND (
                    lower(column_name) LIKE '%%password%%'
                    OR lower(column_name) LIKE '%%master%%'
                    OR lower(column_name) LIKE '%%descifrad%%'
                  )
                """
            )
            if cursor.fetchone() != (0,):
                raise VerificationError("CU07 persistence contains a forbidden plaintext key field.")


def verify() -> None:
    if not shutil.which("docker"):
        raise VerificationError("Docker is required for the CU07 E2E verification.")
    suffix = uuid.uuid4().hex[:12]
    admin = Account(f"cu07-admin-{suffix}@boveda.com", _random_password())
    owner = Account(f"cu07-owner-{suffix}@boveda.com", _random_password())
    database_user = f"cu07_{suffix[:8]}"
    database_password = secrets.token_urlsafe(32)
    database_port = _free_port()
    database_url = (
        f"postgresql+psycopg://{database_user}:{database_password}"
        f"@127.0.0.1:{database_port}/{TEMPORARY_DATABASE}"
    )
    environment = _server_environment(database_url, admin, owner)
    container = f"boveda-cu07-e2e-{suffix}"
    server: subprocess.Popen[bytes] | None = None
    started_container = False

    try:
        _run(
            [
                "docker",
                "run",
                "--detach",
                "--name",
                container,
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
        started_container = True
        _wait_for_database(database_url)
        _run(
            [sys.executable, "-m", "alembic", "upgrade", "head"],
            cwd=ROOT,
            environment=environment,
            name="Alembic migration",
        )
        _run(
            [sys.executable, "-m", "alembic", "current"],
            cwd=ROOT,
            environment=environment,
            name="Alembic current",
        )
        _run(
            [sys.executable, "-m", "alembic", "heads"],
            cwd=ROOT,
            environment=environment,
            name="Alembic heads",
        )
        _run(
            [sys.executable, "-m", "alembic", "check"],
            cwd=ROOT,
            environment=environment,
            name="Alembic check",
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
            first_vault_token = _open_vault_session(client, owner_identity, owner_native)

            with tempfile.TemporaryDirectory(prefix="boveda-cu07-e2e-") as temp_dir:
                config_path = Path(temp_dir) / "flutter-contract.json"
                config_path.write_text(
                    json.dumps(
                        {
                            "base_url": base_url,
                            "native_token": owner_native.access_token,
                            "vault_token": first_vault_token,
                            "user_id": owner_native.user_id,
                            "device_id": owner_native.device_id,
                            "installation_id": owner_identity.installation_id,
                            "installation_seed": _private_seed(owner_identity, vault_key=False),
                            "vault_signing_seed": _private_seed(owner_identity, vault_key=True),
                            "device_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                            "master_password": secrets.token_urlsafe(24),
                            "vault_name": f"cu07-{suffix}",
                            "vault_description": f"unlock-{suffix}",
                        }
                    ),
                    encoding="utf-8",
                )
                _run_flutter_contract(config_path)
                contract = json.loads(config_path.read_text(encoding="utf-8"))
                vault_id = contract.get("vault_id")
                second_vault_token = contract.get("cu07_vault_token")
                if (
                    contract.get("cu07_flutter_complete") is not True
                    or not isinstance(vault_id, str)
                    or not isinstance(second_vault_token, str)
                ):
                    raise VerificationError("Flutter did not complete the CU07 contract.")

            _assert_e2e_persistence(database_url, vault_id)
            _assert_cu07_persistence(database_url, vault_id)

            revoked = _require(
                client.delete(
                    f"/devices/{owner_native.device_id}",
                    headers={"Authorization": f"Bearer {owner_native.access_token}"},
                ),
                200,
                "revoking the CU07 device",
            )
            if revoked.get("dispositivo", {}).get("estado") != "REVOKED":
                raise VerificationError("The CU07 device was not revoked.")
            if (
                _vault_request(
                    client,
                    owner_identity,
                    second_vault_token,
                    "GET",
                    f"/vaults/{vault_id}",
                ).status_code
                != 401
            ):
                raise VerificationError("Device revocation did not reject CU07 envelope retrieval.")

        postgres_test_environment = environment.copy()
        postgres_test_environment.update(
            {
                "CU06_TEST_POSTGRES": "1",
                "BOVEDA_L2B_DISPOSABLE_DATABASE": "1",
                "SESSION_COOKIE_SECURE": "true",
            }
        )
        _run(
            [
                sys.executable,
                "scripts/verify_lote2b_backup_restore.py",
                "--temporary-database-url",
                database_url,
                "--confirm-temporary-database",
                "--postgres-tools-container",
                container,
            ],
            cwd=ROOT,
            environment=postgres_test_environment,
            name="PostgreSQL backup and restore",
        )
        _run(
            [sys.executable, "-m", "pytest", "-q"],
            cwd=ROOT,
            environment=postgres_test_environment,
            name="PostgreSQL backend suite",
        )
    finally:
        if server is not None:
            server.terminate()
            try:
                server.wait(timeout=10)
            except subprocess.TimeoutExpired:
                server.kill()
                server.wait(timeout=10)
        if started_container:
            _quiet(["docker", "stop", container])
            _quiet(["docker", "rm", container])


def main() -> int:
    try:
        verify()
    except VerificationError as error:
        print(f"CU07 E2E verification failed: {error}", file=sys.stderr)
        return 1
    except Exception:
        print("CU07 E2E verification failed; temporary resources were cleaned.", file=sys.stderr)
        return 1
    print("CU07 E2E HTTP, Flutter and PostgreSQL verification succeeded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
