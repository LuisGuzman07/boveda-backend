"""Run the CU06 HTTP contract against disposable PostgreSQL and Flutter crypto.

Every credential, token, key and encrypted payload is generated in memory or a
TemporaryDirectory. The script deliberately emits only a success/failure summary.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import uuid

import httpx
import jwt
import psycopg
import pyotp
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


ROOT = Path(__file__).resolve().parents[1]
MOBILE_ROOT = ROOT.parent / "boveda-mobile"
POSTGRES_IMAGE = "postgres:16-alpine"
TEMPORARY_DATABASE = "boveda_lote2b_tmp_cu06_e2e"


class VerificationError(RuntimeError):
    pass


@dataclass
class Account:
    email: str
    password: str
    totp_secret: str | None = None


@dataclass
class DeviceIdentity:
    installation_id: str
    installation_key: Ed25519PrivateKey
    vault_key: Ed25519PrivateKey

    @classmethod
    def create(cls) -> "DeviceIdentity":
        return cls(
            installation_id=str(uuid.uuid4()),
            installation_key=Ed25519PrivateKey.generate(),
            vault_key=Ed25519PrivateKey.generate(),
        )

    @staticmethod
    def _public_key(value: Ed25519PrivateKey) -> str:
        return base64.b64encode(
            value.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        ).decode("ascii")

    def login_payload(self) -> dict[str, str]:
        return {
            "nombre": "CU06 E2E device",
            "tipo": "DESKTOP",
            "sistema_operativo": "E2E",
            "identificador_seguro": self.installation_id,
            "public_key": self._public_key(self.installation_key),
            "vault_public_key": self._public_key(self.vault_key),
        }

    def vault_seed(self) -> str:
        return base64.b64encode(
            self.vault_key.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
        ).decode("ascii")


@dataclass
class NativeSession:
    access_token: str
    user_id: str
    device_id: str


def _run(command: list[str], *, cwd: Path, environment: dict[str, str], name: str) -> None:
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        check=False,
    )
    if completed.returncode:
        raise VerificationError(f"{name} failed with exit status {completed.returncode}.")


def _quiet(command: list[str]) -> None:
    subprocess.run(
        command,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        check=False,
    )


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def _random_password() -> str:
    return f"Aa1!{secrets.token_urlsafe(24)}"


def _wait_for_database(database_url: str, timeout_seconds: float = 30) -> None:
    deadline = time.monotonic() + timeout_seconds
    driver_url = database_url.replace("postgresql+psycopg://", "postgresql://", 1)
    while time.monotonic() < deadline:
        try:
            with psycopg.connect(driver_url, connect_timeout=1) as connection:
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    if cursor.fetchone() == (1,):
                        return
        except psycopg.Error:
            time.sleep(0.25)
    raise VerificationError("Temporary PostgreSQL did not become ready.")


def _wait_for_health(base_url: str, server: subprocess.Popen[bytes]) -> None:
    deadline = time.monotonic() + 30
    with httpx.Client(timeout=2) as client:
        while time.monotonic() < deadline:
            if server.poll() is not None:
                raise VerificationError("Uvicorn exited before becoming ready.")
            try:
                if client.get(f"{base_url}/health").status_code == 200:
                    return
            except httpx.HTTPError:
                pass
            time.sleep(0.25)
    raise VerificationError("Uvicorn did not become ready.")


def _require(response: httpx.Response, status_code: int, operation: str) -> dict:
    if response.status_code != status_code:
        raise VerificationError(f"Unexpected status while {operation}: {response.status_code}.")
    try:
        value = response.json()
    except ValueError as error:
        raise VerificationError(f"Invalid JSON while {operation}.") from error
    if not isinstance(value, dict):
        raise VerificationError(f"Invalid response shape while {operation}.")
    return value


def _claims(token: str) -> dict:
    try:
        payload = jwt.decode(token, options={"verify_signature": False})
    except jwt.PyJWTError as error:
        raise VerificationError("The API returned an invalid JWT.") from error
    if not isinstance(payload, dict):
        raise VerificationError("The API returned an invalid JWT payload.")
    return payload


def _authenticate(client: httpx.Client, account: Account, identity: DeviceIdentity) -> NativeSession:
    initial = _require(
        client.post(
            "/auth/login",
            json={
                "correo": account.email,
                "password": account.password,
                "dispositivo": identity.login_payload(),
            },
        ),
        200,
        "logging in",
    )
    if not initial.get("mfa_required"):
        setup_access = initial.get("access_token")
        if not isinstance(setup_access, str):
            raise VerificationError("The API did not issue an MFA setup session.")
        setup = _require(
            client.post("/auth/mfa/setup", headers={"Authorization": f"Bearer {setup_access}"}),
            200,
            "starting MFA",
        )
        secret = setup.get("secret")
        if not isinstance(secret, str):
            raise VerificationError("The API did not return a TOTP setup secret.")
        account.totp_secret = secret
        _require(
            client.post(
                "/auth/mfa/enable",
                headers={"Authorization": f"Bearer {setup_access}"},
                json={"code": pyotp.TOTP(secret).now()},
            ),
            200,
            "enabling MFA",
        )
        initial = _require(
            client.post(
                "/auth/login",
                json={
                    "correo": account.email,
                    "password": account.password,
                    "dispositivo": identity.login_payload(),
                },
            ),
            200,
            "logging in after MFA setup",
        )
    mfa_token = initial.get("mfa_token")
    if not isinstance(mfa_token, str) or not account.totp_secret:
        raise VerificationError("The API did not require the expected MFA verification.")
    verified = _require(
        client.post(
            "/auth/mfa/verify-login",
            json={"mfa_token": mfa_token, "code": pyotp.TOTP(account.totp_secret).now()},
        ),
        200,
        "verifying MFA",
    )
    access_token = verified.get("access_token")
    if not isinstance(access_token, str):
        raise VerificationError("The API did not issue a native access token.")
    claims = _claims(access_token)
    user_id = claims.get("sub")
    device_id = claims.get("did")
    if not isinstance(user_id, str) or not isinstance(device_id, str):
        raise VerificationError("The native access token is missing device bindings.")
    return NativeSession(access_token, user_id, device_id)


def _challenge_signature(
    identity: DeviceIdentity,
    challenge: dict,
    session: NativeSession,
) -> dict[str, str]:
    challenge_id = challenge.get("id_desafio")
    purpose = challenge.get("proposito")
    nonce = challenge.get("nonce")
    expires_at = challenge.get("fecha_expiracion")
    if not all(isinstance(value, str) for value in (challenge_id, purpose, nonce, expires_at)):
        raise VerificationError("The API returned an invalid device challenge.")
    try:
        expiry = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        transcript = "\n".join(
            (
                "boveda-device-challenge-v1",
                challenge_id,
                purpose,
                session.user_id,
                session.device_id,
                nonce,
                str(int(expiry.timestamp())),
            )
        ).encode("utf-8")
    except ValueError as error:
        raise VerificationError("The API returned an invalid device challenge expiration.") from error
    return {
        "id_desafio": challenge_id,
        "nonce": nonce,
        "firma": base64.b64encode(identity.installation_key.sign(transcript)).decode("ascii"),
    }


def _issue_challenge(
    client: httpx.Client,
    identity: DeviceIdentity,
    session: NativeSession,
    purpose: str,
) -> tuple[dict, dict[str, str]]:
    challenge = _require(
        client.post(
            "/devices/challenge",
            headers={
                "Authorization": f"Bearer {session.access_token}",
                "X-Device-Id": identity.installation_id,
            },
            json={"proposito": purpose},
        ),
        200,
        f"issuing a {purpose} challenge",
    )
    return challenge, _challenge_signature(identity, challenge, session)


def _enroll(client: httpx.Client, identity: DeviceIdentity, session: NativeSession) -> str:
    _, proof = _issue_challenge(client, identity, session, "DEVICE_ENROLLMENT")
    response = _require(
        client.post(
            "/devices/challenge/prove",
            headers={
                "Authorization": f"Bearer {session.access_token}",
                "X-Device-Id": identity.installation_id,
            },
            json=proof,
        ),
        200,
        "proving device enrollment",
    )
    device = response.get("dispositivo")
    if not isinstance(device, dict) or device.get("estado") != "PENDING":
        raise VerificationError("Device enrollment did not remain pending.")
    device_id = device.get("id_dispositivo")
    if not isinstance(device_id, str) or device_id != session.device_id:
        raise VerificationError("Device enrollment returned an unexpected identity.")
    return device_id


def _approve(client: httpx.Client, admin: NativeSession, device_id: str) -> None:
    response = _require(
        client.post(
            f"/devices/admin/{device_id}/approve",
            headers={"Authorization": f"Bearer {admin.access_token}"},
        ),
        200,
        "approving a device",
    )
    device = response.get("dispositivo")
    if not isinstance(device, dict) or device.get("estado") != "TRUSTED":
        raise VerificationError("Administrative approval did not establish trusted state.")


def _open_vault_session(
    client: httpx.Client,
    identity: DeviceIdentity,
    session: NativeSession,
) -> str:
    _, proof = _issue_challenge(client, identity, session, "VAULT_SESSION")
    response = _require(
        client.post(
            "/vaults/session",
            headers={
                "Authorization": f"Bearer {session.access_token}",
                "X-Device-Id": identity.installation_id,
            },
            json=proof,
        ),
        200,
        "opening a vault session",
    )
    token = response.get("access_token")
    if not isinstance(token, str):
        raise VerificationError("The API did not issue a vault token.")
    return token


def _vault_request(
    client: httpx.Client,
    identity: DeviceIdentity,
    vault_token: str,
    method: str,
    path: str,
) -> httpx.Response:
    claims = _claims(vault_token)
    jti = claims.get("jti")
    if not isinstance(jti, str):
        raise VerificationError("Vault token is missing its replay binding.")
    timestamp = str(int(time.time()))
    message = "\n".join(
        (jti, timestamp, method, f"/api/v1{path}", "", hashlib.sha256(b"").hexdigest())
    ).encode("utf-8")
    signature = base64.b64encode(identity.vault_key.sign(message)).decode("ascii")
    return client.request(
        method,
        path,
        headers={
            "Authorization": f"Bearer {vault_token}",
            "X-Vault-Timestamp": timestamp,
            "X-Vault-Signature": signature,
        },
    )


def _assert_e2e_persistence(database_url: str, vault_id: str) -> None:
    driver_url = database_url.replace("postgresql+psycopg://", "postgresql://", 1)
    with psycopg.connect(driver_url) as connection:
        with connection.cursor() as cursor:
            for table in ("boveda", "membresia_boveda", "clave_envuelta"):
                cursor.execute(f"SELECT COUNT(*) FROM {table} WHERE id_boveda = %s", (vault_id,))
                if cursor.fetchone() != (1,):
                    raise VerificationError("CU06 persistence was incomplete.")
            cursor.execute(
                """
                SELECT COUNT(*)
                FROM evento_auditoria
                WHERE accion = 'CREAR_BOVEDA' AND recurso_id = %s
                """,
                (vault_id,),
            )
            if cursor.fetchone() != (1,):
                raise VerificationError("CU06 audit persistence was incomplete.")


def _run_flutter_contract(config_path: Path) -> None:
    flutter = shutil.which("flutter")
    if not flutter:
        raise VerificationError("Flutter is required for the CU06 contract runner.")
    _run(
        [
            flutter,
            "test",
            "test/cu06_http_e2e_test.dart",
            f"--dart-define=CU06_E2E_CONFIG={config_path.as_posix()}",
            "--reporter",
            "expanded",
        ],
        cwd=MOBILE_ROOT,
        environment=os.environ.copy(),
        name="Flutter CU06 contract runner",
    )


def _server_environment(database_url: str, admin: Account, member: Account) -> dict[str, str]:
    environment = os.environ.copy()
    environment.update(
        {
            "APP_ENV": "test",
            "DATABASE_URL": database_url,
            "JWT_SECRET_KEY": secrets.token_urlsafe(48),
            "TOTP_ENCRYPTION_KEY": base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
            "SEED_DEMO_ACCOUNTS": "1",
            "SEED_ADMIN_NAME": "CU06 E2E administrator",
            "SEED_ADMIN_EMAIL": admin.email,
            "SEED_ADMIN_PASSWORD": admin.password,
            "SEED_MEMBER_NAME": "CU06 E2E member",
            "SEED_MEMBER_EMAIL": member.email,
            "SEED_MEMBER_PASSWORD": member.password,
            "SMTP_ENABLED": "false",
            "SESSION_COOKIE_SECURE": "false",
            "CORS_ORIGINS": '["http://localhost:5173"]',
        }
    )
    return environment


def verify() -> None:
    if not shutil.which("docker"):
        raise VerificationError("Docker is required for the CU06 E2E verification.")
    suffix = uuid.uuid4().hex[:12]
    admin = Account(f"cu06-admin-{suffix}@boveda.com", _random_password())
    owner = Account(f"cu06-owner-{suffix}@boveda.com", _random_password())
    database_user = f"cu06_{suffix[:8]}"
    database_password = secrets.token_urlsafe(32)
    database_port = _free_port()
    database_url = (
        f"postgresql+psycopg://{database_user}:{database_password}"
        f"@127.0.0.1:{database_port}/{TEMPORARY_DATABASE}"
    )
    environment = _server_environment(database_url, admin, owner)
    container = f"boveda-cu06-e2e-{suffix}"
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
            owner_vault = _open_vault_session(client, owner_identity, owner_native)

            with tempfile.TemporaryDirectory(prefix="boveda-cu06-e2e-") as temp_dir:
                config_path = Path(temp_dir) / "flutter-contract.json"
                config_path.write_text(
                    json.dumps(
                        {
                            "base_url": base_url,
                            "vault_token": owner_vault,
                            "device_id": owner_native.device_id,
                            "vault_signing_seed": owner_identity.vault_seed(),
                            "device_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                            "other_device_key": base64.b64encode(secrets.token_bytes(32)).decode("ascii"),
                            "master_password": secrets.token_urlsafe(24),
                            "vault_name": f"cu06-{suffix}",
                            "vault_description": f"contract-{suffix}",
                        }
                    ),
                    encoding="utf-8",
                )
                _run_flutter_contract(config_path)
                contract = json.loads(config_path.read_text(encoding="utf-8"))
                vault_id = contract.get("vault_id")
                if contract.get("flutter_e2e_complete") is not True or not isinstance(vault_id, str):
                    raise VerificationError("Flutter did not complete the CU06 contract.")

            _assert_e2e_persistence(database_url, vault_id)

            second_identity = DeviceIdentity.create()
            second_native = _authenticate(client, owner, second_identity)
            second_device = _enroll(client, second_identity, second_native)
            _approve(client, admin_native, second_device)
            second_vault = _open_vault_session(client, second_identity, second_native)
            second_list = _vault_request(client, second_identity, second_vault, "GET", "/vaults")
            if second_list.status_code != 200 or second_list.json() != {"items": []}:
                raise VerificationError("A second owner device received another device envelope.")
            if _vault_request(client, second_identity, second_vault, "GET", f"/vaults/{vault_id}").status_code != 404:
                raise VerificationError("A second owner device retrieved another device envelope.")

            stranger = Account(f"cu06-stranger-{suffix}@boveda.com", _random_password())
            _require(
                client.post(
                    "/auth/register",
                    json={
                        "nombre": "CU06 E2E stranger",
                        "correo": stranger.email,
                        "password": stranger.password,
                    },
                ),
                201,
                "registering the isolation user",
            )
            stranger_identity = DeviceIdentity.create()
            stranger_native = _authenticate(client, stranger, stranger_identity)
            stranger_device = _enroll(client, stranger_identity, stranger_native)
            _approve(client, admin_native, stranger_device)
            stranger_vault = _open_vault_session(client, stranger_identity, stranger_native)
            stranger_list = _vault_request(client, stranger_identity, stranger_vault, "GET", "/vaults")
            if stranger_list.status_code != 200 or stranger_list.json() != {"items": []}:
                raise VerificationError("Another user received a foreign envelope.")
            if _vault_request(client, stranger_identity, stranger_vault, "GET", f"/vaults/{vault_id}").status_code != 404:
                raise VerificationError("Another user retrieved a foreign envelope.")

            forged_claims = _claims(second_vault)
            forged_claims["did"] = owner_native.device_id
            forged_token = jwt.encode(
                forged_claims,
                environment["JWT_SECRET_KEY"],
                algorithm="HS256",
            )
            if _vault_request(client, second_identity, forged_token, "GET", f"/vaults/{vault_id}").status_code != 401:
                raise VerificationError("A tampered vault device binding was accepted.")

            revoked = _require(
                client.delete(
                    f"/devices/{owner_native.device_id}",
                    headers={"Authorization": f"Bearer {owner_native.access_token}"},
                ),
                200,
                "revoking the owner device",
            )
            if revoked.get("dispositivo", {}).get("estado") != "REVOKED":
                raise VerificationError("The owner device was not revoked.")
            if _vault_request(client, owner_identity, owner_vault, "GET", "/vaults").status_code != 401:
                raise VerificationError("Revocation did not invalidate the owner vault session.")

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
        print(f"CU06 E2E verification failed: {error}", file=sys.stderr)
        return 1
    except Exception:
        print("CU06 E2E verification failed; temporary resources were cleaned.", file=sys.stderr)
        return 1
    print("CU06 E2E HTTP, Flutter and PostgreSQL verification succeeded.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
