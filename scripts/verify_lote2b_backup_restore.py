"""Prove the Lote 2B backup/recovery path against one disposable PostgreSQL database.

The script deliberately refuses non-local or ambiguously named databases. It never
prints the connection URL or its credentials.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import tempfile
import uuid

from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url


ROOT = Path(__file__).resolve().parents[1]
LEGACY_REVISION = "f2a1b3c4d5e6"
DEVICE_BOUND_SESSIONS_REVISION = "d2b20260919"
TEMPORARY_HOSTS = {"localhost", "127.0.0.1", "::1"}
TEMPORARY_DATABASE_PATTERN = re.compile(r"^boveda_lote2b_(tmp|temp|test)(?:[_-].+)?$")
DISPOSABLE_MARKER = "BOVEDA_L2B_DISPOSABLE_DATABASE"


def parse_temporary_database_url(raw_url: str) -> URL:
    url = make_url(raw_url)
    if not url.drivername.startswith("postgresql"):
        raise ValueError("Only PostgreSQL URLs are accepted.")
    if (url.host or "").lower() not in TEMPORARY_HOSTS:
        raise ValueError("The database host must be local to run this destructive verification.")
    if not url.database or not TEMPORARY_DATABASE_PATTERN.search(url.database.lower()):
        raise ValueError("The database name must start with boveda_lote2b_tmp, _temp, or _test.")
    if not url.username:
        raise ValueError("The database URL must include a database user.")
    if url.query:
        raise ValueError("Connection URL query parameters are not allowed for destructive verification.")
    return url


def canonical_database_url(url: URL) -> str:
    """Discard untrusted URL query options before any connection can be opened."""
    return URL.create(
        drivername=url.drivername,
        username=url.username,
        password=url.password,
        host=url.host,
        port=url.port,
        database=url.database,
    ).render_as_string(hide_password=False)


def _process_environment(database_url: str, url: URL) -> dict[str, str]:
    environment = os.environ.copy()
    environment["DATABASE_URL"] = database_url
    # Alembic imports Settings even though this verification does not use runtime auth.
    environment.setdefault("JWT_SECRET_KEY", secrets.token_urlsafe(48))
    environment.setdefault(
        "TOTP_ENCRYPTION_KEY",
        base64.urlsafe_b64encode(secrets.token_bytes(32)).decode("ascii"),
    )
    environment["PGHOST"] = url.host or ""
    environment["PGPORT"] = str(url.port or 5432)
    environment["PGUSER"] = url.username or ""
    if url.password:
        environment["PGPASSWORD"] = url.password
    return environment


def _run(
    command: list[str],
    environment: dict[str, str],
    *,
    input_data: bytes | None = None,
) -> bytes:
    completed = subprocess.run(
        command,
        cwd=ROOT,
        env=environment,
        capture_output=True,
        input=input_data,
        check=False,
    )
    if completed.returncode:
        # Command output can contain a DSN on failure; expose only the exit status.
        raise RuntimeError(f"Verification command failed with exit code {completed.returncode}.")
    return completed.stdout


def _alembic_upgrade(revision: str, environment: dict[str, str]) -> None:
    _run([sys.executable, "-m", "alembic", "upgrade", revision], environment)


def _reset_disposable_database(engine) -> None:
    with engine.begin() as connection:
        connection.execute(text("DROP SCHEMA public CASCADE"))
        connection.execute(text("CREATE SCHEMA public"))


def _assert_tools_container_matches_target(
    url: URL, environment: dict[str, str], tools_container: str | None
) -> None:
    if not tools_container:
        return
    try:
        ports = json.loads(
            _run(
                ["docker", "inspect", "--format", "{{json .NetworkSettings.Ports}}", tools_container],
                environment,
            )
        )
    except json.JSONDecodeError as error:
        raise ValueError("The PostgreSQL tools container did not expose valid port metadata.") from error

    target_port = str(url.port or 5432)
    local_bindings = {"", "0.0.0.0", "127.0.0.1", "::", "[::]"}
    mappings = ports.get("5432/tcp") or []
    if not any(
        mapping.get("HostPort") == target_port
        and mapping.get("HostIp", "") in local_bindings
        for mapping in mappings
    ):
        raise ValueError(
            "The PostgreSQL tools container must expose its own 5432/tcp on the validated local URL port."
        )


def _postgres_tool_command(
    tool: str,
    arguments: list[str],
    environment: dict[str, str],
    tools_container: str | None,
) -> list[str]:
    if not tools_container:
        return [tool, *arguments]
    command = [
        "docker",
        "exec",
        "-i",
        tools_container,
        "env",
        "PGHOST=localhost",
        "PGPORT=5432",
        f"PGUSER={environment['PGUSER']}",
    ]
    if environment.get("PGPASSWORD"):
        command.append(f"PGPASSWORD={environment['PGPASSWORD']}")
    return [*command, tool, *arguments]


def _backup_database(
    backup_file: Path,
    url: URL,
    environment: dict[str, str],
    tools_container: str | None,
) -> None:
    arguments = ["--format=custom", "--dbname", url.database or ""]
    if not tools_container:
        _run(["pg_dump", "--file", str(backup_file), *arguments], environment)
        return
    backup = _run(
        _postgres_tool_command("pg_dump", arguments, environment, tools_container),
        environment,
    )
    backup_file.write_bytes(backup)


def _restore_database(
    backup_file: Path,
    url: URL,
    environment: dict[str, str],
    tools_container: str | None,
) -> None:
    arguments = ["--no-owner", "--dbname", url.database or ""]
    if not tools_container:
        _run(["pg_restore", *arguments, str(backup_file)], environment)
        return
    _run(
        _postgres_tool_command("pg_restore", arguments, environment, tools_container),
        environment,
        input_data=backup_file.read_bytes(),
    )


def _seed_preapproval_state(engine) -> dict[str, uuid.UUID]:
    """Creates only synthetic legacy state required to prove the security migrations."""
    ids = {
        "user": uuid.uuid4(),
        "device": uuid.uuid4(),
        "auditor_role": uuid.uuid4(),
        "admin_role": uuid.uuid4(),
        "export_permission": uuid.uuid4(),
    }
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO usuario (
                    id_usuario, nombre, correo, password_hash,
                    correo_verificado, estado, intentos_fallidos
                ) VALUES (
                    :id_usuario, 'Migration verification user',
                    'migration-verification@invalid.test', 'migration-verification-only',
                    TRUE, 'ACTIVO', 0
                )
                """
            ),
            {"id_usuario": ids["user"]},
        )
        connection.execute(
            text(
                """
                INSERT INTO dispositivo (
                    id_dispositivo, id_usuario, identificador_seguro, estado, es_confiable
                ) VALUES (:id_dispositivo, :id_usuario, 'migration-trusted-device', 'TRUSTED', TRUE)
                """
            ),
            {"id_dispositivo": ids["device"], "id_usuario": ids["user"]},
        )
        connection.execute(
            text(
                """
                INSERT INTO permiso (id_permiso, codigo, nombre, descripcion)
                VALUES (:id_permiso, 'audit:export', 'Legacy audit export', 'legacy test data')
                """
            ),
            {"id_permiso": ids["export_permission"]},
        )
        for role_key, role_name in (("auditor_role", "Auditor"), ("admin_role", "Administrador")):
            connection.execute(
                text("INSERT INTO rol (id_rol, nombre, descripcion) VALUES (:id_rol, :nombre, 'legacy test data')"),
                {"id_rol": ids[role_key], "nombre": role_name},
            )
        connection.execute(
            text(
                "INSERT INTO rol_permiso (id_rol, id_permiso) VALUES (:id_rol, :id_permiso)"
            ),
            {"id_rol": ids["auditor_role"], "id_permiso": ids["export_permission"]},
        )
    return ids


def _seed_global_identity_collision(engine) -> None:
    """Creates a cross-account legacy collision that d2b20260921 must reject."""
    duplicate_user_id = uuid.uuid4()
    with engine.begin() as connection:
        connection.execute(
            text(
                """
                INSERT INTO usuario (
                    id_usuario, nombre, correo, password_hash,
                    correo_verificado, estado, intentos_fallidos
                ) VALUES (
                    :id_usuario, 'Duplicate identity user',
                    'duplicate-identity@invalid.test', 'migration-verification-only',
                    TRUE, 'ACTIVO', 0
                )
                """
            ),
            {"id_usuario": duplicate_user_id},
        )
        connection.execute(
            text(
                """
                INSERT INTO dispositivo (
                    id_dispositivo, id_usuario, identificador_seguro, estado, es_confiable
                ) VALUES (:id_dispositivo, :id_usuario, 'migration-trusted-device', 'PENDING', FALSE)
                """
            ),
            {"id_dispositivo": uuid.uuid4(), "id_usuario": duplicate_user_id},
        )


def _assert_global_identity_collision_is_rejected(engine, environment: dict[str, str]) -> None:
    _reset_disposable_database(engine)
    _alembic_upgrade(DEVICE_BOUND_SESSIONS_REVISION, environment)
    _seed_preapproval_state(engine)
    _seed_global_identity_collision(engine)
    try:
        _alembic_upgrade("head", environment)
    except RuntimeError:
        return
    raise RuntimeError("The global device identity collision was accepted by the security migration.")


def _assert_lote2b_migration_state(engine, ids: dict[str, uuid.UUID]) -> None:
    with engine.connect() as connection:
        device = connection.execute(
            text(
                "SELECT estado, es_confiable FROM dispositivo WHERE id_dispositivo = :id_dispositivo"
            ),
            {"id_dispositivo": ids["device"]},
        ).mappings().one()
        auditor_export = connection.execute(
            text(
                """
                SELECT 1
                FROM rol_permiso
                WHERE id_rol = :id_rol AND id_permiso = :id_permiso
                """
            ),
            {
                "id_rol": ids["auditor_role"],
                "id_permiso": ids["export_permission"],
            },
        ).scalar_one_or_none()
        admin_approval = connection.execute(
            text(
                """
                SELECT 1
                FROM rol_permiso rp
                JOIN permiso p ON p.id_permiso = rp.id_permiso
                WHERE rp.id_rol = :id_rol AND p.codigo = 'devices:approve'
                """
            ),
            {"id_rol": ids["admin_role"]},
        ).scalar_one_or_none()
        identity_claim = connection.execute(
            text(
                """
                SELECT 1
                FROM identidad_dispositivo
                WHERE id_dispositivo = :id_dispositivo
                  AND tipo = 'INSTALLATION_ID'
                  AND huella = :huella
                """
            ),
            {
                "id_dispositivo": ids["device"],
                "huella": hashlib.sha256(b"migration-trusted-device").hexdigest(),
            },
        ).scalar_one_or_none()
    if (
        device["estado"] != "PENDING"
        or device["es_confiable"]
        or auditor_export
        or not admin_approval
        or not identity_claim
    ):
        raise RuntimeError("Lote 2B migration checks did not produce the required secure state.")


def verify_backup_restore(database_url: str, tools_container: str | None = None) -> None:
    if os.getenv(DISPOSABLE_MARKER) != "1":
        raise ValueError(f"{DISPOSABLE_MARKER}=1 is required.")
    url = parse_temporary_database_url(database_url)
    database_url = canonical_database_url(url)
    environment = _process_environment(database_url, url)
    _assert_tools_container_matches_target(url, environment, tools_container)
    engine = create_engine(database_url)
    sentinel_id = uuid.uuid4()

    try:
        _reset_disposable_database(engine)
        _alembic_upgrade(LEGACY_REVISION, environment)
        with engine.begin() as connection:
            connection.execute(
                text(
                    """
                    INSERT INTO usuario (
                        id_usuario, nombre, correo, password_hash,
                        correo_verificado, estado, intentos_fallidos
                    ) VALUES (
                        :id_usuario, :nombre, :correo, :password_hash,
                        TRUE, 'ACTIVO', 0
                    )
                    """
                ),
                {
                    "id_usuario": sentinel_id,
                    "nombre": "Backup verification sentinel",
                    "correo": f"backup-{sentinel_id.hex}@invalid.test",
                    "password_hash": "backup-verification-only",
                },
            )

        with tempfile.TemporaryDirectory(prefix="boveda-lote2b-") as temp_dir:
            backup_file = Path(temp_dir) / "before_lote2b.dump"
            _backup_database(backup_file, url, environment, tools_container)
            _assert_global_identity_collision_is_rejected(engine, environment)
            _reset_disposable_database(engine)
            _alembic_upgrade(DEVICE_BOUND_SESSIONS_REVISION, environment)
            migration_ids = _seed_preapproval_state(engine)
            _alembic_upgrade("head", environment)
            _assert_lote2b_migration_state(engine, migration_ids)
            _reset_disposable_database(engine)
            _restore_database(backup_file, url, environment, tools_container)

        with engine.connect() as connection:
            revision = connection.execute(text("SELECT version_num FROM alembic_version")).scalar_one()
            restored = connection.execute(
                text("SELECT id_usuario FROM usuario WHERE id_usuario = :id_usuario"),
                {"id_usuario": sentinel_id},
            ).scalar_one_or_none()
        if revision != LEGACY_REVISION or restored != sentinel_id:
            raise RuntimeError("Backup restoration did not reproduce the pre-Lote-2B state.")
    finally:
        engine.dispose()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify the Lote 2B backup/restore procedure on a disposable local PostgreSQL database."
    )
    parser.add_argument("--temporary-database-url", required=True)
    parser.add_argument(
        "--confirm-temporary-database",
        action="store_true",
        help="Required acknowledgement that the target database will be reset.",
    )
    parser.add_argument(
        "--postgres-tools-container",
        help="Optional disposable PostgreSQL container that supplies pg_dump and pg_restore.",
    )
    args = parser.parse_args()
    if not args.confirm_temporary_database:
        parser.error("--confirm-temporary-database is required.")

    try:
        verify_backup_restore(args.temporary_database_url, args.postgres_tools_container)
    except (RuntimeError, ValueError) as error:
        print(f"Backup/restore verification failed: {error}", file=sys.stderr)
        return 1

    print("Backup/restore verification succeeded for the disposable local database.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
