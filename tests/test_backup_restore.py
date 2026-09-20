import importlib.util
from pathlib import Path

import pytest


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "verify_lote2b_backup_restore.py"
SPEC = importlib.util.spec_from_file_location("verify_lote2b_backup_restore", SCRIPT)
assert SPEC and SPEC.loader
backup_restore = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(backup_restore)


def test_backup_restore_rejects_query_parameters_before_connecting():
    with pytest.raises(ValueError, match="query parameters"):
        backup_restore.parse_temporary_database_url(
            "postgresql+psycopg://tester@localhost:55432/"
            "boveda_lote2b_tmp?host=production.invalid"
        )


def test_backup_restore_canonicalizes_an_accepted_local_target():
    url = backup_restore.parse_temporary_database_url(
        "postgresql+psycopg://tester@127.0.0.1:55432/boveda_lote2b_test_ci"
    )

    assert backup_restore.canonical_database_url(url) == (
        "postgresql+psycopg://tester@127.0.0.1:55432/boveda_lote2b_test_ci"
    )


def test_tools_container_must_publish_the_validated_database_port(monkeypatch):
    url = backup_restore.parse_temporary_database_url(
        "postgresql+psycopg://tester@127.0.0.1:55432/boveda_lote2b_test_ci"
    )
    monkeypatch.setattr(
        backup_restore,
        "_run",
        lambda *_args, **_kwargs: b'{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"55432"}]}',
    )

    backup_restore._assert_tools_container_matches_target(url, {}, "temporary-postgres")


def test_tools_container_cannot_be_a_different_postgres_target(monkeypatch):
    url = backup_restore.parse_temporary_database_url(
        "postgresql+psycopg://tester@127.0.0.1:55432/boveda_lote2b_test_ci"
    )
    monkeypatch.setattr(
        backup_restore,
        "_run",
        lambda *_args, **_kwargs: b'{"5432/tcp":[{"HostIp":"127.0.0.1","HostPort":"5433"}]}',
    )

    with pytest.raises(ValueError, match="validated local URL port"):
        backup_restore._assert_tools_container_matches_target(url, {}, "other-postgres")
