import secrets

import pytest
from pydantic import ValidationError
from starlette.requests import Request

from app.core.config import Settings
from app.core.request_security import get_client_ip
from app.core.security import (
    create_access_token,
    create_mfa_token,
    create_refresh_token,
    decode_token,
    get_jwt_secret,
)


@pytest.mark.parametrize(
    "secret",
    [
        "",
        "short-secret",
        "a" * 32,
        "boveda_super_secret_jwt_key_2026_change_in_production_hybrid_vault",
        "REPLACE_WITH_A_SECRET_GENERATED_OUTSIDE_THIS_REPOSITORY",
    ],
)
def test_settings_reject_missing_or_insecure_jwt_secret(monkeypatch, secret):
    if secret:
        monkeypatch.setenv("JWT_SECRET_KEY", secret)
    else:
        monkeypatch.delenv("JWT_SECRET_KEY", raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_settings_accepts_an_explicit_valid_jwt_secret(monkeypatch):
    secret = secrets.token_urlsafe(48)
    monkeypatch.setenv("JWT_SECRET_KEY", secret)

    configured = Settings(_env_file=None)

    assert configured.JWT_SECRET_KEY.get_secret_value() == secret


def test_settings_rejects_missing_totp_encryption_key(monkeypatch):
    monkeypatch.setenv("JWT_SECRET_KEY", secrets.token_urlsafe(48))
    monkeypatch.delenv("TOTP_ENCRYPTION_KEY", raising=False)

    with pytest.raises(ValidationError):
        Settings(_env_file=None)


def test_pytest_injected_secret_initializes_all_jwt_types():
    assert len(get_jwt_secret()) >= 32

    for token, token_type in (
        (create_access_token("user-id"), "access"),
        (create_refresh_token("user-id"), "refresh"),
        (create_mfa_token("user-id"), "mfa_pending"),
    ):
        assert decode_token(token)["type"] == token_type


def test_client_ip_ignores_untrusted_forwarded_header():
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-forwarded-for", b"198.51.100.10")],
            "client": ("203.0.113.42", 443),
        }
    )

    assert get_client_ip(request) == "203.0.113.42"
