import base64
import binascii
from typing import List, Literal, Union
import json
from urllib.parse import urlsplit

from pydantic import SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


MINIMUM_JWT_SECRET_LENGTH = 32
MINIMUM_JWT_SECRET_UNIQUE_CHARACTERS = 12
TOTP_ENCRYPTION_KEY_BYTES = 32
INSECURE_JWT_SECRET_VALUES = frozenset(
    {
        "boveda_super_secret_jwt_key_2026_change_in_production_hybrid_vault",
        "change-me",
        "your-jwt-secret",
        "replace_with_a_secret_generated_outside_this_repository",
    }
)


def _canonical_configured_origin(value: str) -> str:
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("CORS_ORIGINS entries must be absolute origins without paths.")

    host = parsed.hostname.rstrip(".").lower()
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("CORS_ORIGINS contains an invalid port.") from error

    if ":" in host:
        host = f"[{host}]"
    if port and (parsed.scheme, port) not in {("http", 80), ("https", 443)}:
        host = f"{host}:{port}"
    return f"{parsed.scheme}://{host}"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

    APP_NAME: str = "Boveda Hibrida API"
    APP_ENV: str = "development"
    APP_HOST: str = "0.0.0.0"
    APP_PORT: int = 8000

    CORS_ORIGINS: List[str] = ["http://localhost:5173"]

    POSTGRES_DB: str = "boveda_db"
    POSTGRES_USER: str = "boveda_user"
    POSTGRES_PASSWORD: str = "boveda_password"
    POSTGRES_HOST: str = "db"
    POSTGRES_PORT: int = 5432

    DATABASE_URL: str = "postgresql+psycopg://boveda_user:boveda_password@db:5432/boveda_db"

    # JWT & Authentication
    JWT_SECRET_KEY: SecretStr
    JWT_ALGORITHM: Literal["HS256"] = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 5
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7
    MFA_VAULT_MAX_AGE_MINUTES: int = 5
    VAULT_SESSION_EXPIRE_MINUTES: int = 5
    DEVICE_CHALLENGE_TTL_SECONDS: int = 120
    SESSION_COOKIE_NAME: str = "boveda_refresh"
    CSRF_COOKIE_NAME: str = "csrf_token"
    SESSION_COOKIE_SECURE: bool = True
    SESSION_COOKIE_SAMESITE: Literal["lax", "strict", "none"] = "lax"

    # AES-256-GCM key encoded as URL-safe base64. It has no fallback by design.
    TOTP_ENCRYPTION_KEY: SecretStr

    # Security Policies
    MAX_FAILED_LOGIN_ATTEMPTS: int = 5
    LOCKOUT_DURATION_MINUTES: int = 15

    # SMTP / Correo Electrónico (Gmail u otro proveedor)
    SMTP_ENABLED: bool = True
    SMTP_HOST: str = "smtp.gmail.com"
    SMTP_PORT: int = 587
    SMTP_USER: str = ""
    SMTP_PASSWORD: str = ""
    SMTP_FROM_EMAIL: str = ""
    SMTP_FROM_NAME: str = "Bóveda Híbrida"
    FRONTEND_URL: str = "http://localhost:5173"

    @field_validator("CORS_ORIGINS", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Union[str, List[str]]) -> List[str]:
        origins: List[str]
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                try:
                    origins = json.loads(v)
                except Exception:
                    origins = [i.strip() for i in v.split(",") if i.strip()]
            else:
                origins = [i.strip() for i in v.split(",") if i.strip()]
        else:
            origins = v
        if not origins or "*" in origins:
            raise ValueError("CORS_ORIGINS must list explicit origins when credentials are enabled.")
        return [_canonical_configured_origin(origin) for origin in origins]

    @model_validator(mode="after")
    def validate_production_web_security(self):
        if self.APP_ENV.lower() in {"production", "prod"}:
            if not self.SESSION_COOKIE_SECURE:
                raise ValueError("SESSION_COOKIE_SECURE must be enabled in production.")
            if any(not origin.startswith("https://") for origin in self.CORS_ORIGINS):
                raise ValueError("CORS_ORIGINS must use HTTPS in production.")
            if not _canonical_configured_origin(self.FRONTEND_URL).startswith("https://"):
                raise ValueError("FRONTEND_URL must use HTTPS in production.")
        return self

    @field_validator("JWT_SECRET_KEY")
    @classmethod
    def validate_jwt_secret(cls, value: SecretStr) -> SecretStr:
        secret = value.get_secret_value().strip()
        if not secret:
            raise ValueError("JWT_SECRET_KEY must not be empty.")
        if len(secret) < MINIMUM_JWT_SECRET_LENGTH:
            raise ValueError(
                f"JWT_SECRET_KEY must contain at least {MINIMUM_JWT_SECRET_LENGTH} characters."
            )
        if secret.lower() in INSECURE_JWT_SECRET_VALUES:
            raise ValueError("JWT_SECRET_KEY uses a known insecure example value.")
        if len(set(secret)) < MINIMUM_JWT_SECRET_UNIQUE_CHARACTERS:
            raise ValueError("JWT_SECRET_KEY does not contain enough entropy.")
        return SecretStr(secret)

    @field_validator("TOTP_ENCRYPTION_KEY")
    @classmethod
    def validate_totp_encryption_key(cls, value: SecretStr) -> SecretStr:
        encoded_key = value.get_secret_value().strip()
        if not encoded_key:
            raise ValueError("TOTP_ENCRYPTION_KEY must not be empty.")

        try:
            padded_key = encoded_key + "=" * (-len(encoded_key) % 4)
            key = base64.b64decode(
                padded_key.encode("ascii"), altchars=b"-_", validate=True
            )
        except (UnicodeEncodeError, binascii.Error, ValueError) as error:
            raise ValueError(
                "TOTP_ENCRYPTION_KEY must be URL-safe base64 encoded."
            ) from error

        if len(key) != TOTP_ENCRYPTION_KEY_BYTES:
            raise ValueError("TOTP_ENCRYPTION_KEY must decode to 32 bytes.")
        return SecretStr(encoded_key)


settings = Settings()
