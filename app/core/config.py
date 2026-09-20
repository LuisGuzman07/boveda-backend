import json
import base64
import binascii
import re
from typing import List, Literal, Union
from urllib.parse import urlsplit

from pydantic import Field, SecretStr, field_validator, model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


MINIMUM_JWT_SECRET_LENGTH = 32
MINIMUM_JWT_SECRET_UNIQUE_CHARACTERS = 12
TOTP_ENCRYPTION_KEY_BYTES = 32
MINIMUM_OBJECT_STORAGE_SECRET_LENGTH = 16
MINIMUM_OBJECT_STORAGE_ACCESS_KEY_LENGTH = 3
OBJECT_STORAGE_BUCKET_PATTERN = re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$")
INSECURE_JWT_SECRET_VALUES = frozenset(
    {
        "boveda_super_secret_jwt_key_2026_change_in_production_hybrid_vault",
        "change-me",
        "your-jwt-secret",
        "replace_with_a_secret_generated_outside_this_repository",
    }
)
INSECURE_OBJECT_STORAGE_CREDENTIALS = frozenset(
    {
        "minioadmin",
        "change-me",
        "replace-with-a-secret",
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


def _canonical_object_store_endpoint(value: str, *, public: bool) -> str:
    raw_value = value.strip()
    if not raw_value:
        return ""
    parsed = urlsplit(raw_value if public else f"//{raw_value}")
    if (
        (public and parsed.scheme not in {"http", "https"})
        or (not public and parsed.scheme)
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        label = "MINIO_PUBLIC_ENDPOINT" if public else "MINIO_INTERNAL_ENDPOINT"
        raise ValueError(f"{label} must not include credentials, paths, queries, or fragments.")

    host = parsed.hostname.rstrip(".").lower()
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("MinIO endpoint contains an invalid port.") from error
    if ":" in host:
        host = f"[{host}]"
    endpoint = f"{host}:{port}" if port else host
    return f"{parsed.scheme}://{endpoint}" if public else endpoint


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

    # Object storage is disabled until an operator supplies every MinIO setting.
    # No credential has a functional fallback.
    OBJECT_STORAGE_ENABLED: bool = False
    MINIO_INTERNAL_ENDPOINT: str = ""
    MINIO_PUBLIC_ENDPOINT: str = ""
    MINIO_ACCESS_KEY: SecretStr | None = None
    MINIO_SECRET_KEY: SecretStr | None = None
    MINIO_BUCKET: str = "boveda-ciphertext"
    MINIO_REGION: str = "us-east-1"
    MINIO_SECURE: bool = True
    MINIO_PRESIGNED_TTL_SECONDS: int = Field(default=300, ge=30, le=900)
    FILE_UPLOAD_MAX_BYTES: int = Field(default=20 * 1024 * 1024, ge=1, le=100 * 1024 * 1024)

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

    @field_validator("MINIO_INTERNAL_ENDPOINT")
    @classmethod
    def validate_minio_internal_endpoint(cls, value: str) -> str:
        return _canonical_object_store_endpoint(value, public=False)

    @field_validator("MINIO_PUBLIC_ENDPOINT")
    @classmethod
    def validate_minio_public_endpoint(cls, value: str) -> str:
        return _canonical_object_store_endpoint(value, public=True)

    @field_validator("MINIO_BUCKET")
    @classmethod
    def validate_minio_bucket(cls, value: str) -> str:
        bucket = value.strip().lower()
        if not OBJECT_STORAGE_BUCKET_PATTERN.fullmatch(bucket) or ".." in bucket:
            raise ValueError("MINIO_BUCKET must be a valid private S3 bucket name.")
        return bucket

    @field_validator("MINIO_REGION")
    @classmethod
    def validate_minio_region(cls, value: str) -> str:
        region = value.strip().lower()
        if not re.fullmatch(r"[a-z0-9-]{2,32}", region):
            raise ValueError("MINIO_REGION must be a valid S3 region identifier.")
        return region

    @field_validator("MINIO_ACCESS_KEY", "MINIO_SECRET_KEY")
    @classmethod
    def normalize_object_storage_secret(cls, value: SecretStr | None) -> SecretStr | None:
        if value is None:
            return None
        secret = value.get_secret_value().strip()
        return SecretStr(secret) if secret else None

    @model_validator(mode="after")
    def validate_production_web_security(self):
        object_storage_enabled = self.OBJECT_STORAGE_ENABLED
        access_key = (
            self.MINIO_ACCESS_KEY.get_secret_value() if self.MINIO_ACCESS_KEY else ""
        )
        secret_key = (
            self.MINIO_SECRET_KEY.get_secret_value() if self.MINIO_SECRET_KEY else ""
        )
        if object_storage_enabled:
            if not self.MINIO_INTERNAL_ENDPOINT or not self.MINIO_PUBLIC_ENDPOINT:
                raise ValueError("MinIO endpoints are required when object storage is enabled.")
            if len(access_key) < MINIMUM_OBJECT_STORAGE_ACCESS_KEY_LENGTH:
                raise ValueError("MINIO_ACCESS_KEY is required when object storage is enabled.")
            if len(secret_key) < MINIMUM_OBJECT_STORAGE_SECRET_LENGTH:
                raise ValueError("MINIO_SECRET_KEY is required when object storage is enabled.")
            if (
                access_key.lower() in INSECURE_OBJECT_STORAGE_CREDENTIALS
                or secret_key.lower() in INSECURE_OBJECT_STORAGE_CREDENTIALS
            ):
                raise ValueError("MinIO credentials use a known insecure example value.")
        if self.APP_ENV.lower() in {"production", "prod"}:
            if not self.SESSION_COOKIE_SECURE:
                raise ValueError("SESSION_COOKIE_SECURE must be enabled in production.")
            if any(not origin.startswith("https://") for origin in self.CORS_ORIGINS):
                raise ValueError("CORS_ORIGINS must use HTTPS in production.")
            if not _canonical_configured_origin(self.FRONTEND_URL).startswith("https://"):
                raise ValueError("FRONTEND_URL must use HTTPS in production.")
            if object_storage_enabled and (
                not self.MINIO_SECURE or not self.MINIO_PUBLIC_ENDPOINT.startswith("https://")
            ):
                raise ValueError("MinIO must use HTTPS in production.")
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
