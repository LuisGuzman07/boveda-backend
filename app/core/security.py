from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Union
import hashlib
import uuid
import bcrypt
import jwt
from app.core.config import settings


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifica si una contraseña en texto plano coincide con su hash bcrypt."""
    try:
        password_bytes = plain_password.encode("utf-8")
        hash_bytes = hashed_password.encode("utf-8")
        return bcrypt.checkpw(password_bytes, hash_bytes)
    except Exception:
        return False


def get_password_hash(password: str) -> str:
    """Genera un hash seguro con bcrypt para la contraseña."""
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=12)
    hashed = bcrypt.hashpw(password_bytes, salt)
    return hashed.decode("utf-8")


def hash_token(token: str) -> str:
    """Calcula el hash SHA-256 de un token para almacenamiento seguro en la tabla SESION."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def get_jwt_secret() -> str:
    """Returns the validated JWT key without exposing it in configuration reprs."""
    return settings.JWT_SECRET_KEY.get_secret_value()


def create_access_token(
    subject: Union[str, Any],
    roles: Optional[List[str]] = None,
    permissions: Optional[List[str]] = None,
    expires_delta: Optional[timedelta] = None,
    session_id: Optional[uuid.UUID] = None,
    device_id: Optional[uuid.UUID] = None,
    mfa_verified_at: Optional[datetime] = None,
) -> str:
    """Genera un JWT Access Token con los roles y permisos del usuario."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode: Dict[str, Any] = {
        "sub": str(subject),
        "roles": roles or [],
        "permissions": permissions or [],
        "iat": now,
        "exp": expire,
        "type": "access",
    }
    if session_id is not None:
        to_encode["sid"] = str(session_id)
    if device_id is not None:
        to_encode["did"] = str(device_id)
    if mfa_verified_at is not None:
        to_encode["mfa_at"] = int(mfa_verified_at.timestamp())
    encoded_jwt = jwt.encode(
        to_encode, get_jwt_secret(), algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def create_refresh_token(
    subject: Union[str, Any],
    expires_delta: Optional[timedelta] = None,
    session_id: Optional[uuid.UUID] = None,
    device_id: Optional[uuid.UUID] = None,
    family_id: Optional[uuid.UUID] = None,
    token_jti: Optional[uuid.UUID] = None,
) -> str:
    """Genera un JWT Refresh Token."""
    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)

    to_encode: Dict[str, Any] = {
        "sub": str(subject),
        "iat": now,
        "exp": expire,
        "type": "refresh",
    }
    if session_id is not None:
        to_encode["sid"] = str(session_id)
    if device_id is not None:
        to_encode["did"] = str(device_id)
    if family_id is not None:
        to_encode["fid"] = str(family_id)
    if token_jti is not None:
        to_encode["jti"] = str(token_jti)
    encoded_jwt = jwt.encode(
        to_encode, get_jwt_secret(), algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def create_mfa_token(
    subject: Union[str, Any],
    device_id: Optional[uuid.UUID] = None,
    client_type: str = "NATIVE",
    security_version: Optional[int] = None,
) -> str:
    """Genera un JWT temporal de 5 minutos para el flujo de segundo factor MFA."""
    now = datetime.now(timezone.utc)
    expire = now + timedelta(minutes=5)
    to_encode: Dict[str, Any] = {
        "sub": str(subject),
        "iat": now,
        "exp": expire,
        "type": "mfa_pending",
        "client": client_type,
    }
    if device_id is not None:
        to_encode["did"] = str(device_id)
    if security_version is not None:
        to_encode["sv"] = security_version
    encoded_jwt = jwt.encode(
        to_encode, get_jwt_secret(), algorithm=settings.JWT_ALGORITHM
    )
    return encoded_jwt


def decode_token(token: str) -> Optional[Dict[str, Any]]:
    """Decodifica y valida la firma y expiración de un JWT."""
    try:
        payload = jwt.decode(
            token,
            get_jwt_secret(),
            algorithms=[settings.JWT_ALGORITHM],
        )
        return payload
    except (jwt.PyJWTError, Exception):
        return None
