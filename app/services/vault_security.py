import hashlib
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.device_crypto import DeviceCryptoError, verify_ed25519_signature
from app.core.security import decode_token, get_jwt_secret
from app.models.auth import Dispositivo, Sesion, SesionBoveda, Usuario
from app.repositories.auth_repository import AuthRepository
from app.schemas.vault import VaultSessionRequest
from app.services.auth_service import AuthenticatedSession, get_current_auth_context
from app.services.device_identity_service import CHALLENGE_VAULT, DeviceIdentityService


vault_bearer = HTTPBearer(auto_error=False)


def reject(status_code: int, message: str) -> None:
    raise HTTPException(status_code=status_code, detail=message)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def active_session(
    db: Session, session_id: uuid.UUID, user_id: uuid.UUID, device_id: uuid.UUID
) -> tuple[Usuario, Dispositivo, Sesion]:
    session = db.get(Sesion, session_id)
    device = db.get(Dispositivo, device_id)
    user = db.get(Usuario, user_id)
    now = datetime.now(timezone.utc)
    if (
        not session
        or session.revocada
        or _as_utc(session.fecha_expiracion) <= now
        or session.id_usuario != user_id
        or session.id_dispositivo != device_id
    ):
        reject(401, "Sesión expirada o revocada.")
    if not user or user.estado != "ACTIVO":
        reject(401, "Usuario inactivo.")
    if (
        not device
        or device.id_usuario != user_id
        or device.estado != "TRUSTED"
        or not device.es_confiable
        or not device.public_key
        or not device.clave_firma_boveda
    ):
        reject(403, "El dispositivo debe estar TRUSTED y vigente.")
    if not session.mfa_verificado_en:
        reject(403, "Se requiere MFA para abrir una sesión de bóveda.")
    mfa_verified_at = _as_utc(session.mfa_verificado_en)
    if mfa_verified_at + timedelta(minutes=settings.MFA_VAULT_MAX_AGE_MINUTES) < now:
        reject(403, "La verificación MFA debe renovarse.")
    return user, device, session


def issue_vault_session(
    db: Session, context: AuthenticatedSession, body: VaultSessionRequest, request: Request
) -> dict:
    user, device, session = active_session(
        db, context.session.id_sesion, context.user.id_usuario, context.device.id_dispositivo
    )
    DeviceIdentityService(db).prove_challenge(
        user,
        session,
        device,
        body.id_desafio,
        body.nonce,
        body.firma,
        CHALLENGE_VAULT,
        client_ip=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.VAULT_SESSION_EXPIRE_MINUTES)
    vault_session = SesionBoveda(
        id_sesion_boveda=uuid.uuid4(),
        id_usuario=user.id_usuario,
        id_dispositivo=device.id_dispositivo,
        id_sesion=session.id_sesion,
        id_desafio=body.id_desafio,
        jti=str(uuid.uuid4()),
        mfa_verificado_en=session.mfa_verificado_en,
        fecha_expiracion=expires_at,
    )
    db.add(vault_session)
    db.commit()
    token = jwt.encode(
        {
            "sub": str(user.id_usuario),
            "sid": str(session.id_sesion),
            "did": str(device.id_dispositivo),
            "vsid": str(vault_session.id_sesion_boveda),
            "jti": vault_session.jti,
            "iat": now,
            "exp": expires_at,
            "type": "vault_access",
        },
        get_jwt_secret(),
        algorithm=settings.JWT_ALGORITHM,
    )
    AuthRepository(db).create_audit_event(
        accion="SESION_BOVEDA_CREADA",
        tipo_evento="SEGURIDAD",
        resultado="EXITO",
        user_id=user.id_usuario,
        device_id=device.id_dispositivo,
        ip=request.client.host if request.client else None,
        user_agent=request.headers.get("User-Agent", "Desconocido"),
        detalles={"expira_en_minutos": settings.VAULT_SESSION_EXPIRE_MINUTES},
    )
    return {
        "access_token": token,
        "id_dispositivo": str(device.id_dispositivo),
        "id_usuario": str(user.id_usuario),
        "expires_in": settings.VAULT_SESSION_EXPIRE_MINUTES * 60,
    }


async def get_vault_context(
    request: Request,
    credentials=Depends(vault_bearer),
    db: Session = Depends(get_db),
) -> tuple[Usuario, Dispositivo]:
    payload = decode_token(credentials.credentials) if credentials else None
    if not payload or payload.get("type") != "vault_access":
        reject(401, "Se requiere una sesión de bóveda válida.")
    try:
        user_id = uuid.UUID(payload["sub"])
        session_id = uuid.UUID(payload["sid"])
        device_id = uuid.UUID(payload["did"])
        vault_session_id = uuid.UUID(payload["vsid"])
        timestamp = request.headers["X-Vault-Timestamp"]
        if abs(time.time() - int(timestamp)) > 60:
            reject(401, "Firma expirada; verifica la hora del dispositivo.")
        digest = hashlib.sha256(await request.body()).hexdigest()
        message = "\n".join(
            [
                payload["jti"],
                timestamp,
                request.method,
                request.url.path,
                request.headers.get("Idempotency-Key", ""),
                digest,
            ]
        ).encode("utf-8")
    except HTTPException:
        raise
    except (KeyError, TypeError, ValueError):
        reject(401, "Firma del dispositivo inválida.")

    vault_session = db.get(SesionBoveda, vault_session_id)
    now = datetime.now(timezone.utc)
    if (
        not vault_session
        or vault_session.revocada
        or _as_utc(vault_session.fecha_expiracion) <= now
        or vault_session.id_usuario != user_id
        or vault_session.id_dispositivo != device_id
        or vault_session.id_sesion != session_id
        or vault_session.jti != payload["jti"]
    ):
        reject(401, "Sesión de bóveda expirada o revocada.")

    user, device, _ = active_session(db, session_id, user_id, device_id)
    try:
        verify_ed25519_signature(
            device.clave_firma_boveda or "", request.headers["X-Vault-Signature"], message
        )
    except (KeyError, DeviceCryptoError):
        reject(401, "Firma del dispositivo inválida.")
    return user, device
