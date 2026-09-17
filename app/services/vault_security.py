import base64
import hashlib
import time
import uuid
from datetime import datetime, timedelta, timezone
import jwt
import pyotp
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.core.security import decode_token, hash_token
from app.models.auth import Dispositivo, Sesion, Usuario
from app.models.mfa import AutenticadorMfa
from app.schemas.vault import VaultSessionRequest

vault_bearer = HTTPBearer(auto_error=False)


def reject(status, message):
    raise HTTPException(status_code=status, detail=message)


def active_session(db, session_id, user_id, device_id):
    session = db.get(Sesion, session_id)
    device = db.get(Dispositivo, device_id)
    user = db.get(Usuario, user_id)
    now = datetime.now(timezone.utc)
    expires = session.fecha_expiracion if session else now
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if not session or session.revocada or expires <= now or session.id_usuario != user_id or session.id_dispositivo != device_id:
        reject(401, "Sesión expirada o revocada.")
    if not user or user.estado != "ACTIVO":
        reject(401, "Usuario inactivo.")
    if not device or device.id_usuario != user_id or device.estado != "ACTIVO" or not device.es_confiable:
        reject(403, "El dispositivo debe estar autorizado y vigente.")
    return user, device


def issue_vault_session(db: Session, user: Usuario, body: VaultSessionRequest):
    payload = decode_token(body.refresh_token)
    if not payload or payload.get("type") != "refresh" or payload.get("sub") != str(user.id_usuario):
        reject(401, "Refresh token inválido.")
    session = db.scalar(select(Sesion).where(Sesion.refresh_token_hash == hash_token(body.refresh_token), Sesion.id_usuario == user.id_usuario, Sesion.revocada.is_(False)))
    if not session or not session.id_dispositivo:
        reject(401, "No existe una sesión asociada al dispositivo.")
    _, device = active_session(db, session.id_sesion, user.id_usuario, session.id_dispositivo)
    if device.public_key != body.public_key:
        reject(403, "La clave de firma no corresponde al dispositivo registrado.")
    mfa = db.scalar(select(AutenticadorMfa).where(AutenticadorMfa.id_usuario == user.id_usuario, AutenticadorMfa.estado == "ACTIVO", AutenticadorMfa.tipo == "TOTP"))
    if not mfa or not pyotp.TOTP(mfa.secreto_cifrado).verify(body.code, valid_window=1):
        reject(403, "Se requiere un código TOTP válido para abrir la sesión de bóvedas.")
    try:
        public_key = base64.b64decode(body.public_key, validate=True)
        Ed25519PublicKey.from_public_bytes(public_key)
    except Exception:
        reject(422, "Clave pública Ed25519 inválida.")
    now = datetime.now(timezone.utc)
    token = jwt.encode({"sub": str(user.id_usuario), "sid": str(session.id_sesion), "did": str(session.id_dispositivo), "pk": body.public_key, "mfa": True, "type": "vault_access", "jti": str(uuid.uuid4()), "iat": now, "exp": now + timedelta(minutes=15)}, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return {"access_token": token, "id_dispositivo": str(session.id_dispositivo), "id_usuario": str(user.id_usuario), "expires_in": 900}


async def get_vault_context(request: Request, credentials=Depends(vault_bearer), db: Session = Depends(get_db)):
    payload = decode_token(credentials.credentials) if credentials else None
    if not payload or payload.get("type") != "vault_access" or payload.get("mfa") is not True:
        reject(401, "Se requiere una sesión de bóvedas con MFA.")
    try:
        user_id, session_id, device_id = (uuid.UUID(payload[field]) for field in ("sub", "sid", "did"))
        timestamp = request.headers["X-Vault-Timestamp"]
        if abs(time.time() - int(timestamp)) > 60:
            reject(401, "Firma expirada; verifica la hora del dispositivo.")
        digest = hashlib.sha256(await request.body()).hexdigest()
        message = "\n".join([payload["jti"], timestamp, request.method, request.url.path, request.headers.get("Idempotency-Key", ""), digest]).encode()
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(payload["pk"], validate=True))
        public_key.verify(base64.b64decode(request.headers["X-Vault-Signature"], validate=True), message)
    except HTTPException:
        raise
    except Exception:
        reject(401, "Firma del dispositivo inválida.")
    user, device = active_session(db, session_id, user_id, device_id)
    if device.public_key != payload["pk"]:
        reject(403, "La clave del dispositivo ha cambiado; inicia sesión nuevamente.")
    return user, device
