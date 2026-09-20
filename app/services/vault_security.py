import hashlib
import time
import uuid
from datetime import datetime, timedelta, timezone

import jwt
from fastapi import Depends, HTTPException, Request
from fastapi.security import HTTPBearer
from sqlalchemy import select, update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.device_crypto import DeviceCryptoError, verify_ed25519_signature
from app.core.security import decode_token, get_jwt_secret
from app.models.auth import Dispositivo, Sesion, SesionBoveda, Usuario
from app.repositories.auth_repository import AuthRepository
from app.repositories.mfa_repository import MfaRepository
from app.schemas.vault import VaultSessionRequest
from app.services.auth_service import AuthenticatedSession, get_current_auth_context
from app.services.device_identity_service import CHALLENGE_VAULT, DeviceIdentityService


vault_bearer = HTTPBearer(auto_error=False)


def reject(status_code: int, message: str) -> None:
    raise HTTPException(status_code=status_code, detail=message)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


def active_session(
    db: Session,
    session_id: uuid.UUID,
    user_id: uuid.UUID,
    device_id: uuid.UUID,
    *,
    lock: bool = False,
) -> tuple[Usuario, Dispositivo, Sesion]:
    user_query = select(Usuario).where(Usuario.id_usuario == user_id)
    device_query = select(Dispositivo).where(Dispositivo.id_dispositivo == device_id)
    session_query = select(Sesion).where(Sesion.id_sesion == session_id)
    if lock:
        # Every vault/revocation flow acquires user, device, session, then vault-session.
        user_query = user_query.with_for_update().execution_options(populate_existing=True)
        device_query = device_query.with_for_update().execution_options(populate_existing=True)
        session_query = session_query.with_for_update().execution_options(populate_existing=True)
    user = db.scalars(user_query).first()
    device = db.scalars(device_query).first()
    session = db.scalars(session_query).first()
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
    if not MfaRepository(db).get_active_mfa(user_id):
        reject(403, "La configuración MFA actual no permite abrir una sesión de bóveda.")
    mfa_verified_at = _as_utc(session.mfa_verificado_en)
    if mfa_verified_at + timedelta(minutes=settings.MFA_VAULT_MAX_AGE_MINUTES) < now:
        reject(403, "La verificación MFA debe renovarse.")
    return user, device, session


def issue_vault_session(
    db: Session, context: AuthenticatedSession, body: VaultSessionRequest, request: Request
) -> dict:
    user, device, session = active_session(
        db,
        context.session.id_sesion,
        context.user.id_usuario,
        context.device.id_dispositivo,
        lock=True,
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
    # Proof commits its one-time consumption. Re-lock and revalidate before issuing
    # a server capability so a revocation that won the race cannot be bypassed.
    user, device, session = active_session(
        db,
        context.session.id_sesion,
        context.user.id_usuario,
        context.device.id_dispositivo,
        lock=True,
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

    # Hold the same canonical locks through the protected route. A remote revocation
    # cannot commit between signature validation and a vault write.
    user, device, session = active_session(db, session_id, user_id, device_id, lock=True)
    vault_session = db.scalars(
        select(SesionBoveda)
        .where(SesionBoveda.id_sesion_boveda == vault_session_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).first()
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

    try:
        verify_ed25519_signature(
            device.clave_firma_boveda or "", request.headers["X-Vault-Signature"], message
        )
    except (KeyError, DeviceCryptoError):
        reject(401, "Firma del dispositivo inválida.")
    request.state.vault_session = vault_session
    return user, device


def revoke_current_vault_session(
    db: Session,
    request: Request,
    user: Usuario,
    device: Dispositivo,
) -> None:
    """Revoke only the currently authenticated vault capability, idempotently."""
    vault_session = getattr(request.state, "vault_session", None)
    if not vault_session:
        reject(401, "Sesión de bóveda expirada o revocada.")
    result = db.execute(
        update(SesionBoveda)
        .where(
            SesionBoveda.id_sesion_boveda == vault_session.id_sesion_boveda,
            SesionBoveda.revocada.is_(False),
        )
        .values(revocada=True, motivo_revocacion="LOGOUT_BOVEDA_REMOTO")
    )
    if result.rowcount:
        AuthRepository(db).add_audit_event(
            accion="SESION_BOVEDA_REVOCADA",
            tipo_evento="SEGURIDAD",
            resultado="EXITO",
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            ip=request.client.host if request.client else None,
            user_agent=request.headers.get("User-Agent", "Desconocido"),
            detalles={"motivo": "LOGOUT_BOVEDA_REMOTO"},
        )
    db.commit()
