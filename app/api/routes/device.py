from typing import Optional
import uuid

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.request_security import get_client_ip, require_allowed_web_origin
from app.schemas.device import (
    DeviceActionResponse,
    DeviceAuthorizeRequest,
    DeviceChallengeProofRequest,
    DeviceChallengeRequest,
    DeviceChallengeResponse,
    DeviceListResponse,
    DeviceRead,
    DeviceRegisterRequest,
)
from app.services.auth_service import AuthenticatedSession, get_current_auth_context, get_current_user
from app.services.device_identity_service import (
    CHALLENGE_ENROLLMENT,
    DeviceIdentityService,
)
from app.services.device_service import DeviceService


router = APIRouter(prefix="/devices", tags=["Dispositivos"])


def _require_current_installation(
    context: AuthenticatedSession, installation_id: Optional[str]
) -> None:
    if installation_id and installation_id != context.device.identificador_seguro:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="La solicitud no corresponde al dispositivo de la sesión activa.",
        )


@router.get("", response_model=DeviceListResponse)
def list_devices(
    context: AuthenticatedSession = Depends(get_current_auth_context),
    db: Session = Depends(get_db),
):
    return DeviceService(db).list_devices(
        user=context.user,
        current_device_id=context.device.id_dispositivo,
    )


@router.post("/register", response_model=DeviceActionResponse, status_code=status.HTTP_201_CREATED)
def register_device(
    device_data: DeviceRegisterRequest,
    request: Request,
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
    context: AuthenticatedSession = Depends(get_current_auth_context),
    db: Session = Depends(get_db),
):
    _require_current_installation(context, x_device_id)
    return DeviceService(db).register_device(
        user=context.user,
        current_device=context.device,
        session=context.session,
        request=device_data,
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )


@router.post("/challenge", response_model=DeviceChallengeResponse)
def issue_device_challenge(
    body: DeviceChallengeRequest,
    request: Request,
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
    context: AuthenticatedSession = Depends(get_current_auth_context),
    db: Session = Depends(get_db),
):
    _require_current_installation(context, x_device_id)
    challenge, nonce = DeviceIdentityService(db).issue_challenge(
        context.user,
        context.session,
        context.device,
        body.proposito,
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )
    return DeviceChallengeResponse(
        id_desafio=challenge.id_desafio,
        nonce=nonce,
        proposito=challenge.proposito,
        fecha_expiracion=challenge.fecha_expiracion,
    )


@router.post("/challenge/prove", response_model=DeviceActionResponse)
def prove_device_challenge(
    body: DeviceChallengeProofRequest,
    request: Request,
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
    context: AuthenticatedSession = Depends(get_current_auth_context),
    db: Session = Depends(get_db),
):
    _require_current_installation(context, x_device_id)
    # The persisted challenge determines its own purpose; callers cannot upgrade it.
    from app.models.auth import DesafioDispositivo

    stored_challenge = db.get(DesafioDispositivo, body.id_desafio)
    if not stored_challenge:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Desafio de dispositivo invalido o expirado.")
    DeviceIdentityService(db).prove_challenge(
        context.user,
        context.session,
        context.device,
        body.id_desafio,
        body.nonce,
        body.firma,
        stored_challenge.proposito,
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )
    db.refresh(context.device)
    return DeviceActionResponse(
        message=(
            "Posesión de identidad verificada. El dispositivo continúa PENDING hasta aprobación administrativa."
            if stored_challenge.proposito == CHALLENGE_ENROLLMENT
            else "Prueba de posesión del dispositivo verificada."
        ),
        dispositivo=DeviceRead.model_validate(context.device),
    )


@router.post("/{device_id}/authorize", response_model=DeviceActionResponse)
def authorize_device(
    device_id: uuid.UUID,
    body: Optional[DeviceAuthorizeRequest] = None,
):
    raise HTTPException(
        status_code=status.HTTP_410_GONE,
        detail="La autorización directa fue retirada. Usa el desafío criptográfico del dispositivo.",
    )


@router.post("/{device_id}/revoke-trust", response_model=DeviceActionResponse)
def revoke_device_trust(
    device_id: uuid.UUID,
    request: Request,
    context: AuthenticatedSession = Depends(get_current_auth_context),
    db: Session = Depends(get_db),
):
    return DeviceService(db).revoke_device(
        device_id=device_id,
        user=context.user,
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )


@router.delete("/{device_id}", response_model=DeviceActionResponse)
def delete_device(
    device_id: uuid.UUID,
    request: Request,
    context: AuthenticatedSession = Depends(get_current_auth_context),
    db: Session = Depends(get_db),
):
    return DeviceService(db).revoke_device(
        device_id=device_id,
        user=context.user,
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )


def _require_web_origin_for_context(request: Request, context: AuthenticatedSession) -> None:
    if context.session.tipo_cliente == "WEB":
        require_allowed_web_origin(request)


def verify_admin_role(
    request: Request,
    context: AuthenticatedSession = Depends(get_current_auth_context),
) -> AuthenticatedSession:
    _require_web_origin_for_context(request, context)
    if "Administrador" not in {role.nombre for role in context.user.roles}:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso restringido: se requieren privilegios de Administrador.",
        )
    return context


def verify_device_approval_authority(
    request: Request,
    context: AuthenticatedSession = Depends(get_current_auth_context),
) -> AuthenticatedSession:
    _require_web_origin_for_context(request, context)
    roles = {role.nombre for role in context.user.roles}
    permissions = {permission.codigo for role in context.user.roles for permission in role.permisos}
    if "Administrador" not in roles and "devices:approve" not in permissions:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Se requiere el permiso devices:approve para aprobar un dispositivo.",
        )
    DeviceIdentityService.require_recent_mfa(context.session)
    return context


@router.get("/admin/all")
def list_all_devices_admin(
    query: Optional[str] = None,
    solo_confiables: Optional[bool] = None,
    estado: Optional[str] = None,
    context: AuthenticatedSession = Depends(verify_admin_role),
    db: Session = Depends(get_db),
):
    return DeviceService(db).list_all_devices_admin(query, solo_confiables, estado)


@router.post("/admin/{device_id}/revoke", response_model=DeviceActionResponse)
def revoke_device_admin(
    device_id: uuid.UUID,
    request: Request,
    body: Optional[dict] = None,
    context: AuthenticatedSession = Depends(verify_admin_role),
    db: Session = Depends(get_db),
):
    return DeviceService(db).revoke_device_admin(
        device_id=device_id,
        context=context,
        motivo=(body or {}).get("motivo", "Revocación administrativa preventiva de seguridad"),
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )


@router.post("/admin/{device_id}/approve", response_model=DeviceActionResponse)
def approve_device_admin(
    device_id: uuid.UUID,
    request: Request,
    context: AuthenticatedSession = Depends(verify_device_approval_authority),
    db: Session = Depends(get_db),
):
    return DeviceService(db).approve_device_admin(
        device_id=device_id,
        context=context,
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )


@router.post("/admin/user/{target_user_id}/revoke-all")
def revoke_all_user_devices_admin(
    target_user_id: uuid.UUID,
    request: Request,
    body: Optional[dict] = None,
    context: AuthenticatedSession = Depends(verify_admin_role),
    db: Session = Depends(get_db),
):
    return DeviceService(db).revoke_all_user_devices_admin(
        target_user_id=target_user_id,
        context=context,
        motivo=(body or {}).get("motivo", "Revocación masiva de terminales por seguridad"),
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )
