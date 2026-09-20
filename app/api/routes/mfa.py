from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.core.request_security import get_client_ip
from app.models.auth import Usuario
from app.schemas.auth import LoginResponse
from app.schemas.mfa import (
    MfaDisableRequest,
    MfaEnableRequest,
    MfaSetupResponse,
    MfaStatusResponse,
    MfaVerifyLoginRequest,
)
from app.services.auth_service import get_current_user
from app.services.mfa_service import MfaService

router = APIRouter(prefix="/auth/mfa", tags=["MFA (Doble Factor)"])


@router.post(
    "/setup",
    response_model=MfaSetupResponse,
    summary="CU-02: Iniciar configuración de MFA (TOTP)",
    description="Genera la clave secreta Base32, la URI otpauth, el código QR en Base64 y los 8 códigos de respaldo de emergencia.",
)
def setup_mfa(
    request: Request,
    current_user: Usuario = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = MfaService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.setup_mfa(current_user, client_ip=client_ip, user_agent=user_agent)


@router.post(
    "/enable",
    summary="CU-02: Activar MFA tras verificar código de la app móvil",
    description="Verifica el código de 6 dígitos generado por la app Bóveda Authenticator y activa la protección 2FA.",
)
def enable_mfa(
    request: Request,
    body: MfaEnableRequest,
    current_user: Usuario = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = MfaService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.enable_mfa(current_user, body, client_ip=client_ip, user_agent=user_agent)


@router.post(
    "/verify-login",
    response_model=LoginResponse,
    summary="CU-02: Completar inicio de sesión con código de 6 dígitos o de respaldo",
    description="Valida el segundo factor tras el paso de contraseña y emite los tokens JWT finales.",
)
def verify_login_mfa(
    request: Request,
    body: MfaVerifyLoginRequest,
    db: Session = Depends(get_db),
):
    service = MfaService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.verify_login_mfa(body, client_ip=client_ip, user_agent=user_agent)


@router.post(
    "/disable",
    summary="CU-02: Desactivar MFA con confirmación de contraseña",
)
def disable_mfa(
    request: Request,
    body: MfaDisableRequest,
    current_user: Usuario = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = MfaService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.disable_mfa(current_user, body, client_ip=client_ip, user_agent=user_agent)


@router.get(
    "/status",
    response_model=MfaStatusResponse,
    summary="CU-02: Consultar estado de activación de MFA",
)
def get_mfa_status(
    current_user: Usuario = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = MfaService(db)
    return service.get_status(current_user)
