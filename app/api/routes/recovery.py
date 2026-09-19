from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.recovery import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    ValidateTokenRequest,
    ValidateTokenResponse,
)
from app.services.recovery_service import RecoveryService

router = APIRouter(prefix="/auth/recovery", tags=["CU-03: Recuperación de Cuenta"])


def get_client_ip(request: Request) -> str:
    return request.client.host if request.client else "unknown"


def get_recovery_service(db: Session = Depends(get_db)) -> RecoveryService:
    return RecoveryService(db)


@router.post(
    "/forgot-password",
    response_model=ForgotPasswordResponse,
    status_code=status.HTTP_200_OK,
    summary="CU-03: Solicitar recuperación de acceso",
    description="Genera un token de recuperación seguro y temporal para restablecer credenciales sin comprometer la bóveda ni revelar si el usuario existe.",
)
def forgot_password(
    body: ForgotPasswordRequest,
    request: Request,
    service: RecoveryService = Depends(get_recovery_service),
):
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.request_forgot_password(body, client_ip=client_ip, user_agent=user_agent)


@router.post(
    "/validate-token",
    response_model=ValidateTokenResponse,
    summary="CU-03: Validar estado de token de recuperación",
    description="Checks whether a mail-delivered token is still valid without exposing it in a URL or disclosing the associated account.",
)
def validate_token(
    body: ValidateTokenRequest,
    service: RecoveryService = Depends(get_recovery_service),
):
    return service.validate_token(body.token)


@router.post(
    "/reset-password",
    response_model=ResetPasswordResponse,
    summary="CU-03: Restablecer contraseña con token de recuperación",
    description="Aplica la nueva contraseña del usuario, consume el token, revoca todas las sesiones activas anteriores y audita la operación garantizando Zero-Knowledge.",
)
def reset_password(
    body: ResetPasswordRequest,
    request: Request,
    service: RecoveryService = Depends(get_recovery_service),
):
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.reset_password(body, client_ip=client_ip, user_agent=user_agent)
