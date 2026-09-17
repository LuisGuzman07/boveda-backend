from typing import Optional
from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.recovery import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    ValidateTokenResponse,
)
from app.services.recovery_service import RecoveryService

router = APIRouter(prefix="/auth/recovery", tags=["CU-03: Recuperación de Cuenta"])


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


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
    db: Session = Depends(get_db),
):
    service = RecoveryService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.request_forgot_password(body, client_ip=client_ip, user_agent=user_agent)


@router.get(
    "/validate-token",
    response_model=ValidateTokenResponse,
    summary="CU-03: Validar estado de token de recuperación",
    description="Comprueba si el token proporcionado existe, no ha sido utilizado y se encuentra dentro de su ventana de expiración.",
)
def validate_token(
    token: str = Query(..., min_length=10, description="Token recibido para validar"),
    db: Session = Depends(get_db),
):
    service = RecoveryService(db)
    return service.validate_token(token)


@router.post(
    "/reset-password",
    response_model=ResetPasswordResponse,
    summary="CU-03: Restablecer contraseña con token de recuperación",
    description="Aplica la nueva contraseña del usuario, consume el token, revoca todas las sesiones activas anteriores y audita la operación garantizando Zero-Knowledge.",
)
def reset_password(
    body: ResetPasswordRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    service = RecoveryService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.reset_password(body, client_ip=client_ip, user_agent=user_agent)
