from typing import Optional
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.auth import Usuario
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    RefreshTokenRequest,
    RegistroUsuarioRequest,
    UsuarioRead,
)
from app.services.auth_service import AuthService, get_current_user

router = APIRouter(prefix="/auth", tags=["Autenticación"])


def get_client_ip(request: Request) -> str:
    """Extrae la IP real del cliente detrás de proxies o de la conexión directa."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


@router.post(
    "/register",
    response_model=UsuarioRead,
    status_code=status.HTTP_201_CREATED,
    summary="CU-01: Registro de nuevo usuario",
    description="Registra un nuevo usuario en la bóveda, valida la fortaleza de la contraseña, asigna el rol por defecto (Miembro) mediante RBAC y audita la operación.",
)
def register(
    registro_data: RegistroUsuarioRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    service = AuthService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.register_user(registro_data, client_ip=client_ip, user_agent=user_agent)


@router.post(
    "/login",
    response_model=LoginResponse,
    summary="Iniciar sesión y obtener tokens JWT",
    description="Autentica las credenciales del usuario, registra o actualiza el dispositivo, crea la sesión y audita el acceso.",
)
def login(
    login_data: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    service = AuthService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.login(login_data, client_ip=client_ip, user_agent=user_agent)


@router.post(
    "/refresh",
    summary="Renovar access token mediante refresh token",
)
def refresh_token(
    refresh_data: RefreshTokenRequest,
    db: Session = Depends(get_db),
):
    service = AuthService(db)
    return service.refresh_token(refresh_data)


@router.post(
    "/logout",
    response_model=LogoutResponse,
    summary="Cerrar sesión y revocar refresh token",
)
def logout(
    request: Request,
    body: Optional[RefreshTokenRequest] = None,
    current_user: Usuario = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = AuthService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    refresh_token = body.refresh_token if body else None
    service.logout(refresh_token, current_user, client_ip=client_ip, user_agent=user_agent)
    return LogoutResponse()


@router.get(
    "/me",
    response_model=UsuarioRead,
    summary="Obtener perfil y roles del usuario autenticado",
)
def get_me(
    current_user: Usuario = Depends(get_current_user),
):
    return current_user
