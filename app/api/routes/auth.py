from typing import Optional

from fastapi import APIRouter, Cookie, Depends, Header, Request, Response, status
from fastapi import HTTPException
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.request_security import get_client_ip, require_allowed_web_origin
from app.schemas.auth import (
    LoginRequest,
    LoginResponse,
    LogoutResponse,
    RefreshTokenRequest,
    RegistroUsuarioRequest,
    UsuarioRead,
)
from app.schemas.mfa import MfaVerifyLoginRequest
from app.services.auth_service import (
    AuthService,
    AuthenticatedSession,
    IssuedSession,
    get_current_auth_context,
    get_current_user,
)
from app.services.mfa_service import MfaService


router = APIRouter(prefix="/auth", tags=["Autenticación"])
WEB_REFRESH_COOKIE_PATH = "/api/v1/auth/web"
CSRF_COOKIE_PATH = "/"


def _set_web_session_cookies(response: Response, issued: IssuedSession) -> None:
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=issued.refresh_token,
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        path=WEB_REFRESH_COOKIE_PATH,
        secure=settings.SESSION_COOKIE_SECURE,
        httponly=True,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=issued.csrf_token or "",
        max_age=settings.REFRESH_TOKEN_EXPIRE_DAYS * 24 * 60 * 60,
        # The SPA must read this non-secret double-submit value from its root route.
        path=CSRF_COOKIE_PATH,
        secure=settings.SESSION_COOKIE_SECURE,
        httponly=False,
        samesite=settings.SESSION_COOKIE_SAMESITE,
    )


def _clear_web_session_cookies(response: Response) -> None:
    for key, path, http_only in (
        (settings.SESSION_COOKIE_NAME, WEB_REFRESH_COOKIE_PATH, True),
        (settings.CSRF_COOKIE_NAME, CSRF_COOKIE_PATH, False),
    ):
        response.delete_cookie(
            key=key,
            path=path,
            secure=settings.SESSION_COOKIE_SECURE,
            httponly=http_only,
            samesite=settings.SESSION_COOKIE_SAMESITE,
        )


@router.post("/register", response_model=UsuarioRead, status_code=status.HTTP_201_CREATED)
def register(registro_data: RegistroUsuarioRequest, request: Request, db: Session = Depends(get_db)):
    return AuthService(db).register_user(
        registro_data,
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )


@router.post("/login", response_model=LoginResponse)
def login(login_data: LoginRequest, request: Request, db: Session = Depends(get_db)):
    return AuthService(db).login(
        login_data,
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )


@router.post("/web/login", response_model=LoginResponse)
def login_web(
    login_data: LoginRequest,
    request: Request,
    response: Response,
    _: None = Depends(require_allowed_web_origin),
    db: Session = Depends(get_db),
):
    result, issued = AuthService(db).login_web(
        login_data,
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )
    if issued:
        _set_web_session_cookies(response, issued)
    return result


@router.post("/refresh")
def refresh_token(refresh_data: RefreshTokenRequest, db: Session = Depends(get_db)):
    return AuthService(db).refresh_token(refresh_data)


@router.post("/web/refresh", response_model=LoginResponse)
def refresh_web(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Cookie(None, alias=settings.SESSION_COOKIE_NAME),
    csrf_token: Optional[str] = Header(None, alias="X-CSRF-Token"),
    _: None = Depends(require_allowed_web_origin),
    db: Session = Depends(get_db),
):
    if not refresh_token:
        _clear_web_session_cookies(response)
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión expirada o revocada.")
    issued = AuthService(db).refresh_web(refresh_token, csrf_token)
    _set_web_session_cookies(response, issued)
    return issued.response


@router.post("/logout", response_model=LogoutResponse)
def logout(
    request: Request,
    body: Optional[RefreshTokenRequest] = None,
    context: AuthenticatedSession = Depends(get_current_auth_context),
    db: Session = Depends(get_db),
):
    AuthService(db).logout(
        body.refresh_token if body else None,
        context,
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )
    return LogoutResponse()


@router.post("/web/logout", response_model=LogoutResponse)
def logout_web(
    request: Request,
    response: Response,
    refresh_token: Optional[str] = Cookie(None, alias=settings.SESSION_COOKIE_NAME),
    csrf_token: Optional[str] = Header(None, alias="X-CSRF-Token"),
    _: None = Depends(require_allowed_web_origin),
    db: Session = Depends(get_db),
):
    AuthService(db).logout_web(refresh_token, csrf_token)
    _clear_web_session_cookies(response)
    return LogoutResponse()


@router.post("/web/mfa/verify-login", response_model=LoginResponse)
def verify_login_mfa_web(
    body: MfaVerifyLoginRequest,
    request: Request,
    response: Response,
    _: None = Depends(require_allowed_web_origin),
    db: Session = Depends(get_db),
):
    result, issued = MfaService(db).verify_login_mfa_web(
        body,
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )
    _set_web_session_cookies(response, issued)
    return result


@router.get("/me", response_model=UsuarioRead)
def get_me(current_user=Depends(get_current_user)):
    return current_user
