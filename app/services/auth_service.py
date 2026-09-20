from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import List, Optional
import secrets
import uuid

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    create_mfa_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    hash_token,
    verify_password,
)
from app.models.auth import Dispositivo, Sesion, Usuario
from app.repositories.auth_repository import AuthRepository
from app.repositories.mfa_repository import MfaRepository
from app.schemas.auth import (
    DispositivoInfo,
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    RegistroUsuarioRequest,
    UsuarioRead,
)


security_scheme = HTTPBearer(auto_error=True)


def _as_utc(value: Optional[datetime]) -> Optional[datetime]:
    return value.replace(tzinfo=timezone.utc) if value and value.tzinfo is None else value


def _roles_and_permissions(user: Usuario) -> tuple[List[str], List[str]]:
    return (
        [role.nombre for role in user.roles],
        list({permission.codigo for role in user.roles for permission in role.permisos}),
    )


@dataclass(frozen=True)
class AuthenticatedSession:
    user: Usuario
    session: Sesion
    device: Dispositivo
    payload: dict


@dataclass(frozen=True)
class IssuedSession:
    session: Sesion
    access_token: str
    refresh_token: str
    csrf_token: Optional[str]
    response: LoginResponse


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = AuthRepository(db)
        self.mfa_repo = MfaRepository(db)

    def register_user(
        self,
        request: RegistroUsuarioRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UsuarioRead:
        existing_user = self.repo.get_user_by_email(request.correo)
        if existing_user:
            self.repo.create_audit_event(
                accion="REGISTRO_DUPLICADO",
                tipo_evento="AUTENTICACION",
                resultado="FALLO",
                ip=client_ip,
                user_agent=user_agent,
                detalles={"motivo": "Correo ya registrado"},
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Ya existe una cuenta registrada con este correo electrónico.",
            )

        default_role = self.repo.get_role_by_name("Miembro")
        roles = [default_role] if default_role else []
        new_user = self.repo.create_user(
            nombre=request.nombre,
            correo=request.correo,
            password_hash=get_password_hash(request.password),
            roles=roles,
        )
        self.repo.create_audit_event(
            accion="REGISTRO_USUARIO",
            tipo_evento="AUTENTICACION",
            resultado="EXITO",
            user_id=new_user.id_usuario,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"roles": [role.nombre for role in roles]},
        )
        return UsuarioRead.model_validate(new_user)

    def login(
        self,
        request: LoginRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> LoginResponse:
        response, _ = self._login(
            request, "NATIVE", client_ip=client_ip, user_agent=user_agent
        )
        return response

    def login_web(
        self,
        request: LoginRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> tuple[LoginResponse, Optional[IssuedSession]]:
        return self._login(request, "WEB", client_ip=client_ip, user_agent=user_agent)

    def _login(
        self,
        request: LoginRequest,
        client_type: str,
        client_ip: Optional[str],
        user_agent: Optional[str],
    ) -> tuple[LoginResponse, Optional[IssuedSession]]:
        now = datetime.now(timezone.utc)
        user = self.repo.get_user_by_email(request.correo)
        if not user:
            self.repo.create_audit_event(
                accion="LOGIN_FALLIDO",
                tipo_evento="AUTENTICACION",
                resultado="FALLO",
                ip=client_ip,
                user_agent=user_agent,
                detalles={"motivo": "Credenciales invalidas"},
            )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas.")

        locked_until = _as_utc(user.bloqueado_hasta)
        if locked_until and locked_until > now:
            self.repo.create_audit_event(
                accion="LOGIN_BLOQUEADO",
                tipo_evento="AUTENTICACION",
                resultado="DENEGADO",
                user_id=user.id_usuario,
                ip=client_ip,
                user_agent=user_agent,
                detalles={"motivo": "Cuenta bloqueada temporalmente"},
            )
            raise HTTPException(
                status_code=status.HTTP_423_LOCKED,
                detail="Cuenta bloqueada temporalmente por seguridad.",
            )

        if user.estado == "BLOQUEADO" and locked_until:
            user.estado = "ACTIVO"
            user.bloqueado_hasta = None
            user.intentos_fallidos = 0
            self.repo.update_user(user)

        if user.estado != "ACTIVO":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="La cuenta de usuario no se encuentra activa.",
            )

        if not verify_password(request.password, user.password_hash):
            user.intentos_fallidos += 1
            if user.intentos_fallidos >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
                user.bloqueado_hasta = now + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
                user.estado = "BLOQUEADO"
            self.repo.update_user(user)
            self.repo.create_audit_event(
                accion="LOGIN_FALLIDO",
                tipo_evento="AUTENTICACION",
                resultado="FALLO",
                user_id=user.id_usuario,
                ip=client_ip,
                user_agent=user_agent,
                detalles={"intentos": user.intentos_fallidos},
            )
            if user.intentos_fallidos >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail="Demasiados intentos fallidos. Cuenta bloqueada temporalmente.",
                )
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Credenciales inválidas.")

        user.intentos_fallidos = 0
        user.bloqueado_hasta = None
        user.ultimo_acceso = now
        if user.estado == "BLOQUEADO":
            user.estado = "ACTIVO"
        self.repo.update_user(user)

        device_info = request.dispositivo or DispositivoInfo()
        device = self.repo.get_or_create_device(user.id_usuario, device_info)
        active_mfa = self.mfa_repo.get_active_mfa(user.id_usuario)
        if active_mfa:
            self.repo.create_audit_event(
                accion="LOGIN_MFA_SOLICITADO",
                tipo_evento="AUTENTICACION",
                resultado="PENDIENTE",
                user_id=user.id_usuario,
                device_id=device.id_dispositivo,
                ip=client_ip,
                user_agent=user_agent,
                detalles={"cliente": client_type},
            )
            return (
                LoginResponse(
                    mfa_required=True,
                    mfa_token=create_mfa_token(
                        user.id_usuario,
                        device_id=device.id_dispositivo,
                        client_type=client_type,
                    ),
                    usuario=UsuarioRead.model_validate(user),
                ),
                None,
            )

        issued = self.create_authenticated_session(user, device, client_type)
        self.repo.create_audit_event(
            accion="LOGIN_EXITOSO",
            tipo_evento="AUTENTICACION",
            resultado="EXITO",
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"cliente": client_type},
        )
        return issued.response, issued

    def create_authenticated_session(
        self,
        user: Usuario,
        device: Dispositivo,
        client_type: str,
        mfa_verified_at: Optional[datetime] = None,
    ) -> IssuedSession:
        now = datetime.now(timezone.utc)
        session_id = uuid.uuid4()
        family_id = uuid.uuid4()
        refresh_jti = uuid.uuid4()
        csrf_token = secrets.token_urlsafe(32) if client_type == "WEB" else None
        refresh_token = create_refresh_token(
            subject=user.id_usuario,
            session_id=session_id,
            device_id=device.id_dispositivo,
            family_id=family_id,
            token_jti=refresh_jti,
        )
        session = self.repo.create_session(
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            refresh_token_hash=hash_token(refresh_token),
            expires_at=now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS),
            session_id=session_id,
            family_id=family_id,
            refresh_jti=str(refresh_jti),
            client_type=client_type,
            csrf_hash=hash_token(csrf_token) if csrf_token else None,
            mfa_verified_at=mfa_verified_at,
        )
        roles, permissions = _roles_and_permissions(user)
        access_token = create_access_token(
            subject=user.id_usuario,
            roles=roles,
            permissions=permissions,
            session_id=session.id_sesion,
            device_id=device.id_dispositivo,
            mfa_verified_at=mfa_verified_at,
        )
        response = LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token if client_type == "NATIVE" else None,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            usuario=UsuarioRead.model_validate(user),
            roles=roles,
            permisos=permissions,
        )
        return IssuedSession(session, access_token, refresh_token, csrf_token, response)

    def refresh_token(self, request: RefreshTokenRequest) -> dict:
        issued = self._refresh(request.refresh_token, "NATIVE")
        return {
            "access_token": issued.access_token,
            "refresh_token": issued.refresh_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }

    def refresh_web(self, refresh_token: str, csrf_token: Optional[str]) -> IssuedSession:
        return self._refresh(refresh_token, "WEB", csrf_token)

    def _refresh(
        self,
        refresh_token: str,
        client_type: str,
        csrf_token: Optional[str] = None,
    ) -> IssuedSession:
        payload = decode_token(refresh_token)
        claims = self._parse_refresh_claims(payload)
        session = self.repo.get_session_by_id(claims["session_id"])
        if not session or session.familia_refresh_id != claims["family_id"]:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión expirada o revocada.")

        user = self.repo.get_user_by_id(session.id_usuario)
        device = self.repo.get_device_by_id(session.id_dispositivo) if session.id_dispositivo else None
        if (
            session.revocada
            or _as_utc(session.fecha_expiracion) <= datetime.now(timezone.utc)
            or session.id_usuario != claims["user_id"]
            or session.id_dispositivo != claims["device_id"]
            or session.tipo_cliente != client_type
            or not user
            or user.estado != "ACTIVO"
            or not device
            or device.id_usuario != user.id_usuario
            or device.estado == "REVOKED"
        ):
            self.repo.revoke_refresh_family(session.familia_refresh_id, "SESION_INVALIDA")
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión expirada o revocada.")

        if client_type == "WEB" and (
            not csrf_token
            or not session.csrf_hash
            or not secrets.compare_digest(hash_token(csrf_token), session.csrf_hash)
        ):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Validación CSRF inválida.")

        presented_hash = hash_token(refresh_token)
        if session.refresh_jti != claims["jti"] or not secrets.compare_digest(
            session.refresh_token_hash, presented_hash
        ):
            self._revoke_reused_family(session, user, device)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token reutilizado.")

        new_jti = uuid.uuid4()
        new_csrf = secrets.token_urlsafe(32) if client_type == "WEB" else None
        new_refresh = create_refresh_token(
            subject=user.id_usuario,
            session_id=session.id_sesion,
            device_id=device.id_dispositivo,
            family_id=session.familia_refresh_id,
            token_jti=new_jti,
        )
        now = datetime.now(timezone.utc)
        if not self.repo.rotate_refresh_token(
            session,
            expected_jti=claims["jti"],
            expected_hash=presented_hash,
            new_jti=str(new_jti),
            new_hash=hash_token(new_refresh),
            csrf_hash=hash_token(new_csrf) if new_csrf else None,
            now=now,
        ):
            self._revoke_reused_family(session, user, device)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token reutilizado.")

        roles, permissions = _roles_and_permissions(user)
        access_token = create_access_token(
            subject=user.id_usuario,
            roles=roles,
            permissions=permissions,
            session_id=session.id_sesion,
            device_id=device.id_dispositivo,
            mfa_verified_at=session.mfa_verificado_en,
        )
        refreshed = LoginResponse(
            access_token=access_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            usuario=UsuarioRead.model_validate(user),
            roles=roles,
            permisos=permissions,
        )
        self.repo.create_audit_event(
            accion="REFRESH_ROTADO",
            tipo_evento="AUTENTICACION",
            resultado="EXITO",
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            detalles={"cliente": client_type},
        )
        return IssuedSession(session, access_token, new_refresh, new_csrf, refreshed)

    @staticmethod
    def _parse_refresh_claims(payload: Optional[dict]) -> dict:
        if not payload or payload.get("type") != "refresh":
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token de renovación inválido o expirado.")
        try:
            return {
                "user_id": uuid.UUID(payload["sub"]),
                "session_id": uuid.UUID(payload["sid"]),
                "device_id": uuid.UUID(payload["did"]),
                "family_id": uuid.UUID(payload["fid"]),
                "jti": str(uuid.UUID(payload["jti"])),
            }
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Refresh token inválido.") from error

    def _revoke_reused_family(self, session: Sesion, user: Usuario, device: Dispositivo) -> None:
        self.repo.revoke_refresh_family(session.familia_refresh_id, "REUTILIZACION_REFRESH")
        self.repo.create_audit_event(
            accion="REFRESH_REUTILIZADO",
            tipo_evento="SEGURIDAD",
            resultado="DENEGADO",
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            detalles={"motivo": "Rotacion de refresh incumplida"},
        )

    def logout(
        self,
        refresh_token: Optional[str],
        context: AuthenticatedSession,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        session = context.session
        if refresh_token:
            try:
                claims = self._parse_refresh_claims(decode_token(refresh_token))
            except HTTPException:
                claims = None
            if claims and claims["session_id"] == session.id_sesion:
                session = self.repo.get_session_by_id(claims["session_id"]) or session
        self.repo.revoke_refresh_family(session.familia_refresh_id, "LOGOUT_VOLUNTARIO")
        self.repo.create_audit_event(
            accion="LOGOUT",
            tipo_evento="AUTENTICACION",
            resultado="EXITO",
            user_id=context.user.id_usuario,
            device_id=context.device.id_dispositivo,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"cliente": context.session.tipo_cliente},
        )

    def logout_web(self, refresh_token: Optional[str], csrf_token: Optional[str]) -> None:
        if not refresh_token:
            return
        try:
            claims = self._parse_refresh_claims(decode_token(refresh_token))
        except HTTPException:
            return
        session = self.repo.get_session_by_id(claims["session_id"])
        if (
            not session
            or session.tipo_cliente != "WEB"
            or not csrf_token
            or not session.csrf_hash
            or not secrets.compare_digest(hash_token(csrf_token), session.csrf_hash)
        ):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Validación CSRF inválida.")
        user = self.repo.get_user_by_id(session.id_usuario)
        device = self.repo.get_device_by_id(session.id_dispositivo) if session.id_dispositivo else None
        self.repo.revoke_refresh_family(session.familia_refresh_id, "LOGOUT_WEB")
        if user and device:
            self.repo.create_audit_event(
                accion="LOGOUT",
                tipo_evento="AUTENTICACION",
                resultado="EXITO",
                user_id=user.id_usuario,
                device_id=device.id_dispositivo,
                detalles={"cliente": "WEB"},
            )


def get_current_auth_context(
    auth_header: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> AuthenticatedSession:
    payload = decode_token(auth_header.credentials)
    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acceso inválido o expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    try:
        user_id = uuid.UUID(payload["sub"])
        session_id = uuid.UUID(payload["sid"])
        device_id = uuid.UUID(payload["did"])
    except (KeyError, TypeError, ValueError) as error:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="El token no está vinculado a una sesión activa.",
        ) from error

    repo = AuthRepository(db)
    session = repo.get_session_by_id(session_id)
    user = repo.get_user_by_id(user_id)
    device = repo.get_device_by_id(device_id)
    now = datetime.now(timezone.utc)
    if (
        not session
        or session.revocada
        or _as_utc(session.fecha_expiracion) <= now
        or session.id_usuario != user_id
        or session.id_dispositivo != device_id
        or not user
        or user.estado != "ACTIVO"
        or not device
        or device.id_usuario != user_id
        or device.estado == "REVOKED"
    ):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Sesión expirada o revocada.")
    return AuthenticatedSession(user=user, session=session, device=device, payload=payload)


def get_current_user(
    context: AuthenticatedSession = Depends(get_current_auth_context),
) -> Usuario:
    return context.user
