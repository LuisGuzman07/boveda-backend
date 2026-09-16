from datetime import datetime, timedelta, timezone
from typing import List, Optional
import uuid
from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.database import get_db
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    get_password_hash,
    hash_token,
    verify_password,
)
from app.models.auth import Usuario
from app.repositories.auth_repository import AuthRepository
from app.schemas.auth import (
    DispositivoInfo,
    LoginRequest,
    LoginResponse,
    RefreshTokenRequest,
    RegistroUsuarioRequest,
    UsuarioRead,
)

security_scheme = HTTPBearer(auto_error=True)


class AuthService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = AuthRepository(db)

    def register_user(
        self,
        request: RegistroUsuarioRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> UsuarioRead:
        """CU-01: Registro de nuevo usuario con asignación automática del rol Miembro (RBAC)."""
        # 1. Verificar si el correo ya está registrado
        existing_user = self.repo.get_user_by_email(request.correo)
        if existing_user:
            self.repo.create_audit_event(
                accion="REGISTRO_DUPLICADO",
                tipo_evento="AUTENTICACION",
                resultado="FALLO",
                ip=client_ip,
                user_agent=user_agent,
                detalles={"motivo": "Correo ya registrado", "correo": request.correo},
            )
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Ya existe una cuenta registrada con este correo electrónico.",
            )

        # 2. Obtener el rol por defecto (Miembro) para la asignación RBAC
        default_role = self.repo.get_role_by_name("Miembro")
        roles = [default_role] if default_role else []

        # 3. Hashear la contraseña de forma segura
        password_hash = get_password_hash(request.password)

        # 4. Crear el usuario en la BD
        new_user = self.repo.create_user(
            nombre=request.nombre,
            correo=request.correo,
            password_hash=password_hash,
            roles=roles,
        )

        # 5. Registrar evento en la auditoría
        self.repo.create_audit_event(
            accion="REGISTRO_USUARIO",
            tipo_evento="AUTENTICACION",
            resultado="EXITO",
            user_id=new_user.id_usuario,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"nombre": new_user.nombre, "correo": new_user.correo, "roles": [r.nombre for r in roles]},
        )

        return UsuarioRead.model_validate(new_user)

    def login(
        self,
        request: LoginRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> LoginResponse:
        now = datetime.now(timezone.utc)
        user = self.repo.get_user_by_email(request.correo)

        # 1. Validar existencia del usuario
        if not user:
            self.repo.create_audit_event(
                accion="LOGIN_FALLIDO",
                tipo_evento="AUTENTICACION",
                resultado="FALLO",
                ip=client_ip,
                user_agent=user_agent,
                detalles={"motivo": "Usuario no encontrado", "correo": request.correo},
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas.",
            )

        # 2. Validar si la cuenta está bloqueada
        if user.bloqueado_hasta and user.bloqueado_hasta > now:
            minutos_restantes = int((user.bloqueado_hasta - now).total_seconds() / 60) + 1
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
                detail=f"Cuenta bloqueada temporalmente por seguridad. Intente de nuevo en {minutos_restantes} minutos.",
            )

        # 3. Validar estado general del usuario
        if user.estado == "INACTIVO":
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="La cuenta se encuentra inactiva. Contacte al administrador.",
            )

        # 4. Validar contraseña
        if not verify_password(request.password, user.password_hash):
            user.intentos_fallidos += 1
            detalles_audit = {"intentos": user.intentos_fallidos}

            # Si alcanza el límite de intentos, bloquear cuenta
            if user.intentos_fallidos >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
                user.bloqueado_hasta = now + timedelta(minutes=settings.LOCKOUT_DURATION_MINUTES)
                user.estado = "BLOQUEADO"
                detalles_audit["bloqueado_hasta"] = user.bloqueado_hasta.isoformat()

            self.repo.update_user(user)

            self.repo.create_audit_event(
                accion="LOGIN_FALLIDO",
                tipo_evento="AUTENTICACION",
                resultado="FALLO",
                user_id=user.id_usuario,
                ip=client_ip,
                user_agent=user_agent,
                detalles=detalles_audit,
            )

            if user.intentos_fallidos >= settings.MAX_FAILED_LOGIN_ATTEMPTS:
                raise HTTPException(
                    status_code=status.HTTP_423_LOCKED,
                    detail=f"Demasiados intentos fallidos. Cuenta bloqueada por {settings.LOCKOUT_DURATION_MINUTES} minutos.",
                )

            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Credenciales inválidas.",
            )

        # 5. Contraseña correcta -> Resetear intentos y registrar acceso
        user.intentos_fallidos = 0
        user.bloqueado_hasta = None
        user.ultimo_acceso = now
        if user.estado == "BLOQUEADO":
            user.estado = "ACTIVO"
        self.repo.update_user(user)

        # 6. Registrar o actualizar dispositivo
        dispositivo_info = request.dispositivo or DispositivoInfo()
        device = self.repo.get_or_create_device(user.id_usuario, dispositivo_info)

        # 7. Obtener roles y permisos del usuario
        role_names: List[str] = [r.nombre for r in user.roles]
        perm_codes: List[str] = list(
            {p.codigo for r in user.roles for p in r.permisos}
        )

        # 8. Generar tokens JWT
        access_token = create_access_token(
            subject=str(user.id_usuario),
            roles=role_names,
            permissions=perm_codes,
        )
        refresh_token = create_refresh_token(subject=str(user.id_usuario))

        # 9. Almacenar sesión en la base de datos
        refresh_hash = hash_token(refresh_token)
        refresh_expires = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        self.repo.create_session(
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            refresh_token_hash=refresh_hash,
            expires_at=refresh_expires,
        )

        # 10. Registrar evento de auditoría de inicio exitoso
        self.repo.create_audit_event(
            accion="LOGIN_EXITOSO",
            tipo_evento="AUTENTICACION",
            resultado="EXITO",
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"roles": role_names},
        )

        return LoginResponse(
            access_token=access_token,
            refresh_token=refresh_token,
            token_type="bearer",
            expires_in=settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
            usuario=UsuarioRead.model_validate(user),
            roles=role_names,
            permisos=perm_codes,
        )

    def refresh_token(self, request: RefreshTokenRequest) -> dict:
        now = datetime.now(timezone.utc)
        payload = decode_token(request.refresh_token)

        if not payload or payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de renovación inválido o expirado.",
            )

        token_hash = hash_token(request.refresh_token)
        session = self.repo.get_session_by_token_hash(token_hash)

        if not session or session.revocada or session.fecha_expiracion <= now:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Sesión expirada o revocada.",
            )

        user = self.repo.get_user_by_id(session.id_usuario)
        if not user or user.estado != "ACTIVO":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario inactivo o no disponible.",
            )

        # Actualizar última actividad en la sesión
        session.ultima_actividad = now
        self.db.add(session)
        self.db.commit()

        # Emitir nuevo Access Token
        role_names = [r.nombre for r in user.roles]
        perm_codes = list({p.codigo for r in user.roles for p in r.permisos})

        new_access_token = create_access_token(
            subject=str(user.id_usuario),
            roles=role_names,
            permissions=perm_codes,
        )

        return {
            "access_token": new_access_token,
            "token_type": "bearer",
            "expires_in": settings.ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        }

    def logout(
        self,
        refresh_token: Optional[str],
        current_user: Usuario,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> None:
        if refresh_token:
            token_hash = hash_token(refresh_token)
            session = self.repo.get_session_by_token_hash(token_hash)
            if session:
                self.repo.revoke_session(session, motivo="LOGOUT_VOLUNTARIO")

        self.repo.create_audit_event(
            accion="LOGOUT",
            tipo_evento="AUTENTICACION",
            resultado="EXITO",
            user_id=current_user.id_usuario,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"correo": current_user.correo},
        )


def get_current_user(
    auth_header: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> Usuario:
    """Dependencia FastAPI para proteger endpoints y resolver el usuario autenticado."""
    token = auth_header.credentials
    payload = decode_token(token)

    if not payload or payload.get("type") != "access":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token de acceso inválido o expirado.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    user_id_str = payload.get("sub")
    if not user_id_str:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token no contiene identificador de usuario válido.",
        )

    try:
        user_id = uuid.UUID(user_id_str)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Formato de usuario inválido en token.",
        )

    repo = AuthRepository(db)
    user = repo.get_user_by_id(user_id)

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Usuario no encontrado.",
        )

    if user.estado != "ACTIVO":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="La cuenta de usuario no se encuentra activa.",
        )

    return user
