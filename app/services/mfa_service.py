import base64
from datetime import datetime, timedelta, timezone
import io
import secrets
from typing import List, Optional
import uuid
from fastapi import HTTPException, status
import pyotp
import qrcode
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.security import (
    create_access_token,
    create_refresh_token,
    decode_token,
    hash_token,
    verify_password,
)
from app.models.auth import Usuario
from app.models.mfa import AutenticadorMfa
from app.repositories.auth_repository import AuthRepository
from app.repositories.mfa_repository import MfaRepository
from app.schemas.auth import DispositivoInfo, LoginResponse, UsuarioRead
from app.schemas.mfa import (
    MfaDisableRequest,
    MfaEnableRequest,
    MfaSetupResponse,
    MfaStatusResponse,
    MfaVerifyLoginRequest,
)


class MfaService:
    def __init__(self, db: Session):
        self.db = db
        self.mfa_repo = MfaRepository(db)
        self.auth_repo = AuthRepository(db)

    def setup_mfa(
        self,
        user: Usuario,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> MfaSetupResponse:
        """Genera secreto TOTP, código QR y códigos de respaldo de emergencia."""
        # 1. Generar secreto Base32 estándar RFC 6238
        secret = pyotp.random_base32()

        # 2. Construir URI estándar para autenticadores móviles
        totp = pyotp.TOTP(secret)
        otpauth_url = totp.provisioning_uri(
            name=user.correo,
            issuer_name="Boveda Hibrida",
        )

        # 3. Generar código QR en Base64
        qr = qrcode.QRCode(
            version=1,
            error_correction=qrcode.constants.ERROR_CORRECT_L,
            box_size=8,
            border=2,
        )
        qr.add_data(otpauth_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buffered = io.BytesIO()
        img.save(buffered, format="PNG")
        qr_base64 = f"data:image/png;base64,{base64.b64encode(buffered.getvalue()).decode()}"

        # 4. Generar 8 códigos de respaldo (formato XXXX-XXXX)
        backup_codes: List[str] = [
            f"{secrets.token_hex(2).upper()}-{secrets.token_hex(2).upper()}"
            for _ in range(8)
        ]

        # 5. Guardar autenticador en estado PENDIENTE
        existing_mfa = self.mfa_repo.get_pending_or_active_mfa(user.id_usuario)
        if existing_mfa:
            existing_mfa.secreto_cifrado = secret
            existing_mfa.estado = "PENDIENTE"
            self.mfa_repo.save_mfa(existing_mfa)
        else:
            new_mfa = AutenticadorMfa(
                id_autenticador=uuid.uuid4(),
                id_usuario=user.id_usuario,
                tipo="TOTP",
                secreto_cifrado=secret,
                estado="PENDIENTE",
            )
            self.mfa_repo.save_mfa(new_mfa)

        # 6. Guardar códigos de respaldo
        self.mfa_repo.save_recovery_codes(user.id_usuario, backup_codes)

        # 7. Auditar inicio de configuración
        self.auth_repo.create_audit_event(
            accion="MFA_SETUP_INICIADO",
            tipo_evento="SEGURIDAD_MFA",
            resultado="EXITO",
            user_id=user.id_usuario,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"tipo": "TOTP"},
        )

        return MfaSetupResponse(
            secret=secret,
            otpauth_url=otpauth_url,
            qr_code_base64=qr_base64,
            backup_codes=backup_codes,
        )

    def enable_mfa(
        self,
        user: Usuario,
        request: MfaEnableRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> dict:
        """Verifica el código de la app móvil y activa el segundo factor."""
        mfa = self.mfa_repo.get_pending_or_active_mfa(user.id_usuario)
        if not mfa:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No hay una configuración de MFA pendiente. Inicie el proceso primero.",
            )

        totp = pyotp.TOTP(mfa.secreto_cifrado)
        if not totp.verify(request.code.strip(), valid_window=1):
            self.auth_repo.create_audit_event(
                accion="MFA_ACTIVACION_FALLIDA",
                tipo_evento="SEGURIDAD_MFA",
                resultado="FALLO",
                user_id=user.id_usuario,
                ip=client_ip,
                user_agent=user_agent,
                detalles={"motivo": "Código TOTP inválido"},
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Código de autenticación incorrecto o expirado.",
            )

        mfa.estado = "ACTIVO"
        mfa.ultimo_uso = datetime.now(timezone.utc)
        self.mfa_repo.save_mfa(mfa)

        self.auth_repo.create_audit_event(
            accion="MFA_ACTIVADO",
            tipo_evento="SEGURIDAD_MFA",
            resultado="EXITO",
            user_id=user.id_usuario,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"tipo": "TOTP"},
        )

        return {"status": "ok", "message": "Autenticación de dos factores activada exitosamente."}

    def verify_login_mfa(
        self,
        request: MfaVerifyLoginRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> LoginResponse:
        """Completa el inicio de sesión validando el código 2FA de la app móvil o un código de respaldo."""
        payload = decode_token(request.mfa_token)
        if not payload or payload.get("type") != "mfa_pending":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de verificación MFA inválido o expirado.",
            )

        user_id_str = payload.get("sub")
        user = self.auth_repo.get_user_by_id(uuid.UUID(user_id_str))
        if not user or user.estado != "ACTIVO":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Usuario no válido o inactivo.",
            )

        mfa = self.mfa_repo.get_active_mfa(user.id_usuario)
        if not mfa:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El usuario no tiene MFA activo configurado.",
            )

        # 1. Intentar validar código TOTP (6 dígitos)
        code_input = request.code.strip()
        is_valid = False
        method_used = "TOTP"

        if len(code_input) == 6 and code_input.isdigit():
            totp = pyotp.TOTP(mfa.secreto_cifrado)
            if totp.verify(code_input, valid_window=1):
                is_valid = True
                mfa.ultimo_uso = datetime.now(timezone.utc)
                self.mfa_repo.save_mfa(mfa)

        # 2. Si falló TOTP, intentar como código de respaldo
        if not is_valid:
            if self.mfa_repo.verify_and_consume_recovery_code(user.id_usuario, code_input):
                is_valid = True
                method_used = "BACKUP_CODE"

        if not is_valid:
            self.auth_repo.create_audit_event(
                accion="LOGIN_MFA_FALLIDO",
                tipo_evento="AUTENTICACION",
                resultado="FALLO",
                user_id=user.id_usuario,
                ip=client_ip,
                user_agent=user_agent,
                detalles={"motivo": "Código 2FA incorrecto"},
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Código de autenticación inválido o ya utilizado.",
            )

        # 3. Éxito: Crear sesión y emitir JWTs finales
        now = datetime.now(timezone.utc)
        device_info = request.dispositivo or DispositivoInfo()
        if request.confiar_dispositivo is not None:
            device_info.confiar_dispositivo = request.confiar_dispositivo
        device = self.auth_repo.get_or_create_device(user.id_usuario, device_info)

        role_names = [r.nombre for r in user.roles]
        perm_codes = list({p.codigo for r in user.roles for p in r.permisos})

        access_token = create_access_token(
            subject=str(user.id_usuario),
            roles=role_names,
            permissions=perm_codes,
        )
        refresh_token = create_refresh_token(subject=str(user.id_usuario))

        refresh_hash = hash_token(refresh_token)
        refresh_expires = now + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
        self.auth_repo.create_session(
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            refresh_token_hash=refresh_hash,
            expires_at=refresh_expires,
        )

        self.auth_repo.create_audit_event(
            accion="LOGIN_MFA_EXITOSO",
            tipo_evento="AUTENTICACION",
            resultado="EXITO",
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"metodo": method_used, "roles": role_names},
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

    def disable_mfa(
        self,
        user: Usuario,
        request: MfaDisableRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> dict:
        """Desactiva el 2FA tras confirmar la contraseña del usuario."""
        if not verify_password(request.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Contraseña incorrecta.",
            )

        self.mfa_repo.revoke_mfa(user.id_usuario)

        self.auth_repo.create_audit_event(
            accion="MFA_DESACTIVADO",
            tipo_evento="SEGURIDAD_MFA",
            resultado="EXITO",
            user_id=user.id_usuario,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"motivo": "Solicitud de usuario"},
        )

        return {"status": "ok", "message": "Autenticación de dos factores desactivada."}

    def get_status(self, user: Usuario) -> MfaStatusResponse:
        """Consulta el estado del segundo factor para el usuario."""
        mfa = self.mfa_repo.get_active_mfa(user.id_usuario)
        if mfa:
            return MfaStatusResponse(
                enabled=True,
                mfa_enabled=True,
                type=mfa.tipo,
                registered_at=mfa.fecha_registro,
            )
        return MfaStatusResponse(enabled=False, mfa_enabled=False)
