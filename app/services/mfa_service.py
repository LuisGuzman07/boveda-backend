import base64
from datetime import datetime, timedelta, timezone
import io
import secrets
import hashlib
from typing import List, Optional
import uuid
from fastapi import HTTPException, status
import pyotp
import qrcode
from sqlalchemy.orm import Session
from app.core.config import settings
from app.core.security import (
    decode_token,
    verify_password,
)
from app.models.auth import Dispositivo, Usuario
from app.models.mfa import AutenticadorMfa
from app.repositories.auth_repository import AuthRepository
from app.repositories.mfa_repository import MfaRepository
from app.services.totp_secret_service import get_totp_secret, store_encrypted_totp_secret
from app.services.recovery_service import RecoveryRateLimiter
from app.services.auth_service import AuthService, IssuedSession
from app.schemas.auth import DispositivoInfo, LoginResponse, UsuarioRead
from app.schemas.mfa import (
    MfaDisableRequest,
    MfaEnableRequest,
    MfaSetupResponse,
    MfaStatusResponse,
    MfaVerifyLoginRequest,
)


mfa_login_rate_limiter = RecoveryRateLimiter(max_attempts=5, window_seconds=300)


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
            f"{secrets.token_hex(8).upper()}-{secrets.token_hex(8).upper()}"
            for _ in range(8)
        ]

        # 5. Guardar autenticador en estado PENDIENTE
        existing_mfa = self.mfa_repo.get_pending_or_active_mfa(user.id_usuario)
        if existing_mfa:
            store_encrypted_totp_secret(existing_mfa, secret)
            existing_mfa.estado = "PENDIENTE"
            self.mfa_repo.save_mfa(existing_mfa)
        else:
            new_mfa = AutenticadorMfa(
                id_autenticador=uuid.uuid4(),
                id_usuario=user.id_usuario,
                tipo="TOTP",
                estado="PENDIENTE",
            )
            store_encrypted_totp_secret(new_mfa, secret)
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

        totp = pyotp.TOTP(get_totp_secret(mfa))
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
        response, _ = self._verify_login_mfa(
            request, "NATIVE", client_ip=client_ip, user_agent=user_agent
        )
        return response

    def verify_login_mfa_web(
        self,
        request: MfaVerifyLoginRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> tuple[LoginResponse, IssuedSession]:
        response, issued = self._verify_login_mfa(
            request, "WEB", client_ip=client_ip, user_agent=user_agent
        )
        return response, issued

    def _verify_login_mfa(
        self,
        request: MfaVerifyLoginRequest,
        expected_client_type: str,
        client_ip: Optional[str],
        user_agent: Optional[str],
    ) -> tuple[LoginResponse, IssuedSession]:
        """Completa el inicio de sesión con una identidad de dispositivo fijada antes del MFA."""
        payload = decode_token(request.mfa_token)
        if not payload or payload.get("type") != "mfa_pending":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de verificación MFA inválido o expirado.",
            )

        try:
            user_id = uuid.UUID(payload["sub"])
            device_id = uuid.UUID(payload["did"])
        except (KeyError, TypeError, ValueError) as error:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token de verificación MFA inválido o expirado.",
            ) from error
        if payload.get("client") != expected_client_type:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="El desafío MFA no pertenece a este tipo de cliente.",
            )

        user = self.auth_repo.get_user_by_id(user_id)
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

        limiter_key = hashlib.sha256(
            f"{user.id_usuario}:{client_ip or 'unknown'}".encode("utf-8")
        ).hexdigest()
        if not mfa_login_rate_limiter.allow(limiter_key):
            self.auth_repo.create_audit_event(
                accion="LOGIN_MFA_LIMITADO",
                tipo_evento="AUTENTICACION",
                resultado="DENEGADO",
                user_id=user.id_usuario,
                ip=client_ip,
                user_agent=user_agent,
            )
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Demasiados intentos MFA. Intenta más tarde.",
            )

        # 1. Intentar validar código TOTP (6 dígitos)
        code_input = request.code.strip()
        is_valid = False
        method_used = "TOTP"

        if len(code_input) == 6 and code_input.isdigit():
            totp = pyotp.TOTP(get_totp_secret(mfa))
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

        # The device comes from the MFA-pending token, never from a second client payload.
        now = datetime.now(timezone.utc)
        device = self.auth_repo.get_device_by_id(device_id)
        if (
            not device
            or device.id_usuario != user.id_usuario
            or device.estado == "REVOKED"
        ):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="El dispositivo asociado al desafío MFA ya no es válido.",
            )
        issued = AuthService(self.db).create_authenticated_session(
            user,
            device,
            expected_client_type,
            mfa_verified_at=now,
        )

        self.auth_repo.create_audit_event(
            accion="LOGIN_MFA_EXITOSO",
            tipo_evento="AUTENTICACION",
            resultado="EXITO",
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"metodo": method_used, "cliente": expected_client_type},
        )
        return issued.response, issued

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
