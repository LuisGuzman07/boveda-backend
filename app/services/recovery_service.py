import secrets
from typing import Optional
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.core.security import get_password_hash, verify_password
from app.repositories.recovery_repository import RecoveryRepository
from app.schemas.recovery import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    ValidateTokenResponse,
)
from app.services.audit_service import log_audit_event
from app.services.email_service import send_recovery_email


class RecoveryService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = RecoveryRepository(db)

    def request_forgot_password(
        self,
        data: ForgotPasswordRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> ForgotPasswordResponse:
        """CU-03: Inicia solicitud de recuperación de cuenta y genera token seguro."""
        user = self.repo.find_user_by_email(data.correo)

        if not user:
            # Registrar evento de auditoría por intento fallido sin revelar existencia del usuario
            log_audit_event(
                db=self.db,
                user_id=None,
                accion="SOLICITUD_RECUPERACION_FALLIDA",
                tipo_evento="RECUPERACION",
                resultado="FALLO",
                recurso_tipo="USUARIO",
                ip=client_ip,
                user_agent=user_agent,
                detalles={
                    "correo_solicitado": data.correo,
                    "motivo": "Usuario no registrado en el sistema",
                },
            )
            # Retornar mensaje estándar de seguridad para evitar enumeración de usuarios
            return ForgotPasswordResponse(
                message="Si el correo se encuentra registrado, se han generado las instrucciones de recuperación.",
            )

        # Generar token criptográficamente seguro
        raw_token = secrets.token_urlsafe(32)
        expires_in = 15  # minutos de vigencia
        token_record = self.repo.create_recovery_token(
            user_id=user.id_usuario,
            raw_token=raw_token,
            expires_in_minutes=expires_in,
        )

        simulation_url = f"http://localhost:5173/reset-password?token={raw_token}"

        # 1. Despachar correo electrónico real vía SMTP si está configurado
        email_sent = send_recovery_email(
            to_email=user.correo,
            reset_token=raw_token,
            expires_in_minutes=expires_in,
        )

        # 2. Registrar auditoría exitosa (CU-21)
        log_audit_event(
            db=self.db,
            user_id=user.id_usuario,
            accion="SOLICITUD_RECUPERACION",
            tipo_evento="RECUPERACION",
            resultado="EXITO",
            recurso_id=str(token_record.id_recuperacion),
            recurso_tipo="RECUPERACION_CUENTA",
            ip=client_ip,
            user_agent=user_agent,
            detalles={
                "correo": user.correo,
                "codigo_referencia": token_record.codigo,
                "expira_en_minutos": expires_in,
                "email_enviado": email_sent,
            },
        )

        msg = (
            f"Hemos enviado las instrucciones y el enlace de recuperación a tu cuenta {user.correo}."
            if email_sent
            else "Si el correo se encuentra registrado, se han generado las instrucciones de recuperación."
        )

        return ForgotPasswordResponse(
            message=msg,
            expires_in_minutes=expires_in,
            email_sent=email_sent,
            simulation_token=raw_token if not email_sent else None,
            simulation_reset_url=simulation_url if not email_sent else None,
        )

    def validate_token(self, token: str) -> ValidateTokenResponse:
        """CU-03: Valida el estado de vigencia de un token de recuperación."""
        token_record = self.repo.get_valid_token_record(token)
        if not token_record:
            return ValidateTokenResponse(
                valid=False,
                message="El enlace de recuperación es inválido, ya fue utilizado o ha expirado.",
            )

        user = self.repo.find_user_by_id(token_record.id_usuario)
        if not user:
            return ValidateTokenResponse(
                valid=False,
                message="El usuario asociado a este token ya no existe.",
            )

        return ValidateTokenResponse(
            valid=True,
            correo=user.correo,
            message="Token de recuperación verificado correctamente.",
        )

    def reset_password(
        self,
        data: ResetPasswordRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> ResetPasswordResponse:
        """CU-03: Restablece credenciales, invalida token y revoca sesiones anteriores."""
        token_record = self.repo.get_valid_token_record(data.token)
        if not token_record:
            log_audit_event(
                db=self.db,
                user_id=None,
                accion="RESTABLECIMIENTO_PASSWORD_FALLIDO",
                tipo_evento="RECUPERACION",
                resultado="FALLO",
                recurso_tipo="RECUPERACION_CUENTA",
                ip=client_ip,
                user_agent=user_agent,
                detalles={"motivo": "Token inválido, expirado o ya utilizado"},
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El enlace de recuperación es inválido, ya fue utilizado o ha expirado.",
            )

        user = self.repo.find_user_by_id(token_record.id_usuario)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado.",
            )

        # Validar que la nueva contraseña no sea idéntica a la actual
        if verify_password(data.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La nueva contraseña no puede ser idéntica a la contraseña actual.",
            )

        # 1. Actualizar contraseña y remover bloqueos por intentos fallidos
        new_hash = get_password_hash(data.password)
        self.repo.update_user_password(user, new_hash)

        # 2. Consumir token
        self.repo.consume_token(token_record)

        # 3. Revocar todas las sesiones activas anteriores
        revoked_sessions = self.repo.revoke_all_user_sessions(
            user.id_usuario, motivo="RESTABLECIMIENTO_CONTRASENA"
        )

        zero_knowledge_message = (
            "La contraseña de tu cuenta ha sido restablecida exitosamente. "
            "Tus bóvedas cifradas permanecen seguras e inalteradas bajo la arquitectura "
            "de Cero Conocimiento (Zero-Knowledge), ya que sus claves maestras se derivan en tu dispositivo local."
        )

        # 4. Registrar evento inmutable de auditoría (CU-21)
        log_audit_event(
            db=self.db,
            user_id=user.id_usuario,
            accion="RESTABLECIMIENTO_PASSWORD_EXITOSO",
            tipo_evento="RECUPERACION",
            resultado="EXITO",
            recurso_id=str(user.id_usuario),
            recurso_tipo="USUARIO",
            ip=client_ip,
            user_agent=user_agent,
            detalles={
                "correo": user.correo,
                "sesiones_revocadas": revoked_sessions,
                "token_id": str(token_record.id_recuperacion),
                "zero_knowledge_garantizado": True,
            },
        )

        return ResetPasswordResponse(
            message="Contraseña actualizada exitosamente.",
            sesiones_revocadas=revoked_sessions,
            zero_knowledge_notice=zero_knowledge_message,
        )
