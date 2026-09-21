from collections import deque
from typing import Callable, Deque, Optional
import hashlib
import logging
import secrets
import time
import uuid

from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from app.core.security import get_password_hash, verify_password
from app.models.auth import EventoAuditoria
from app.repositories.recovery_repository import RecoveryRepository
from app.schemas.recovery import (
    ForgotPasswordRequest,
    ForgotPasswordResponse,
    ResetPasswordRequest,
    ResetPasswordResponse,
    ValidateTokenResponse,
)
from app.services.email_service import send_recovery_email
from app.services.policy_service import PolicyService


logger = logging.getLogger(__name__)
GENERIC_RECOVERY_MESSAGE = (
    "Si el correo se encuentra registrado, recibiras instrucciones de recuperacion."
)


class RecoveryRateLimiter:
    """Small process-local throttle for repeated recovery requests."""

    def __init__(self, max_attempts: int = 3, window_seconds: int = 900):
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._attempts: dict[str, Deque[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.monotonic()
        attempts = self._attempts.setdefault(key, deque())
        while attempts and now - attempts[0] >= self.window_seconds:
            attempts.popleft()
        if len(attempts) >= self.max_attempts:
            return False
        attempts.append(now)
        return True


recovery_rate_limiter = RecoveryRateLimiter()


class RecoveryService:
    def __init__(
        self,
        db: Session,
        email_sender: Callable[[str, str, int], bool] = send_recovery_email,
        rate_limiter: Optional[RecoveryRateLimiter] = None,
    ):
        self.db = db
        self.repo = RecoveryRepository(db)
        self.email_sender = email_sender
        self.rate_limiter = rate_limiter or recovery_rate_limiter

    @staticmethod
    def _request_key(email: str, client_ip: Optional[str]) -> str:
        source = f"{email.lower().strip()}:{client_ip or 'unknown'}"
        return hashlib.sha256(source.encode("utf-8")).hexdigest()

    @staticmethod
    def _response() -> ForgotPasswordResponse:
        return ForgotPasswordResponse(message=GENERIC_RECOVERY_MESSAGE)

    def _add_audit(
        self,
        action: str,
        result: str,
        user_id: Optional[uuid.UUID],
        client_ip: Optional[str],
        user_agent: Optional[str],
        details: Optional[dict] = None,
    ) -> None:
        self.db.add(
            EventoAuditoria(
                id_evento=uuid.uuid4(),
                id_usuario=user_id,
                accion=action,
                tipo_evento="RECUPERACION",
                resultado=result,
                recurso_tipo="RECUPERACION_CUENTA",
                direccion_ip=client_ip,
                user_agent=user_agent,
                detalles=details or {},
            )
        )

    def request_forgot_password(
        self,
        data: ForgotPasswordRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> ForgotPasswordResponse:
        """Starts recovery without disclosing whether the account exists."""
        if not self.rate_limiter.allow(self._request_key(data.correo, client_ip)):
            self._add_audit(
                "SOLICITUD_RECUPERACION_LIMITADA",
                "DENEGADO",
                None,
                client_ip,
                user_agent,
            )
            self.db.commit()
            return self._response()

        user = self.repo.find_user_by_email(data.correo)
        if not user:
            self._add_audit(
                "SOLICITUD_RECUPERACION",
                "EXITO",
                None,
                client_ip,
                user_agent,
            )
            self.db.commit()
            return self._response()

        raw_token = secrets.token_urlsafe(32)
        expires_in = 15
        token_record = self.repo.create_recovery_token(
            user_id=user.id_usuario,
            raw_token=raw_token,
            expires_in_minutes=expires_in,
        )

        try:
            email_sent = self.email_sender(user.correo, raw_token, expires_in)
        except Exception:
            logger.error("Recovery email delivery failed.")
            email_sent = False

        if not email_sent:
            self.repo.invalidate_token(token_record)
            self._add_audit(
                "SOLICITUD_RECUPERACION_NO_ENTREGADA",
                "FALLO",
                user.id_usuario,
                client_ip,
                user_agent,
            )
            self.db.commit()
            return self._response()

        self._add_audit(
            "SOLICITUD_RECUPERACION",
            "EXITO",
            user.id_usuario,
            client_ip,
            user_agent,
            {"expira_en_minutos": expires_in},
        )
        self.db.commit()
        return self._response()

    def validate_token(self, token: str) -> ValidateTokenResponse:
        """Checks a token without disclosing the account associated with it."""
        if not self.repo.get_valid_token_record(token):
            return ValidateTokenResponse(
                valid=False,
                message="El enlace de recuperacion es invalido, ya fue utilizado o ha expirado.",
            )
        return ValidateTokenResponse(
            valid=True,
            message="Token de recuperacion verificado correctamente.",
        )

    def reset_password(
        self,
        data: ResetPasswordRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> ResetPasswordResponse:
        """Resets credentials and consumes the token in one database transaction."""
        token_record = self.repo.get_valid_token_record(data.token)
        if not token_record:
            self._add_audit(
                "RESTABLECIMIENTO_PASSWORD_FALLIDO",
                "FALLO",
                None,
                client_ip,
                user_agent,
            )
            self.db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El enlace de recuperacion es invalido, ya fue utilizado o ha expirado.",
            )

        # Share the user lock with session issuance and MFA changes so recovery wins
        # over an in-flight authentication that started before the password reset.
        user = self.repo.find_user_by_id_for_update(token_record.id_usuario)
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Usuario no encontrado.",
            )

        PolicyService(self.db).validate_password_length(data.password)

        if verify_password(data.password, user.password_hash):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="La nueva contrasena no puede ser identica a la contrasena actual.",
            )

        new_hash = get_password_hash(data.password)
        if not self.repo.consume_token_if_valid(token_record, data.token):
            self.db.rollback()
            self._add_audit(
                "RESTABLECIMIENTO_PASSWORD_FALLIDO",
                "FALLO",
                None,
                client_ip,
                user_agent,
            )
            self.db.commit()
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="El enlace de recuperacion es invalido, ya fue utilizado o ha expirado.",
            )

        self.repo.update_user_password(user, new_hash)
        revoked_sessions = self.repo.revoke_all_user_sessions(
            user.id_usuario, motivo="RESTABLECIMIENTO_CONTRASENA"
        )
        self.repo.revoke_mfa_and_backup_codes(user.id_usuario)

        zero_knowledge_message = (
            "La contrasena de tu cuenta ha sido restablecida exitosamente. "
            "Tus bovedas cifradas permanecen seguras e inalteradas bajo la arquitectura "
            "de Cero Conocimiento (Zero-Knowledge), ya que sus claves maestras se derivan en tu dispositivo local."
        )

        self._add_audit(
            "RESTABLECIMIENTO_PASSWORD_EXITOSO",
            "EXITO",
            user.id_usuario,
            client_ip,
            user_agent,
            {"sesiones_revocadas": revoked_sessions, "zero_knowledge_garantizado": True},
        )
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
            raise

        return ResetPasswordResponse(
            message="Contrasena actualizada exitosamente.",
            sesiones_revocadas=revoked_sessions,
            zero_knowledge_notice=zero_knowledge_message,
        )
