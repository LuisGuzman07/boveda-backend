import hashlib
import secrets
from datetime import datetime, timedelta, timezone
from typing import Literal
import uuid

from fastapi import HTTPException, status
from sqlalchemy import update
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.device_crypto import (
    DeviceCryptoError,
    normalize_ed25519_public_key,
    verify_ed25519_signature,
)
from app.models.auth import DesafioDispositivo, Dispositivo, Sesion, Usuario
from app.repositories.auth_repository import AuthRepository


DEVICE_PENDING = "PENDING"
DEVICE_TRUSTED = "TRUSTED"
DEVICE_REVOKED = "REVOKED"
CHALLENGE_ENROLLMENT = "DEVICE_ENROLLMENT"
CHALLENGE_VAULT = "VAULT_SESSION"
ChallengePurpose = Literal["DEVICE_ENROLLMENT", "VAULT_SESSION"]


def challenge_transcript(
    challenge_id: uuid.UUID,
    purpose: str,
    user_id: uuid.UUID,
    device_id: uuid.UUID,
    nonce: str,
    expires_at: datetime,
) -> bytes:
    expires = expires_at if expires_at.tzinfo else expires_at.replace(tzinfo=timezone.utc)
    return "\n".join(
        (
            "boveda-device-challenge-v1",
            str(challenge_id),
            purpose,
            str(user_id),
            str(device_id),
            nonce,
            str(int(expires.timestamp())),
        )
    ).encode("utf-8")


class DeviceIdentityService:
    def __init__(self, db: Session):
        self.db = db
        self.auth_repo = AuthRepository(db)

    def issue_challenge(
        self,
        user: Usuario,
        session: Sesion,
        device: Dispositivo,
        purpose: ChallengePurpose,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> tuple[DesafioDispositivo, str]:
        locked_user, locked_device, locked_session = self.auth_repo.lock_authenticated_session(
            user.id_usuario,
            device.id_dispositivo,
            session.id_sesion,
        )
        if not locked_device.public_key:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="El dispositivo no tiene una identidad criptografica registrada.",
            )
        if purpose == CHALLENGE_VAULT:
            self.require_recent_mfa(locked_session)
            if locked_device.estado != DEVICE_TRUSTED:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="El dispositivo debe estar TRUSTED para abrir una sesion de boveda.",
                )

        nonce = secrets.token_urlsafe(32)
        expires_at = datetime.now(timezone.utc) + timedelta(
            seconds=settings.DEVICE_CHALLENGE_TTL_SECONDS
        )
        challenge = DesafioDispositivo(
            id_desafio=uuid.uuid4(),
            id_usuario=locked_user.id_usuario,
            id_dispositivo=locked_device.id_dispositivo,
            id_sesion=locked_session.id_sesion,
            proposito=purpose,
            nonce_hash=hashlib.sha256(nonce.encode("utf-8")).hexdigest(),
            context_hash="",
            fecha_expiracion=expires_at,
        )
        # Bind the transcript to the persisted challenge identifier, not a caller value.
        challenge.context_hash = hashlib.sha256(
            challenge_transcript(
                challenge.id_desafio,
                purpose,
                locked_user.id_usuario,
                locked_device.id_dispositivo,
                nonce,
                expires_at,
            )
        ).hexdigest()
        self.db.add(challenge)
        self.db.commit()
        self.db.refresh(challenge)
        self.auth_repo.create_audit_event(
            accion="DESAFIO_DISPOSITIVO_EMITIDO",
            tipo_evento="DISPOSITIVO",
            resultado="EXITO",
            user_id=locked_user.id_usuario,
            device_id=locked_device.id_dispositivo,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"proposito": purpose},
        )
        return challenge, nonce

    def prove_challenge(
        self,
        user: Usuario,
        session: Sesion,
        device: Dispositivo,
        challenge_id: uuid.UUID,
        nonce: str,
        signature: str,
        purpose: ChallengePurpose,
        client_ip: str | None = None,
        user_agent: str | None = None,
    ) -> DesafioDispositivo:
        locked_user, locked_device, locked_session = self.auth_repo.lock_authenticated_session(
            user.id_usuario,
            device.id_dispositivo,
            session.id_sesion,
        )
        if purpose == CHALLENGE_VAULT:
            self.require_recent_mfa(locked_session)
            if locked_device.estado != DEVICE_TRUSTED:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="El dispositivo debe estar TRUSTED para abrir una sesion de boveda.",
                )
        challenge = self.db.get(DesafioDispositivo, challenge_id)
        now = datetime.now(timezone.utc)
        if (
            not challenge
            or challenge.id_usuario != locked_user.id_usuario
            or challenge.id_dispositivo != locked_device.id_dispositivo
            or challenge.id_sesion != locked_session.id_sesion
            or challenge.proposito != purpose
            or challenge.consumido_en is not None
            or self._as_utc(challenge.fecha_expiracion) <= now
        ):
            self._audit_failure(locked_user, locked_device, purpose, client_ip, user_agent)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Desafio de dispositivo invalido o expirado.")

        expected_nonce_hash = hashlib.sha256(nonce.encode("utf-8")).hexdigest()
        transcript = challenge_transcript(
            challenge.id_desafio,
            challenge.proposito,
            locked_user.id_usuario,
            locked_device.id_dispositivo,
            nonce,
            self._as_utc(challenge.fecha_expiracion),
        )
        if (
            not secrets.compare_digest(expected_nonce_hash, challenge.nonce_hash)
            or not secrets.compare_digest(hashlib.sha256(transcript).hexdigest(), challenge.context_hash)
            or not locked_device.public_key
        ):
            self._consume_failed_challenge(challenge, now)
            self._audit_failure(locked_user, locked_device, purpose, client_ip, user_agent)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Prueba de posesion invalida.")

        try:
            public_key, fingerprint = normalize_ed25519_public_key(locked_device.public_key)
            if locked_device.huella_clave_publica and not secrets.compare_digest(
                fingerprint, locked_device.huella_clave_publica
            ):
                raise ValueError("Fingerprint mismatch")
            verify_ed25519_signature(public_key, signature, transcript)
        except (DeviceCryptoError, ValueError):
            self._consume_failed_challenge(challenge, now)
            self._audit_failure(locked_user, locked_device, purpose, client_ip, user_agent)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Prueba de posesion invalida.")

        consumed = self.db.execute(
            update(DesafioDispositivo)
            .where(
                DesafioDispositivo.id_desafio == challenge.id_desafio,
                DesafioDispositivo.consumido_en.is_(None),
            )
            .values(consumido_en=now, intentos=DesafioDispositivo.intentos + 1)
        )
        if consumed.rowcount != 1:
            self.db.rollback()
            self._audit_failure(locked_user, locked_device, purpose, client_ip, user_agent)
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Desafio de dispositivo ya utilizado.")

        if purpose == CHALLENGE_ENROLLMENT:
            verified = self.db.execute(
                update(Dispositivo)
                .where(
                    Dispositivo.id_dispositivo == locked_device.id_dispositivo,
                    Dispositivo.estado.in_([DEVICE_PENDING, DEVICE_TRUSTED]),
                )
                .values(
                    identidad_verificada_en=now,
                    ultimo_acceso=now,
                )
            )
            if verified.rowcount != 1:
                self.db.rollback()
                self._audit_failure(locked_user, locked_device, purpose, client_ip, user_agent)
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="DEVICE_REVOKED")
        self.db.commit()
        self.db.refresh(challenge)
        self.auth_repo.create_audit_event(
            accion=(
                "IDENTIDAD_DISPOSITIVO_VERIFICADA"
                if purpose == CHALLENGE_ENROLLMENT
                else "PRUEBA_POSESION_BOVEDA_VERIFICADA"
            ),
            tipo_evento="DISPOSITIVO",
            resultado="EXITO",
            user_id=locked_user.id_usuario,
            device_id=locked_device.id_dispositivo,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"proposito": purpose},
        )
        return challenge

    @staticmethod
    def _as_utc(value: datetime) -> datetime:
        return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value

    @staticmethod
    def require_recent_mfa(session: Sesion) -> None:
        verified_at = session.mfa_verificado_en
        if verified_at is None:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Se requiere MFA para esta operacion.")
        verified_at = verified_at.replace(tzinfo=timezone.utc) if verified_at.tzinfo is None else verified_at
        if verified_at + timedelta(minutes=settings.MFA_VAULT_MAX_AGE_MINUTES) < datetime.now(timezone.utc):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="La verificacion MFA debe renovarse.")

    def _consume_failed_challenge(self, challenge: DesafioDispositivo, now: datetime) -> None:
        self.db.execute(
            update(DesafioDispositivo)
            .where(
                DesafioDispositivo.id_desafio == challenge.id_desafio,
                DesafioDispositivo.consumido_en.is_(None),
            )
            .values(consumido_en=now, intentos=DesafioDispositivo.intentos + 1)
        )
        self.db.commit()

    def _audit_failure(
        self,
        user: Usuario,
        device: Dispositivo,
        purpose: str,
        client_ip: str | None,
        user_agent: str | None,
    ) -> None:
        self.auth_repo.create_audit_event(
            accion="PRUEBA_POSESION_DISPOSITIVO_FALLIDA",
            tipo_evento="DISPOSITIVO",
            resultado="FALLO",
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            ip=client_ip,
            user_agent=user_agent,
            detalles={"proposito": purpose},
        )
