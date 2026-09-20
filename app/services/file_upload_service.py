"""CU08 control plane for client-encrypted file uploads."""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

from app.core.config import settings
from app.models.auth import Dispositivo, SesionBoveda, Usuario
from app.models.vault import Archivo, ArchivoVersion, ReplicaArchivo
from app.repositories.auth_repository import AuthRepository
from app.repositories.file_upload_repository import FileUploadRepository
from app.repositories.vault_repository import VaultRepository
from app.schemas.vault import FileUploadCompleteRequest, FileUploadIntentRequest
from app.services.object_storage import (
    ObjectStorage,
    ObjectStorageIntegrityError,
    ObjectStorageObjectMissing,
    ObjectStorageUnavailable,
)


def _as_utc(value: datetime) -> datetime:
    return value.replace(tzinfo=timezone.utc) if value.tzinfo is None else value


class FileUploadService:
    def __init__(self, db, storage: ObjectStorage):
        self.db = db
        self.storage = storage
        self.repo = FileUploadRepository(db)
        self.vaults = VaultRepository(db)
        self.audit = AuthRepository(db)

    @staticmethod
    def _request_hash(body) -> str:
        serialized = json.dumps(
            body.model_dump(mode="json"), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return hashlib.sha256(serialized).hexdigest()

    @staticmethod
    def _permissions(user: Usuario) -> set[str]:
        return {permission.codigo for role in user.roles for permission in role.permisos}

    def _require_upload_access(
        self,
        user: Usuario,
        device: Dispositivo,
        vault_id: uuid.UUID,
    ) -> None:
        if "vaults:write" not in self._permissions(user):
            raise HTTPException(403, "No tienes permiso para cargar archivos en la bóveda.")
        if not self.vaults.get_owned(
            user.id_usuario, device.id_dispositivo, vault_id, lock=True
        ):
            raise HTTPException(404, "Bóveda no disponible para este dispositivo.")

    @staticmethod
    def _assert_bound_intent(
        version: ArchivoVersion,
        user: Usuario,
        device: Dispositivo,
        vault_session: SesionBoveda,
    ) -> None:
        if (
            version.id_usuario_origen != user.id_usuario
            or version.id_dispositivo_origen != device.id_dispositivo
            or version.id_sesion_boveda_origen != vault_session.id_sesion_boveda
        ):
            raise HTTPException(404, "Carga no disponible para esta sesión de bóveda.")

    @staticmethod
    def _response(file: Archivo, version: ArchivoVersion, *, upload_url: str | None = None):
        response = {
            "id_archivo": file.id_archivo,
            "id_version": version.id_version,
            "estado": version.estado,
        }
        if upload_url is not None:
            response.update(
                {
                    "upload_url": upload_url,
                    "expira_en": version.fecha_expiracion,
                    "content_type": "application/octet-stream",
                }
            )
        return response

    @staticmethod
    def _operation_response(file: Archivo, version: ArchivoVersion):
        return {
            "id_archivo": file.id_archivo,
            "id_version": version.id_version,
            "estado": version.estado,
        }

    @staticmethod
    def _staging_object_key() -> str:
        return f"uploads/{uuid.uuid4().hex}"

    @staticmethod
    def _final_object_key(version_id: uuid.UUID) -> str:
        return f"files/{version_id.hex}"

    @staticmethod
    def _expiration_for(vault_session: SesionBoveda, now: datetime) -> datetime:
        short_lived = now + timedelta(seconds=settings.MINIO_PRESIGNED_TTL_SECONDS)
        return min(short_lived, _as_utc(vault_session.fecha_expiracion))

    @staticmethod
    def _is_expired(version: ArchivoVersion, now: datetime) -> bool:
        return _as_utc(version.fecha_expiracion) <= now

    def _add_audit(
        self,
        action: str,
        result: str,
        *,
        file: Archivo,
        version: ArchivoVersion,
        user: Usuario,
        device: Dispositivo,
        ip: str | None,
        user_agent: str | None,
        details: dict,
    ) -> None:
        self.audit.add_audit_event(
            accion=action,
            tipo_evento="ARCHIVO",
            resultado=result,
            user_id=user.id_usuario,
            device_id=device.id_dispositivo,
            resource_id=str(version.id_version),
            resource_type="ARCHIVO_VERSION",
            ip=ip,
            user_agent=user_agent,
            detalles=details,
        )

    def _safe_delete(self, replica: ReplicaArchivo) -> None:
        for object_key in filter(
            None,
            (replica.staging_object_key, replica.object_key),
        ):
            try:
                self.storage.delete_object(object_key)
            except ObjectStorageUnavailable:
                # Terminal rows are reconciled later; never revive a cancelled upload.
                pass

    def _abort(
        self,
        file: Archivo,
        version: ArchivoVersion,
        replica: ReplicaArchivo,
        *,
        user: Usuario,
        device: Dispositivo,
        retry_key: str | None,
        ip: str | None,
        user_agent: str | None,
        action: str = "ABORTAR_CARGA_ARCHIVO",
        result: str = "EXITO",
        details: dict | None = None,
    ) -> None:
        file.estado = "ABORTED"
        version.estado = "ABORTED"
        version.abort_idempotency_key = retry_key
        replica.estado = "ABORTED"
        self._add_audit(
            action,
            result,
            file=file,
            version=version,
            user=user,
            device=device,
            ip=ip,
            user_agent=user_agent,
            details=details or {"estado": "ABORTED"},
        )
        self.db.commit()
        self._safe_delete(replica)

    def _mark_failed(
        self,
        file: Archivo,
        version: ArchivoVersion,
        replica: ReplicaArchivo,
        *,
        user: Usuario,
        device: Dispositivo,
        ip: str | None,
        user_agent: str | None,
        reason: str,
    ) -> None:
        file.estado = "FAILED"
        version.estado = "FAILED"
        replica.estado = "FAILED"
        self._add_audit(
            "FALLO_CARGA_ARCHIVO",
            "FALLO",
            file=file,
            version=version,
            user=user,
            device=device,
            ip=ip,
            user_agent=user_agent,
            details={"motivo": reason},
        )
        self.db.commit()
        self._safe_delete(replica)

    def _presigned_response(
        self,
        file: Archivo,
        version: ArchivoVersion,
        replica: ReplicaArchivo,
        vault_session: SesionBoveda,
    ):
        now = datetime.now(timezone.utc)
        if self._is_expired(version, now):
            raise HTTPException(409, "La autorización temporal de carga expiró.")
        expiration = self._expiration_for(vault_session, now)
        if expiration <= now:
            raise HTTPException(401, "La sesión de bóveda expiró antes de iniciar la carga.")
        staging_object_key = replica.staging_object_key
        if not staging_object_key:
            raise HTTPException(409, "La reserva de carga ya no está disponible.")
        version.fecha_expiracion = expiration
        try:
            upload_url = self.storage.create_upload_url(
                staging_object_key,
                version.tamano_ciphertext_esperado,
                expiration - now,
            )
        except ObjectStorageUnavailable as error:
            raise HTTPException(503, "El almacenamiento cifrado no está disponible.") from error
        return self._response(file, version, upload_url=upload_url)

    def create_intent(
        self,
        user: Usuario,
        device: Dispositivo,
        vault_session: SesionBoveda,
        vault_id: uuid.UUID,
        body: FileUploadIntentRequest,
        retry_key: str,
        ip: str | None,
        user_agent: str | None,
    ):
        max_ciphertext_size = settings.FILE_UPLOAD_MAX_BYTES
        if body.tamano_ciphertext_esperado > max_ciphertext_size:
            raise HTTPException(422, "El archivo excede el límite de carga permitido.")
        self._require_upload_access(user, device, vault_id)
        fingerprint = self._request_hash(body)
        existing = self.repo.find_intent_retry(
            vault_id, user.id_usuario, retry_key, lock=True
        )
        if existing:
            file, version, _replica = existing
            if version.solicitud_hash != fingerprint:
                raise HTTPException(409, "Idempotency-Key ya fue utilizada con otros datos.")
            self._assert_bound_intent(version, user, device, vault_session)
            if self._is_expired(version, datetime.now(timezone.utc)) and version.estado in {
                "PENDING",
                "UPLOADING",
            }:
                self._abort(
                    file,
                    version,
                    _replica,
                    user=user,
                    device=device,
                    retry_key=None,
                    ip=ip,
                    user_agent=user_agent,
                    action="FALLO_CARGA_ARCHIVO",
                    result="FALLO",
                    details={"motivo": "INTENT_EXPIRED"},
                )
                raise HTTPException(409, "La autorización temporal de carga expiró.")
            if version.estado == "UPLOADING":
                try:
                    response = self._presigned_response(file, version, _replica, vault_session)
                    self.db.commit()
                    return response
                except Exception:
                    self.db.rollback()
                    raise
            return self._response(file, version)

        now = datetime.now(timezone.utc)
        expires_at = self._expiration_for(vault_session, now)
        if expires_at <= now:
            raise HTTPException(401, "La sesión de bóveda expiró antes de iniciar la carga.")
        file = Archivo(
            id_archivo=uuid.uuid4(),
            id_boveda=vault_id,
            id_creado_por=user.id_usuario,
            estado="PENDING",
        )
        version = ArchivoVersion(
            id_version=uuid.uuid4(),
            id_archivo=file.id_archivo,
            id_boveda=vault_id,
            numero_version=1,
            id_usuario_origen=user.id_usuario,
            id_dispositivo_origen=device.id_dispositivo,
            id_sesion_boveda_origen=vault_session.id_sesion_boveda,
            estado="PENDING",
            version_criptografica=body.version_criptografica,
            tamano_ciphertext_esperado=body.tamano_ciphertext_esperado,
            idempotency_key=retry_key,
            solicitud_hash=fingerprint,
            fecha_expiracion=expires_at,
        )
        replica = ReplicaArchivo(
            id_replica=uuid.uuid4(),
            id_version=version.id_version,
            proveedor="MINIO",
            bucket=settings.MINIO_BUCKET,
            object_key=self._final_object_key(version.id_version),
            staging_object_key=self._staging_object_key(),
            estado="PENDING",
        )
        try:
            self.db.add_all((file, version, replica))
            self.db.flush()
            file.estado = "UPLOADING"
            version.estado = "UPLOADING"
            replica.estado = "UPLOADING"
            self._add_audit(
                "INICIAR_CARGA_ARCHIVO",
                "EXITO",
                file=file,
                version=version,
                user=user,
                device=device,
                ip=ip,
                user_agent=user_agent,
                details={"estado": "UPLOADING", "tamano_ciphertext_esperado": body.tamano_ciphertext_esperado},
            )
            response = self._presigned_response(file, version, replica, vault_session)
            self.db.commit()
        except IntegrityError:
            self.db.rollback()
            existing = self.repo.find_intent_retry(vault_id, user.id_usuario, retry_key, lock=True)
            if existing and existing[1].solicitud_hash == fingerprint:
                self._assert_bound_intent(existing[1], user, device, vault_session)
                if existing[1].estado == "UPLOADING":
                    try:
                        response = self._presigned_response(
                            existing[0], existing[1], existing[2], vault_session
                        )
                        self.db.commit()
                        return response
                    except Exception:
                        self.db.rollback()
                        raise
                return self._response(existing[0], existing[1])
            raise HTTPException(409, "No fue posible reservar la carga cifrada.")
        except Exception:
            self.db.rollback()
            raise
        return response

    def complete(
        self,
        user: Usuario,
        device: Dispositivo,
        vault_session: SesionBoveda,
        vault_id: uuid.UUID,
        file_id: uuid.UUID,
        version_id: uuid.UUID,
        body: FileUploadCompleteRequest,
        retry_key: str,
        ip: str | None,
        user_agent: str | None,
    ):
        self._require_upload_access(user, device, vault_id)
        row = self.repo.get_version(vault_id, file_id, version_id, lock=True)
        if not row:
            raise HTTPException(404, "Carga no disponible para esta bóveda.")
        file, version, replica = row
        self._assert_bound_intent(version, user, device, vault_session)
        now = datetime.now(timezone.utc)
        if self._is_expired(version, now) and version.estado in {"PENDING", "UPLOADING"}:
            self._abort(
                file,
                version,
                replica,
                user=user,
                device=device,
                retry_key=None,
                ip=ip,
                user_agent=user_agent,
                action="FALLO_CARGA_ARCHIVO",
                result="FALLO",
                details={"motivo": "INTENT_EXPIRED"},
            )
            raise HTTPException(409, "La autorización temporal de carga expiró.")

        fingerprint = self._request_hash(body)
        if version.estado == "AVAILABLE":
            if version.complete_solicitud_hash == fingerprint:
                return self._operation_response(file, version)
            raise HTTPException(409, "La versión ya fue completada con otros datos.")
        if version.estado != "UPLOADING":
            raise HTTPException(409, "La carga no se encuentra disponible para completar.")
        if (
            body.tamano_ciphertext != version.tamano_ciphertext_esperado
            or body.tamano_ciphertext > settings.FILE_UPLOAD_MAX_BYTES
        ):
            raise HTTPException(409, "El tamaño ciphertext no coincide con la reserva.")

        try:
            staging_object_key = replica.staging_object_key
            if not staging_object_key:
                raise ObjectStorageIntegrityError("Ciphertext staging key is unavailable.")
            stored = self.storage.finalize_ciphertext(
                staging_object_key,
                replica.object_key,
                body.tamano_ciphertext,
                body.checksum_ciphertext_sha256,
            )
        except ObjectStorageObjectMissing as error:
            raise HTTPException(409, "El ciphertext todavía no está disponible para verificación.") from error
        except ObjectStorageIntegrityError as error:
            self._mark_failed(
                file,
                version,
                replica,
                user=user,
                device=device,
                ip=ip,
                user_agent=user_agent,
                reason="CIPHERTEXT_VERIFICATION_FAILED",
            )
            raise HTTPException(409, "La verificación del ciphertext falló.") from error
        except ObjectStorageUnavailable as error:
            raise HTTPException(503, "El almacenamiento cifrado no está disponible.") from error

        version.tamano_ciphertext = stored.size
        version.checksum_ciphertext_sha256 = stored.sha256
        version.contenido_cifrado = body.contenido_cifrado.model_dump(mode="json")
        version.clave_archivo_envuelta = body.clave_archivo_envuelta.model_dump(mode="json")
        version.metadata_cifrada = body.metadata_cifrada.model_dump(mode="json")
        version.complete_idempotency_key = retry_key
        version.complete_solicitud_hash = fingerprint
        version.fecha_completado = now
        version.estado = "AVAILABLE"
        replica.etag = stored.etag
        replica.estado = "AVAILABLE"
        file.estado = "AVAILABLE"
        try:
            self.storage.delete_object(staging_object_key)
        except ObjectStorageUnavailable:
            # The final key is already immutable to the direct capability. A job retries staging cleanup.
            pass
        self._add_audit(
            "COMPLETAR_CARGA_ARCHIVO",
            "EXITO",
            file=file,
            version=version,
            user=user,
            device=device,
            ip=ip,
            user_agent=user_agent,
            details={"estado": "AVAILABLE", "tamano_ciphertext": stored.size},
        )
        try:
            self.db.commit()
        except Exception:
            self.db.rollback()
            try:
                self.storage.delete_object(replica.object_key)
            except ObjectStorageUnavailable:
                pass
            raise
        return self._operation_response(file, version)

    def abort(
        self,
        user: Usuario,
        device: Dispositivo,
        vault_session: SesionBoveda,
        vault_id: uuid.UUID,
        file_id: uuid.UUID,
        version_id: uuid.UUID,
        retry_key: str,
        ip: str | None,
        user_agent: str | None,
    ):
        self._require_upload_access(user, device, vault_id)
        row = self.repo.get_version(vault_id, file_id, version_id, lock=True)
        if not row:
            raise HTTPException(404, "Carga no disponible para esta bóveda.")
        file, version, replica = row
        self._assert_bound_intent(version, user, device, vault_session)
        if version.estado == "AVAILABLE":
            raise HTTPException(409, "Una carga disponible no puede abortarse.")
        if version.estado in {"ABORTED", "FAILED"}:
            return self._operation_response(file, version)
        self._abort(
            file,
            version,
            replica,
            user=user,
            device=device,
            retry_key=retry_key,
            ip=ip,
            user_agent=user_agent,
        )
        return self._operation_response(file, version)

    def reconcile_expired_uploads(self, limit: int = 100) -> int:
        """Abort expired intents; safe for a cron job and repeatable after crashes."""

        now = datetime.now(timezone.utc)
        expired = self.repo.stale_uploads(now, limit)
        cleaned = 0
        for file, version, replica in expired:
            file.estado = "ABORTED"
            version.estado = "ABORTED"
            replica.estado = "ABORTED"
            self.audit.add_audit_event(
                accion="FALLO_CARGA_ARCHIVO",
                tipo_evento="ARCHIVO",
                resultado="FALLO",
                user_id=version.id_usuario_origen,
                device_id=version.id_dispositivo_origen,
                resource_id=str(version.id_version),
                resource_type="ARCHIVO_VERSION",
                detalles={"motivo": "INTENT_EXPIRED"},
            )
            self.db.commit()
            self._safe_delete(replica)
            cleaned += 1
        return cleaned

    def reconcile_terminal_objects(self, limit: int = 100) -> int:
        """Retries deletion for objects left after a failed or aborted transaction."""

        cleaned = 0
        for replica in self.repo.cleanup_candidates(limit):
            self._safe_delete(replica)
            cleaned += 1
        now = datetime.now(timezone.utc)
        for replica in self.repo.available_staging_candidates(now, limit):
            staging_object_key = replica.staging_object_key
            if not staging_object_key:
                continue
            try:
                self.storage.delete_object(staging_object_key)
            except ObjectStorageUnavailable:
                continue
            replica.staging_object_key = None
            self.db.commit()
            cleaned += 1
        return cleaned
