import hashlib
from datetime import datetime, timezone

from fastapi import HTTPException

from app.core.config import settings
from app.models.auth import EventoAuditoria
from app.models.vault import ReplicaAlmacenamiento
from app.repositories.file_repository import FileRepository
from app.services.minio_service import MinioStorage


class ReplicationService:
    def __init__(self, db, local_storage=None, replica_storage=None):
        self.db = db
        self.repo = FileRepository(db)
        self.local_storage = local_storage or MinioStorage()
        self.replica_storage = replica_storage

    def replicate(self, user, device, vault_id, version_id, ip=None):
        if not self.repo.get_active_membership(vault_id, user.id_usuario):
            raise HTTPException(403, "No tienes una membresía activa en esta bóveda.")
        if not settings.S3_ENABLED and self.replica_storage is None:
            raise HTTPException(503, "La réplica S3 no está configurada.")
        rows = self.repo.get_replication(vault_id, version_id)
        if not rows:
            raise HTTPException(404, "La versión solicitada no está disponible.")
        version = rows[0][0]
        local = next((replica for _, replica in rows if replica.proveedor == "MINIO"), None)
        if not local:
            raise HTTPException(409, "La copia local no está disponible para replicar.")
        destination = next((replica for _, replica in rows if replica.proveedor == "S3"), None)
        if not destination:
            destination = ReplicaAlmacenamiento(
                id_version_archivo=version.id_version_archivo,
                proveedor="S3",
                clave_objeto=local.clave_objeto,
                hash_cifrado=version.hash_cifrado,
                tamano_esperado=local.tamano_esperado,
                intentos=0,
                estado="PENDING",
            )
            self.db.add(destination)
            self.db.flush()
        if destination.estado == "VERIFIED":
            return self._serialize(destination)

        destination.estado = "COPYING"
        destination.intentos += 1
        destination.ultimo_error = None
        self.db.flush()
        try:
            ciphertext = self.local_storage.get_ciphertext(local.clave_objeto)
            self._validate(ciphertext, version.hash_cifrado, local.tamano_esperado)
            result = self._storage().put_ciphertext(destination.clave_objeto, ciphertext, version.hash_cifrado)
            copied = self._storage().get_ciphertext(destination.clave_objeto)
            self._validate(copied, version.hash_cifrado, local.tamano_esperado)
            destination.etag = result.get("etag")
            destination.version_id = result.get("version_id")
            destination.estado = "VERIFIED"
            destination.fecha_verificacion = datetime.now(timezone.utc)
            self._audit(user, device, version_id, ip, "EXITO", {"proveedor": "S3"})
            self.db.commit()
            return self._serialize(destination)
        except Exception as error:
            destination.estado = "RETRYABLE"
            destination.ultimo_error = str(error)[:500]
            self._audit(user, device, version_id, ip, "FALLO", {"proveedor": "S3", "reintentable": True})
            self.db.commit()
            raise HTTPException(503, "La réplica no pudo verificarse; puede reintentarse.") from error

    def _storage(self):
        if self.replica_storage:
            return self.replica_storage
        from app.services.s3_service import S3Storage
        return S3Storage()

    @staticmethod
    def _validate(content, expected_hash, expected_size):
        if len(content) != expected_size or hashlib.sha256(content).hexdigest() != expected_hash:
            raise ValueError("La copia cifrada no coincide con el hash o tamaño esperado.")

    def _audit(self, user, device, version_id, ip, result, details):
        self.db.add(EventoAuditoria(
            id_usuario=user.id_usuario,
            id_dispositivo=device.id_dispositivo,
            accion="REPLICAR_ARCHIVO_CIFRADO",
            tipo_evento="ARCHIVO",
            resultado=result,
            recurso_id=str(version_id),
            recurso_tipo="VERSION_ARCHIVO",
            direccion_ip=ip,
            detalles=details,
        ))

    @staticmethod
    def _serialize(replica):
        return {
            "proveedor": replica.proveedor,
            "clave_objeto": replica.clave_objeto,
            "version_id": replica.version_id,
            "estado": replica.estado,
            "intentos": replica.intentos,
            "fecha_verificacion": replica.fecha_verificacion,
        }
