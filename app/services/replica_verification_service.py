import hashlib
from datetime import datetime, timezone

from fastapi import HTTPException

from app.models.auth import EventoAuditoria
from app.repositories.file_repository import FileRepository


class ReplicaVerificationService:
    def __init__(self, db, storages=None):
        self.db = db
        self.repo = FileRepository(db)
        self.storages = storages or {}

    def verify(self, user, device, vault_id, version_id, ip=None):
        permissions = {permission.codigo for role in user.roles for permission in role.permisos}
        if "files:read" not in permissions:
            raise HTTPException(403, "No tienes permiso para verificar archivos.")
        if not self.repo.get_active_membership(vault_id, user.id_usuario):
            raise HTTPException(403, "No tienes una membresía activa en esta bóveda.")

        rows = self.repo.get_replication(vault_id, version_id)
        if not rows:
            raise HTTPException(404, "La versión solicitada no está disponible.")
        version = rows[0][0]
        results = []
        for _, replica in rows:
            if replica is None:
                continue
            self._verify_replica(replica, version.hash_cifrado)
            results.append(self._serialize(replica, version.hash_cifrado))

        self.db.add(EventoAuditoria(
            id_usuario=user.id_usuario,
            id_dispositivo=device.id_dispositivo,
            accion="VERIFICAR_REPLICAS_ARCHIVO",
            tipo_evento="ARCHIVO",
            resultado="EXITO",
            recurso_id=str(version_id),
            recurso_tipo="VERSION_ARCHIVO",
            direccion_ip=ip,
            detalles={"proveedores": [item["proveedor"] for item in results]},
        ))
        self.db.commit()
        return {"id_version_archivo": version_id, "replicas": results}

    def _verify_replica(self, replica, expected_hash):
        now = datetime.now(timezone.utc)
        storage = self.storages.get(replica.proveedor)
        if storage is None:
            replica.estado = "UNAVAILABLE"
            replica.fecha_verificacion = None
            replica.ultimo_error = None
            return
        try:
            metadata = storage.get_ciphertext_metadata(replica.clave_objeto) if hasattr(storage, "get_ciphertext_metadata") else None
            if metadata and metadata.get("hash") is not None and metadata.get("size") is not None:
                actual_size = metadata["size"]
                actual_hash = str(metadata["hash"]).lower()
            else:
                content = storage.get_ciphertext(replica.clave_objeto)
                actual_size = len(content)
                actual_hash = hashlib.sha256(content).hexdigest()
            if actual_size != replica.tamano_esperado:
                replica.estado = "SIZE_MISMATCH"
            elif actual_hash != expected_hash or actual_hash != replica.hash_cifrado:
                replica.estado = "HASH_MISMATCH"
            else:
                replica.estado = "VERIFIED"
                replica.fecha_verificacion = now
                replica.ultimo_error = None
                return
            replica.fecha_verificacion = now
            replica.ultimo_error = None
        except Exception as error:
            replica.estado = "MISSING" if self._is_missing(error) else "RETRYABLE"
            replica.fecha_verificacion = None
            replica.ultimo_error = type(error).__name__[:500]

    @staticmethod
    def _is_missing(error):
        return isinstance(error, FileNotFoundError) or getattr(error, "status_code", None) == 404 or getattr(error, "code", None) in ("NoSuchKey", "NotFound")

    @staticmethod
    def _serialize(replica, expected_hash):
        return {
            "proveedor": replica.proveedor,
            "estado": replica.estado,
            "hash_esperado": expected_hash,
            "tamano_esperado": replica.tamano_esperado,
            "fecha_verificacion": replica.fecha_verificacion,
        }
