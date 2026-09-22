import base64
import hashlib
import uuid
from datetime import datetime, timezone

from fastapi import HTTPException
from sqlalchemy.exc import IntegrityError

from app.models.auth import EventoAuditoria
from app.models.vault import Archivo, ClaveEnvuelta, ReplicaAlmacenamiento, VersionArchivo
from app.repositories.file_repository import FileRepository
from app.services.minio_service import MinioStorage
from app.services.sharing_service import SharingService
from app.core.config import settings


class FileService:
    def __init__(self, db, storage=None):
        self.db = db
        self.repo = FileRepository(db)
        self.storage = storage or MinioStorage()
        self.s3_storage = None
        if storage is None and settings.S3_ENABLED:
            from app.services.s3_service import S3Storage
            self.s3_storage = S3Storage()

    def upload(self, user, device, vault_id, body, retry_key, ip=None):
        if not self.repo.get_active_membership(vault_id, user.id_usuario):
            raise HTTPException(403, "No tienes una membresía activa en esta bóveda.")

        existing = self.repo.find_retry(vault_id, retry_key)
        if existing:
            if existing.id_version_archivo != body.id_version_archivo:
                raise HTTPException(409, "Idempotency-Key ya fue utilizada con otros datos.")
            return self._serialize(existing)

        ciphertext = base64.b64decode(body.contenido_cifrado.ciphertext, validate=True)
        if len(ciphertext) + 16 != body.tamano_cifrado:
            raise HTTPException(422, "El tamaño declarado no coincide con el ciphertext.")
        if hashlib.sha256(ciphertext).hexdigest() != body.hash_cifrado:
            raise HTTPException(422, "El hash del ciphertext no coincide.")

        version_number = self.repo.next_version(vault_id)
        object_key = f"vaults/{vault_id}/versions/{body.id_version_archivo}.blob"
        try:
            self.storage.put_ciphertext(object_key, ciphertext, body.hash_cifrado)
            stored_ciphertext = self.storage.get_ciphertext(object_key)
            if len(stored_ciphertext) != len(ciphertext) or hashlib.sha256(stored_ciphertext).hexdigest() != body.hash_cifrado:
                raise HTTPException(409, "La integridad del ciphertext no pudo verificarse.")
        except Exception:
            self.storage.delete(object_key)
            raise
        try:
            archivo = Archivo(
                id_archivo=body.id_archivo,
                id_boveda=vault_id,
                nombre_cifrado=body.nombre_cifrado.model_dump(mode="json"),
                idempotency_key=retry_key,
            )
            version = VersionArchivo(
                id_version_archivo=body.id_version_archivo,
                id_archivo=body.id_archivo,
                id_boveda=vault_id,
                numero_version=version_number,
                tamano_cifrado=body.tamano_cifrado,
                hash_cifrado=body.hash_cifrado,
                nonce_iv=body.contenido_cifrado.nonce,
                auth_tag=body.contenido_cifrado.tag,
                algoritmo=body.contenido_cifrado.algoritmo,
                idempotency_key=retry_key,
            )
            wrapped = ClaveEnvuelta(
                id_boveda=vault_id,
                id_version_archivo=body.id_version_archivo,
                id_usuario=user.id_usuario,
                id_dispositivo=device.id_dispositivo,
                algoritmo=body.clave_archivo_envuelta.algoritmo,
                ciphertext=body.clave_archivo_envuelta.ciphertext,
                nonce=body.clave_archivo_envuelta.nonce,
                tag=body.clave_archivo_envuelta.tag,
                version_clave=version_number,
            )
            replica = ReplicaAlmacenamiento(
                id_version_archivo=body.id_version_archivo,
                proveedor="MINIO",
                clave_objeto=object_key,
                hash_cifrado=body.hash_cifrado,
                estado="VERIFIED",
                tamano_esperado=len(ciphertext),
                fecha_verificacion=datetime.now(timezone.utc),
            )
            self.db.add_all([archivo, version])
            self.db.flush()
            self.db.add_all([wrapped, replica, EventoAuditoria(
                id_usuario=user.id_usuario,
                id_dispositivo=device.id_dispositivo,
                accion="CARGAR_ARCHIVO_CIFRADO",
                tipo_evento="ARCHIVO",
                resultado="EXITO",
                recurso_id=str(body.id_archivo),
                recurso_tipo="ARCHIVO",
                direccion_ip=ip,
                detalles={"version": version_number, "tamano_cifrado": body.tamano_cifrado, "proveedor": "MINIO"},
            )])
            self.db.commit()
        except IntegrityError as error:
            self.db.rollback()
            self.storage.delete(object_key)
            raise HTTPException(409, "El archivo o la versión ya fueron registrados.") from error
        except Exception:
            self.db.rollback()
            self.storage.delete(object_key)
            raise
        return self._serialize(version)

    def list_metadata(self, user, device, vault_id, page, page_size):
        permissions = {permission.codigo for role in user.roles for permission in role.permisos}
        if "files:read" not in permissions:
            raise HTTPException(403, "No tienes permiso para consultar archivos.")
        membership = self.repo.get_active_membership(vault_id, user.id_usuario)
        grant = None if membership else SharingService(self.db).recipient_grant(user, device, vault_id)
        if not membership and not grant:
            raise HTTPException(403, "No tienes una membresía activa en esta bóveda.")

        if grant and grant.id_archivo:
            total = self.repo.count_metadata_for_file(vault_id, grant.id_archivo)
            rows = self.repo.list_metadata_for_file(vault_id, grant.id_archivo, (page - 1) * page_size, page_size, user.id_usuario, device.id_dispositivo)
        else:
            total = self.repo.count_metadata(vault_id)
            rows = self.repo.list_metadata(vault_id, (page - 1) * page_size, page_size, user.id_usuario, device.id_dispositivo)
        items = []
        for row in rows:
            version, archivo, replica = row[0], row[1], row[2]
            clave = row[3] if len(row) > 3 else None
            wrapped_envelope = None
            if clave:
                wrapped_envelope = {
                    "algoritmo": clave.algoritmo,
                    "ciphertext": clave.ciphertext,
                    "nonce": clave.nonce,
                    "tag": clave.tag,
                }
            items.append({
                "id_archivo": version.id_archivo,
                "id_version_archivo": version.id_version_archivo,
                "numero_version": version.numero_version,
                "nombre_cifrado": archivo.nombre_cifrado,
                "tamano_cifrado": version.tamano_cifrado,
                "hash_cifrado": version.hash_cifrado,
                "nonce_iv": version.nonce_iv,
                "auth_tag": version.auth_tag,
                "algoritmo": version.algoritmo,
                "fecha_creacion": version.fecha_creacion,
                "proveedor": replica.proveedor if replica else None,
                "estado_replica": replica.estado if replica else None,
                "fecha_verificacion_replica": replica.fecha_verificacion if replica else None,
                "clave_archivo_envuelta": wrapped_envelope,
            })
        return {
            "items": items,
            "page": page,
            "page_size": page_size,
            "total": total,
            "has_next": page * page_size < total,
        }

    def download(self, user, device, vault_id, version_id, ip=None):
        permissions = {permission.codigo for role in user.roles for permission in role.permisos}
        membership = self.repo.get_active_membership(vault_id, user.id_usuario)
        shared_rows = self.repo.get_download_shared(vault_id, version_id)
        file_id = shared_rows[0][0].id_archivo if shared_rows else None
        grant = None if membership else SharingService(self.db).recipient_grant(user, device, vault_id, file_id)
        rows = self.repo.get_download(vault_id, version_id, user.id_usuario, device.id_dispositivo) if membership else shared_rows
        if "files:read" not in permissions or (not membership and not grant):
            self._audit(user, device, "FALLO_AUTORIZACION_DESCARGA", vault_id, ip)
            raise HTTPException(403, "No tienes permiso para descargar esta versión.")
        if not rows:
            self._audit(user, device, "FALLO_VERSION_DESCARGA", version_id, ip)
            raise HTTPException(404, "La versión solicitada no está disponible.")

        version = rows[0][0]
        wrapped = rows[0][3] if membership else SharingService(self.db).repo.envelopes(grant.id_acceso_compartido, device.id_dispositivo)[0]
        ciphertext, source = self._read_verified_replica(rows, self.storage, self.s3_storage, version.hash_cifrado)
        if ciphertext is None:
            self._audit(user, device, "FALLO_INTEGRIDAD_DESCARGA", version_id, ip)
            raise HTTPException(409, "La integridad del ciphertext no pudo verificarse.")

        self._audit(user, device, "DESCARGAR_ARCHIVO_CIFRADO", version_id, ip, resultado="EXITO", detalles={"proveedor": source})
        response = {
            "id_archivo": version.id_archivo,
            "id_version_archivo": version.id_version_archivo,
            "numero_version": version.numero_version,
            "tamano_cifrado": version.tamano_cifrado,
            "hash_cifrado": version.hash_cifrado,
            "algoritmo": version.algoritmo,
            "nonce_iv": version.nonce_iv,
            "auth_tag": version.auth_tag,
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "clave_archivo_envuelta": {
                "algoritmo": wrapped.algoritmo,
                "ciphertext": wrapped.ciphertext,
                "nonce": wrapped.nonce,
                "tag": wrapped.tag,
            },
        }
        return response

    def delete(self, user, device, vault_id, file_id, body, request_id, ip=None):
        permissions = {permission.codigo for role in user.roles for permission in role.permisos}
        if "files:delete" not in permissions or not self.repo.get_active_membership(vault_id, user.id_usuario):
            self._audit(user, device, "FALLO_AUTORIZACION_ELIMINAR_ARCHIVO", file_id, ip)
            raise HTTPException(403, "No tienes permiso para eliminar este archivo.")

        archivo = self.repo.get_file_for_deletion(vault_id, file_id)
        if not archivo:
            self._audit(user, device, "FALLO_ARCHIVO_ELIMINAR", file_id, ip)
            raise HTTPException(404, "El archivo solicitado no está disponible.")
        if archivo.estado == "ELIMINADO":
            return self._delete_response(archivo, True)

        archivo.estado = "ELIMINADO"
        archivo.fecha_eliminacion = datetime.now(timezone.utc)
        archivo.eliminado_por = user.id_usuario
        archivo.motivo_eliminacion = body.motivo
        archivo.solicitud_eliminacion_id = request_id
        # Ciphertext remains retained until a separate, retryable cleanup worker acts.
        archivo.estado_limpieza = "RETENCION"
        self.db.add(EventoAuditoria(
            id_usuario=user.id_usuario,
            id_dispositivo=device.id_dispositivo,
            accion="ELIMINAR_ARCHIVO_CIFRADO",
            tipo_evento="ARCHIVO",
            resultado="EXITO",
            recurso_id=str(file_id),
            recurso_tipo="ARCHIVO",
            direccion_ip=ip,
            detalles={"solicitud_id": request_id, "estado_limpieza": archivo.estado_limpieza},
        ))
        self.db.commit()
        return self._delete_response(archivo, False)

    def attempt_retained_cleanup(self, file_id, storages):
        """Worker-only cleanup after retention; logical deletion is always committed first."""
        archivo = self.repo.get_file_for_deletion_any_state(file_id)
        if not archivo or archivo.estado != "ELIMINADO":
            return None
        try:
            for replica in self.repo.get_file_replicas(file_id):
                storage = storages.get(replica.proveedor)
                if storage is None:
                    raise RuntimeError("storage unavailable")
                storage.delete(replica.clave_objeto)
            archivo.estado_limpieza = "LIMPIADO"
            self.db.commit()
            return archivo.estado_limpieza
        except Exception:
            archivo.estado_limpieza = "REINTENTO_LIMPIEZA"
            self.db.add(EventoAuditoria(
                accion="FALLO_LIMPIEZA_ARCHIVO_CIFRADO",
                tipo_evento="ARCHIVO",
                resultado="REINTENTABLE",
                recurso_id=str(file_id),
                recurso_tipo="ARCHIVO",
                detalles={"estado_limpieza": archivo.estado_limpieza},
            ))
            self.db.commit()
            return archivo.estado_limpieza

    def _audit(self, user, device, action, resource_id, ip, resultado="FALLO", detalles=None):
        self.db.add(EventoAuditoria(
            id_usuario=user.id_usuario,
            id_dispositivo=device.id_dispositivo,
            accion=action,
            tipo_evento="ARCHIVO",
            resultado=resultado,
            recurso_id=str(resource_id),
            recurso_tipo="VERSION_ARCHIVO",
            direccion_ip=ip,
            detalles=detalles or {},
        ))
        self.db.commit()

    @staticmethod
    def _delete_response(archivo, idempotent):
        return {
            "id_archivo": archivo.id_archivo,
            "estado": archivo.estado,
            "estado_limpieza": archivo.estado_limpieza,
            "idempotente": idempotent,
        }

    @staticmethod
    def _read_verified_replica(rows, minio_storage, s3_storage, expected_hash):
        for row in rows:
            replica = row[2]
            storage = minio_storage if replica.proveedor == "MINIO" else s3_storage
            if storage is None:
                continue
            try:
                candidate = storage.get_ciphertext(replica.clave_objeto)
            except Exception:
                continue
            if len(candidate) == replica.tamano_esperado and hashlib.sha256(candidate).hexdigest() == replica.hash_cifrado == expected_hash:
                return candidate, replica.proveedor
        return None, None

    @staticmethod
    def _serialize(version):
        return {
            "id_archivo": version.id_archivo,
            "id_version_archivo": version.id_version_archivo,
            "numero_version": version.numero_version,
            "tamano_cifrado": version.tamano_cifrado,
            "hash_cifrado": version.hash_cifrado,
            "proveedor": "MINIO",
            "estado": "VERIFIED",
        }
