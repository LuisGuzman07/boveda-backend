from __future__ import annotations

import uuid
from datetime import datetime

from sqlalchemy import select

from app.models.vault import Archivo, ArchivoVersion, ReplicaArchivo


class FileUploadRepository:
    def __init__(self, db):
        self.db = db

    @staticmethod
    def _lock(statement, lock: bool):
        if lock:
            return statement.with_for_update().execution_options(populate_existing=True)
        return statement

    def find_intent_retry(
        self,
        vault_id: uuid.UUID,
        user_id: uuid.UUID,
        idempotency_key: str,
        *,
        lock: bool = False,
    ):
        statement = (
            select(Archivo, ArchivoVersion, ReplicaArchivo)
            .join(ArchivoVersion, ArchivoVersion.id_archivo == Archivo.id_archivo)
            .join(ReplicaArchivo, ReplicaArchivo.id_version == ArchivoVersion.id_version)
            .where(
                ArchivoVersion.id_boveda == vault_id,
                ArchivoVersion.id_usuario_origen == user_id,
                ArchivoVersion.idempotency_key == idempotency_key,
            )
        )
        return self.db.execute(self._lock(statement, lock)).first()

    def get_version(
        self,
        vault_id: uuid.UUID,
        file_id: uuid.UUID,
        version_id: uuid.UUID,
        *,
        lock: bool = False,
    ):
        statement = (
            select(Archivo, ArchivoVersion, ReplicaArchivo)
            .join(ArchivoVersion, ArchivoVersion.id_archivo == Archivo.id_archivo)
            .join(ReplicaArchivo, ReplicaArchivo.id_version == ArchivoVersion.id_version)
            .where(
                Archivo.id_boveda == vault_id,
                Archivo.id_archivo == file_id,
                ArchivoVersion.id_version == version_id,
            )
        )
        return self.db.execute(self._lock(statement, lock)).first()

    def stale_uploads(self, now: datetime, limit: int):
        statement = (
            select(Archivo, ArchivoVersion, ReplicaArchivo)
            .join(ArchivoVersion, ArchivoVersion.id_archivo == Archivo.id_archivo)
            .join(ReplicaArchivo, ReplicaArchivo.id_version == ArchivoVersion.id_version)
            .where(
                ArchivoVersion.estado.in_(("PENDING", "UPLOADING")),
                ArchivoVersion.fecha_expiracion <= now,
            )
            .order_by(ArchivoVersion.fecha_expiracion)
            .limit(limit)
            .with_for_update(skip_locked=True)
        )
        return self.db.execute(statement).all()

    def cleanup_candidates(self, limit: int):
        statement = (
            select(ReplicaArchivo)
            .where(ReplicaArchivo.estado.in_(("FAILED", "ABORTED")))
            .order_by(ReplicaArchivo.fecha_actualizacion)
            .limit(limit)
        )
        return self.db.scalars(statement).all()

    def available_staging_candidates(self, now: datetime, limit: int):
        statement = (
            select(ReplicaArchivo)
            .join(ArchivoVersion, ArchivoVersion.id_version == ReplicaArchivo.id_version)
            .where(
                ArchivoVersion.estado == "AVAILABLE",
                ArchivoVersion.fecha_expiracion <= now,
                ReplicaArchivo.staging_object_key.is_not(None),
            )
            .order_by(ReplicaArchivo.fecha_actualizacion)
            .limit(limit)
        )
        return self.db.scalars(statement).all()
