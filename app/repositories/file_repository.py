from sqlalchemy import and_, func, select

from app.models.vault import Boveda, Archivo, ClaveEnvuelta, MembresiaBoveda, ReplicaAlmacenamiento, VersionArchivo


class FileRepository:
    def __init__(self, db):
        self.db = db

    def get_active_membership(self, vault_id, user_id):
        return self.db.scalar(
            select(MembresiaBoveda).where(
                MembresiaBoveda.id_boveda == vault_id,
                MembresiaBoveda.id_usuario == user_id,
                MembresiaBoveda.estado == "ACTIVA",
            )
        )

    def find_retry(self, vault_id, retry_key):
        return self.db.scalar(
            select(VersionArchivo).where(
                VersionArchivo.id_boveda == vault_id,
                VersionArchivo.idempotency_key == retry_key,
            )
        )

    def next_version(self, vault_id):
        current = self.db.scalar(
            select(func.max(VersionArchivo.numero_version)).where(VersionArchivo.id_boveda == vault_id)
        )
        return (current or 0) + 1

    def count_metadata(self, vault_id):
        return self.db.scalar(
            select(func.count(VersionArchivo.id_version_archivo))
            .join(Archivo, Archivo.id_archivo == VersionArchivo.id_archivo)
            .join(Boveda, Boveda.id_boveda == VersionArchivo.id_boveda)
            .where(
                VersionArchivo.id_boveda == vault_id,
                Archivo.id_boveda == vault_id,
                Archivo.estado == "ACTIVO",
                Boveda.id_boveda == vault_id,
                Boveda.estado == "ACTIVA",
            )
        ) or 0

    def list_metadata(self, vault_id, offset, limit):
        statement = (
            select(VersionArchivo, Archivo, ReplicaAlmacenamiento)
            .join(Archivo, Archivo.id_archivo == VersionArchivo.id_archivo)
            .join(Boveda, Boveda.id_boveda == VersionArchivo.id_boveda)
            .outerjoin(
                ReplicaAlmacenamiento,
                and_(
                    ReplicaAlmacenamiento.id_version_archivo == VersionArchivo.id_version_archivo,
                ReplicaAlmacenamiento.proveedor == "MINIO",
                ),
            )
            .where(
                VersionArchivo.id_boveda == vault_id,
                Archivo.id_boveda == vault_id,
                Archivo.estado == "ACTIVO",
                Boveda.estado == "ACTIVA",
            )
            .order_by(
                VersionArchivo.id_archivo.asc(),
                VersionArchivo.numero_version.desc(),
                VersionArchivo.id_version_archivo.asc(),
            )
            .offset(offset)
            .limit(limit)
        )
        return self.db.execute(statement).all()

    def count_metadata_for_file(self, vault_id, file_id):
        return self.db.scalar(select(func.count(VersionArchivo.id_version_archivo)).join(Archivo, Archivo.id_archivo == VersionArchivo.id_archivo).where(VersionArchivo.id_boveda == vault_id, VersionArchivo.id_archivo == file_id, Archivo.estado == "ACTIVO")) or 0

    def list_metadata_for_file(self, vault_id, file_id, offset, limit):
        return self.db.execute(select(VersionArchivo, Archivo, ReplicaAlmacenamiento).join(Archivo, Archivo.id_archivo == VersionArchivo.id_archivo).outerjoin(ReplicaAlmacenamiento, and_(ReplicaAlmacenamiento.id_version_archivo == VersionArchivo.id_version_archivo, ReplicaAlmacenamiento.proveedor == "MINIO")).where(VersionArchivo.id_boveda == vault_id, VersionArchivo.id_archivo == file_id, Archivo.estado == "ACTIVO").order_by(VersionArchivo.numero_version.desc(), VersionArchivo.id_version_archivo.asc()).offset(offset).limit(limit)).all()

    def get_download(self, vault_id, version_id, user_id, device_id):
        statement = (
            select(VersionArchivo, Archivo, ReplicaAlmacenamiento, ClaveEnvuelta)
            .join(Archivo, Archivo.id_archivo == VersionArchivo.id_archivo)
            .join(Boveda, Boveda.id_boveda == VersionArchivo.id_boveda)
            .join(
                ReplicaAlmacenamiento,
                and_(
                    ReplicaAlmacenamiento.id_version_archivo == VersionArchivo.id_version_archivo,
            ),
            )
            .join(
                ClaveEnvuelta,
                and_(
                    ClaveEnvuelta.id_version_archivo == VersionArchivo.id_version_archivo,
                    ClaveEnvuelta.id_usuario == user_id,
                    ClaveEnvuelta.id_dispositivo == device_id,
                ),
            )
            .where(
                VersionArchivo.id_version_archivo == version_id,
                VersionArchivo.id_boveda == vault_id,
                Archivo.id_boveda == vault_id,
                Archivo.estado == "ACTIVO",
                Boveda.estado == "ACTIVA",
                ReplicaAlmacenamiento.estado == "VERIFIED",
                ClaveEnvuelta.estado == "ACTIVA",
            )
        )
        return self.db.execute(statement.order_by(ReplicaAlmacenamiento.proveedor.asc())).all()

    def get_download_shared(self, vault_id, version_id):
        statement = select(VersionArchivo, Archivo, ReplicaAlmacenamiento).join(Archivo, Archivo.id_archivo == VersionArchivo.id_archivo).join(Boveda, Boveda.id_boveda == VersionArchivo.id_boveda).join(ReplicaAlmacenamiento, ReplicaAlmacenamiento.id_version_archivo == VersionArchivo.id_version_archivo).where(VersionArchivo.id_version_archivo == version_id, VersionArchivo.id_boveda == vault_id, Archivo.id_boveda == vault_id, Archivo.estado == "ACTIVO", Boveda.estado == "ACTIVA", ReplicaAlmacenamiento.estado == "VERIFIED")
        return self.db.execute(statement.order_by(ReplicaAlmacenamiento.proveedor.asc())).all()

    def get_file_for_deletion(self, vault_id, file_id):
        return self.db.scalar(
            select(Archivo)
            .join(Boveda, Boveda.id_boveda == Archivo.id_boveda)
            .where(
                Archivo.id_archivo == file_id,
                Archivo.id_boveda == vault_id,
                Boveda.estado == "ACTIVA",
            )
        )

    def get_file_for_deletion_any_state(self, file_id):
        return self.db.scalar(select(Archivo).where(Archivo.id_archivo == file_id))

    def get_file_replicas(self, file_id):
        return self.db.scalars(
            select(ReplicaAlmacenamiento)
            .join(VersionArchivo, VersionArchivo.id_version_archivo == ReplicaAlmacenamiento.id_version_archivo)
            .where(VersionArchivo.id_archivo == file_id)
        ).all()

    def get_replication(self, vault_id, version_id):
        statement = (
            select(VersionArchivo, ReplicaAlmacenamiento)
            .join(Archivo, Archivo.id_archivo == VersionArchivo.id_archivo)
            .join(Boveda, Boveda.id_boveda == VersionArchivo.id_boveda)
            .outerjoin(ReplicaAlmacenamiento, ReplicaAlmacenamiento.id_version_archivo == VersionArchivo.id_version_archivo)
            .where(
                VersionArchivo.id_version_archivo == version_id,
                VersionArchivo.id_boveda == vault_id,
                Archivo.estado == "ACTIVO",
                Boveda.estado == "ACTIVA",
            )
            .order_by(ReplicaAlmacenamiento.proveedor.asc())
        )
        return self.db.execute(statement).all()
