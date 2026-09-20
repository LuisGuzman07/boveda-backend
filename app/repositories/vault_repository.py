from sqlalchemy import select
from app.models.vault import Boveda, ClaveEnvuelta, MembresiaBoveda


class VaultRepository:
    def __init__(self, db):
        self.db = db

    def find_retry(self, user_id, key):
        return self.db.scalar(select(Boveda).where(Boveda.id_propietario == user_id, Boveda.idempotency_key == key))

    def get_owned(self, user_id, device_id, vault_id=None, *, lock=False):
        statement = select(Boveda, ClaveEnvuelta).join(MembresiaBoveda, MembresiaBoveda.id_boveda == Boveda.id_boveda).join(ClaveEnvuelta, ClaveEnvuelta.id_boveda == Boveda.id_boveda).where(MembresiaBoveda.id_usuario == user_id, MembresiaBoveda.estado == "ACTIVA", ClaveEnvuelta.id_usuario == user_id, ClaveEnvuelta.id_dispositivo == device_id, ClaveEnvuelta.estado == "ACTIVA", Boveda.estado == "ACTIVA")
        if vault_id:
            statement = statement.where(Boveda.id_boveda == vault_id)
        if lock:
            statement = statement.with_for_update().execution_options(populate_existing=True)
        return self.db.execute(statement.order_by(Boveda.fecha_creacion.desc())).all()
