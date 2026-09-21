from datetime import datetime, timezone

from sqlalchemy import and_, func, select, update

from app.models.auth import Dispositivo, Sesion, SesionBoveda, Usuario
from app.models.vault import AccesoCompartido, Archivo, Boveda, SobreAccesoCompartido


class SharingRepository:
    def __init__(self, db):
        self.db = db

    def recipient(self, email):
        return self.db.scalar(select(Usuario).where(Usuario.correo == email.lower().strip(), Usuario.estado == "ACTIVO"))

    def trusted_devices(self, user_id, ids):
        return self.db.scalars(select(Dispositivo).where(Dispositivo.id_usuario == user_id, Dispositivo.id_dispositivo.in_(ids), Dispositivo.estado == "TRUSTED", Dispositivo.es_confiable.is_(True), Dispositivo.public_key.is_not(None), Dispositivo.huella_clave_publica.is_not(None))).all()

    def owner_of_scope(self, owner_id, vault_id=None, file_id=None):
        statement = select(Boveda).where(Boveda.id_propietario == owner_id, Boveda.estado == "ACTIVA")
        if vault_id:
            statement = statement.where(Boveda.id_boveda == vault_id)
        else:
            statement = statement.join(Archivo, Archivo.id_boveda == Boveda.id_boveda).where(Archivo.id_archivo == file_id, Archivo.estado == "ACTIVO")
        return self.db.scalar(statement)

    def retry(self, grantor_id, key):
        return self.db.scalar(select(AccesoCompartido).where(AccesoCompartido.id_otorgante == grantor_id, AccesoCompartido.idempotency_key == key))

    def get_owned(self, grant_id, grantor_id):
        return self.db.scalar(select(AccesoCompartido).where(AccesoCompartido.id_acceso_compartido == grant_id, AccesoCompartido.id_otorgante == grantor_id))

    def list_owned(self, grantor_id, vault_id=None):
        statement = select(AccesoCompartido).where(AccesoCompartido.id_otorgante == grantor_id)
        if vault_id:
            statement = statement.where(AccesoCompartido.id_boveda == vault_id)
        return self.db.scalars(statement.order_by(AccesoCompartido.fecha_creacion.desc())).all()

    def envelopes(self, grant_id, device_id=None):
        statement = select(SobreAccesoCompartido).where(SobreAccesoCompartido.id_acceso_compartido == grant_id)
        if device_id:
            statement = statement.where(SobreAccesoCompartido.id_dispositivo_destinatario == device_id, SobreAccesoCompartido.estado == "ACTIVO")
        return self.db.scalars(statement).all()

    def active_recipient_grant(self, user_id, device_id, vault_id, file_id=None):
        now = datetime.now(timezone.utc)
        scope = [AccesoCompartido.id_destinatario == user_id, AccesoCompartido.estado == "ACTIVO", AccesoCompartido.inicia_en <= now, (AccesoCompartido.expira_en.is_(None) | (AccesoCompartido.expira_en > now))]
        if file_id:
            scope.append((AccesoCompartido.id_archivo == file_id) | (AccesoCompartido.id_boveda == vault_id))
        else:
            scope.append(AccesoCompartido.id_boveda == vault_id)
        return self.db.scalar(select(AccesoCompartido).join(SobreAccesoCompartido, SobreAccesoCompartido.id_acceso_compartido == AccesoCompartido.id_acceso_compartido).where(*scope, SobreAccesoCompartido.id_dispositivo_destinatario == device_id, SobreAccesoCompartido.estado == "ACTIVO"))

    def revoke_recipient_sessions(self, user_id, reason):
        session_ids = select(Sesion.id_sesion).where(Sesion.id_usuario == user_id, Sesion.revocada.is_(False))
        self.db.execute(update(SesionBoveda).where(SesionBoveda.id_sesion.in_(session_ids), SesionBoveda.revocada.is_(False)).values(revocada=True, motivo_revocacion=reason))
        return self.db.execute(update(Sesion).where(Sesion.id_usuario == user_id, Sesion.revocada.is_(False)).values(revocada=True, motivo_revocacion=reason)).rowcount or 0
