from datetime import datetime, timezone
from typing import List, Optional
import uuid
from sqlalchemy import select
from sqlalchemy.orm import Session
from app.models.auth import Dispositivo, EventoAuditoria, Rol, Sesion, Usuario
from app.schemas.auth import DispositivoInfo


class AuthRepository:
    def __init__(self, db: Session):
        self.db = db

    def get_user_by_email(self, email: str) -> Optional[Usuario]:
        """Obtiene un usuario por su correo electrónico."""
        stmt = select(Usuario).where(Usuario.correo == email.lower().strip())
        return self.db.scalars(stmt).first()

    def get_user_by_id(self, user_id: uuid.UUID) -> Optional[Usuario]:
        """Obtiene un usuario por su ID primario."""
        stmt = select(Usuario).where(Usuario.id_usuario == user_id)
        return self.db.scalars(stmt).first()

    def get_role_by_name(self, name: str) -> Optional[Rol]:
        """Obtiene un rol por su nombre."""
        stmt = select(Rol).where(Rol.nombre == name)
        return self.db.scalars(stmt).first()

    def create_user(
        self,
        nombre: str,
        correo: str,
        password_hash: str,
        roles: Optional[List[Rol]] = None,
    ) -> Usuario:
        """Crea y persiste un nuevo usuario con sus roles asignados."""
        user = Usuario(
            id_usuario=uuid.uuid4(),
            nombre=nombre.strip(),
            correo=correo.lower().strip(),
            password_hash=password_hash,
            correo_verificado=False,
            estado="ACTIVO",
            intentos_fallidos=0,
            roles=roles or [],
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def update_user(self, user: Usuario) -> Usuario:
        """Actualiza y persiste el estado de un usuario."""
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def get_or_create_device(
        self, user_id: uuid.UUID, info: DispositivoInfo
    ) -> Dispositivo:
        """Busca un dispositivo por identificador seguro o crea uno nuevo."""
        stmt = select(Dispositivo).where(
            Dispositivo.id_usuario == user_id,
            Dispositivo.identificador_seguro == info.identificador_seguro,
        )
        device = self.db.scalars(stmt).first()

        if device:
            device.ultimo_acceso = datetime.now(timezone.utc)
            if info.nombre:
                device.nombre = info.nombre
            if info.sistema_operativo:
                device.sistema_operativo = info.sistema_operativo
            if info.public_key:
                device.public_key = info.public_key
            if getattr(info, "confiar_dispositivo", False):
                device.es_confiable = True
            if device.estado == "REVOCADO":
                device.estado = "ACTIVO"
        else:
            device = Dispositivo(
                id_usuario=user_id,
                nombre=info.nombre,
                tipo=info.tipo,
                sistema_operativo=info.sistema_operativo,
                identificador_seguro=info.identificador_seguro or str(uuid.uuid4()),
                public_key=getattr(info, "public_key", None),
                es_confiable=bool(getattr(info, "confiar_dispositivo", False)),
                estado="ACTIVO",
            )
            self.db.add(device)

        self.db.commit()
        self.db.refresh(device)
        return device

    def create_session(
        self,
        user_id: uuid.UUID,
        device_id: Optional[uuid.UUID],
        refresh_token_hash: str,
        expires_at: datetime,
    ) -> Sesion:
        """Registra una nueva sesión en la base de datos."""
        session = Sesion(
            id_usuario=user_id,
            id_dispositivo=device_id,
            refresh_token_hash=refresh_token_hash,
            revocada=False,
            fecha_expiracion=expires_at,
        )
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    def get_session_by_token_hash(self, token_hash: str) -> Optional[Sesion]:
        """Busca una sesión activa por el hash del refresh token."""
        stmt = select(Sesion).where(
            Sesion.refresh_token_hash == token_hash,
            Sesion.revocada == False,
        )
        return self.db.scalars(stmt).first()

    def revoke_session(self, session: Sesion, motivo: str = "LOGOUT") -> Sesion:
        """Marca una sesión como revocada."""
        session.revocada = True
        session.motivo_revocacion = motivo
        session.ultima_actividad = datetime.now(timezone.utc)
        self.db.add(session)
        self.db.commit()
        self.db.refresh(session)
        return session

    def create_audit_event(
        self,
        accion: str,
        tipo_evento: str,
        resultado: str,
        user_id: Optional[uuid.UUID] = None,
        device_id: Optional[uuid.UUID] = None,
        ip: Optional[str] = None,
        user_agent: Optional[str] = None,
        detalles: Optional[dict] = None,
    ) -> EventoAuditoria:
        """Crea un registro inmutable en la tabla EVENTO_AUDITORIA."""
        event = EventoAuditoria(
            id_usuario=user_id,
            id_dispositivo=device_id,
            accion=accion,
            tipo_evento=tipo_evento,
            resultado=resultado,
            direccion_ip=ip,
            user_agent=user_agent,
            detalles=detalles,
        )
        self.db.add(event)
        self.db.commit()
        self.db.refresh(event)
        return event
