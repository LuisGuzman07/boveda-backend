import logging
import os
import uuid

from sqlalchemy import select

from app.core.database import SessionLocal
from app.core.security import get_password_hash
from app.models.auth import Permiso, Rol, Usuario


logger = logging.getLogger(__name__)


def _demo_accounts_from_environment() -> list[dict[str, str]]:
    if os.getenv("SEED_DEMO_ACCOUNTS") != "1":
        return []
    required = (
        "SEED_ADMIN_NAME",
        "SEED_ADMIN_EMAIL",
        "SEED_ADMIN_PASSWORD",
        "SEED_MEMBER_NAME",
        "SEED_MEMBER_EMAIL",
        "SEED_MEMBER_PASSWORD",
    )
    missing = [name for name in required if not os.getenv(name)]
    if missing:
        raise RuntimeError("SEED_DEMO_ACCOUNTS requires externally supplied account values.")
    return [
        {
            "name": os.environ["SEED_ADMIN_NAME"],
            "email": os.environ["SEED_ADMIN_EMAIL"],
            "password": os.environ["SEED_ADMIN_PASSWORD"],
            "role": "Administrador",
        },
        {
            "name": os.environ["SEED_MEMBER_NAME"],
            "email": os.environ["SEED_MEMBER_EMAIL"],
            "password": os.environ["SEED_MEMBER_PASSWORD"],
            "role": "Miembro",
        },
    ]


def seed_database() -> None:
    """Seeds roles and permissions; demo accounts are opt-in external configuration."""
    db = SessionLocal()
    try:
        permissions_data = [
            ("users:read", "Consultar Usuarios", "Permite ver la lista y detalle de usuarios"),
            ("users:create", "Crear Usuarios", "Permite registrar nuevos usuarios"),
            ("users:update", "Modificar Usuarios", "Permite actualizar datos de usuarios"),
            ("users:delete", "Eliminar Usuarios", "Permite dar de baja o eliminar usuarios"),
            ("users:assign_role", "Asignar Roles", "Permite asignar y revocar roles a usuarios"),
            ("vaults:create", "Crear Bóvedas", "Permite crear nuevas bóvedas de archivos"),
            ("vaults:read", "Consultar Bóvedas", "Permite ver bóvedas asignadas"),
            ("vaults:update", "Modificar Bóvedas", "Permite editar configuraciones de bóvedas"),
            ("vaults:delete", "Eliminar Bóvedas", "Permite eliminar bóvedas"),
            ("files:upload", "Subir Archivos", "Permite cargar y cifrar archivos"),
            ("files:read", "Leer/Descargar Archivos", "Permite consultar y descargar archivos"),
            ("files:delete", "Eliminar Archivos", "Permite eliminar archivos"),
            ("files:share", "Compartir Archivos", "Permite compartir accesos a archivos"),
            ("devices:approve", "Aprobar Dispositivos", "Permite aprobar identidades de dispositivo verificadas"),
            ("audit:read", "Consultar Auditoría", "Permite ver logs y eventos de auditoría"),
            ("audit:export", "Exportar Auditoría", "Permite exportar reportes de seguridad"),
        ]
        permissions = {}
        for code, name, description in permissions_data:
            permission = db.scalars(select(Permiso).where(Permiso.codigo == code)).first()
            if not permission:
                permission = Permiso(
                    id_permiso=uuid.uuid4(),
                    codigo=code,
                    nombre=name,
                    descripcion=description,
                )
                db.add(permission)
                db.flush()
            permissions[code] = permission

        roles_data = [
            ("Administrador", "Acceso completo al sistema", list(permissions.values())),
            (
                "Miembro",
                "Investigador con gestión de bóvedas y archivos propios",
                [
                    permissions["vaults:create"],
                    permissions["vaults:read"],
                    permissions["vaults:update"],
                    permissions["files:upload"],
                    permissions["files:read"],
                    permissions["files:share"],
                ],
            ),
            (
                "Auditor",
                "Acceso de solo lectura a auditoría",
                [permissions["audit:read"], permissions["users:read"]],
            ),
            ("Invitado", "Acceso temporal de lectura", [permissions["files:read"]]),
        ]
        roles = {}
        for name, description, role_permissions in roles_data:
            role = db.scalars(select(Rol).where(Rol.nombre == name)).first()
            if not role:
                role = Rol(
                    id_rol=uuid.uuid4(),
                    nombre=name,
                    descripcion=description,
                    permisos=role_permissions,
                )
                db.add(role)
                db.flush()
            else:
                role.permisos = role_permissions
            roles[name] = role

        for account in _demo_accounts_from_environment():
            user = db.scalars(
                select(Usuario).where(Usuario.correo == account["email"].lower().strip())
            ).first()
            if not user:
                db.add(
                    Usuario(
                        id_usuario=uuid.uuid4(),
                        nombre=account["name"],
                        correo=account["email"].lower().strip(),
                        password_hash=get_password_hash(account["password"]),
                        correo_verificado=True,
                        estado="ACTIVO",
                        intentos_fallidos=0,
                        roles=[roles[account["role"]]],
                    )
                )
        db.commit()
        logger.info("Initial roles and permissions seeded.")
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
