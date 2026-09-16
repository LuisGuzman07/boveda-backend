import sys
import os
import uuid

# Añadir la raíz al path
sys.path.insert(0, os.path.realpath(os.path.join(os.path.dirname(__file__), '../..')))

# pyrefly: ignore [missing-import]
from sqlalchemy import select
from app.core.database import SessionLocal
from app.core.security import get_password_hash
from app.models.auth import Permiso, Rol, Usuario


def seed_database():
    db = SessionLocal()
    try:
        print("🌱 Iniciando siembra de datos iniciales...")

        # 1. Permisos base por módulo
        permisos_data = [
            # Usuarios
            ("users:read", "Consultar Usuarios", "Permite ver la lista y detalle de usuarios"),
            ("users:create", "Crear Usuarios", "Permite registrar nuevos usuarios"),
            ("users:update", "Modificar Usuarios", "Permite actualizar datos de usuarios"),
            ("users:delete", "Eliminar Usuarios", "Permite dar de baja o eliminar usuarios"),
            ("users:assign_role", "Asignar Roles", "Permite asignar y revocar roles a usuarios"),
            # Bóvedas
            ("vaults:create", "Crear Bóvedas", "Permite crear nuevas bóvedas de archivos"),
            ("vaults:read", "Consultar Bóvedas", "Permite ver bóvedas asignadas"),
            ("vaults:update", "Modificar Bóvedas", "Permite editar configuraciones de bóvedas"),
            ("vaults:delete", "Eliminar Bóvedas", "Permite eliminar bóvedas"),
            # Archivos
            ("files:upload", "Subir Archivos", "Permite cargar y cifrar archivos"),
            ("files:read", "Leer/Descargar Archivos", "Permite consultar y descargar archivos"),
            ("files:delete", "Eliminar Archivos", "Permite eliminar archivos"),
            ("files:share", "Compartir Archivos", "Permite compartir accesos a archivos"),
            # Auditoría
            ("audit:read", "Consultar Auditoría", "Permite ver logs y eventos de auditoría"),
            ("audit:export", "Exportar Auditoría", "Permite exportar reportes de seguridad"),
        ]

        permisos_map = {}
        for codigo, nombre, descripcion in permisos_data:
            stmt = select(Permiso).where(Permiso.codigo == codigo)
            perm = db.scalars(stmt).first()
            if not perm:
                perm = Permiso(
                    id_permiso=uuid.uuid4(),
                    codigo=codigo,
                    nombre=nombre,
                    descripcion=descripcion,
                )
                db.add(perm)
                db.flush()
                print(f"  + Permiso creado: {codigo}")
            permisos_map[codigo] = perm

        # 2. Roles base
        roles_data = [
            (
                "Administrador",
                "Acceso completo a todos los módulos y configuraciones del sistema",
                list(permisos_map.values()),
            ),
            (
                "Miembro",
                "Investigador/Usuario estándar con gestión de bóvedas y archivos propios",
                [
                    permisos_map["vaults:create"],
                    permisos_map["vaults:read"],
                    permisos_map["vaults:update"],
                    permisos_map["files:upload"],
                    permisos_map["files:read"],
                    permisos_map["files:share"],
                ],
            ),
            (
                "Auditor",
                "Acceso de solo lectura a eventos de auditoría y reportes de seguridad",
                [
                    permisos_map["audit:read"],
                    permisos_map["audit:export"],
                    permisos_map["users:read"],
                ],
            ),
            (
                "Invitado",
                "Acceso temporal de solo lectura a archivos compartidos",
                [
                    permisos_map["files:read"],
                ],
            ),
        ]

        roles_map = {}
        for nombre, descripcion, lista_permisos in roles_data:
            stmt = select(Rol).where(Rol.nombre == nombre)
            rol = db.scalars(stmt).first()
            if not rol:
                rol = Rol(
                    id_rol=uuid.uuid4(),
                    nombre=nombre,
                    descripcion=descripcion,
                    permisos=lista_permisos,
                )
                db.add(rol)
                db.flush()
                print(f"  + Rol creado: {nombre}")
            roles_map[nombre] = rol

        # 3. Usuario Administrador por Defecto
        admin_email = "admin@boveda.com"
        stmt = select(Usuario).where(Usuario.correo == admin_email)
        admin_user = db.scalars(stmt).first()

        if not admin_user:
            admin_user = Usuario(
                id_usuario=uuid.uuid4(),
                nombre="Administrador del Sistema",
                correo=admin_email,
                password_hash=get_password_hash("Admin1234!*"),
                correo_verificado=True,
                estado="ACTIVO",
                intentos_fallidos=0,
                roles=[roles_map["Administrador"]],
            )
            db.add(admin_user)
            print(f"  + Usuario Administrador creado: {admin_email} (Contraseña: Admin1234!*)")

        # 4. Usuario Miembro de Prueba
        user_email = "investigador@boveda.com"
        stmt = select(Usuario).where(Usuario.correo == user_email)
        test_user = db.scalars(stmt).first()

        if not test_user:
            test_user = Usuario(
                id_usuario=uuid.uuid4(),
                nombre="Dr. Luis Guzmán",
                correo=user_email,
                password_hash=get_password_hash("User1234!*"),
                correo_verificado=True,
                estado="ACTIVO",
                intentos_fallidos=0,
                roles=[roles_map["Miembro"]],
            )
            db.add(test_user)
            print(f"  + Usuario Miembro creado: {user_email} (Contraseña: User1234!*)")

        db.commit()
        print("✅ Siembra de datos completada exitosamente.")

    except Exception as e:
        db.rollback()
        print(f"❌ Error durante el sembrado: {e}")
        raise e
    finally:
        db.close()


if __name__ == "__main__":
    seed_database()
