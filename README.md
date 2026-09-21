# Bóveda Backend — API REST

Backend del sistema **Bóveda híbrida de archivos cifrados para equipos académicos y pequeñas organizaciones**, construido con **FastAPI**, **PostgreSQL**, **SQLAlchemy 2.x**, **Alembic** y **Docker**.

---

## 1. Requisitos Previos

- [Docker Desktop](https://www.docker.com/products/docker-desktop/) (con Docker Compose v2+)
- [Git](https://git-scm.com/)
- (Opcional) Python 3.12+ para herramientas y linters locales.

---

## 2. Cómo Clonar el Repositorio

```bash
git clone https://github.com/<tu-usuario-o-organizacion>/boveda-backend.git
cd boveda-backend
```

---

## 3. Configuración de Variables de Entorno (`.env`)

Copia la plantilla de variables de entorno:

```bash
cp .env.example .env
```

Contenido por defecto de `.env`:

```env
APP_NAME=Boveda Hibrida API
APP_ENV=development
APP_HOST=0.0.0.0
APP_PORT=8000
CORS_ORIGINS=["http://localhost:5173"]

POSTGRES_DB=boveda_db
POSTGRES_USER=boveda_user
POSTGRES_PASSWORD=boveda_password
POSTGRES_HOST=db
POSTGRES_PORT=5432

DATABASE_URL=postgresql+psycopg://boveda_user:boveda_password@db:5432/boveda_db
```

`JWT_SECRET_KEY` is required and has no default value. Generate a local value of at least 32 characters before starting the API:

```bash
python -c "import secrets; print(secrets.token_urlsafe(48))"
```

Store the result only in the local environment or `.env` file. Do not use the `.env.example` placeholder, log it, or commit it.

S3 replication is optional. Keep `S3_ENABLED=false` for the local MinIO-only stack. When enabled, configure `S3_ENDPOINT`, `S3_REGION`, `S3_BUCKET`, `S3_ACCESS_KEY`, `S3_SECRET_KEY`, and `S3_SECURE` only through the environment. The API copies and verifies ciphertext bytes; it never decrypts or sends plaintext to either provider.

CU-13 replication is triggered with the existing signed vault session:
`POST /api/v1/vaults/{vault_id}/files/{version_id}/replicate`. CU-10 download prefers a verified MinIO replica and falls back to a verified S3 replica after checking the stored SHA-256 and byte size. CU-15 consistency reporting and CU-20 Emergency Kit are intentionally out of scope.

> ⚠️ **IMPORTANTE:** El archivo `.env` nunca debe subirse al repositorio de Git.

El refresh web se entrega mediante cookies `HttpOnly` y requiere una cookie/encabezado
CSRF separado. `SESSION_COOKIE_SECURE=true` debe mantenerse en cualquier entorno
desplegado. Para desarrollo estrictamente local sobre HTTP se puede usar
`SESSION_COOKIE_SECURE=false` solo en el `.env` no versionado. `CORS_ORIGINS` debe
contener orígenes explícitos; no se admite `*` cuando se usan credenciales.
La SPA y la API deben compartir host de cookie (por ejemplo, mediante un proxy
same-origin); CORS no permite que JavaScript lea cookies de un host API distinto.

Las cuentas demo no se crean por defecto. `SEED_DEMO_ACCOUNTS=1` exige valores de
cuentas administradora y miembro entregados externamente. No agregues esos valores a
esta plantilla ni al repositorio.

---

## 4. Cómo Levantar el Proyecto

Para construir las imágenes y levantar los contenedores de FastAPI y PostgreSQL:

```bash
docker compose up --build
```

Si deseas ejecutar en segundo plano (modo detached):

```bash
docker compose up -d --build
```

---

## 5. Cómo Detener los Contenedores

```bash
docker compose down
```

Para detener y eliminar también los volúmenes de datos:

```bash
docker compose down -v
```

---

## 6. Cómo Reconstruir las Imágenes

Si agregas dependencias en `requirements.txt` o modificas el `Dockerfile`:

```bash
docker compose build --no-cache
docker compose up -d
```

---

## 7. Cómo Ejecutar Migraciones (Alembic)

Para aplicar las migraciones pendientes en PostgreSQL:

```bash
docker compose exec backend alembic upgrade head
```

La migración de sesiones vinculadas a dispositivo del Lote 2B realiza un backfill y
revoca sesiones legacy no vinculadas. Ejecuta primero una copia de seguridad y aplícala
en línea contra PostgreSQL; no genera SQL offline válido por diseño.

Para generar una nueva migración automática tras crear o modificar modelos:

```bash
docker compose exec backend alembic revision --autogenerate -m "descripcion_de_migracion"
```

---

## 8. Documentación Interactiva de la API (Swagger & ReDoc)

Con los contenedores en ejecución, accede en tu navegador a:

- **Swagger UI:** [http://localhost:8000/docs](http://localhost:8000/docs)
- **ReDoc:** [http://localhost:8000/redoc](http://localhost:8000/redoc)

---

## 9. Verificación de Salud del Servicio (Health Check)

Puedes comprobar el estado del servicio FastAPI consumiendo:

- **URL:** `http://localhost:8000/api/v1/health`
- **Método:** `GET`
- **Respuesta esperada:**
  ```json
  {
    "status": "ok",
    "service": "boveda-backend"
  }
  ```

---

## 10. Verificación de Conexión a PostgreSQL

Puedes comprobar la conexión activa entre FastAPI y PostgreSQL consumiendo:

- **URL:** `http://localhost:8000/api/v1/health/database`
- **Método:** `GET`
- **Respuesta esperada:**
  ```json
  {
    "status": "ok",
    "database": "connected"
  }
  ```

---

## 11. Estándar de Trazabilidad y Registro en Bitácora (CU-21)

> 🛡️ **REGLA DE ORO PARA CADA CASO DE USO:**
> Toda acción crítica realizada en el sistema (crear/eliminar bóvedas, subir/descargar/borrar archivos, compartir accesos, iniciar sesión, cambiar contraseñas, etc.) **DEBE** registrar un evento inmutable en la tabla `EVENTO_AUDITORIA`.

### Cómo registrar un evento en cualquier servicio o endpoint:

Utiliza la función centralizada `log_audit_event`:

```python
from app.services.audit_service import log_audit_event

# Ejemplo al ejecutar una acción:
log_audit_event(
    db=db,
    user_id=current_user.id_usuario,       # UUID del usuario que ejecuta la acción
    device_id=dispositivo.id_dispositivo,   # UUID del dispositivo (opcional)
    accion="CREAR_BOVEDA",                 # Código único de la acción realizada
    tipo_evento="BOVEDA",                  # Categoría: AUTENTICACION, SEGURIDAD_MFA, BOVEDA, ARCHIVO, ACCESO
    resultado="EXITO",                     # EXITO | FALLO | DENEGADO | BLOQUEO
    recurso_id=str(nueva_boveda.id_boveda),# ID del recurso afectado (opcional)
    recurso_tipo="BOVEDA",                 # Tipo de recurso: BOVEDA, ARCHIVO, USUARIO, etc.
    ip=client_ip,                          # IP del cliente
    user_agent=user_agent,                 # User-Agent del cliente
    detalles={                             # Diccionario JSON con metadatos contextuales
        "nombre_boveda": nueva_boveda.nombre,
        "algoritmo_cifrado": "AES-256-GCM",
    },
)
```

### Campos oficiales del modelo UML (`EVENTO_AUDITORIA`):
- `id_evento`: Identificador único (UUID).
- `id_usuario`: Relación con la tabla `USUARIO`.
- `id_dispositivo`: Relación con la tabla `DISPOSITIVO` (nullable).
- `accion`: `VARCHAR(100)` — Código descriptivo de la acción.
- `tipo_evento`: `VARCHAR(50)` — Categoría para filtrado y reportes.
- `resultado`: `VARCHAR(20)` — Estado final de la operación.
- `recurso_id` / `recurso_tipo`: Identificación del objeto manipulado.
- `direccion_ip` / `user_agent`: Trazabilidad técnica del origen.
- `detalles`: `JSON` — Información adicional no estructurada.
- `fecha_evento`: `TIMESTAMP` — Timestamp UTC generado automáticamente.

