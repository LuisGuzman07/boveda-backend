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

> ⚠️ **IMPORTANTE:** El archivo `.env` nunca debe subirse al repositorio de Git.

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

## Estructura del Proyecto

```text
boveda-backend/
│
├── app/
│   ├── api/
│   │   ├── routes/
│   │   │   ├── __init__.py
│   │   │   └── health.py
│   │   ├── __init__.py
│   │   └── router.py
│   ├── core/
│   │   ├── __init__.py
│   │   ├── config.py
│   │   └── database.py
│   ├── models/
│   ├── repositories/
│   ├── schemas/
│   ├── services/
│   ├── __init__.py
│   └── main.py
│
├── migrations/
│   ├── versions/
│   ├── env.py
│   └── script.py.mako
├── tests/
├── .env.example
├── .gitignore
├── alembic.ini
├── docker-compose.yml
├── Dockerfile
├── requirements.txt
└── README.md
```
