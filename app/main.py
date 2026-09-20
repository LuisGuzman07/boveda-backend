from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.api.router import api_router
from app.core.config import settings

app = FastAPI(
    title=settings.APP_NAME,
    description="API de Bóveda Híbrida de archivos cifrados para equipos académicos y pequeñas organizaciones",
    version="0.1.0",
    docs_url="/docs",
    redoc_url="/redoc",
)

# Configuración de CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=[
        "Authorization",
        "Content-Type",
        "Idempotency-Key",
        "X-CSRF-Token",
        "X-Device-Id",
        "X-Vault-Signature",
        "X-Vault-Timestamp",
    ],
)

# Registrar rutas de la API
app.include_router(api_router)


@app.get("/", tags=["Root"])
def root():
    return {
        "message": f"Bienvenido a {settings.APP_NAME}",
        "docs": "/docs",
        "health": "/api/v1/health",
    }
