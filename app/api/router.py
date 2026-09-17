from fastapi import APIRouter
from app.api.routes import audit, auth, device, health, mfa, recovery
from app.api.routes import vault

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(mfa.router)
api_router.include_router(recovery.router)
api_router.include_router(audit.router)
api_router.include_router(device.router)
api_router.include_router(vault.router)


