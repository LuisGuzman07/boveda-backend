from fastapi import APIRouter
from app.api.routes import admin_users, assistant, audit, auth, device, emergency_kit, health, mfa, policy, recovery, sharing
from app.api.routes import vault

api_router = APIRouter(prefix="/api/v1")
api_router.include_router(health.router)
api_router.include_router(auth.router)
api_router.include_router(mfa.router)
api_router.include_router(recovery.router)
api_router.include_router(audit.router)
api_router.include_router(device.router)
api_router.include_router(vault.router)
api_router.include_router(emergency_kit.router)
api_router.include_router(policy.router)
api_router.include_router(admin_users.router)
api_router.include_router(sharing.router)
api_router.include_router(assistant.router)



