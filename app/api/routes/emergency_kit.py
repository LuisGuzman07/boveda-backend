import uuid

from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.request_security import get_client_ip
from app.schemas.vault import EmergencyKitCreateRequest, EmergencyKitRead, EmergencyKitRecoverRequest
from app.services.emergency_kit_service import EmergencyKitService
from app.services.vault_security import get_vault_context


router = APIRouter(prefix="/vaults", tags=["CU-20: Emergency Kit"])


def _meta(request: Request):
    return get_client_ip(request), request.headers.get("User-Agent", "Desconocido")


@router.post("/{vault_id}/emergency-kit", response_model=EmergencyKitRead)
def create_kit(vault_id: uuid.UUID, body: EmergencyKitCreateRequest, request: Request, context=Depends(get_vault_context), db: Session = Depends(get_db)):
    ip, agent = _meta(request)
    return EmergencyKitService(db).create(*context, vault_id, body, ip, agent)


@router.get("/{vault_id}/emergency-kit", response_model=EmergencyKitRead)
def export_kit(vault_id: uuid.UUID, request: Request, context=Depends(get_vault_context), db: Session = Depends(get_db)):
    ip, agent = _meta(request)
    return EmergencyKitService(db).export(*context, vault_id, ip, agent)


@router.post("/{vault_id}/emergency-kit/recover")
def recover_kit(vault_id: uuid.UUID, body: EmergencyKitRecoverRequest, request: Request, context=Depends(get_vault_context), db: Session = Depends(get_db)):
    ip, agent = _meta(request)
    return EmergencyKitService(db).recover(*context, vault_id, body, ip, agent)


@router.post("/{vault_id}/emergency-kit/revoke")
def revoke_kit(vault_id: uuid.UUID, request: Request, context=Depends(get_vault_context), db: Session = Depends(get_db)):
    ip, agent = _meta(request)
    return EmergencyKitService(db).revoke(*context, vault_id, ip, agent)
