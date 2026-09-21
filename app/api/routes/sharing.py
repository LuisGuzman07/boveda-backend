import uuid

from fastapi import APIRouter, Depends, Header, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.sharing import ShareCreateRequest, ShareRevokeRequest
from app.services.sharing_service import SharingService
from app.services.vault_security import get_vault_context

router = APIRouter(prefix="/shares", tags=["CU-18/CU-19: Accesos compartidos cifrados"])


@router.post("", status_code=201)
def create_share(body: ShareCreateRequest, request: Request, idempotency_key: str = Header(min_length=16, max_length=100), context=Depends(get_vault_context), db: Session = Depends(get_db)):
    return SharingService(db).create(*context, body, idempotency_key, request.client.host if request.client else None)


@router.get("")
def list_shares(vault_id: uuid.UUID | None = None, context=Depends(get_vault_context), db: Session = Depends(get_db)):
    return {"items": SharingService(db).list_owned(*context, vault_id)}


@router.get("/{grant_id}")
def get_share(grant_id: uuid.UUID, context=Depends(get_vault_context), db: Session = Depends(get_db)):
    return SharingService(db).get_owned(*context, grant_id)


@router.post("/{grant_id}/revoke")
def revoke_share(grant_id: uuid.UUID, body: ShareRevokeRequest, request: Request, context=Depends(get_vault_context), db: Session = Depends(get_db)):
    return SharingService(db).revoke(*context, grant_id, body.motivo, request.client.host if request.client else None)
