import uuid
from fastapi import APIRouter, Depends, Header, Request, Response, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.vault import VaultCreateRequest, VaultSessionRequest
from app.services.auth_service import AuthenticatedSession, get_current_auth_context
from app.services.vault_security import (
    get_vault_context,
    issue_vault_session,
    revoke_current_vault_session,
)
from app.services.vault_service import VaultService

router = APIRouter(prefix="/vaults", tags=["CU-06: Bóvedas cifradas"])


@router.post("/session")
def create_vault_session(
    body: VaultSessionRequest,
    request: Request,
    context: AuthenticatedSession = Depends(get_current_auth_context),
    db: Session = Depends(get_db),
):
    return issue_vault_session(db, context, body, request)


@router.get("/session")
async def validate_vault_session(
    context=Depends(get_vault_context),
):
    """Revalidates a signed vault capability without exposing vault contents."""
    return {"status": "active"}


@router.delete("/session", status_code=status.HTTP_204_NO_CONTENT)
async def delete_vault_session(
    request: Request,
    context=Depends(get_vault_context),
    db: Session = Depends(get_db),
):
    revoke_current_vault_session(db, request, *context)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("", status_code=201)
def create_vault(body: VaultCreateRequest, request: Request, idempotency_key: str = Header(min_length=16, max_length=100), context=Depends(get_vault_context), db: Session = Depends(get_db)):
    return VaultService(db).create(*context, body, idempotency_key, request.client.host if request.client else None)


@router.get("")
def list_vaults(context=Depends(get_vault_context), db: Session = Depends(get_db)):
    return {"items": VaultService(db).list_vaults(*context)}


@router.get("/{vault_id}")
def get_vault(vault_id: uuid.UUID, context=Depends(get_vault_context), db: Session = Depends(get_db)):
    return VaultService(db).get_vault(*context, vault_id)
