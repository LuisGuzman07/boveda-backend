import uuid
from fastapi import APIRouter, Depends, Header, Request, Response, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.vault import (
    FileUploadCompleteRequest,
    FileUploadIntentRequest,
    FileUploadIntentResponse,
    FileUploadOperationResponse,
    VaultCreateRequest,
    VaultSessionRequest,
)
from app.services.auth_service import AuthenticatedSession, get_current_auth_context
from app.services.vault_security import (
    get_vault_context,
    issue_vault_session,
    revoke_current_vault_session,
)
from app.services.vault_service import VaultService
from app.services.file_upload_service import FileUploadService
from app.services.object_storage import ObjectStorage, get_object_storage

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


@router.post(
    "/{vault_id}/files/upload-intents",
    status_code=status.HTTP_201_CREATED,
    response_model=FileUploadIntentResponse,
)
def create_file_upload_intent(
    vault_id: uuid.UUID,
    body: FileUploadIntentRequest,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key", min_length=16, max_length=100),
    context=Depends(get_vault_context),
    db: Session = Depends(get_db),
    storage: ObjectStorage = Depends(get_object_storage),
):
    return FileUploadService(db, storage).create_intent(
        *context,
        request.state.vault_session,
        vault_id,
        body,
        idempotency_key,
        request.client.host if request.client else None,
        request.headers.get("User-Agent"),
    )


@router.post(
    "/{vault_id}/files/{file_id}/versions/{version_id}/complete",
    response_model=FileUploadOperationResponse,
)
def complete_file_upload(
    vault_id: uuid.UUID,
    file_id: uuid.UUID,
    version_id: uuid.UUID,
    body: FileUploadCompleteRequest,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key", min_length=16, max_length=100),
    context=Depends(get_vault_context),
    db: Session = Depends(get_db),
    storage: ObjectStorage = Depends(get_object_storage),
):
    return FileUploadService(db, storage).complete(
        *context,
        request.state.vault_session,
        vault_id,
        file_id,
        version_id,
        body,
        idempotency_key,
        request.client.host if request.client else None,
        request.headers.get("User-Agent"),
    )


@router.post(
    "/{vault_id}/files/{file_id}/versions/{version_id}/abort",
    response_model=FileUploadOperationResponse,
)
def abort_file_upload(
    vault_id: uuid.UUID,
    file_id: uuid.UUID,
    version_id: uuid.UUID,
    request: Request,
    idempotency_key: str = Header(alias="Idempotency-Key", min_length=16, max_length=100),
    context=Depends(get_vault_context),
    db: Session = Depends(get_db),
    storage: ObjectStorage = Depends(get_object_storage),
):
    return FileUploadService(db, storage).abort(
        *context,
        request.state.vault_session,
        vault_id,
        file_id,
        version_id,
        idempotency_key,
        request.client.host if request.client else None,
        request.headers.get("User-Agent"),
    )


@router.get("/{vault_id}")
def get_vault(
    vault_id: uuid.UUID,
    request: Request,
    context=Depends(get_vault_context),
    db: Session = Depends(get_db),
):
    return VaultService(db).get_vault(
        *context,
        vault_id,
        request.client.host if request.client else None,
        request.headers.get("User-Agent", "Desconocido"),
    )
