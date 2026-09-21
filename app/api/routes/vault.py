import uuid
from fastapi import APIRouter, Depends, Header, Query, Request
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.schemas.file import FileDeleteRequest, FileDeleteResponse, FileDownloadResponse, FileMetadataListResponse, FileUploadRequest
from app.schemas.replica import FileReplicaVerificationResponse
from app.schemas.vault import VaultCreateRequest, VaultSessionRequest
from app.services.auth_service import AuthenticatedSession, get_current_auth_context
from app.services.vault_security import get_vault_context, issue_vault_session
from app.services.vault_service import VaultService
from app.services.file_service import FileService
from app.services.replication_service import ReplicationService
from app.services.replica_verification_service import ReplicaVerificationService
from app.services.minio_service import MinioStorage

router = APIRouter(prefix="/vaults", tags=["CU-06: Bóvedas cifradas"])


@router.post("/session")
def create_vault_session(
    body: VaultSessionRequest,
    request: Request,
    context: AuthenticatedSession = Depends(get_current_auth_context),
    db: Session = Depends(get_db),
):
    return issue_vault_session(db, context, body, request)


@router.post("", status_code=201)
def create_vault(body: VaultCreateRequest, request: Request, idempotency_key: str = Header(min_length=16, max_length=100), context=Depends(get_vault_context), db: Session = Depends(get_db)):
    return VaultService(db).create(*context, body, idempotency_key, request.client.host if request.client else None)


@router.get("")
def list_vaults(context=Depends(get_vault_context), db: Session = Depends(get_db)):
    return {"items": VaultService(db).list_vaults(*context)}


@router.get("/{vault_id}")
def get_vault(vault_id: uuid.UUID, context=Depends(get_vault_context), db: Session = Depends(get_db)):
    return VaultService(db).get_vault(*context, vault_id)


@router.post("/{vault_id}/files", status_code=201, tags=["CU-08: Archivos cifrados"])
def upload_file(
    vault_id: uuid.UUID,
    body: FileUploadRequest,
    request: Request,
    idempotency_key: str = Header(min_length=16, max_length=100),
    context=Depends(get_vault_context),
    db: Session = Depends(get_db),
):
    return FileService(db).upload(
        *context,
        vault_id,
        body,
        idempotency_key,
        request.client.host if request.client else None,
    )


@router.get(
    "/{vault_id}/files",
    response_model=FileMetadataListResponse,
    tags=["CU-09: Metadatos de archivos"],
)
def list_files(
    vault_id: uuid.UUID,
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    context=Depends(get_vault_context),
    db: Session = Depends(get_db),
):
    return FileService(db).list_metadata(*context, vault_id, page, page_size)


@router.get(
    "/{vault_id}/files/{version_id}/download",
    response_model=FileDownloadResponse,
    tags=["CU-10: Descarga cifrada"],
)
def download_file(
    vault_id: uuid.UUID,
    version_id: uuid.UUID,
    request: Request,
    context=Depends(get_vault_context),
    db: Session = Depends(get_db),
):
    return FileService(db).download(
        *context,
        vault_id,
        version_id,
        request.client.host if request.client else None,
    )


@router.delete(
    "/{vault_id}/files/{file_id}",
    response_model=FileDeleteResponse,
    tags=["CU-11: Eliminación lógica de archivos"],
)
def delete_file(
    vault_id: uuid.UUID,
    file_id: uuid.UUID,
    body: FileDeleteRequest,
    request: Request,
    idempotency_key: str = Header(min_length=16, max_length=100),
    context=Depends(get_vault_context),
    db: Session = Depends(get_db),
):
    return FileService(db).delete(
        *context, vault_id, file_id, body, idempotency_key, request.client.host if request.client else None
    )


@router.post(
    "/{vault_id}/files/{version_id}/replicate",
    status_code=200,
    tags=["CU-13: Réplica cifrada"],
)
def replicate_file(
    vault_id: uuid.UUID,
    version_id: uuid.UUID,
    request: Request,
    context=Depends(get_vault_context),
    db: Session = Depends(get_db),
):
    return ReplicationService(db).replicate(
        *context,
        vault_id,
        version_id,
        request.client.host if request.client else None,
    )


@router.post(
    "/{vault_id}/files/{version_id}/verify-replicas",
    response_model=FileReplicaVerificationResponse,
    tags=["CU-15: Consistencia de réplicas"],
)
def verify_file_replicas(
    vault_id: uuid.UUID,
    version_id: uuid.UUID,
    request: Request,
    context=Depends(get_vault_context),
    db: Session = Depends(get_db),
):
    storages = {"MINIO": MinioStorage()}
    from app.core.config import settings
    if settings.S3_ENABLED:
        from app.services.s3_service import S3Storage
        storages["S3"] = S3Storage()
    return ReplicaVerificationService(db, storages).verify(
        *context, vault_id, version_id, request.client.host if request.client else None
    )
