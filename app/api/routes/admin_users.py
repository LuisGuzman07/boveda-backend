import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Query
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.schemas.admin import (
    AdminUserActionResponse,
    AdminUserListResponse,
    PermissionCatalogResponse,
    RoleCatalogResponse,
    UserRoleAssignmentRequest,
    UserStatusUpdateRequest,
)
from app.schemas.auth import PermisoRead, RolRead
from app.services.admin_user_service import AdminUserService, require_permission
from app.services.auth_service import AuthenticatedSession


router = APIRouter(prefix="/admin", tags=["Administración de usuarios"])


@router.get("/users", response_model=AdminUserListResponse)
def list_users(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    query: Optional[str] = Query(None, max_length=255),
    estado: Optional[str] = Query(None, pattern="^(ACTIVO|INACTIVO|BLOQUEADO)$"),
    _context: AuthenticatedSession = Depends(require_permission("users:read")),
    db: Session = Depends(get_db),
):
    return AdminUserService(db).list_users(page, page_size, query, estado)


@router.get("/roles", response_model=RoleCatalogResponse)
def list_roles(
    _context: AuthenticatedSession = Depends(require_permission("users:read")),
    db: Session = Depends(get_db),
):
    return RoleCatalogResponse(roles=[RolRead.model_validate(role) for role in AdminUserService(db).catalog_roles()])


@router.get("/permissions", response_model=PermissionCatalogResponse)
def list_permissions(
    _context: AuthenticatedSession = Depends(require_permission("users:read")),
    db: Session = Depends(get_db),
):
    return PermissionCatalogResponse(permisos=[PermisoRead.model_validate(item) for item in AdminUserService(db).catalog_permissions()])


@router.put("/users/{user_id}/status", response_model=AdminUserActionResponse)
def update_user_status(
    user_id: uuid.UUID,
    body: UserStatusUpdateRequest,
    context: AuthenticatedSession = Depends(require_permission("users:update")),
    db: Session = Depends(get_db),
):
    return AdminUserService(db).update_status(context.user, user_id, body.estado, body.motivo)


@router.post("/users/{user_id}/roles", response_model=AdminUserActionResponse)
def assign_user_role(
    user_id: uuid.UUID,
    body: UserRoleAssignmentRequest,
    context: AuthenticatedSession = Depends(require_permission("users:assign_role")),
    db: Session = Depends(get_db),
):
    return AdminUserService(db).assign_role(context.user, user_id, body.id_rol, body.motivo)


@router.delete("/users/{user_id}/roles/{role_id}", response_model=AdminUserActionResponse)
def remove_user_role(
    user_id: uuid.UUID,
    role_id: uuid.UUID,
    motivo: str = Query(..., min_length=3, max_length=255),
    context: AuthenticatedSession = Depends(require_permission("users:assign_role")),
    db: Session = Depends(get_db),
):
    return AdminUserService(db).remove_role(context.user, user_id, role_id, motivo)
