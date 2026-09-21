import uuid
from typing import List

from pydantic import BaseModel, ConfigDict, Field

from app.schemas.auth import PermisoRead, RolRead, UsuarioRead


class AdminUserListResponse(BaseModel):
    total: int
    page: int
    page_size: int
    total_pages: int
    items: List[UsuarioRead]


class UserStatusUpdateRequest(BaseModel):
    estado: str = Field(pattern="^(ACTIVO|INACTIVO)$")
    motivo: str = Field(min_length=3, max_length=255)


class UserRoleAssignmentRequest(BaseModel):
    id_rol: uuid.UUID
    motivo: str = Field(min_length=3, max_length=255)


class AdminUserActionResponse(BaseModel):
    message: str
    usuario: UsuarioRead


class RoleCatalogResponse(BaseModel):
    roles: List[RolRead]


class PermissionCatalogResponse(BaseModel):
    permisos: List[PermisoRead]
