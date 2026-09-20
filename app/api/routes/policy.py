from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.auth import Usuario
from app.schemas.policy import (
    EffectivePoliciesResponse,
    PolicyBatchUpdateRequest,
    PolicyRead,
    PolicyUpdateRequest,
)
from app.services.auth_service import get_current_user
from app.services.policy_service import PolicyService

router = APIRouter(prefix="/policies", tags=["CU-17: Políticas de Seguridad Globales"])


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


def require_admin(user: Usuario = Depends(get_current_user)) -> Usuario:
    is_admin = any(rol.nombre == "Administrador" for rol in user.roles)
    if not is_admin:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Operación restringida. Se requiere rol de Administrador.",
        )
    return user


@router.get(
    "/effective",
    response_model=EffectivePoliciesResponse,
    summary="Consultar políticas de seguridad vigentes (CU-12/CU-17)",
    description="Retorna los valores efectivos de inactividad, umbrales de bloqueo y parámetros de sesión.",
)
def get_effective_policies(db: Session = Depends(get_db)):
    service = PolicyService(db)
    return service.get_effective_policies()


@router.get(
    "",
    response_model=List[PolicyRead],
    summary="CU-17: Listar todas las políticas de seguridad globales (Admin)",
    description="Retorna el inventario de parámetros de seguridad configurables con auditoría de modificación.",
)
def list_policies(
    admin: Usuario = Depends(require_admin),
    db: Session = Depends(get_db),
):
    service = PolicyService(db)
    return service.list_policies()


@router.put(
    "/{codigo}",
    response_model=PolicyRead,
    summary="CU-17: Modificar una política de seguridad global (Admin)",
    description="Actualiza el valor de un parámetro de seguridad y registra la acción en la bitácora inmutable.",
)
def update_policy(
    codigo: str,
    body: PolicyUpdateRequest,
    request: Request,
    admin: Usuario = Depends(require_admin),
    db: Session = Depends(get_db),
):
    service = PolicyService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.update_policy(
        code=codigo,
        data=body,
        admin=admin,
        client_ip=client_ip,
        user_agent=user_agent,
    )


@router.post(
    "/batch",
    response_model=List[PolicyRead],
    summary="CU-17: Modificación en lote de políticas de seguridad (Admin)",
)
def batch_update_policies(
    body: PolicyBatchUpdateRequest,
    request: Request,
    admin: Usuario = Depends(require_admin),
    db: Session = Depends(get_db),
):
    service = PolicyService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.batch_update_policies(
        batch_data=body,
        admin=admin,
        client_ip=client_ip,
        user_agent=user_agent,
    )
