from fastapi import APIRouter, Depends, Request
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.request_security import get_client_ip, require_allowed_web_origin
from app.schemas.policy import (
    PoliticaSeguridadBatchUpdateRequest,
    PoliticaSeguridadEffectiveResponse,
    PoliticaSeguridadListResponse,
    PoliticaSeguridadRead,
    PoliticaSeguridadUpdateRequest,
)
from app.services.auth_service import AuthenticatedSession, get_current_auth_context
from app.services.policy_service import PolicyService


router = APIRouter(prefix="/policies", tags=["CU-17: Políticas de seguridad"])


def _require_web_origin_for_context(request: Request, context: AuthenticatedSession) -> None:
    if context.session.tipo_cliente == "WEB":
        require_allowed_web_origin(request)


@router.get("/effective", response_model=PoliticaSeguridadEffectiveResponse)
def get_effective_policies(
    request: Request,
    context: AuthenticatedSession = Depends(get_current_auth_context),
    db: Session = Depends(get_db),
):
    _require_web_origin_for_context(request, context)
    items, policies = PolicyService(db).effective_policies(context)
    return PoliticaSeguridadEffectiveResponse(items=items, policies=policies)


@router.get("", response_model=PoliticaSeguridadListResponse)
def list_policies(
    request: Request,
    context: AuthenticatedSession = Depends(get_current_auth_context),
    db: Session = Depends(get_db),
):
    _require_web_origin_for_context(request, context)
    return PoliticaSeguridadListResponse(items=PolicyService(db).list_policies(context))


@router.put("/batch", response_model=PoliticaSeguridadListResponse)
def batch_update_policies(
    body: PoliticaSeguridadBatchUpdateRequest,
    request: Request,
    context: AuthenticatedSession = Depends(get_current_auth_context),
    db: Session = Depends(get_db),
):
    _require_web_origin_for_context(request, context)
    items = PolicyService(db).batch_update_policies(
        context,
        body.actualizaciones,
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )
    return PoliticaSeguridadListResponse(items=items)


@router.put("/{codigo}", response_model=PoliticaSeguridadRead)
def update_policy(
    codigo: str,
    body: PoliticaSeguridadUpdateRequest,
    request: Request,
    context: AuthenticatedSession = Depends(get_current_auth_context),
    db: Session = Depends(get_db),
):
    _require_web_origin_for_context(request, context)
    return PolicyService(db).update_policy(
        context,
        codigo,
        body,
        client_ip=get_client_ip(request),
        user_agent=request.headers.get("User-Agent", "Desconocido"),
    )
