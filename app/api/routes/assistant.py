import logging
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, Request
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.orm import Session

from app.core.database import get_db
from app.core.security import decode_token
from app.models.auth import Usuario
from app.repositories.auth_repository import AuthRepository
from app.schemas.assistant import (
    AssistantChatRequest,
    AssistantChatResponse,
    AssistantTopicsResponse,
)
from app.services.assistant_service import AssistantService

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/assistant", tags=["Asistente IA"])

security_scheme_optional = HTTPBearer(auto_error=False)


def get_optional_current_user(
    auth_header: Optional[HTTPAuthorizationCredentials] = Depends(security_scheme_optional),
    db: Session = Depends(get_db),
) -> Optional[Usuario]:
    """Obtiene el usuario autenticado si el token está presente y es válido; retorna None si es anónimo."""
    if not auth_header or not auth_header.credentials:
        return None
    try:
        payload = decode_token(auth_header.credentials)
        if not payload or payload.get("type") != "access":
            return None
        user_id = uuid.UUID(payload["sub"])
        repo = AuthRepository(db)
        user = repo.get_user_by_id(user_id)
        if user and user.estado == "ACTIVO":
            return user
    except Exception:
        return None
    return None


def get_client_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


@router.get("/topics", response_model=AssistantTopicsResponse)
def get_assistant_topics(db: Session = Depends(get_db)):
    """Retorna los temas de ayuda y preguntas frecuentes estructuradas."""
    return AssistantService(db).get_topics()


@router.post("/chat", response_model=AssistantChatResponse)
def chat_with_assistant(
    request_data: AssistantChatRequest,
    request: Request,
    user: Optional[Usuario] = Depends(get_optional_current_user),
    db: Session = Depends(get_db),
):
    """
    Interactúa con el Asistente Inteligente de Bóveda.
    Proporciona respuestas explicativas paso a paso, atajos interactivos a vistas y modales,
    y registra auditoría bajo estricto Conocimiento Cero.
    """
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")

    service = AssistantService(db)
    return service.process_chat(
        request=request_data,
        user=user,
        client_ip=client_ip,
        user_agent=user_agent,
    )
