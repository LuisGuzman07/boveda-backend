from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


AssistantRole = Literal["user", "assistant", "system"]
AssistantCategory = Literal[
    "BOVEDAS",
    "DISPOSITIVOS",
    "RECUPERACION",
    "COMPARTICION",
    "AUDITORIA_IA",
    "SEGURIDAD_MFA",
    "GENERAL",
]


class AssistantMessage(BaseModel):
    role: AssistantRole
    content: str


class AssistantAction(BaseModel):
    label: str = Field(..., description="Texto visible del botón de acción")
    action_type: Literal["navigate", "modal", "link"] = "navigate"
    target: str = Field(..., description="Ruta URL (ej. /vaults) o identificador del modal (ej. trusted_devices)")
    icon: Optional[str] = None
    params: Optional[Dict[str, Any]] = None


class AssistantChatRequest(BaseModel):
    message: str = Field(..., min_length=1, max_length=1500, description="Pregunta o solicitud del usuario")
    history: Optional[List[AssistantMessage]] = Field(default=[], description="Historial de mensajes previos")
    current_path: Optional[str] = Field(default=None, description="Ruta actual en la aplicación web")


class AssistantChatResponse(BaseModel):
    message: str = Field(..., description="Respuesta estructurada en markdown")
    category: AssistantCategory = Field(default="GENERAL", description="Categoría temática de la respuesta")
    suggested_actions: List[AssistantAction] = Field(default=[], description="Botones de acción rápida en la UI")
    suggested_questions: List[str] = Field(default=[], description="Preguntas de seguimiento sugeridas")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AssistantTopic(BaseModel):
    id: str
    title: str
    description: str
    category: AssistantCategory
    sample_queries: List[str]
    icon: Optional[str] = None


class AssistantTopicsResponse(BaseModel):
    topics: List[AssistantTopic]
    categories: List[Dict[str, str]]
