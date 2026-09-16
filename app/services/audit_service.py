import csv
from datetime import datetime, timezone
import io
import math
from typing import Any, Dict, List, Optional
import uuid
from sqlalchemy.orm import Session
from app.models.auth import EventoAuditoria, Usuario
from app.repositories.audit_repository import AuditRepository
from app.schemas.audit import (
    AuditListResponse,
    AuditStatsResponse,
    DispositivoAuditBrief,
    EventoAuditoriaRead,
    UsuarioAuditBrief,
)


class AuditService:
    def __init__(self, db: Session):
        self.db = db
        self.repo = AuditRepository(db)

    def get_events(
        self,
        page: int = 1,
        page_size: int = 20,
        fecha_inicio: Optional[datetime] = None,
        fecha_fin: Optional[datetime] = None,
        tipo_evento: Optional[str] = None,
        resultado: Optional[str] = None,
        query: Optional[str] = None,
        user_id: Optional[uuid.UUID] = None,
    ) -> AuditListResponse:
        """CU-21: Consulta paginada y filtrada de la bitácora centralizada."""
        items, total = self.repo.get_events(
            page=page,
            page_size=page_size,
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            tipo_evento=tipo_evento,
            resultado=resultado,
            query=query,
            user_id=user_id,
        )

        read_items: List[EventoAuditoriaRead] = []
        for ev in items:
            u_brief = None
            if ev.usuario:
                u_brief = UsuarioAuditBrief(
                    id_usuario=ev.usuario.id_usuario,
                    nombre=ev.usuario.nombre,
                    correo=ev.usuario.correo,
                )
            d_brief = None
            if ev.dispositivo:
                d_brief = DispositivoAuditBrief(
                    id_dispositivo=ev.dispositivo.id_dispositivo,
                    nombre=ev.dispositivo.nombre or "Desconocido",
                    tipo=ev.dispositivo.tipo or "WEB",
                    sistema_operativo=ev.dispositivo.sistema_operativo,
                )

            read_items.append(
                EventoAuditoriaRead(
                    id_evento=ev.id_evento,
                    id_usuario=ev.id_usuario or uuid.UUID(int=0),
                    id_dispositivo=ev.id_dispositivo,
                    accion=ev.accion,
                    tipo_evento=ev.tipo_evento,
                    resultado=ev.resultado,
                    recurso_id=ev.recurso_id,
                    recurso_tipo=ev.recurso_tipo,
                    direccion_ip=ev.direccion_ip,
                    user_agent=ev.user_agent,
                    detalles=ev.detalles,
                    fecha_evento=ev.fecha_evento,
                    usuario=u_brief,
                    dispositivo=d_brief,
                )
            )

        total_pages = math.ceil(total / page_size) if total > 0 else 1
        return AuditListResponse(
            total=total,
            page=page,
            page_size=page_size,
            total_pages=total_pages,
            items=read_items,
        )

    def get_stats(self) -> AuditStatsResponse:
        """Obtiene métricas globales de eventos de seguridad."""
        stats = self.repo.get_stats()
        return AuditStatsResponse(
            total_eventos=stats["total_eventos"],
            eventos_exitosos=stats["eventos_exitosos"],
            eventos_fallidos=stats["eventos_fallidos"],
            eventos_denegados=stats["eventos_denegados"],
            por_tipo=stats["por_tipo"],
            por_accion=stats["por_accion"],
        )

    def export_csv(
        self,
        fecha_inicio: Optional[datetime] = None,
        fecha_fin: Optional[datetime] = None,
        tipo_evento: Optional[str] = None,
        resultado: Optional[str] = None,
        query: Optional[str] = None,
    ) -> str:
        """Exporta los eventos de la bitácora a un string en formato CSV."""
        events = self.repo.get_all_for_export(
            fecha_inicio=fecha_inicio,
            fecha_fin=fecha_fin,
            tipo_evento=tipo_evento,
            resultado=resultado,
            query=query,
        )

        output = io.StringIO()
        writer = csv.writer(output, delimiter=";", quoting=csv.QUOTE_MINIMAL)

        # Encabezados
        writer.writerow([
            "ID Evento",
            "Fecha y Hora (UTC)",
            "Usuario",
            "Correo",
            "Acción",
            "Categoría / Tipo",
            "Resultado",
            "Recurso Tipo",
            "Recurso ID",
            "Dirección IP",
            "Dispositivo",
            "User Agent",
            "Detalles (JSON)",
        ])

        for ev in events:
            user_name = ev.usuario.nombre if ev.usuario else "Sistema / Anónimo"
            user_email = ev.usuario.correo if ev.usuario else "-"
            dev_name = ev.dispositivo.nombre if ev.dispositivo else "-"

            writer.writerow([
                str(ev.id_evento),
                ev.fecha_evento.isoformat(),
                user_name,
                user_email,
                ev.accion,
                ev.tipo_evento,
                ev.resultado,
                ev.recurso_tipo or "-",
                ev.recurso_id or "-",
                ev.direccion_ip or "-",
                dev_name,
                ev.user_agent or "-",
                str(ev.detalles or {}),
            ])

        return output.getvalue()


def log_audit_event(
    db: Session,
    accion: str,
    tipo_evento: str,
    resultado: str,
    user_id: Optional[uuid.UUID] = None,
    device_id: Optional[uuid.UUID] = None,
    recurso_id: Optional[str] = None,
    recurso_tipo: Optional[str] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
    detalles: Optional[dict] = None,
) -> EventoAuditoria:
    """Helper global reutilizable para registrar cualquier evento en la bitácora de auditoría."""
    repo = AuditRepository(db)
    return repo.create_audit_event(
        accion=accion,
        tipo_evento=tipo_evento,
        resultado=resultado,
        user_id=user_id,
        device_id=device_id,
        recurso_id=recurso_id,
        recurso_tipo=recurso_tipo,
        ip=ip,
        user_agent=user_agent,
        detalles=detalles,
    )
