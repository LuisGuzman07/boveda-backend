from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple
import uuid
from sqlalchemy import desc, func, or_, select
from sqlalchemy.orm import Session
from app.models.auth import Dispositivo, EventoAuditoria, Usuario


class AuditRepository:
    def __init__(self, db: Session):
        self.db = db

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
    ) -> Tuple[List[EventoAuditoria], int]:
        """Obtiene la lista paginada y filtrada de eventos de auditoría y el total general."""
        stmt = select(EventoAuditoria).join(Usuario, EventoAuditoria.id_usuario == Usuario.id_usuario, isouter=True)

        if fecha_inicio:
            stmt = stmt.where(EventoAuditoria.fecha_evento >= fecha_inicio)
        if fecha_fin:
            stmt = stmt.where(EventoAuditoria.fecha_evento <= fecha_fin)
        if tipo_evento:
            stmt = stmt.where(EventoAuditoria.tipo_evento == tipo_evento.strip())
        if resultado:
            stmt = stmt.where(EventoAuditoria.resultado == resultado.strip().upper())
        if user_id:
            stmt = stmt.where(EventoAuditoria.id_usuario == user_id)
        if query:
            q = f"%{query.strip()}%"
            stmt = stmt.where(
                or_(
                    EventoAuditoria.accion.ilike(q),
                    EventoAuditoria.recurso_tipo.ilike(q),
                    EventoAuditoria.direccion_ip.ilike(q),
                    Usuario.nombre.ilike(q),
                    Usuario.correo.ilike(q),
                )
            )

        # Total count
        count_stmt = select(func.count()).select_from(stmt.subquery())
        total = self.db.scalar(count_stmt) or 0

        # Pagination & sorting (most recent first)
        stmt = stmt.order_by(desc(EventoAuditoria.fecha_evento))
        offset = (page - 1) * page_size
        stmt = stmt.offset(offset).limit(page_size)

        items = list(self.db.scalars(stmt).all())
        return items, total

    def get_all_for_export(
        self,
        fecha_inicio: Optional[datetime] = None,
        fecha_fin: Optional[datetime] = None,
        tipo_evento: Optional[str] = None,
        resultado: Optional[str] = None,
        query: Optional[str] = None,
        limit: int = 2000,
    ) -> List[EventoAuditoria]:
        """Obtiene los eventos para exportación (hasta un límite de seguridad)."""
        stmt = select(EventoAuditoria).join(Usuario, EventoAuditoria.id_usuario == Usuario.id_usuario, isouter=True)

        if fecha_inicio:
            stmt = stmt.where(EventoAuditoria.fecha_evento >= fecha_inicio)
        if fecha_fin:
            stmt = stmt.where(EventoAuditoria.fecha_evento <= fecha_fin)
        if tipo_evento:
            stmt = stmt.where(EventoAuditoria.tipo_evento == tipo_evento.strip())
        if resultado:
            stmt = stmt.where(EventoAuditoria.resultado == resultado.strip().upper())
        if query:
            q = f"%{query.strip()}%"
            stmt = stmt.where(
                or_(
                    EventoAuditoria.accion.ilike(q),
                    EventoAuditoria.recurso_tipo.ilike(q),
                    EventoAuditoria.direccion_ip.ilike(q),
                    Usuario.nombre.ilike(q),
                    Usuario.correo.ilike(q),
                )
            )

        stmt = stmt.order_by(desc(EventoAuditoria.fecha_evento)).limit(limit)
        return list(self.db.scalars(stmt).all())

    def get_stats(self) -> Dict[str, Any]:
        """Calcula métricas agregadas de eventos de auditoría."""
        total = self.db.scalar(select(func.count(EventoAuditoria.id_evento))) or 0
        exitosos = self.db.scalar(select(func.count(EventoAuditoria.id_evento)).where(EventoAuditoria.resultado == "EXITO")) or 0
        fallidos = self.db.scalar(select(func.count(EventoAuditoria.id_evento)).where(EventoAuditoria.resultado == "FALLO")) or 0
        denegados = self.db.scalar(select(func.count(EventoAuditoria.id_evento)).where(EventoAuditoria.resultado.in_(["DENEGADO", "BLOQUEO"]))) or 0

        # Por tipo de evento
        stmt_tipo = select(EventoAuditoria.tipo_evento, func.count(EventoAuditoria.id_evento)).group_by(EventoAuditoria.tipo_evento)
        por_tipo = dict(self.db.execute(stmt_tipo).all())

        # Por accion
        stmt_accion = select(EventoAuditoria.accion, func.count(EventoAuditoria.id_evento)).group_by(EventoAuditoria.accion).order_by(desc(func.count(EventoAuditoria.id_evento))).limit(10)
        por_accion = dict(self.db.execute(stmt_accion).all())

        return {
            "total_eventos": total,
            "eventos_exitosos": exitosos,
            "eventos_fallidos": fallidos,
            "eventos_denegados": denegados,
            "por_tipo": por_tipo,
            "por_accion": por_accion,
        }

    def create_audit_event(
        self,
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
        """Crea y persiste un nuevo evento inmutable en la bitácora."""
        evento = EventoAuditoria(
            id_evento=uuid.uuid4(),
            id_usuario=user_id,
            id_dispositivo=device_id,
            accion=accion,
            tipo_evento=tipo_evento,
            resultado=resultado,
            recurso_id=recurso_id,
            recurso_tipo=recurso_tipo,
            direccion_ip=ip,
            user_agent=user_agent,
            detalles=detalles or {},
        )
        self.db.add(evento)
        self.db.commit()
        self.db.refresh(evento)
        return evento
