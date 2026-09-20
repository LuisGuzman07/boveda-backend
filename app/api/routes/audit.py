from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.auth import Usuario
from app.repositories.auth_repository import AuthRepository
from app.schemas.audit import AuditListResponse, AuditStatsResponse
from app.services.auth_service import get_current_user
from app.services.audit_service import AuditService

router = APIRouter(prefix="/audit", tags=["CU-21: Bitácora de Auditoría"])


def verify_audit_permission(current_user: Usuario = Depends(get_current_user)) -> Usuario:
    """Verifica que el usuario tenga el permiso audit:read o el rol Administrador."""
    user_roles = [r.nombre for r in current_user.roles]
    user_perms = {p.codigo for r in current_user.roles for p in r.permisos}

    if "audit:read" not in user_perms and "Administrador" not in user_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes los privilegios necesarios (audit:read) para consultar la bitácora de auditoría.",
        )
    return current_user


def verify_audit_export_permission(current_user: Usuario = Depends(get_current_user)) -> Usuario:
    """Export is intentionally more privileged than read-only audit access."""
    user_roles = {role.nombre for role in current_user.roles}
    user_perms = {permission.codigo for role in current_user.roles for permission in role.permisos}
    if "audit:export" not in user_perms and "Administrador" not in user_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="No tienes los privilegios necesarios (audit:export) para exportar la bitácora.",
        )
    return current_user


@router.get(
    "/events",
    response_model=AuditListResponse,
    summary="CU-21: Consultar bitácora centralizada de eventos de auditoría",
    description="Retorna el listado paginado de eventos de seguridad con filtros dinámicos por rango de fechas, tipo de evento, resultado y búsqueda textual.",
)
def get_audit_events(
    page: int = Query(1, ge=1, description="Número de página"),
    page_size: int = Query(20, ge=1, le=100, description="Cantidad de registros por página"),
    fecha_inicio: Optional[datetime] = Query(None, description="Fecha/hora inicial de filtro"),
    fecha_fin: Optional[datetime] = Query(None, description="Fecha/hora final de filtro"),
    tipo_evento: Optional[str] = Query(None, description="Categoría (AUTENTICACION, SEGURIDAD_MFA, etc.)"),
    resultado: Optional[str] = Query(None, description="Resultado (EXITO, FALLO, DENEGADO, BLOQUEO)"),
    query: Optional[str] = Query(None, description="Búsqueda por nombre de usuario, correo, IP o acción"),
    current_user: Usuario = Depends(verify_audit_permission),
    db: Session = Depends(get_db),
):
    service = AuditService(db)
    return service.get_events(
        page=page,
        page_size=page_size,
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        tipo_evento=tipo_evento,
        resultado=resultado,
        query=query,
    )


@router.get(
    "/stats",
    response_model=AuditStatsResponse,
    summary="CU-21: Métricas y estadísticas de la bitácora",
    description="Calcula totales, conteos por categoría y acciones más frecuentes para monitoreo de seguridad.",
)
def get_audit_stats(
    current_user: Usuario = Depends(verify_audit_permission),
    db: Session = Depends(get_db),
):
    service = AuditService(db)
    return service.get_stats()


@router.get(
    "/export",
    summary="CU-21 / CU-23: Exportar bitácora a formato CSV",
    description="Descarga el historial de eventos de auditoría filtrado en formato CSV estándar para reportes y conformidad.",
)
def export_audit_csv(
    fecha_inicio: Optional[datetime] = Query(None),
    fecha_fin: Optional[datetime] = Query(None),
    tipo_evento: Optional[str] = Query(None),
    resultado: Optional[str] = Query(None),
    query: Optional[str] = Query(None),
    current_user: Usuario = Depends(verify_audit_export_permission),
    db: Session = Depends(get_db),
):
    service = AuditService(db)
    csv_content = service.export_csv(
        fecha_inicio=fecha_inicio,
        fecha_fin=fecha_fin,
        tipo_evento=tipo_evento,
        resultado=resultado,
        query=query,
    )
    AuthRepository(db).create_audit_event(
        accion="AUDITORIA_EXPORTADA",
        tipo_evento="AUDITORIA",
        resultado="EXITO",
        user_id=current_user.id_usuario,
        detalles={"formato": "CSV"},
    )

    filename = f"bitacora_auditoria_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )
