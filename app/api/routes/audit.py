from datetime import datetime
import uuid
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.auth import Usuario
from app.schemas.audit import AuditListResponse, AuditStatsResponse
from app.schemas.compliance_report import ComplianceReportCreate, ComplianceReportRead
from app.schemas.anomaly import AnomalyFindingRead, AnomalyRunRead, AnomalyStatsRead, ChainVerificationRead
from app.services.auth_service import get_current_user
from app.services.audit_service import AuditService
from app.services.anomaly_service import AnomalyService
from app.services.compliance_report_service import ComplianceReportService

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
    """Exports are a separate privilege; audit:read never grants report download."""
    user_perms = {p.codigo for role in current_user.roles for p in role.permisos}
    if "audit:export" not in user_perms:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="No tienes el permiso audit:export para generar o descargar reportes.")
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


@router.get("/integrity", response_model=ChainVerificationRead, summary="Verificar integridad de la cadena de auditoría")
def verify_audit_chain(current_user: Usuario = Depends(verify_audit_permission), db: Session = Depends(get_db)):
    return AnomalyService(db).verify_chain()


@router.post("/anomalies/runs", response_model=AnomalyRunRead, status_code=status.HTTP_201_CREATED, summary="Ejecutar análisis local de anomalías")
def create_anomaly_run(current_user: Usuario = Depends(verify_audit_permission), db: Session = Depends(get_db)):
    return AnomalyService(db).create_run(current_user.id_usuario)


@router.get("/anomalies/runs", response_model=list[AnomalyRunRead], summary="Listar análisis locales de anomalías")
def list_anomaly_runs(current_user: Usuario = Depends(verify_audit_permission), db: Session = Depends(get_db)):
    return AnomalyService(db).list_runs()


@router.get("/anomalies/latest", response_model=Optional[AnomalyRunRead], summary="Consultar el análisis local más reciente")
def get_latest_anomaly_run(current_user: Usuario = Depends(verify_audit_permission), db: Session = Depends(get_db)):
    return AnomalyService(db).get_latest_run()


@router.get("/anomalies/stats", response_model=AnomalyStatsRead, summary="Consultar métricas y estadísticas del motor de IA")
def get_anomaly_stats(current_user: Usuario = Depends(verify_audit_permission), db: Session = Depends(get_db)):
    return AnomalyService(db).get_stats()


@router.get("/anomalies/runs/{run_id}", response_model=AnomalyRunRead, summary="Consultar análisis local de anomalías")
def get_anomaly_run(run_id: str, current_user: Usuario = Depends(verify_audit_permission), db: Session = Depends(get_db)):
    try:
        return AnomalyService(db).get_run(run_id)
    except LookupError:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Análisis no encontrado.")


@router.post("/reports", response_model=ComplianceReportRead, status_code=status.HTTP_201_CREATED, summary="Generar reporte seguro de cumplimiento")
def generate_compliance_report(
    body: ComplianceReportCreate,
    current_user: Usuario = Depends(verify_audit_export_permission),
    db: Session = Depends(get_db),
):
    try:
        return ComplianceReportService(db).generate(body, current_user.id_usuario)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc))


@router.get("/reports", response_model=list[ComplianceReportRead], summary="Listar reportes seguros de cumplimiento")
def list_compliance_reports(
    current_user: Usuario = Depends(verify_audit_export_permission),
    db: Session = Depends(get_db),
):
    return ComplianceReportService(db).list_reports()


@router.get("/reports/{report_id}/download", summary="Descargar reporte seguro de cumplimiento")
def download_compliance_report(
    report_id: str,
    formato: str = Query("json", pattern="^(json|csv)$"),
    current_user: Usuario = Depends(verify_audit_export_permission),
    db: Session = Depends(get_db),
):
    try:
        service = ComplianceReportService(db)
        report = service.get_report(uuid.UUID(report_id))
    except (LookupError, ValueError):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Reporte no encontrado.")
    content, media_type = service.serialize(report, formato)
    service.audit_download(report, current_user.id_usuario, formato)
    return Response(
        content=content,
        media_type=media_type,
        headers={
            "Content-Disposition": f'attachment; filename="reporte_cumplimiento_{report.id_reporte}.{formato}"',
            "Access-Control-Expose-Headers": "Content-Disposition",
        },
    )


@router.get("/export", status_code=status.HTTP_410_GONE, summary="Exportación cruda retirada")
def retired_raw_audit_export():
    """The former event-level CSV export could expose sensitive audit fields."""
    raise HTTPException(status_code=status.HTTP_410_GONE, detail="La exportación cruda fue retirada. Use /audit/reports para reportes agregados seguros.")
