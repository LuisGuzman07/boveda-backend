"""Safe, aggregate-only compliance report generation and serialization."""

import csv
import io
import json
import uuid
from datetime import datetime, timezone
from typing import Literal

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from app.models.anomaly import AnalisisAnomalia, HallazgoAnomalia
from app.models.auth import EventoAuditoria
from app.models.compliance_report import ReporteCumplimiento
from app.models.vault import ReplicaAlmacenamiento
from app.schemas.compliance_report import ComplianceReportCreate
from app.services.anomaly_service import AnomalyService
from app.services.audit_service import log_audit_event


REPORT_VERSION = "compliance-security-v1"


class ComplianceReportService:
    def __init__(self, db: Session):
        self.db = db

    @staticmethod
    def _utc(value: datetime) -> datetime:
        return value.astimezone(timezone.utc) if value.tzinfo else value.replace(tzinfo=timezone.utc)

    def _event_filters(self, body: ComplianceReportCreate):
        filters = [
            EventoAuditoria.fecha_evento >= self._utc(body.fecha_inicio),
            EventoAuditoria.fecha_evento <= self._utc(body.fecha_fin),
        ]
        if body.tipo_evento:
            filters.append(EventoAuditoria.tipo_evento == body.tipo_evento.strip())
        if body.resultado:
            filters.append(EventoAuditoria.resultado == body.resultado.strip().upper())
        return filters

    def generate(self, body: ComplianceReportCreate, requester_id: uuid.UUID) -> ReporteCumplimiento:
        integrity = AnomalyService(self.db).verify_chain()
        if integrity["status"] != "VALID":
            raise ValueError("The audit chain is invalid; compliance report generation is blocked.")

        filters = self._event_filters(body)
        normalized_filters = {
            "fecha_inicio": self._utc(body.fecha_inicio).isoformat().replace("+00:00", "Z"),
            "fecha_fin": self._utc(body.fecha_fin).isoformat().replace("+00:00", "Z"),
            "tipo_evento": body.tipo_evento.strip() if body.tipo_evento else None,
            "resultado": body.resultado.strip().upper() if body.resultado else None,
            "formato_solicitado": body.formato,
        }
        outcomes = dict(self.db.execute(
            select(EventoAuditoria.resultado, func.count()).where(*filters).group_by(EventoAuditoria.resultado).order_by(EventoAuditoria.resultado)
        ).all())
        event_types = dict(self.db.execute(
            select(EventoAuditoria.tipo_evento, func.count()).where(*filters).group_by(EventoAuditoria.tipo_evento).order_by(EventoAuditoria.tipo_evento)
        ).all())
        total_events = sum(outcomes.values())
        governance_actions = self.db.scalar(select(func.count(EventoAuditoria.id_evento)).where(
            *filters,
            or_(
                EventoAuditoria.tipo_evento.in_(("CONTROL_ACCESO", "ADMINISTRACION_USUARIOS")),
                EventoAuditoria.accion == "MODIFICACION_POLITICA_SEGURIDAD",
            )
        )) or 0
        replicas = dict(self.db.execute(
            select(ReplicaAlmacenamiento.estado, func.count()).group_by(ReplicaAlmacenamiento.estado).order_by(ReplicaAlmacenamiento.estado)
        ).all())
        anomaly_runs = self.db.scalar(select(func.count(AnalisisAnomalia.id_analisis)).where(
            AnalisisAnomalia.fecha_creacion >= self._utc(body.fecha_inicio),
            AnalisisAnomalia.fecha_creacion <= self._utc(body.fecha_fin),
        )) or 0
        anomaly_findings = dict(self.db.execute(
            select(HallazgoAnomalia.etiqueta, func.count())
            .join(AnalisisAnomalia)
            .where(AnalisisAnomalia.fecha_creacion >= self._utc(body.fecha_inicio), AnalisisAnomalia.fecha_creacion <= self._utc(body.fecha_fin))
            .group_by(HallazgoAnomalia.etiqueta).order_by(HallazgoAnomalia.etiqueta)
        ).all())
        latest_run = self.db.scalar(select(AnalisisAnomalia).where(
            AnalisisAnomalia.fecha_creacion >= self._utc(body.fecha_inicio), AnalisisAnomalia.fecha_creacion <= self._utc(body.fecha_fin)
        ).order_by(AnalisisAnomalia.fecha_creacion.desc()))
        summary = {
            "period": {"start": normalized_filters["fecha_inicio"], "end": normalized_filters["fecha_fin"]},
            "event_counts": {"total": total_events, "by_outcome": outcomes, "by_type": event_types},
            "audit_chain_integrity": integrity,
            "rbac_policy_changes": {"event_count": governance_actions},
            "replica_verification": {"by_status": replicas, "total": sum(replicas.values())},
            "anomaly_analysis": {
                "run_count": anomaly_runs,
                "finding_counts": anomaly_findings,
                "latest_run_reference": str(latest_run.id_analisis) if latest_run else None,
                "latest_run_status": latest_run.estado if latest_run else None,
            },
        }
        report = ReporteCumplimiento(
            id_reporte=uuid.uuid4(), id_solicitante=requester_id, version=REPORT_VERSION,
            filtros=normalized_filters, resumen=summary,
        )
        self.db.add(report)
        self.db.commit()
        self.db.refresh(report)
        log_audit_event(
            self.db, "GENERAR_REPORTE_CUMPLIMIENTO", "REPORTE_CUMPLIMIENTO", "EXITO", requester_id,
            recurso_id=str(report.id_reporte), recurso_tipo="REPORTE_CUMPLIMIENTO",
            detalles={"report_id": str(report.id_reporte), "filters": normalized_filters},
        )
        return report

    def list_reports(self) -> list[ReporteCumplimiento]:
        return list(self.db.scalars(select(ReporteCumplimiento).order_by(ReporteCumplimiento.fecha_generacion.desc())).all())

    def get_report(self, report_id: uuid.UUID) -> ReporteCumplimiento:
        report = self.db.get(ReporteCumplimiento, report_id)
        if not report:
            raise LookupError("Compliance report not found")
        return report

    @staticmethod
    def _csv_cell(value: object) -> str:
        text = value if isinstance(value, str) else json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return f"'{text}" if text.startswith(("=", "+", "-", "@", "\t", "\r")) else text

    def serialize(self, report: ReporteCumplimiento, format_: Literal["json", "csv"]) -> tuple[str, str]:
        payload = {
            "report_id": str(report.id_reporte), "version": report.version,
            "generated_at": self._utc(report.fecha_generacion).isoformat().replace("+00:00", "Z"),
            "filters": report.filtros, "summary": report.resumen,
        }
        if format_ == "json":
            return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True), "application/json"
        output = io.StringIO(newline="")
        writer = csv.writer(output, lineterminator="\n")
        writer.writerow(["section", "metric", "value"])
        for section, values in payload.items():
            writer.writerow([self._csv_cell(section), "value", self._csv_cell(values)])
        return output.getvalue(), "text/csv"

    def audit_download(self, report: ReporteCumplimiento, requester_id: uuid.UUID, format_: str) -> None:
        log_audit_event(
            self.db, "DESCARGAR_REPORTE_CUMPLIMIENTO", "REPORTE_CUMPLIMIENTO", "EXITO", requester_id,
            recurso_id=str(report.id_reporte), recurso_tipo="REPORTE_CUMPLIMIENTO",
            detalles={"report_id": str(report.id_reporte), "format": format_, "filters": report.filtros},
        )
