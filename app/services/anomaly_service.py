"""Local-only anomaly detection over an explicit operational audit-field allowlist."""

import hashlib
from typing import Any

from sklearn.ensemble import IsolationForest
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from app.models.anomaly import AnalisisAnomalia, HallazgoAnomalia
from app.models.auth import EventoAuditoria
from app.services.audit_chain import event_hash
from app.services.audit_service import log_audit_event

MODEL_VERSION = "isolation-forest-local-1"
FEATURE_SCHEMA_VERSION = "operational-audit-v1"
RANDOM_STATE = 20260921
MINIMUM_EVENTS = 4
FEATURE_ALLOWLIST = ("accion", "tipo_evento", "resultado", "recurso_tipo", "fecha_evento", "id_usuario", "id_dispositivo")


class AnomalyService:
    def __init__(self, db: Session):
        self.db = db

    def verify_chain(self) -> dict[str, Any]:
        events = list(self.db.scalars(select(EventoAuditoria).order_by(EventoAuditoria.chain_sequence)).all())
        previous_hash = "0" * 64
        previous_sequence = 0
        for checked_events, item in enumerate(events, start=1):
            # PostgreSQL sequences deliberately permit gaps after rolled-back writes.
            if item.chain_sequence <= previous_sequence or item.previous_hash != previous_hash or item.event_hash != event_hash(item):
                return {"status": "INVALID", "checked_events": checked_events, "first_invalid_sequence": item.chain_sequence}
            previous_hash = item.event_hash
            previous_sequence = item.chain_sequence
        return {"status": "VALID", "checked_events": len(events), "first_invalid_sequence": None}

    @staticmethod
    def _token_value(value: object) -> float:
        # A stable bounded representation, not a source identifier or raw text.
        digest = hashlib.sha256(str(value or "").encode("utf-8")).digest()
        return int.from_bytes(digest[:4], "big") / 2**32

    def _features(self, event: EventoAuditoria) -> list[float]:
        occurred = event.fecha_evento
        return [
            self._token_value(event.accion),
            self._token_value(event.tipo_evento),
            self._token_value(event.resultado),
            self._token_value(event.recurso_tipo),
            occurred.hour / 23 if occurred else 0.0,
            float(event.id_usuario is not None),
            float(event.id_dispositivo is not None),
        ]

    def create_run(self, requester_id) -> AnalisisAnomalia:
        integrity = self.verify_chain()
        # Exclude this subsystem's own audit events to avoid a self-generated feedback loop.
        events = list(self.db.scalars(
            select(EventoAuditoria)
            .where(EventoAuditoria.tipo_evento != "ANALISIS_LOCAL")
            .order_by(EventoAuditoria.chain_sequence)
        ).all())
        config = {
            "algorithm": "IsolationForest",
            "contamination": "auto",
            "n_estimators": 100,
            "random_state": RANDOM_STATE,
            "feature_allowlist": list(FEATURE_ALLOWLIST),
            "feature_schema_version": FEATURE_SCHEMA_VERSION,
            "local_only": True,
        }
        run = AnalisisAnomalia(
            id_solicitante=requester_id,
            estado="COMPLETADO",
            model_version=MODEL_VERSION,
            random_state=RANDOM_STATE,
            feature_schema_version=FEATURE_SCHEMA_VERSION,
            configuracion=config,
            secuencia_inicio=events[0].chain_sequence if events else None,
            secuencia_fin=events[-1].chain_sequence if events else None,
            total_eventos=len(events),
            estado_integridad=integrity["status"],
        )
        if integrity["status"] != "VALID":
            run.estado = "RECHAZADO"
            run.motivo = "La cadena de auditoría no superó la verificación; no se analizó contenido."
        elif len(events) < MINIMUM_EVENTS:
            run.estado = "SIN_DATOS"
            run.motivo = f"Se requieren al menos {MINIMUM_EVENTS} eventos para un análisis local."
        else:
            model = IsolationForest(n_estimators=100, contamination="auto", random_state=RANDOM_STATE, n_jobs=1)
            matrix = [self._features(item) for item in events]
            scores = model.fit(matrix).decision_function(matrix)
            for item, score in zip(events, scores):
                label = "ANOMALIA" if score < 0 else "NORMAL"
                run.hallazgos.append(HallazgoAnomalia(
                    id_evento=item.id_evento,
                    secuencia_evento=item.chain_sequence,
                    decision_score=float(score),
                    etiqueta=label,
                    explicacion=(
                        "Puntaje local de IsolationForest sobre campos operativos permitidos; "
                        "no constituye atribución de características ni incluye detalles del evento."
                    ),
                ))
        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)
        log_audit_event(self.db, "EJECUTAR_ANALISIS_ANOMALIAS", "ANALISIS_LOCAL", "EXITO", requester_id,
                        recurso_id=str(run.id_analisis), recurso_tipo="ANALISIS_ANOMALIA",
                        detalles={"estado": run.estado, "eventos": run.total_eventos, "integridad": run.estado_integridad})
        return self.get_run(run.id_analisis)

    def get_run(self, run_id) -> AnalisisAnomalia:
        run = self.db.scalar(select(AnalisisAnomalia).options(selectinload(AnalisisAnomalia.hallazgos)).where(AnalisisAnomalia.id_analisis == run_id))
        if not run:
            raise LookupError("Analysis run not found")
        return run

    def list_runs(self) -> list[AnalisisAnomalia]:
        return list(self.db.scalars(select(AnalisisAnomalia).options(selectinload(AnalisisAnomalia.hallazgos)).order_by(AnalisisAnomalia.fecha_creacion.desc())).all())
