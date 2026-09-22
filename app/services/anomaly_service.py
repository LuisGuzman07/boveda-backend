"""Local-only anomaly detection using Isolation Forest over verified audit telemetry."""

import hashlib
from typing import Any, Optional

from sklearn.ensemble import IsolationForest
from sqlalchemy import select
from sqlalchemy.orm import Session, joinedload, selectinload

from app.models.anomaly import AnalisisAnomalia, HallazgoAnomalia
from app.models.auth import EventoAuditoria
from app.services.audit_chain import event_hash
from app.services.audit_service import log_audit_event

MODEL_VERSION = "isolation-forest-local-1"
FEATURE_SCHEMA_VERSION = "operational-audit-v2"
RANDOM_STATE = 20260921
MINIMUM_EVENTS = 4
FEATURE_ALLOWLIST = (
    "accion",
    "tipo_evento",
    "resultado",
    "recurso_tipo",
    "fecha_evento",
    "id_usuario",
    "id_dispositivo",
)


class AnomalyService:
    def __init__(self, db: Session):
        self.db = db

    def verify_chain(self) -> dict[str, Any]:
        events = list(self.db.scalars(select(EventoAuditoria).order_by(EventoAuditoria.chain_sequence)).all())
        previous_hash = "0" * 64
        previous_sequence = 0
        for checked_events, item in enumerate(events, start=1):
            if item.chain_sequence <= previous_sequence or item.previous_hash != previous_hash or item.event_hash != event_hash(item):
                return {"status": "INVALID", "checked_events": checked_events, "first_invalid_sequence": item.chain_sequence}
            previous_hash = item.event_hash
            previous_sequence = item.chain_sequence
        return {"status": "VALID", "checked_events": len(events), "first_invalid_sequence": None}

    @staticmethod
    def _token_value(value: object) -> float:
        digest = hashlib.sha256(str(value or "").encode("utf-8")).digest()
        return int.from_bytes(digest[:4], "big") / 2**32

    def _features(self, event: EventoAuditoria) -> list[float]:
        occurred = event.fecha_evento
        hour = occurred.hour if occurred else 12
        is_weekend = occurred.weekday() >= 5 if occurred else False
        is_night = hour in {0, 1, 2, 3, 4, 5}
        is_failure = event.resultado in {"FALLO", "BLOQUEO", "DENEGADO"}

        return [
            self._token_value(event.accion),
            self._token_value(event.tipo_evento),
            self._token_value(event.resultado),
            self._token_value(event.recurso_tipo),
            hour / 23.0,
            1.0 if is_night else 0.0,
            1.0 if is_weekend else 0.0,
            1.0 if is_failure else 0.0,
            1.0 if event.id_usuario is not None else 0.0,
            1.0 if event.id_dispositivo is not None else 0.0,
        ]

    @staticmethod
    def _generate_explanation(event: EventoAuditoria, score: float) -> str:
        if score >= 0:
            return "Comportamiento normal alineado con el perfil estadístico de la organización."

        reasons = []
        hour = event.fecha_evento.hour if event.fecha_evento else 12
        if 0 <= hour <= 5:
            reasons.append(f"actividad en horario no habitual de madrugada ({hour:02d}:00 hrs)")
        if event.resultado in {"FALLO", "BLOQUEO", "DENEGADO"}:
            reasons.append(f"resultado anómalo ({event.resultado})")
        
        accion_upper = (event.accion or "").upper()
        if "DESCARG" in accion_upper:
            reasons.append("operación de descarga con desviación estadística de frecuencia/volumen")
        elif "ELIMIN" in accion_upper or "BORR" in accion_upper:
            reasons.append("eliminación o descarte de recursos de seguridad")
        elif "REVOC" in accion_upper or "DESASOC" in accion_upper:
            reasons.append("revocación de dispositivo o clave de acceso")
        elif "LOGIN" in accion_upper or "AUTENTIC" in accion_upper:
            reasons.append("intento de autenticación o acceso atípico")
        elif "RECOVERY" in accion_upper or "RECUPER" in accion_upper:
            reasons.append("proceso sensible de recuperación de cuenta")

        severity = "Desviación estadística crítica" if score < -0.10 else ("Desviación estadística alta" if score < -0.05 else "Desviación estadística moderada")
        if reasons:
            return f"{severity} detectada por Isolation Forest local: {'; '.join(reasons)}."
        return f"{severity} (score: {score:.4f}) detectada por el modelo Isolation Forest sobre campos operativos."

    def create_run(self, requester_id) -> AnalisisAnomalia:
        integrity = self.verify_chain()
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
            run.motivo = "La cadena de auditoría no superó la verificación criptográfica; se bloqueó el análisis."
        elif len(events) < MINIMUM_EVENTS:
            run.estado = "SIN_DATOS"
            run.motivo = f"Se requieren al menos {MINIMUM_EVENTS} eventos para inferencia estadística confiable."
        else:
            model = IsolationForest(n_estimators=100, contamination="auto", random_state=RANDOM_STATE, n_jobs=1)
            matrix = [self._features(item) for item in events]
            scores = model.fit(matrix).decision_function(matrix)

            for item, score in zip(events, scores):
                label = "ANOMALIA" if score < 0 else "NORMAL"
                explanation = self._generate_explanation(item, float(score))
                run.hallazgos.append(HallazgoAnomalia(
                    id_evento=item.id_evento,
                    secuencia_evento=item.chain_sequence,
                    decision_score=float(score),
                    etiqueta=label,
                    explicacion=explanation,
                ))

        self.db.add(run)
        self.db.commit()
        self.db.refresh(run)

        # Registro en la bitácora inmutable
        log_audit_event(
            self.db,
            "EJECUTAR_ANALISIS_ANOMALIAS",
            "ANALISIS_LOCAL",
            "EXITO",
            requester_id,
            recurso_id=str(run.id_analisis),
            recurso_tipo="ANALISIS_ANOMALIA",
            detalles={
                "estado": run.estado,
                "eventos_analizados": run.total_eventos,
                "anomalias_detectadas": run.conteo_anomalias,
                "anomalias_criticas": run.conteo_critico,
                "integridad_cadena": run.estado_integridad,
            }
        )

        # Si se detectaron anomalías críticas, emitir alerta de seguridad
        if run.conteo_critico > 0:
            log_audit_event(
                self.db,
                "ALERTA_SEGURIDAD_ANOMALIA_CRITICA",
                "ANALISIS_LOCAL",
                "BLOQUEO",
                requester_id,
                recurso_id=str(run.id_analisis),
                recurso_tipo="ANALISIS_ANOMALIA",
                detalles={
                    "alerta": f"El motor de IA local detectó {run.conteo_critico} patrones anómalos de severidad crítica.",
                    "id_analisis": str(run.id_analisis),
                }
            )

        return self.get_run(run.id_analisis)

    def get_run(self, run_id) -> AnalisisAnomalia:
        run = self.db.scalar(
            select(AnalisisAnomalia)
            .options(
                selectinload(AnalisisAnomalia.hallazgos)
                .joinedload(HallazgoAnomalia.evento)
                .joinedload(EventoAuditoria.usuario)
            )
            .where(AnalisisAnomalia.id_analisis == run_id)
        )
        if not run:
            raise LookupError("Analysis run not found")
        return run

    def list_runs(self) -> list[AnalisisAnomalia]:
        return list(
            self.db.scalars(
                select(AnalisisAnomalia)
                .options(
                    selectinload(AnalisisAnomalia.hallazgos)
                    .joinedload(HallazgoAnomalia.evento)
                    .joinedload(EventoAuditoria.usuario)
                )
                .order_by(AnalisisAnomalia.fecha_creacion.desc())
            ).all()
        )

    def get_latest_run(self) -> Optional[AnalisisAnomalia]:
        return self.db.scalar(
            select(AnalisisAnomalia)
            .options(
                selectinload(AnalisisAnomalia.hallazgos)
                .joinedload(HallazgoAnomalia.evento)
                .joinedload(EventoAuditoria.usuario)
            )
            .order_by(AnalisisAnomalia.fecha_creacion.desc())
            .limit(1)
        )

    def get_stats(self) -> dict[str, Any]:
        runs = self.list_runs()
        integrity = self.verify_chain()
        latest = runs[0] if runs else None

        total_anomalias = sum(r.conteo_anomalias for r in runs)
        anomalias_criticas = sum(r.conteo_critico for r in runs)
        anomalias_altas = sum(r.conteo_alto for r in runs)
        anomalias_medias = sum(r.conteo_medio for r in runs)

        return {
            "total_analisis": len(runs),
            "ultimo_analisis_fecha": latest.fecha_creacion if latest else None,
            "ultimo_analisis_estado": latest.estado if latest else None,
            "total_anomalias_detectadas": total_anomalias,
            "anomalias_criticas": anomalias_criticas,
            "anomalias_altas": anomalias_altas,
            "anomalias_medias": anomalias_medias,
            "cadena_integridad": integrity["status"],
            "eventos_auditados": integrity["checked_events"],
        }
