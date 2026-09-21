from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient
from sqlalchemy import select, text

from app.core.database import SessionLocal
from app.main import app
from app.models.auth import EventoAuditoria, Permiso, Rol, Usuario
from app.schemas.compliance_report import ComplianceReportCreate
from app.services.anomaly_service import AnomalyService
from app.services.audit_service import log_audit_event
from app.services.compliance_report_service import ComplianceReportService


client = TestClient(app)


def _token(email="admin@boveda.com"):
    response = client.post("/api/v1/auth/login", json={
        "correo": email,
        "password": "Admin1234!*" if email.startswith("admin") else "User1234!*",
        "dispositivo": {"identificador_seguro": f"compliance-{email}", "tipo": "WEB"},
    })
    assert response.status_code == 200
    return response.json()["access_token"]


def _period():
    end = datetime.now(timezone.utc)
    return {"fecha_inicio": (end - timedelta(days=1)).isoformat(), "fecha_fin": end.isoformat(), "formato": "json"}


def _grant_audit_read_only():
    db = SessionLocal()
    try:
        user = db.scalar(select(Usuario).where(Usuario.correo == "investigador@boveda.com"))
        permission = db.scalar(select(Permiso).where(Permiso.codigo == "audit:read"))
        user.roles.append(Rol(nombre="Solo lectura de auditoria", permisos=[permission]))
        db.commit()
    finally:
        db.close()


def test_report_export_requires_dedicated_permission_and_legacy_raw_export_is_gone():
    assert client.post("/api/v1/audit/reports", json=_period()).status_code in {401, 403}
    _grant_audit_read_only()
    read_only = _token("investigador@boveda.com")
    assert client.post("/api/v1/audit/reports", json=_period(), headers={"Authorization": f"Bearer {read_only}"}).status_code == 403
    assert client.get("/api/v1/audit/export", headers={"Authorization": f"Bearer {read_only}"}).status_code == 410


def test_report_contains_only_safe_aggregates_and_audits_generation_and_download():
    db = SessionLocal()
    try:
        log_audit_event(db, "=INJECTION", "OPERACION", "EXITO", detalles={
            "password": "secret", "token": "token-value", "ciphertext": "ciphertext-value", "ip": "10.0.0.1",
        }, ip="10.0.0.1", user_agent="secret-agent")
    finally:
        db.close()
    admin = _token()
    generated = client.post("/api/v1/audit/reports", json=_period(), headers={"Authorization": f"Bearer {admin}"})
    assert generated.status_code == 201
    report = generated.json()
    assert set(report["resumen"]) == {"period", "event_counts", "audit_chain_integrity", "rbac_policy_changes", "replica_verification", "anomaly_analysis"}
    serialized = client.get(f"/api/v1/audit/reports/{report['id_reporte']}/download?formato=json", headers={"Authorization": f"Bearer {admin}"})
    assert serialized.status_code == 200
    for forbidden in ("password", "token-value", "ciphertext", "10.0.0.1", "secret-agent", "detalles", "user_agent"):
        assert forbidden not in serialized.text
    db = SessionLocal()
    try:
        actions = set(db.scalars(select(EventoAuditoria.accion)).all())
        assert "GENERAR_REPORTE_CUMPLIMIENTO" in actions
        assert "DESCARGAR_REPORTE_CUMPLIMIENTO" in actions
    finally:
        db.close()


def test_csv_serialization_is_deterministic_and_prevents_formula_injection():
    db = SessionLocal()
    try:
        service = ComplianceReportService(db)
        assert service._csv_cell("=SUM(1,1)") == "'=SUM(1,1)"
        report = service.generate(ComplianceReportCreate(**_period()), _admin_id(db))
        first, _ = service.serialize(report, "csv")
        second, _ = service.serialize(report, "csv")
        assert first == second
        assert "password" not in first.lower()
    finally:
        db.close()


def test_report_blocks_invalid_chain_and_validates_period_and_anomaly_summary():
    db = SessionLocal()
    try:
        for index in range(4):
            log_audit_event(db, f"OPERACION_{index}", "OPERACION", "EXITO")
        AnomalyService(db).create_run(_admin_id(db))
    finally:
        db.close()
    admin = _token()
    response = client.post("/api/v1/audit/reports", json=_period(), headers={"Authorization": f"Bearer {admin}"})
    assert response.status_code == 201
    assert response.json()["resumen"]["anomaly_analysis"]["run_count"] == 1
    invalid_period = _period()
    invalid_period["fecha_inicio"] = invalid_period["fecha_fin"]
    assert client.post("/api/v1/audit/reports", json=invalid_period, headers={"Authorization": f"Bearer {admin}"}).status_code == 422
    db = SessionLocal()
    try:
        db.execute(text("UPDATE evento_auditoria SET accion = 'ALTERADO'"))
        db.commit()
    finally:
        db.close()
    assert client.post("/api/v1/audit/reports", json=_period(), headers={"Authorization": f"Bearer {admin}"}).status_code == 409


def _admin_id(db):
    return db.scalar(select(Usuario.id_usuario).where(Usuario.correo == "admin@boveda.com"))
