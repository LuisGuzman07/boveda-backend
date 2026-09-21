import os
import socket
import uuid

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError, InvalidRequestError

from app.core.database import SessionLocal
from app.main import app
from app.models.auth import EventoAuditoria
from app.repositories.audit_repository import AuditRepository
from app.services.anomaly_service import AnomalyService


client = TestClient(app)


def _token(email="admin@boveda.com"):
    response = client.post("/api/v1/auth/login", json={
        "correo": email,
        "password": "Admin1234!*" if email.startswith("admin") else "User1234!*",
        "dispositivo": {"identificador_seguro": f"hardening-{email}", "tipo": "WEB"},
    })
    assert response.status_code == 200
    return response.json()["access_token"]


def _append_events(count=5):
    db = SessionLocal()
    try:
        repo = AuditRepository(db)
        return [repo.create_audit_event(f"OPERACION_{index}", "OPERACION", "EXITO", detalles={"index": index, "token": "must-not-persist"}) for index in range(count)]
    finally:
        db.close()


def test_chain_is_canonical_secret_safe_and_verifiable():
    events = _append_events()
    db = SessionLocal()
    try:
        loaded = list(db.query(EventoAuditoria).order_by(EventoAuditoria.chain_sequence).all())
        assert [item.chain_sequence for item in loaded] == sorted(item.chain_sequence for item in loaded)
        assert loaded[0].previous_hash == "0" * 64
        assert loaded[1].previous_hash == loaded[0].event_hash
        assert loaded[0].detalles["token"] == "[REDACTED]"
        assert AnomalyService(db).verify_chain()["status"] == "VALID"
    finally:
        db.close()


def test_orm_mutation_and_deletion_are_rejected():
    event = _append_events(1)[0]
    db = SessionLocal()
    try:
        loaded = db.get(EventoAuditoria, event.id_evento)
        loaded.accion = "ALTERADO"
        with pytest.raises(InvalidRequestError):
            db.commit()
        db.rollback()
        db.delete(loaded)
        with pytest.raises(InvalidRequestError):
            db.commit()
    finally:
        db.rollback()
        db.close()


def test_tampering_is_detected_by_chain_verification():
    event = _append_events(1)[0]
    db = SessionLocal()
    try:
        if db.bind.dialect.name == "postgresql":
            pytest.skip("PostgreSQL trigger correctly blocks tampering before verifier can observe it")
        db.execute(text("UPDATE evento_auditoria SET accion = 'ALTERADO'"))
        db.commit()
        assert AnomalyService(db).verify_chain()["status"] == "INVALID"
    finally:
        db.close()


@pytest.mark.skipif(os.getenv("CU06_TEST_POSTGRES") != "1", reason="requires the PostgreSQL append-only trigger")
def test_postgresql_trigger_rejects_direct_sql_update_and_delete():
    event = _append_events(1)[0]
    db = SessionLocal()
    try:
        with pytest.raises(DBAPIError):
            db.execute(text("UPDATE evento_auditoria SET accion = 'ALTERADO' WHERE id_evento = :id"), {"id": event.id_evento})
            db.commit()
        db.rollback()
        with pytest.raises(DBAPIError):
            db.execute(text("DELETE FROM evento_auditoria WHERE id_evento = :id"), {"id": event.id_evento})
            db.commit()
    finally:
        db.rollback()
        db.close()


def test_anomaly_run_is_local_deterministic_and_excludes_details():
    _append_events()
    db = SessionLocal()
    try:
        first = AnomalyService(db).create_run(_admin_id(db))
        second = AnomalyService(db).create_run(_admin_id(db))
        assert first.estado == "COMPLETADO"
        assert first.configuracion["feature_allowlist"] == ["accion", "tipo_evento", "resultado", "recurso_tipo", "fecha_evento", "id_usuario", "id_dispositivo"]
        assert [(f.etiqueta, round(f.decision_score, 8)) for f in first.hallazgos] == [(f.etiqueta, round(f.decision_score, 8)) for f in second.hallazgos]
        assert all("token" not in finding.explicacion.lower() for finding in first.hallazgos)
    finally:
        db.close()


def _admin_id(db):
    return uuid.UUID(str(db.execute(text("SELECT id_usuario FROM usuario WHERE correo = 'admin@boveda.com'" )).scalar_one()))


def test_anomaly_empty_input_and_permission_guards():
    db = SessionLocal()
    try:
        assert AnomalyService(db).create_run(_admin_id(db)).estado == "SIN_DATOS"
    finally:
        db.close()
    admin = _token()
    response = client.post("/api/v1/audit/anomalies/runs", headers={"Authorization": f"Bearer {admin}"})
    assert response.status_code == 201
    assert response.json()["estado"] in {"SIN_DATOS", "COMPLETADO"}
    member = _token("investigador@boveda.com")
    assert client.get("/api/v1/audit/integrity", headers={"Authorization": f"Bearer {member}"}).status_code == 403
    assert client.post("/api/v1/audit/anomalies/runs", headers={"Authorization": f"Bearer {member}"}).status_code == 403


def test_anomaly_analysis_never_opens_a_network_connection(monkeypatch):
    _append_events()
    monkeypatch.setattr(socket, "create_connection", lambda *_args, **_kwargs: (_ for _ in ()).throw(AssertionError("network access is forbidden")))
    db = SessionLocal()
    try:
        assert AnomalyService(db).create_run(_admin_id(db)).estado == "COMPLETADO"
    finally:
        db.close()
