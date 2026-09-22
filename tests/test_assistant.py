import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.main import app
from app.models.auth import EventoAuditoria
from tests.helpers.device_identity import login_with_device, new_device_identity

client = TestClient(app)


def _admin_login(identity=None):
    identity = identity or new_device_identity()
    data = login_with_device(client, "admin@boveda.com", "Admin1234!*", identity)
    return identity, data


def test_get_assistant_topics():
    response = client.get("/api/v1/assistant/topics")
    assert response.status_code == 200
    data = response.json()
    assert "topics" in data
    assert "categories" in data
    assert len(data["topics"]) >= 5
    assert any(t["category"] == "BOVEDAS" for t in data["topics"])
    assert any(t["category"] == "DISPOSITIVOS" for t in data["topics"])
    assert any(t["category"] == "AUDITORIA_IA" for t in data["topics"])


def test_assistant_chat_vault_intent():
    response = client.post(
        "/api/v1/assistant/chat",
        json={"message": "¿Cómo creo una bóveda y subo archivos cifrados?"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["category"] == "BOVEDAS"
    assert "AES-256-GCM" in data["message"] or "Bóveda" in data["message"]
    assert any(a["target"] == "/vaults" for a in data["suggested_actions"])
    assert len(data["suggested_questions"]) > 0


def test_assistant_chat_device_intent():
    response = client.post(
        "/api/v1/assistant/chat",
        json={"message": "¿Cómo autorizo mi equipo como dispositivo de confianza para el CU05?"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["category"] == "DISPOSITIVOS"
    assert "Ed25519" in data["message"] or "desafío criptográfico" in data["message"]
    assert any(a["target"] == "trusted_devices" for a in data["suggested_actions"])


def test_assistant_chat_emergency_kit_intent():
    response = client.post(
        "/api/v1/assistant/chat",
        json={"message": "¿Cómo funciona el kit de recuperación de emergencia CU12?"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["category"] == "RECUPERACION"
    assert "Kit de Emergencia" in data["message"]


def test_assistant_chat_sharing_intent():
    response = client.post(
        "/api/v1/assistant/chat",
        json={"message": "¿Cómo comparto el acceso a una bóveda con otro usuario CU17?"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["category"] == "COMPARTICION"
    assert "LECTURA" in data["message"] or "ESCRITURA" in data["message"]


def test_assistant_chat_anomaly_ai_intent():
    response = client.post(
        "/api/v1/assistant/chat",
        json={"message": "¿Cómo funciona la IA local de anomalías y qué significa riesgo crítico?"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["category"] == "AUDITORIA_IA"
    assert "Isolation Forest" in data["message"]
    assert "CRÍTICO" in data["message"]


def test_assistant_chat_audits_user_query():
    identity, login = _admin_login()
    token = login["access_token"]

    response = client.post(
        "/api/v1/assistant/chat",
        headers={"Authorization": f"Bearer {token}"},
        json={"message": "¿Cómo activo el doble factor de autenticación MFA?"},
    )
    assert response.status_code == 200
    data = response.json()
    assert data["category"] == "SEGURIDAD_MFA"

    db = SessionLocal()
    try:
        audit_event = db.scalars(
            select(EventoAuditoria)
            .where(EventoAuditoria.accion == "ASISTENTE_IA_CONSULTA")
            .order_by(EventoAuditoria.fecha_evento.desc())
        ).first()
        assert audit_event is not None
        assert audit_event.detalles.get("categoria") == "SEGURIDAD_MFA"
    finally:
        db.close()
