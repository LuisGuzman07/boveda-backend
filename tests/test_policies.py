import uuid
from fastapi.testclient import TestClient
from sqlalchemy import select
from app.core.database import SessionLocal
from app.main import app
from app.models.auth import EventoAuditoria, Usuario

client = TestClient(app)


def _get_admin_token():
    res = client.post(
        "/api/v1/auth/login",
        json={
            "correo": "admin@boveda.com",
            "password": "Admin1234!*",
            "dispositivo": {
                "nombre": "Pytest Admin Device",
                "tipo": "DESKTOP",
                "identificador_seguro": f"admin-dev-{uuid.uuid4().hex[:8]}",
            },
        },
    )
    assert res.status_code == 200
    return res.json()["access_token"]


def _get_regular_user_token():
    correo = f"user_{uuid.uuid4().hex[:8]}@boveda.com"
    pwd = "UserSecret2026!#"
    reg_res = client.post(
        "/api/v1/auth/register",
        json={
            "nombre": "Usuario Regular",
            "correo": correo,
            "password": pwd,
        },
    )
    assert reg_res.status_code == 201

    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "correo": correo,
            "password": pwd,
            "dispositivo": {
                "nombre": "Pytest Regular Device",
                "tipo": "WEB",
                "identificador_seguro": f"reg-dev-{uuid.uuid4().hex[:8]}",
            },
        },
    )
    assert login_res.status_code == 200
    return login_res.json()["access_token"]


def test_get_effective_policies_public():
    res = client.get("/api/v1/policies/effective")
    assert res.status_code == 200
    data = res.json()
    assert "inactivity_timeout_minutes" in data
    assert "max_failed_login_attempts" in data
    assert "lockout_duration_minutes" in data
    assert "vault_session_duration_minutes" in data
    assert "audit_retention_days" in data
    assert "password_min_length" in data
    assert data["inactivity_timeout_minutes"] >= 1


def test_list_policies_as_admin():
    admin_token = _get_admin_token()
    res = client.get(
        "/api/v1/policies",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert res.status_code == 200
    policies = res.json()
    assert isinstance(policies, list)
    assert len(policies) >= 6
    codes = [p["codigo"] for p in policies]
    assert "INACTIVITY_TIMEOUT_MINUTES" in codes
    assert "MAX_FAILED_LOGIN_ATTEMPTS" in codes
    assert "LOCKOUT_DURATION_MINUTES" in codes


def test_list_policies_non_admin_forbidden():
    user_token = _get_regular_user_token()
    res = client.get(
        "/api/v1/policies",
        headers={"Authorization": f"Bearer {user_token}"},
    )
    assert res.status_code == 403
    assert "Se requiere rol de Administrador" in res.json()["detail"]


def test_update_policy_as_admin_and_audit():
    admin_token = _get_admin_token()

    # Update inactivity timeout to 25 minutes
    res = client.put(
        "/api/v1/policies/INACTIVITY_TIMEOUT_MINUTES",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"valor": "25", "activa": True},
    )
    assert res.status_code == 200
    data = res.json()
    assert data["codigo"] == "INACTIVITY_TIMEOUT_MINUTES"
    assert data["valor"] == "25"

    # Verify effective policy updated
    eff_res = client.get("/api/v1/policies/effective")
    assert eff_res.status_code == 200
    assert eff_res.json()["inactivity_timeout_minutes"] == 25

    # Check audit log in DB
    db = SessionLocal()
    try:
        stmt = (
            select(EventoAuditoria)
            .where(EventoAuditoria.accion == "MODIFICACION_POLITICA_SEGURIDAD")
            .order_by(EventoAuditoria.fecha_evento.desc())
        )
        audit = db.scalars(stmt).first()
        assert audit is not None
        assert audit.tipo_evento == "SEGURIDAD"
        assert audit.resultado == "EXITO"
        assert audit.detalles.get("codigo") == "INACTIVITY_TIMEOUT_MINUTES"
        assert audit.detalles.get("nuevo_valor") == "25"
    finally:
        db.close()


def test_update_policy_range_validation():
    admin_token = _get_admin_token()

    # Out of range (0 minutes)
    res = client.put(
        "/api/v1/policies/INACTIVITY_TIMEOUT_MINUTES",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"valor": "0"},
    )
    assert res.status_code == 400
    assert "entre 1 y 120" in res.json()["detail"]

    # Invalid non-integer
    res2 = client.put(
        "/api/v1/policies/INACTIVITY_TIMEOUT_MINUTES",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"valor": "abc"},
    )
    assert res2.status_code == 400
    assert "número entero válido" in res2.json()["detail"]


def test_record_inactivity_lock_event_cu12():
    token = _get_regular_user_token()
    res = client.post(
        "/api/v1/auth/inactivity-lock",
        headers={"Authorization": f"Bearer {token}"},
        json={"motivo": "Bloqueo preventivo por 15 minutos sin interacción"},
    )
    assert res.status_code == 200
    assert res.json()["status"] == "ok"

    # Check audit log in DB
    db = SessionLocal()
    try:
        stmt = (
            select(EventoAuditoria)
            .where(EventoAuditoria.accion == "BLOQUEO_INACTIVIDAD")
            .order_by(EventoAuditoria.fecha_evento.desc())
        )
        audit = db.scalars(stmt).first()
        assert audit is not None
        assert audit.tipo_evento == "SESION"
        assert audit.resultado == "EXITO"
    finally:
        db.close()
