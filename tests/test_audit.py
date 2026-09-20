from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.main import app
from app.models.auth import EventoAuditoria, Permiso, Rol, Usuario

client = TestClient(app)


def get_user_token(email: str) -> str:
    password = "Admin1234!*" if email == "admin@boveda.com" else "User1234!*"
    response = client.post(
        "/api/v1/auth/login",
        json={
            "correo": email,
            "password": password,
            "dispositivo": {
                "identificador_seguro": f"audit-{email.replace('@', '-').replace('.', '-')}",
                "tipo": "WEB",
            },
        },
    )
    assert response.status_code == 200
    return response.json()["access_token"]


def test_get_audit_events_as_admin():
    admin_token = get_user_token("admin@boveda.com")

    response = client.get(
        "/api/v1/audit/events?page=1&page_size=10",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "total" in data
    assert "items" in data
    assert "page" in data
    assert "total_pages" in data
    assert isinstance(data["items"], list)


def test_get_audit_events_forbidden_for_member():
    member_token = get_user_token("investigador@boveda.com")

    response = client.get(
        "/api/v1/audit/events",
        headers={"Authorization": f"Bearer {member_token}"},
    )
    assert response.status_code == 403
    assert "audit:read" in response.json()["detail"]


def test_get_audit_events_unauthorized():
    response = client.get("/api/v1/audit/events")
    assert response.status_code in [401, 403]


def test_get_audit_stats():
    admin_token = get_user_token("admin@boveda.com")

    response = client.get(
        "/api/v1/audit/stats",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    data = response.json()
    assert "total_eventos" in data
    assert "eventos_exitosos" in data
    assert "por_tipo" in data
    assert "por_accion" in data


def test_export_audit_csv():
    admin_token = get_user_token("admin@boveda.com")

    response = client.get(
        "/api/v1/audit/export",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200
    assert "text/csv" in response.headers["content-type"]
    assert "attachment; filename=" in response.headers["content-disposition"]
    csv_text = response.text
    assert "ID Evento" in csv_text
    assert "Fecha y Hora" in csv_text
    assert "Acción" in csv_text


def test_audit_read_permission_does_not_grant_export():
    db = SessionLocal()
    try:
        user = db.scalars(select(Usuario).where(Usuario.correo == "investigador@boveda.com")).first()
        permission = db.scalars(select(Permiso).where(Permiso.codigo == "audit:read")).first()
        assert user is not None and permission is not None
        read_only_role = Rol(nombre="Auditor solo lectura", permisos=[permission])
        user.roles.append(read_only_role)
        db.add(user)
        db.commit()
    finally:
        db.close()

    token = get_user_token("investigador@boveda.com")
    readable = client.get(
        "/api/v1/audit/events",
        headers={"Authorization": f"Bearer {token}"},
    )
    forbidden_export = client.get(
        "/api/v1/audit/export",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert readable.status_code == 200
    assert forbidden_export.status_code == 403
    assert "audit:export" in forbidden_export.json()["detail"]


def test_audit_export_records_the_actor():
    admin_token = get_user_token("admin@boveda.com")
    response = client.get(
        "/api/v1/audit/export",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 200

    db = SessionLocal()
    try:
        event = db.scalars(
            select(EventoAuditoria).where(EventoAuditoria.accion == "AUDITORIA_EXPORTADA")
        ).first()
        assert event is not None
        assert event.resultado == "EXITO"
        assert event.id_usuario is not None
    finally:
        db.close()
