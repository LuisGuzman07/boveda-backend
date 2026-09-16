from fastapi.testclient import TestClient
from sqlalchemy import select
from app.core.database import SessionLocal
from app.core.security import create_access_token
from app.main import app
from app.models.auth import Usuario

client = TestClient(app)


def get_user_token(email: str) -> str:
    db = SessionLocal()
    try:
        user = db.scalars(select(Usuario).where(Usuario.correo == email)).first()
        if not user:
            raise ValueError(f"Usuario {email} no encontrado en base de datos.")
        role_names = [r.nombre for r in user.roles]
        perm_codes = list({p.codigo for r in user.roles for p in r.permisos})
        return create_access_token(
            subject=str(user.id_usuario),
            roles=role_names,
            permissions=perm_codes,
        )
    finally:
        db.close()


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
