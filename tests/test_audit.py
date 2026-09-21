from fastapi.testclient import TestClient
from app.main import app

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


def test_raw_audit_export_is_retired():
    admin_token = get_user_token("admin@boveda.com")

    response = client.get(
        "/api/v1/audit/export",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert response.status_code == 410
    assert "reportes agregados seguros" in response.json()["detail"]
