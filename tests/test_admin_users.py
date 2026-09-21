import uuid

from fastapi.testclient import TestClient
from sqlalchemy import select

from app.core.database import SessionLocal
from app.core.security import get_password_hash
from app.main import app
from app.models.auth import EventoAuditoria, Permiso, Rol, Usuario


client = TestClient(app)


def _login(email, password):
    response = client.post("/api/v1/auth/login", json={"correo": email, "password": password})
    assert response.status_code == 200
    return {"Authorization": f"Bearer {response.json()['access_token']}"}, response.json()


def _role_id(name):
    db = SessionLocal()
    try:
        return str(db.scalar(select(Rol).where(Rol.nombre == name)).id_rol)
    finally:
        db.close()


def _member_id():
    db = SessionLocal()
    try:
        return str(db.scalar(select(Usuario).where(Usuario.correo == "investigador@boveda.com")).id_usuario)
    finally:
        db.close()


def test_admin_user_list_filters_and_paginates_and_member_is_denied():
    member_headers, _ = _login("investigador@boveda.com", "User1234!*")
    assert client.get("/api/v1/admin/users", headers=member_headers).status_code == 403

    admin_headers, _ = _login("admin@boveda.com", "Admin1234!*")
    response = client.get("/api/v1/admin/users?page=1&page_size=1&query=investigador", headers=admin_headers)
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 1
    assert body["page_size"] == 1
    assert body["items"][0]["correo"] == "investigador@boveda.com"
    assert client.get("/api/v1/admin/roles", headers=admin_headers).status_code == 200
    assert client.get("/api/v1/admin/permissions", headers=admin_headers).status_code == 200


def test_status_change_invalidates_target_current_session_and_audits_safe_shape():
    admin_headers, _ = _login("admin@boveda.com", "Admin1234!*")
    member_headers, member_login = _login("investigador@boveda.com", "User1234!*")
    response = client.put(
        f"/api/v1/admin/users/{_member_id()}/status",
        headers=admin_headers,
        json={"estado": "INACTIVO", "motivo": "Baja administrativa aprobada"},
    )
    assert response.status_code == 200
    assert client.get("/api/v1/auth/me", headers=member_headers).status_code == 401

    db = SessionLocal()
    try:
        event = db.scalar(select(EventoAuditoria).where(EventoAuditoria.accion == "USUARIO_ESTADO_ACTUALIZADO"))
        assert event is not None
        assert set(event.detalles) == {"actor_user_id", "target_user_id", "before_role_ids", "after_role_ids", "before_status", "after_status", "reason"}
        assert member_login["access_token"] not in str(event.detalles)
        assert "refresh_token" not in str(event.detalles)
    finally:
        db.close()


def test_role_assignment_removal_and_duplicate_protection():
    admin_headers, _ = _login("admin@boveda.com", "Admin1234!*")
    member_headers, _ = _login("investigador@boveda.com", "User1234!*")
    member_id = _member_id()
    auditor_id = _role_id("Auditor")
    assigned = client.post(
        f"/api/v1/admin/users/{member_id}/roles",
        headers=admin_headers,
        json={"id_rol": auditor_id, "motivo": "Cobertura temporal de auditoría"},
    )
    assert assigned.status_code == 200
    assert {role["nombre"] for role in assigned.json()["usuario"]["roles"]} == {"Miembro", "Auditor"}
    assert client.get("/api/v1/auth/me", headers=member_headers).status_code == 401
    duplicate = client.post(
        f"/api/v1/admin/users/{member_id}/roles",
        headers=admin_headers,
        json={"id_rol": auditor_id, "motivo": "No debe duplicarse"},
    )
    assert duplicate.status_code == 409
    member_headers, _ = _login("investigador@boveda.com", "User1234!*")
    removed = client.delete(
        f"/api/v1/admin/users/{member_id}/roles/{auditor_id}?motivo=Fin+de+cobertura",
        headers=admin_headers,
    )
    assert removed.status_code == 200
    assert [role["nombre"] for role in removed.json()["usuario"]["roles"]] == ["Miembro"]
    assert client.get("/api/v1/auth/me", headers=member_headers).status_code == 401
    unknown = client.post(
        f"/api/v1/admin/users/{member_id}/roles",
        headers=admin_headers,
        json={"id_rol": str(uuid.uuid4()), "motivo": "Rol inexistente"},
    )
    assert unknown.status_code == 404


def test_self_lockout_last_administrator_and_privilege_escalation_are_rejected():
    admin_headers, admin_login = _login("admin@boveda.com", "Admin1234!*")
    admin_id = admin_login["usuario"]["id_usuario"]
    self_change = client.put(
        f"/api/v1/admin/users/{admin_id}/status",
        headers=admin_headers,
        json={"estado": "INACTIVO", "motivo": "No permitido"},
    )
    assert self_change.status_code == 403

    db = SessionLocal()
    try:
        assign_permission = db.scalar(select(Permiso).where(Permiso.codigo == "users:assign_role"))
        update_permission = db.scalar(select(Permiso).where(Permiso.codigo == "users:update"))
        limited_role = Rol(nombre="Asignador limitado", permisos=[assign_permission, update_permission])
        actor = Usuario(nombre="Operador", correo="operator@example.com", password_hash=get_password_hash("Operator1234!*"), roles=[limited_role])
        db.add_all([limited_role, actor])
        db.commit()
    finally:
        db.close()

    limited_headers, _ = _login("operator@example.com", "Operator1234!*")
    escalation = client.post(
        f"/api/v1/admin/users/{_member_id()}/roles",
        headers=limited_headers,
        json={"id_rol": _role_id("Administrador"), "motivo": "Intento de escalamiento"},
    )
    assert escalation.status_code == 403
    last_admin = client.put(
        f"/api/v1/admin/users/{admin_id}/status",
        headers=limited_headers,
        json={"estado": "INACTIVO", "motivo": "Intento de dejar sin administrador"},
    )
    assert last_admin.status_code == 409
