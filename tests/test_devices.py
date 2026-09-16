import uuid
from fastapi.testclient import TestClient
from sqlalchemy import select
from app.core.database import SessionLocal
from app.main import app
from app.models.auth import Dispositivo, EventoAuditoria, Usuario

client = TestClient(app)


def _get_auth_tokens(correo="admin@boveda.com", password="Admin1234!*"):
    """Helper para autenticarse y obtener access_token."""
    res = client.post(
        "/api/v1/auth/login",
        json={
            "correo": correo,
            "password": password,
            "dispositivo": {
                "nombre": "Pytest Device Helper",
                "tipo": "DESKTOP",
                "identificador_seguro": f"pytest-sec-id-{uuid.uuid4().hex[:8]}",
            },
        },
    )
    assert res.status_code == 200
    data = res.json()
    return data["access_token"], data["usuario"]


def test_list_devices_empty_or_authenticated():
    token, user = _get_auth_tokens()
    res = client.get(
        "/api/v1/devices",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert res.status_code == 200
    data = res.json()
    assert "total" in data
    assert "dispositivos" in data
    assert isinstance(data["dispositivos"], list)
    assert data["total"] >= 1


def test_register_device_untrusted_and_then_authorize():
    token, user = _get_auth_tokens()
    secure_id = f"test-browser-{uuid.uuid4().hex[:12]}"

    # 1. Registrar dispositivo sin confianza inicial
    reg_payload = {
        "nombre": "Chrome en Windows 11",
        "tipo": "WEB",
        "sistema_operativo": "Windows 11 Pro",
        "identificador_seguro": secure_id,
        "confiar_dispositivo": False,
    }
    reg_res = client.post(
        "/api/v1/devices/register",
        headers={"Authorization": f"Bearer {token}"},
        json=reg_payload,
    )
    assert reg_res.status_code == 201
    reg_data = reg_res.json()
    assert reg_data["status"] == "ok"
    device_obj = reg_data["dispositivo"]
    device_id = device_obj["id_dispositivo"]
    assert device_obj["es_confiable"] is False
    assert device_obj["identificador_seguro"] == secure_id

    # 2. Listar y verificar que aparece
    list_res = client.get(
        "/api/v1/devices",
        headers={
            "Authorization": f"Bearer {token}",
            "X-Device-Id": secure_id,
        },
    )
    assert list_res.status_code == 200
    list_data = list_res.json()
    matched = [d for d in list_data["dispositivos"] if d["id_dispositivo"] == device_id]
    assert len(matched) == 1
    assert matched[0]["es_dispositivo_actual"] is True

    # 3. Elevar a Dispositivo de Confianza (CU-04)
    auth_res = client.post(
        f"/api/v1/devices/{device_id}/authorize",
        headers={"Authorization": f"Bearer {token}"},
        json={"es_confiable": True, "nombre": "Mi Laptop Personal (Confiable)"},
    )
    assert auth_res.status_code == 200
    auth_data = auth_res.json()
    assert auth_data["dispositivo"]["es_confiable"] is True
    assert auth_data["dispositivo"]["nombre"] == "Mi Laptop Personal (Confiable)"

    # 4. Verificar auditoría en base de datos
    db = SessionLocal()
    try:
        stmt = (
            select(EventoAuditoria)
            .where(
                EventoAuditoria.id_dispositivo == uuid.UUID(device_id),
                EventoAuditoria.accion == "AUTORIZAR_DISPOSITIVO_CONFIANZA",
            )
            .order_by(EventoAuditoria.fecha_evento.desc())
        )
        audit_event = db.scalars(stmt).first()
        assert audit_event is not None
        assert audit_event.resultado == "EXITO"
        assert audit_event.tipo_evento == "DISPOSITIVO"
    finally:
        db.close()

    # 5. Revocar estado de confianza
    revoke_res = client.post(
        f"/api/v1/devices/{device_id}/revoke-trust",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json()["dispositivo"]["es_confiable"] is False


def test_login_with_trust_device_flag():
    secure_id = f"trusted-login-{uuid.uuid4().hex[:12]}"
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "correo": "admin@boveda.com",
            "password": "Admin1234!*",
            "confiar_dispositivo": True,
            "dispositivo": {
                "nombre": "Estación de Trabajo Segura",
                "tipo": "DESKTOP",
                "sistema_operativo": "Windows",
                "identificador_seguro": secure_id,
                "confiar_dispositivo": True,
            },
        },
    )
    assert login_res.status_code == 200

    # Verificar en DB que el dispositivo se guardó con es_confiable = True
    db = SessionLocal()
    try:
        stmt = select(Dispositivo).where(Dispositivo.identificador_seguro == secure_id)
        dev = db.scalars(stmt).first()
        assert dev is not None
        assert dev.es_confiable is True
    finally:
        db.close()


def test_delete_and_revoke_device():
    token, user = _get_auth_tokens()
    secure_id = f"dev-to-delete-{uuid.uuid4().hex[:12]}"

    # Registrar
    reg_res = client.post(
        "/api/v1/devices/register",
        headers={"Authorization": f"Bearer {token}"},
        json={
            "nombre": "Dispositivo Temporal",
            "tipo": "MOVIL",
            "identificador_seguro": secure_id,
        },
    )
    assert reg_res.status_code == 201
    device_id = reg_res.json()["dispositivo"]["id_dispositivo"]

    # Eliminar/Revocar
    del_res = client.delete(
        f"/api/v1/devices/{device_id}",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert del_res.status_code == 200
    assert del_res.json()["dispositivo"]["estado"] == "REVOCADO"


# ==============================================================================
# CU-05: PRUEBAS PARA REVOCACIÓN DE DISPOSITIVOS Y SESIONES ACTIVAS
# ==============================================================================

def test_revoke_device_invalidates_active_sessions():
    """CU-05: Comprueba que al revocar un dispositivo, sus sesiones activas se invalidan de inmediato."""
    from app.models.auth import Sesion
    secure_id = f"dev-sesion-test-{uuid.uuid4().hex[:8]}"

    # Iniciar sesión vinculando este dispositivo
    login_res = client.post(
        "/api/v1/auth/login",
        json={
            "correo": "admin@boveda.com",
            "password": "Admin1234!*",
            "dispositivo": {
                "nombre": "Terminal Sesión Test",
                "tipo": "DESKTOP",
                "identificador_seguro": secure_id,
            },
        },
    )
    assert login_res.status_code == 200
    token = login_res.json()["access_token"]

    # Verificar que el dispositivo existe y tiene sesión activa
    db = SessionLocal()
    try:
        dev = db.scalars(select(Dispositivo).where(Dispositivo.identificador_seguro == secure_id)).first()
        assert dev is not None
        device_id = str(dev.id_dispositivo)

        sesion_activa = db.scalars(
            select(Sesion).where(
                Sesion.id_dispositivo == dev.id_dispositivo,
                Sesion.revocada == False,
            )
        ).first()
        assert sesion_activa is not None

        # CU-05: Revocar el dispositivo mediante DELETE /devices/{id}
        del_res = client.delete(
            f"/api/v1/devices/{device_id}",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert del_res.status_code == 200

        # Comprobar en base de datos que la sesión se marcó como revocada
        db.expire_all()
        sesion_revocada = db.scalars(
            select(Sesion).where(Sesion.id_dispositivo == dev.id_dispositivo)
        ).first()
        assert sesion_revocada is not None
        assert sesion_revocada.revocada is True
        assert "DISPOSITIVO_DESVINCULADO" in sesion_revocada.motivo_revocacion
    finally:
        db.close()


def test_admin_list_and_revoke_member_device():
    """CU-05: El Administrador puede auditar todos los dispositivos y revocar el de otro usuario."""
    # 1. Login como Miembro para crear un dispositivo
    member_email = f"miembro_dev_{uuid.uuid4().hex[:8]}@boveda.com"
    client.post(
        "/api/v1/auth/register",
        json={"nombre": "Miembro Test", "correo": member_email, "password": "PasswordFuerte123!*"},
    )
    member_login = client.post(
        "/api/v1/auth/login",
        json={
            "correo": member_email,
            "password": "PasswordFuerte123!*",
            "dispositivo": {
                "nombre": "Laptop Miembro Vulnerable",
                "tipo": "DESKTOP",
                "identificador_seguro": f"sec-member-{uuid.uuid4().hex[:8]}",
            },
        },
    )
    member_token = member_login.json()["access_token"]

    # 2. Login como Admin
    admin_token, _ = _get_auth_tokens()

    # 3. El Miembro NO puede acceder al endpoint de administración (403)
    forbidden_res = client.get(
        "/api/v1/devices/admin/all",
        headers={"Authorization": f"Bearer {member_token}"},
    )
    assert forbidden_res.status_code == 403

    # 4. El Administrador SI puede listar todos los dispositivos globales
    admin_list_res = client.get(
        "/api/v1/devices/admin/all",
        headers={"Authorization": f"Bearer {admin_token}"},
    )
    assert admin_list_res.status_code == 200
    all_devices = admin_list_res.json()["dispositivos"]
    assert len(all_devices) > 0

    target = next((d for d in all_devices if d["usuario_correo"] == member_email), None)
    assert target is not None
    target_device_id = target["id_dispositivo"]

    # 5. El Administrador revoca forzadamente el dispositivo del Miembro
    revoke_res = client.post(
        f"/api/v1/devices/admin/{target_device_id}/revoke",
        headers={"Authorization": f"Bearer {admin_token}"},
        json={"motivo": "Sospecha de acceso indebido reportado"},
    )
    assert revoke_res.status_code == 200
    assert revoke_res.json()["status"] == "ok"
    assert revoke_res.json()["dispositivo"]["estado"] == "REVOCADO"

    # 6. Verificar evento de auditoría en la base de datos
    db = SessionLocal()
    try:
        audit_event = db.scalars(
            select(EventoAuditoria).where(
                EventoAuditoria.accion == "REVOCACION_DISPOSITIVO_ADMIN",
                EventoAuditoria.id_dispositivo == uuid.UUID(target_device_id),
            )
        ).first()
        assert audit_event is not None
        assert audit_event.resultado == "EXITO"
        assert "Sospecha de acceso indebido" in str(audit_event.detalles)
    finally:
        db.close()
