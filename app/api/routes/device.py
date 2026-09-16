from typing import Optional
import uuid
from fastapi import APIRouter, Depends, Header, Request, status
from sqlalchemy.orm import Session
from app.core.database import get_db
from app.models.auth import Usuario
from app.schemas.device import (
    DeviceActionResponse,
    DeviceAuthorizeRequest,
    DeviceListResponse,
    DeviceRegisterRequest,
)
from app.services.auth_service import get_current_user
from app.services.device_service import DeviceService

router = APIRouter(prefix="/devices", tags=["Dispositivos de Confianza (CU-04)"])


def get_client_ip(request: Request) -> str:
    """Extrae la IP real del cliente detrás de proxies o de la conexión directa."""
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "127.0.0.1"


@router.get(
    "",
    response_model=DeviceListResponse,
    summary="CU-04: Listar dispositivos vinculados a la cuenta",
    description="Retorna el inventario de terminales, indicando estado de confianza, sistema operativo y cuál corresponde a la sesión activa.",
)
def list_devices(
    request: Request,
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
    current_user: Usuario = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = DeviceService(db)
    return service.list_devices(
        user=current_user,
        current_device_identifier=x_device_id,
    )


@router.post(
    "/register",
    response_model=DeviceActionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="CU-04: Registrar o sincronizar hardware/navegador local",
    description="Enlaza el hardware local mediante su identificador criptográfico seguro persistente y metadatos de entorno.",
)
def register_device(
    request: Request,
    device_data: DeviceRegisterRequest,
    current_user: Usuario = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = DeviceService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.register_device(
        user=current_user,
        request=device_data,
        client_ip=client_ip,
        user_agent=user_agent,
    )


@router.post(
    "/{device_id}/authorize",
    response_model=DeviceActionResponse,
    summary="CU-04: Autorizar terminal como Dispositivo de Confianza",
    description="Eleva el dispositivo al estado de confianza ('es_confiable = True'), auditando el cambio de nivel de seguridad.",
)
def authorize_device(
    device_id: uuid.UUID,
    request: Request,
    body: Optional[DeviceAuthorizeRequest] = None,
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
    current_user: Usuario = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = DeviceService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    auth_request = body or DeviceAuthorizeRequest(es_confiable=True)
    return service.authorize_device(
        device_id=device_id,
        user=current_user,
        request=auth_request,
        current_device_identifier=x_device_id,
        client_ip=client_ip,
        user_agent=user_agent,
    )


@router.post(
    "/{device_id}/revoke-trust",
    response_model=DeviceActionResponse,
    summary="CU-04: Revocar estado de confianza de un dispositivo",
    description="Revoca la condición de dispositivo de confianza ('es_confiable = False') manteniendo el historial de la terminal.",
)
def revoke_device_trust(
    device_id: uuid.UUID,
    request: Request,
    x_device_id: Optional[str] = Header(None, alias="X-Device-Id"),
    current_user: Usuario = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = DeviceService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    auth_request = DeviceAuthorizeRequest(es_confiable=False)
    return service.authorize_device(
        device_id=device_id,
        user=current_user,
        request=auth_request,
        current_device_identifier=x_device_id,
        client_ip=client_ip,
        user_agent=user_agent,
    )


@router.delete(
    "/{device_id}",
    response_model=DeviceActionResponse,
    summary="CU-04 / CU-05: Desvincular dispositivo y revocar sesiones",
    description="Marca el dispositivo como revocado e invalida de forma inmediata todas las sesiones activas asociadas a él.",
)
def delete_device(
    device_id: uuid.UUID,
    request: Request,
    current_user: Usuario = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    service = DeviceService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    return service.revoke_device(
        device_id=device_id,
        user=current_user,
        client_ip=client_ip,
        user_agent=user_agent,
    )


# ==============================================================================
# CU-05: ENDPOINTS ADMINISTRATIVOS (ACTOR: ADMINISTRADOR)
# ==============================================================================

def verify_admin_role(current_user: Usuario = Depends(get_current_user)) -> Usuario:
    """Verifica que el usuario solicitante posea el rol de Administrador."""
    roles = [r.nombre for r in current_user.roles]
    if "Administrador" not in roles:
        from fastapi import HTTPException
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Acceso restringido: Se requieren privilegios de Administrador para gestionar terminales globales.",
        )
    return current_user


@router.get(
    "/admin/all",
    summary="CU-05: Inventario global de terminales (Admin)",
    description="Permite a los administradores auditar todos los dispositivos registrados en la plataforma con estado y sesiones activas.",
)
def list_all_devices_admin(
    query: Optional[str] = None,
    solo_confiables: Optional[bool] = None,
    estado: Optional[str] = None,
    current_user: Usuario = Depends(verify_admin_role),
    db: Session = Depends(get_db),
):
    service = DeviceService(db)
    return service.list_all_devices_admin(
        query=query,
        solo_confiables=solo_confiables,
        estado=estado,
    )


@router.post(
    "/admin/{device_id}/revoke",
    response_model=DeviceActionResponse,
    summary="CU-05: Revocación administrativa forzada de dispositivo y sesiones",
    description="Invalida de inmediato la terminal de cualquier usuario y cierra todas sus sesiones activas ante incidentes de seguridad.",
)
def revoke_device_admin(
    device_id: uuid.UUID,
    request: Request,
    body: Optional[dict] = None,
    current_user: Usuario = Depends(verify_admin_role),
    db: Session = Depends(get_db),
):
    service = DeviceService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    motivo = (body or {}).get("motivo", "Revocación administrativa preventiva de seguridad")
    return service.revoke_device_admin(
        device_id=device_id,
        admin_user=current_user,
        motivo=motivo,
        client_ip=client_ip,
        user_agent=user_agent,
    )


@router.post(
    "/admin/user/{target_user_id}/revoke-all",
    summary="CU-05: Expulsión total de terminales de una cuenta (Admin)",
    description="Revoca todas las terminales y sesiones activas de un usuario ante compromiso de cuenta o sospecha de ataque.",
)
def revoke_all_user_devices_admin(
    target_user_id: uuid.UUID,
    request: Request,
    body: Optional[dict] = None,
    current_user: Usuario = Depends(verify_admin_role),
    db: Session = Depends(get_db),
):
    service = DeviceService(db)
    client_ip = get_client_ip(request)
    user_agent = request.headers.get("User-Agent", "Desconocido")
    motivo = (body or {}).get("motivo", "Revocación masiva de terminales por compromiso de cuenta")
    return service.revoke_all_user_devices_admin(
        target_user_id=target_user_id,
        admin_user=current_user,
        motivo=motivo,
        client_ip=client_ip,
        user_agent=user_agent,
    )
