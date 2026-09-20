from typing import List, Optional
import uuid
from fastapi import HTTPException, status
from sqlalchemy.orm import Session
from app.models.auth import Usuario
from app.repositories.auth_repository import AuthRepository
from app.repositories.policy_repository import PolicyRepository
from app.schemas.policy import (
    EffectivePoliciesResponse,
    InactivityLockRequest,
    PolicyBatchUpdateRequest,
    PolicyRead,
    PolicyUpdateRequest,
)


class PolicyService:
    VALIDATION_RULES = {
        "INACTIVITY_TIMEOUT_MINUTES": {
            "type": int,
            "min": 1,
            "max": 120,
            "msg": "El tiempo de inactividad debe estar comprendido entre 1 y 120 minutos.",
        },
        "MAX_FAILED_LOGIN_ATTEMPTS": {
            "type": int,
            "min": 3,
            "max": 10,
            "msg": "Los intentos fallidos máximos deben estar entre 3 y 10 intentos.",
        },
        "LOCKOUT_DURATION_MINUTES": {
            "type": int,
            "min": 5,
            "max": 120,
            "msg": "La duración de bloqueo de cuenta debe ser entre 5 y 120 minutos.",
        },
        "VAULT_SESSION_DURATION_MINUTES": {
            "type": int,
            "min": 5,
            "max": 60,
            "msg": "La duración de la sesión de bóveda debe ser entre 5 y 60 minutos.",
        },
        "AUDIT_RETENTION_DAYS": {
            "type": int,
            "min": 30,
            "max": 365,
            "msg": "La retención de auditoría debe configurarse entre 30 y 365 días.",
        },
        "PASSWORD_MIN_LENGTH": {
            "type": int,
            "min": 8,
            "max": 32,
            "msg": "La longitud mínima de contraseña debe ser entre 8 y 32 caracteres.",
        },
    }

    def __init__(self, db: Session):
        self.db = db
        self.policy_repo = PolicyRepository(db)
        self.auth_repo = AuthRepository(db)

    def _validate_value(self, code: str, value_str: str):
        rule = self.VALIDATION_RULES.get(code.upper())
        if not rule:
            return value_str.strip()

        try:
            if rule["type"] == int:
                val = int(value_str.strip())
                if val < rule["min"] or val > rule["max"]:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail=rule["msg"],
                    )
                return str(val)
        except ValueError:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail=f"El valor de la política '{code}' debe ser un número entero válido.",
            )

        return value_str.strip()

    def list_policies(self) -> List[PolicyRead]:
        policies = self.policy_repo.get_all()
        result = []
        for p in policies:
            result.append(
                PolicyRead(
                    id_politica=p.id_politica,
                    codigo=p.codigo,
                    nombre=p.nombre,
                    valor=p.valor,
                    descripcion=p.descripcion,
                    activa=p.activa,
                    modificada_por=p.modificada_por,
                    modificada_por_nombre=p.modificador.nombre if p.modificador else None,
                    fecha_actualizacion=p.fecha_actualizacion,
                )
            )
        return result

    def update_policy(
        self,
        code: str,
        data: PolicyUpdateRequest,
        admin: Usuario,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> PolicyRead:
        code_upper = code.upper()
        policy = self.policy_repo.get_by_code(code_upper)
        if not policy:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=f"La política de seguridad '{code_upper}' no existe.",
            )

        validated_val = self._validate_value(code_upper, data.valor)
        previous_val = policy.valor

        updated = self.policy_repo.update(
            policy=policy,
            valor=validated_val,
            activa=data.activa,
            admin_id=admin.id_usuario,
        )

        self.auth_repo.create_audit_event(
            accion="MODIFICACION_POLITICA_SEGURIDAD",
            tipo_evento="SEGURIDAD",
            resultado="EXITO",
            user_id=admin.id_usuario,
            ip=client_ip,
            user_agent=user_agent,
            detalles={
                "codigo": code_upper,
                "nombre": updated.nombre,
                "valor_anterior": previous_val,
                "nuevo_valor": validated_val,
                "activa": updated.activa,
            },
        )

        return PolicyRead(
            id_politica=updated.id_politica,
            codigo=updated.codigo,
            nombre=updated.nombre,
            valor=updated.valor,
            descripcion=updated.descripcion,
            activa=updated.activa,
            modificada_por=updated.modificada_por,
            modificada_por_nombre=admin.nombre,
            fecha_actualizacion=updated.fecha_actualizacion,
        )

    def batch_update_policies(
        self,
        batch_data: PolicyBatchUpdateRequest,
        admin: Usuario,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ) -> List[PolicyRead]:
        updated_list = []
        for item in batch_data.politicas:
            updated_item = self.update_policy(
                code=item.codigo,
                data=PolicyUpdateRequest(valor=item.valor, activa=item.activa),
                admin=admin,
                client_ip=client_ip,
                user_agent=user_agent,
            )
            updated_list.append(updated_item)
        return updated_list

    def get_effective_policies(self) -> EffectivePoliciesResponse:
        pdict = self.policy_repo.get_effective_dict()

        def _get_int(key: str, default: int) -> int:
            try:
                return int(pdict.get(key, str(default)))
            except (ValueError, TypeError):
                return default

        return EffectivePoliciesResponse(
            inactivity_timeout_minutes=_get_int("INACTIVITY_TIMEOUT_MINUTES", 15),
            max_failed_login_attempts=_get_int("MAX_FAILED_LOGIN_ATTEMPTS", 5),
            lockout_duration_minutes=_get_int("LOCKOUT_DURATION_MINUTES", 15),
            vault_session_duration_minutes=_get_int("VAULT_SESSION_DURATION_MINUTES", 15),
            audit_retention_days=_get_int("AUDIT_RETENTION_DAYS", 90),
            password_min_length=_get_int("PASSWORD_MIN_LENGTH", 12),
        )

    def record_inactivity_lock(
        self,
        user: Usuario,
        device_id: Optional[uuid.UUID],
        request_data: InactivityLockRequest,
        client_ip: Optional[str] = None,
        user_agent: Optional[str] = None,
    ):
        self.auth_repo.create_audit_event(
            accion="BLOQUEO_INACTIVIDAD",
            tipo_evento="SESION",
            resultado="EXITO",
            user_id=user.id_usuario,
            device_id=device_id,
            ip=client_ip,
            user_agent=user_agent,
            detalles={
                "motivo": request_data.motivo,
                "usuario": user.correo,
            },
        )
        return {"status": "ok", "message": "Evento de bloqueo por inactividad auditado exitosamente."}
