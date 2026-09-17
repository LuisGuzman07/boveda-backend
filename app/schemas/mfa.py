from datetime import datetime
from typing import List, Optional
from pydantic import BaseModel, Field
from app.schemas.auth import DispositivoInfo


class MfaSetupResponse(BaseModel):
    secret: str
    otpauth_url: str
    qr_code_base64: str
    backup_codes: List[str]


class MfaEnableRequest(BaseModel):
    code: str = Field(..., min_length=6, max_length=6, description="Código de 6 dígitos generado por la app móvil")


class MfaVerifyLoginRequest(BaseModel):
    mfa_token: str
    code: str = Field(..., min_length=6, max_length=12, description="Código de 6 dígitos de la app o código de respaldo")
    dispositivo: Optional[DispositivoInfo] = Field(default_factory=DispositivoInfo)
    confiar_dispositivo: Optional[bool] = None


class MfaDisableRequest(BaseModel):
    password: str = Field(..., description="Contraseña del usuario para confirmar la desactivación")


class MfaStatusResponse(BaseModel):
    enabled: bool
    mfa_enabled: bool = False
    type: Optional[str] = None
    registered_at: Optional[datetime] = None
