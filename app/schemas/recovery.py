from datetime import datetime
import re
from typing import Optional
from pydantic import BaseModel, ConfigDict, EmailStr, Field, field_validator
from app.schemas.auth import DispositivoInfo


class ForgotPasswordRequest(BaseModel):
    correo: EmailStr = Field(..., description="Correo electrónico de la cuenta a recuperar")


class ForgotPasswordResponse(BaseModel):
    status: str = "ok"
    message: str


class ValidateTokenRequest(BaseModel):
    token: str = Field(..., min_length=10, description="Token received through the recovery email")

class ValidateTokenResponse(BaseModel):
    valid: bool
    message: str


class ResetPasswordRequest(BaseModel):
    token: str = Field(..., min_length=10, description="Token seguro de recuperación")
    password: str = Field(..., min_length=8, max_length=128, description="Nueva contraseña segura")
    dispositivo: Optional[DispositivoInfo] = Field(default_factory=DispositivoInfo)

    @field_validator("password")
    @classmethod
    def validate_password_strength(cls, v: str) -> str:
        if not re.search(r"[A-Z]", v):
            raise ValueError("La contraseña debe contener al menos una letra mayúscula.")
        if not re.search(r"[a-z]", v):
            raise ValueError("La contraseña debe contener al menos una letra minúscula.")
        if not re.search(r"\d", v):
            raise ValueError("La contraseña debe contener al menos un número.")
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError("La contraseña debe contener al menos un carácter especial (!@#$%^&*...).")
        return v


class ResetPasswordResponse(BaseModel):
    status: str = "ok"
    message: str
    sesiones_revocadas: int
    zero_knowledge_notice: str
