import base64
import binascii
import json
import os
from typing import Optional
from uuid import UUID, uuid4

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from sqlalchemy import select, update
from sqlalchemy.engine import Connection

from app.core.config import TOTP_ENCRYPTION_KEY_BYTES, settings
from app.models.mfa import AutenticadorMfa


TOTP_ENCRYPTION_VERSION = 1
_NONCE_BYTES = 12
_AAD_PREFIX = b"boveda-hibrida:totp:v1:"


class TotpSecretEncryptionError(ValueError):
    """Raised without exposing encrypted or decrypted TOTP material."""


class TotpSecretCipher:
    def __init__(self, key: bytes):
        if len(key) != TOTP_ENCRYPTION_KEY_BYTES:
            raise TotpSecretEncryptionError("La clave de cifrado TOTP no es válida.")
        self._cipher = AESGCM(key)

    @classmethod
    def from_settings(cls) -> "TotpSecretCipher":
        encoded_key = settings.TOTP_ENCRYPTION_KEY.get_secret_value()
        try:
            padded_key = encoded_key + "=" * (-len(encoded_key) % 4)
            key = base64.b64decode(
                padded_key.encode("ascii"), altchars=b"-_", validate=True
            )
        except (UnicodeEncodeError, binascii.Error, ValueError) as error:
            raise TotpSecretEncryptionError(
                "La clave de cifrado TOTP no es válida."
            ) from error
        return cls(key)

    @staticmethod
    def _associated_data(authenticator_id: UUID | str) -> bytes:
        return _AAD_PREFIX + str(authenticator_id).encode("ascii")

    @staticmethod
    def _encode(value: bytes) -> str:
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")

    @staticmethod
    def _decode(value: object) -> bytes:
        if not isinstance(value, str):
            raise TotpSecretEncryptionError("El registro TOTP cifrado no es válido.")
        try:
            padded_value = value + "=" * (-len(value) % 4)
            return base64.b64decode(
                padded_value.encode("ascii"), altchars=b"-_", validate=True
            )
        except (UnicodeEncodeError, binascii.Error, ValueError) as error:
            raise TotpSecretEncryptionError(
                "El registro TOTP cifrado no es válido."
            ) from error

    def encrypt(self, secret: str, authenticator_id: UUID | str) -> str:
        if not isinstance(secret, str) or not secret:
            raise TotpSecretEncryptionError("El secreto TOTP no es válido.")

        nonce = os.urandom(_NONCE_BYTES)
        ciphertext = self._cipher.encrypt(
            nonce,
            secret.encode("utf-8"),
            self._associated_data(authenticator_id),
        )
        return json.dumps(
            {
                "ciphertext": self._encode(ciphertext),
                "nonce": self._encode(nonce),
                "version": TOTP_ENCRYPTION_VERSION,
            },
            separators=(",", ":"),
            sort_keys=True,
        )

    def decrypt(self, encrypted_secret: str, authenticator_id: UUID | str) -> str:
        try:
            envelope = json.loads(encrypted_secret)
            if (
                not isinstance(envelope, dict)
                or envelope.get("version") != TOTP_ENCRYPTION_VERSION
            ):
                raise TotpSecretEncryptionError("El registro TOTP cifrado no es compatible.")

            nonce = self._decode(envelope.get("nonce"))
            if len(nonce) != _NONCE_BYTES:
                raise TotpSecretEncryptionError("El registro TOTP cifrado no es válido.")
            plaintext = self._cipher.decrypt(
                nonce,
                self._decode(envelope.get("ciphertext")),
                self._associated_data(authenticator_id),
            )
            return plaintext.decode("utf-8")
        except TotpSecretEncryptionError:
            raise
        except (InvalidTag, UnicodeDecodeError, TypeError, ValueError) as error:
            raise TotpSecretEncryptionError(
                "No se pudo validar el registro TOTP cifrado."
            ) from error


def store_encrypted_totp_secret(
    mfa: AutenticadorMfa,
    secret: str,
    cipher: Optional[TotpSecretCipher] = None,
) -> None:
    if mfa.id_autenticador is None:
        mfa.id_autenticador = uuid4()
    active_cipher = cipher or TotpSecretCipher.from_settings()
    encrypted_secret = active_cipher.encrypt(secret, mfa.id_autenticador)
    if active_cipher.decrypt(encrypted_secret, mfa.id_autenticador) != secret:
        raise TotpSecretEncryptionError("No se pudo verificar el cifrado TOTP.")

    mfa.secreto_cifrado_v2 = encrypted_secret
    mfa.version_criptografica = TOTP_ENCRYPTION_VERSION
    mfa.secreto_cifrado = None


def get_totp_secret(
    mfa: AutenticadorMfa,
    cipher: Optional[TotpSecretCipher] = None,
) -> str:
    if mfa.secreto_cifrado_v2 is not None:
        if mfa.version_criptografica != TOTP_ENCRYPTION_VERSION:
            raise TotpSecretEncryptionError("La versión de cifrado TOTP no es compatible.")
        return (cipher or TotpSecretCipher.from_settings()).decrypt(
            mfa.secreto_cifrado_v2,
            mfa.id_autenticador,
        )

    if mfa.secreto_cifrado:
        return mfa.secreto_cifrado
    raise TotpSecretEncryptionError("No existe un secreto TOTP recuperable.")


def migrate_legacy_totp_secrets(
    connection: Connection,
    cipher: Optional[TotpSecretCipher] = None,
) -> int:
    """Backfill legacy rows without deleting their source value.

    The Alembic transaction rolls back every update if encryption or verification fails.
    """
    active_cipher = cipher or TotpSecretCipher.from_settings()
    table = AutenticadorMfa.__table__
    rows = connection.execute(
        select(table.c.id_autenticador, table.c.secreto_cifrado).where(
            table.c.tipo == "TOTP",
            table.c.secreto_cifrado_v2.is_(None),
            table.c.secreto_cifrado.is_not(None),
        )
    ).mappings()

    migrated = 0
    for row in rows:
        legacy_secret = row["secreto_cifrado"]
        encrypted_secret = active_cipher.encrypt(legacy_secret, row["id_autenticador"])
        if active_cipher.decrypt(encrypted_secret, row["id_autenticador"]) != legacy_secret:
            raise TotpSecretEncryptionError("No se pudo verificar la migración TOTP.")

        result = connection.execute(
            update(table)
            .where(
                table.c.id_autenticador == row["id_autenticador"],
                table.c.secreto_cifrado_v2.is_(None),
            )
            .values(
                secreto_cifrado_v2=encrypted_secret,
                version_criptografica=TOTP_ENCRYPTION_VERSION,
            )
        )
        if result.rowcount != 1:
            raise TotpSecretEncryptionError("No se pudo completar la migración TOTP.")
        migrated += 1

    return migrated
