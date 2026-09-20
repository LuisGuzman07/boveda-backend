import base64
import binascii
import hashlib

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class DeviceCryptoError(ValueError):
    pass


def decode_base64(value: str) -> bytes:
    try:
        return base64.b64decode(value.encode("ascii"), validate=True)
    except (UnicodeEncodeError, binascii.Error, ValueError) as error:
        raise DeviceCryptoError("Invalid base64 value.") from error


def normalize_ed25519_public_key(value: str) -> tuple[str, str]:
    key_bytes = decode_base64(value)
    try:
        Ed25519PublicKey.from_public_bytes(key_bytes)
    except ValueError as error:
        raise DeviceCryptoError("Invalid Ed25519 public key.") from error
    return base64.b64encode(key_bytes).decode("ascii"), hashlib.sha256(key_bytes).hexdigest()


def verify_ed25519_signature(public_key: str, signature: str, message: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(decode_base64(public_key)).verify(
            decode_base64(signature), message
        )
    except (InvalidSignature, ValueError) as error:
        raise DeviceCryptoError("Invalid Ed25519 signature.") from error
