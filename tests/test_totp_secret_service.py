import json
import uuid

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.core.database import Base
from app.models.mfa import AutenticadorMfa
from app.services.totp_secret_service import (
    TotpSecretCipher,
    TotpSecretEncryptionError,
    get_totp_secret,
    migrate_legacy_totp_secrets,
    store_encrypted_totp_secret,
)


def _cipher() -> TotpSecretCipher:
    return TotpSecretCipher(bytes(range(32)))


def test_totp_secret_round_trip_is_authenticated_and_not_stored_as_legacy():
    mfa = AutenticadorMfa(id_autenticador=uuid.uuid4(), id_usuario=uuid.uuid4())
    cipher = _cipher()

    store_encrypted_totp_secret(mfa, "opaque-test-value", cipher)

    assert mfa.secreto_cifrado is None
    assert mfa.secreto_cifrado_v2 is not None
    assert "opaque-test-value" not in mfa.secreto_cifrado_v2
    assert get_totp_secret(mfa, cipher) == "opaque-test-value"


def test_totp_secret_rejects_a_different_key_and_tampering():
    authenticator_id = uuid.uuid4()
    cipher = _cipher()
    encrypted = cipher.encrypt("opaque-test-value", authenticator_id)

    with pytest.raises(TotpSecretEncryptionError):
        TotpSecretCipher(bytes(reversed(range(32)))).decrypt(
            encrypted,
            authenticator_id,
        )

    altered = json.loads(encrypted)
    altered["ciphertext"] = altered["ciphertext"][:-1] + "A"
    with pytest.raises(TotpSecretEncryptionError):
        cipher.decrypt(json.dumps(altered), authenticator_id)


def test_controlled_legacy_backfill_is_idempotent_and_preserves_source_value():
    engine = create_engine("sqlite://", poolclass=StaticPool)
    Base.metadata.create_all(engine)
    mfa = AutenticadorMfa(
        id_autenticador=uuid.uuid4(),
        id_usuario=uuid.uuid4(),
        tipo="TOTP",
        secreto_cifrado="legacy-test-value",
        estado="ACTIVO",
    )
    cipher = _cipher()

    with Session(engine) as session:
        session.add(mfa)
        session.commit()
        connection = session.connection()

        assert migrate_legacy_totp_secrets(connection, cipher) == 1
        session.commit()
        session.expire_all()
        migrated = session.scalar(select(AutenticadorMfa))
        assert migrated.secreto_cifrado == "legacy-test-value"
        assert get_totp_secret(migrated, cipher) == "legacy-test-value"
        assert migrate_legacy_totp_secrets(session.connection(), cipher) == 0


def test_controlled_backfill_leaves_legacy_rows_untouched_after_failure():
    engine = create_engine("sqlite://", poolclass=StaticPool)
    Base.metadata.create_all(engine)
    mfa = AutenticadorMfa(
        id_autenticador=uuid.uuid4(),
        id_usuario=uuid.uuid4(),
        tipo="TOTP",
        secreto_cifrado="legacy-test-value",
        estado="ACTIVO",
    )

    class FailingCipher:
        def encrypt(self, *_args):
            raise TotpSecretEncryptionError("simulated encryption failure")

    with Session(engine) as session:
        session.add(mfa)
        session.commit()
        with pytest.raises(TotpSecretEncryptionError):
            migrate_legacy_totp_secrets(session.connection(), FailingCipher())
        session.rollback()
        session.expire_all()
        unchanged = session.scalar(select(AutenticadorMfa))
        assert unchanged.secreto_cifrado == "legacy-test-value"
        assert unchanged.secreto_cifrado_v2 is None
