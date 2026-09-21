"""Canonical, secret-safe serialization and chain assignment for audit events."""

import hashlib
import json
import threading
import uuid
from datetime import datetime, timezone
from typing import Any

from sqlalchemy import event, select, text
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm import Session

from app.models.auth import EventoAuditoria

SCHEMA_VERSION = 1
GENESIS_HASH = "0" * 64
_sqlite_chain_lock = threading.Lock()
_SECRET_MARKERS = ("secret", "password", "token", "key", "cipher", "plaintext", "private", "nonce")


def redact_audit_details(value: Any, key: str = "") -> Any:
    """Keep structured operational context while removing material that can be secret."""
    if any(marker in key.lower() for marker in _SECRET_MARKERS):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {str(k): redact_audit_details(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_audit_details(item, key) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _normalise(value: Any) -> Any:
    if isinstance(value, datetime):
        return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    return str(value) if value is not None else None


def canonical_event_payload(event: EventoAuditoria) -> bytes:
    """Return stable bytes; JSON key order never affects an event hash."""
    payload = {
        "schema_version": event.schema_version,
        "sequence": event.chain_sequence,
        "previous_hash": event.previous_hash,
        "id_evento": _normalise(event.id_evento),
        "id_usuario": _normalise(event.id_usuario),
        "id_dispositivo": _normalise(event.id_dispositivo),
        "accion": event.accion,
        "tipo_evento": event.tipo_evento,
        "resultado": event.resultado,
        "recurso_id": event.recurso_id,
        "recurso_tipo": event.recurso_tipo,
        "direccion_ip": event.direccion_ip,
        "user_agent": event.user_agent,
        "detalles": redact_audit_details(event.detalles or {}),
        "fecha_evento": _normalise(event.fecha_evento),
    }
    return json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("utf-8")


def event_hash(event: EventoAuditoria) -> str:
    return hashlib.sha256(canonical_event_payload(event)).hexdigest()


def _last_chain(connection) -> tuple[int, str]:
    row = connection.execute(
        select(EventoAuditoria.chain_sequence, EventoAuditoria.event_hash)
        .where(EventoAuditoria.chain_sequence.is_not(None))
        .order_by(EventoAuditoria.chain_sequence.desc())
        .limit(1)
    ).first()
    return (row[0], row[1]) if row else (0, GENESIS_HASH)


@event.listens_for(Session, "before_flush")
def assign_audit_chain(session: Session, _flush_context, _instances) -> None:
    events = [item for item in session.new if isinstance(item, EventoAuditoria)]
    if not events:
        return
    connection = session.connection()
    if connection.dialect.name == "postgresql":
        connection.execute(text("SELECT pg_advisory_xact_lock(21002122)"))
        sequence, previous_hash = _last_chain(connection)
        for item in events:
            item.id_evento = item.id_evento or uuid.uuid4()
            item.chain_sequence = connection.scalar(text("SELECT nextval('evento_auditoria_chain_seq')"))
            item.previous_hash = previous_hash
            item.schema_version = SCHEMA_VERSION
            item.detalles = redact_audit_details(item.detalles or {})
            item.fecha_evento = item.fecha_evento or datetime.now(timezone.utc)
            item.event_hash = event_hash(item)
            previous_hash = item.event_hash
        return

    # SQLite is only the unit-test fallback. PostgreSQL is protected by the DB trigger.
    with _sqlite_chain_lock:
        sequence, previous_hash = _last_chain(connection)
        for item in events:
            item.id_evento = item.id_evento or uuid.uuid4()
            sequence += 1
            item.chain_sequence = sequence
            item.previous_hash = previous_hash
            item.schema_version = SCHEMA_VERSION
            item.detalles = redact_audit_details(item.detalles or {})
            item.fecha_evento = item.fecha_evento or datetime.now(timezone.utc)
            item.event_hash = event_hash(item)
            previous_hash = item.event_hash


@event.listens_for(EventoAuditoria, "before_update")
@event.listens_for(EventoAuditoria, "before_delete")
def reject_orm_audit_mutation(*_args) -> None:
    raise InvalidRequestError("evento_auditoria is append-only")
