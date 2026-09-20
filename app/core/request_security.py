from urllib.parse import urlsplit

from fastapi import HTTPException, Request, status

from app.core.config import settings


def get_client_ip(request: Request) -> str:
    # X-Forwarded-For is client-controlled until trusted proxy middleware is configured.
    return request.client.host if request.client else "unknown"


def canonical_origin(value: str) -> str:
    """Return the only URL shape accepted for credentialed browser origins."""
    parsed = urlsplit(value.strip())
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError("Invalid origin")

    host = parsed.hostname.rstrip(".").lower()
    try:
        port = parsed.port
    except ValueError as error:
        raise ValueError("Invalid origin port") from error

    if ":" in host:
        host = f"[{host}]"
    if port and (parsed.scheme, port) not in {("http", 80), ("https", 443)}:
        host = f"{host}:{port}"
    return f"{parsed.scheme}://{host}"


def require_allowed_web_origin(request: Request) -> None:
    """Reject cookie-capable browser requests outside the configured allowlist."""
    origin = request.headers.get("Origin")
    try:
        normalized = canonical_origin(origin) if origin and origin != "null" else None
    except ValueError:
        normalized = None

    if normalized not in settings.CORS_ORIGINS:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Origen no permitido para una sesión web.",
        )
