from fastapi import Request


def get_client_ip(request: Request) -> str:
    # X-Forwarded-For is client-controlled until trusted proxy middleware is configured.
    return request.client.host if request.client else "unknown"
