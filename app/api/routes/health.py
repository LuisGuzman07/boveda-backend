from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session
from app.core.database import get_db

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", summary="FastAPI service health check")
def health_check():
    return {
        "status": "ok",
        "service": "boveda-backend"
    }


@router.get("/database", summary="PostgreSQL database health check")
def database_health_check(db: Session = Depends(get_db)):
    try:
        db.execute(text("SELECT 1;"))
        return {
            "status": "ok",
            "database": "connected"
        }
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail={
                "status": "error",
                "database": "disconnected",
                "message": str(e)
            }
        )
