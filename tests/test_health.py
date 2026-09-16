# pyrefly: ignore [missing-import]
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_health_check():
    response = client.get("/api/v1/health")
    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": "boveda-backend"
    }


def test_root():
    response = client.get("/")
    assert response.status_code == 200
    data = response.json()
    assert "health" in data
