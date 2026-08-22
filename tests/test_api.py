from fastapi.testclient import TestClient

from sentinel.app import app


client = TestClient(app)


def test_health() -> None:
    assert client.get("/api/health").json() == {"status": "ok"}


def test_demo_is_fail_closed() -> None:
    response = client.get("/api/demo")
    assert response.status_code == 200
    payload = response.json()
    assert payload["state"] == "missing"
    assert payload["missing"] == 1
    assert payload["total"] == 5


def test_scheduled_tick_runs_without_chat() -> None:
    response = client.post("/api/tick")
    assert response.status_code == 200
    assert response.json()["state"] == "missing"


def test_home_page_loads() -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Deadline Sentinel" in response.text
