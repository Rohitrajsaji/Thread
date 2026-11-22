from concurrent.futures import ThreadPoolExecutor
from contextlib import closing
from pathlib import Path
import sqlite3
from threading import Barrier

from fastapi.testclient import TestClient
import yaml

from app.inventory import create_app

PAYLOAD = {"sku": "last-unit", "quantity": 1}


def test_last_unit_race(tmp_path):
    db = tmp_path / "stock.db"
    app = create_app(db)
    gate = Barrier(2)

    def reserve():
        with TestClient(app) as client:
            gate.wait(timeout=5)
            return client.post("/inventory/reservations", json=PAYLOAD).status_code

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [pool.submit(reserve) for _ in range(2)]
        assert sorted(f.result(timeout=10) for f in outcomes) == [201, 409]
    with closing(sqlite3.connect(db)) as conn:
        assert conn.execute("SELECT count(*),sum(quantity) FROM reservations").fetchone() == (1, 1)


def test_reservation_expiry(tmp_path):
    now = [100.0]
    with TestClient(create_app(tmp_path / "stock.db", clock=lambda: now[0], ttl=5)) as client:
        assert client.post("/inventory/reservations", json=PAYLOAD).status_code == 201
        now[0] += 4
        assert client.post("/inventory/reservations", json=PAYLOAD).status_code == 409
        now[0] += 1
        assert client.post("/inventory/reservations", json=PAYLOAD).status_code == 201


def test_openapi_conformance(tmp_path):
    contract_path = Path(__file__).resolve().parents[2] / "contracts" / "openapi.yaml"
    contract = yaml.safe_load(contract_path.read_text(encoding="utf-8"))
    with TestClient(create_app(tmp_path / "stock.db")) as client:
        schema = client.get("/openapi.json").json()
        assert schema == contract
        assert client.post(
            "/inventory/reservations", json={**PAYLOAD, "sku": "unlisted"}
        ).status_code == 404
        held = client.post("/inventory/reservations", json=PAYLOAD)
        assert held.status_code == 201
        path = "/inventory/reservations/" + held.json()["id"]
        assert client.delete(path).status_code == 204
        assert client.delete(path).status_code == 404
