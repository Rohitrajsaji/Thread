"""Reference implementation for the Inventory Reservations release exercise."""
import sqlite3
import time
import uuid
from contextlib import closing
from pathlib import Path

from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, PositiveInt


class ReservationRequest(BaseModel):
    sku: str
    quantity: PositiveInt


def create_app(database: Path, *, clock=time.time, ttl: int = 300) -> FastAPI:
    with closing(sqlite3.connect(database)) as conn, conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS stock(sku TEXT PRIMARY KEY, total INTEGER NOT NULL);
            CREATE TABLE IF NOT EXISTS reservations(
                id TEXT PRIMARY KEY, sku TEXT NOT NULL, quantity INTEGER NOT NULL, expires_at REAL NOT NULL);
            INSERT OR IGNORE INTO stock VALUES ('last-unit', 1);
        """)
    app = FastAPI(title="Inventory reservations", version="1.0")

    @app.post(
        "/inventory/reservations",
        status_code=201,
        responses={
            404: {"description": "Unknown SKU"},
            409: {"description": "Insufficient stock"},
        },
    )
    def reserve(request: ReservationRequest):
        with closing(sqlite3.connect(database)) as conn, conn:
            conn.execute("BEGIN IMMEDIATE")
            now = clock()
            conn.execute("DELETE FROM reservations WHERE expires_at <= ?", (now,))
            stock = conn.execute("SELECT total FROM stock WHERE sku=?", (request.sku,)).fetchone()
            if stock is None:
                raise HTTPException(404, "Unknown SKU")
            allocated = conn.execute("SELECT coalesce(sum(quantity),0) FROM reservations WHERE sku=?", (request.sku,)).fetchone()[0]
            if request.quantity > stock[0] - allocated:
                raise HTTPException(409, "Insufficient stock")
            identifier = uuid.uuid4().hex
            conn.execute("INSERT INTO reservations VALUES(?,?,?,?)", (identifier,request.sku,request.quantity,now+ttl))
            return {"id": identifier, "sku": request.sku, "quantity": request.quantity, "expires_at": now+ttl}

    @app.delete(
        "/inventory/reservations/{identifier}",
        status_code=204,
        responses={404: {"description": "Reservation not found"}},
    )
    def release(identifier: str):
        with closing(sqlite3.connect(database)) as conn, conn:
            if not conn.execute("DELETE FROM reservations WHERE id=?", (identifier,)).rowcount:
                raise HTTPException(404, "Reservation not found")
        return Response(status_code=204)

    @app.get("/", response_class=HTMLResponse, include_in_schema=False)
    def index():
        return """<title>Inventory reservations</title><main><h1>Inventory reservations</h1>
        <button>Reserve the last unit</button><p role="status"></p></main><script>
        document.querySelector('button').onclick=async()=>{const r=await fetch('/inventory/reservations',{
        method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({sku:'last-unit',quantity:1})});
        document.querySelector('p').textContent=r.ok?'Reservation saved':'Stock unavailable';};</script>"""
    return app
