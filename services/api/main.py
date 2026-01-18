# api.py
import os
from datetime import datetime

from fastapi import FastAPI, HTTPException, Request, Depends
from fastapi.responses import Response
from pydantic import BaseModel
import asyncpg
import httpx

# VAR
DATABASE_URL = os.environ.get(
    "DATABASE_URL", "postgresql://user:password@localhost:5432/siem"
)

AUTH_BASE_URL = os.environ.get(
    "AUTH_BASE_URL", "https://auth:8000"
)


app = FastAPI(title="SIEM API")


@app.on_event("startup")
async def startup():
    app.state.db = await asyncpg.create_pool(DATABASE_URL)

@app.on_event("shutdown")
async def shutdown():
    await app.state.db.close()


class Event(BaseModel):
    timestamp: datetime | None = None
    source: str
    severity: str
    event_type: str
    source_ip: str
    destination_ip: str
    message: str

# TOKEN VALIDATION
async def get_current_user(request: Request) -> str:
    auth = request.headers.get("authorization")
    if not auth or not auth.startswith("Bearer "):
        raise HTTPException(401, "Token não fornecido")

    parts = auth.split(" ", 1)
    if len(parts) != 2 or not parts[1].strip():
        raise HTTPException(401, "Token inválido ou vazio")

    token = parts[1].strip()


    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(
                f"{AUTH_BASE_URL}/token/validate",
                json={"token": token},
                timeout=5,
            )
        except httpx.RequestError:
            raise HTTPException(503, "Auth service unavailable")

    if resp.status_code != 200:
        raise HTTPException(401, "Token inválido")

    return resp.json()["device_id"]

# TOKEN ROUTES
@app.api_route(
    "/token/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE"]
)
async def proxy_to_auth(path: str, request: Request):
    url = f"{AUTH_BASE_URL}/token/{path}"
    body = await request.body()

    headers = dict(request.headers)
    headers.pop("host", None)

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.request(
                method=request.method,
                url=url,
                content=body,
                headers=headers,
                timeout=5,
            )
        except httpx.RequestError:
            raise HTTPException(
                status_code=503,
                detail="Auth service unavailable",
            )

    return Response(
        content=resp.content,
        status_code=resp.status_code,
        media_type=resp.headers.get("content-type"),
    )

# API ENDPOINTS
@app.post("/event")
async def ingest_event(
    event: Event,
    _: str = Depends(get_current_user),
):
    ts = event.timestamp or datetime.utcnow()
    if ts.tzinfo:
        ts = ts.replace(tzinfo=None)

    async with app.state.db.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO events
            (timestamp, source, severity, event_type,
             source_ip, destination_ip, message)
            VALUES ($1,$2,$3,$4,$5,$6,$7)
            """,
            ts,
            event.source,
            event.severity,
            event.event_type,
            event.source_ip,
            event.destination_ip,
            event.message,
        )

    return {"status": "stored"}

@app.get("/events")
async def get_events(
    limit: int = 50,
    _: str = Depends(get_current_user),
):
    async with app.state.db.acquire() as conn:
        rows = await conn.fetch(
            """
            SELECT timestamp, source, severity, event_type,
                   source_ip, destination_ip, message
            FROM events
            ORDER BY timestamp DESC
            LIMIT $1
            """,
            limit,
        )
    return [dict(r) for r in rows]

# PROBES
@app.get("/health/live")
async def live():
    return {"ok": True}

@app.get("/health/ready")
async def ready():
    try:
        async with app.state.db.acquire() as conn:
            await conn.fetchval("SELECT 1")
    except Exception:
        raise HTTPException(503, "DB UNAVAILABLE")
    return {"ok": True}