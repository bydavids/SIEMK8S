import os
from datetime import datetime, timedelta
import hashlib

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPBasic, HTTPBasicCredentials
from pydantic import BaseModel
from jose import jwt, JWTError
import asyncpg
from contextlib import asynccontextmanager

# VAR
SECRET_KEY = os.environ["SECRET_KEY"]
ACCESS_DAYS = int(os.environ.get("ACCESS_TOKEN_DAYS", 30))
DATABASE_URL = os.environ["DATABASE_URL"]
ADMIN_USER = os.environ.get("ADMIN_USER")
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")

security = HTTPBasic()

# APP DEF
@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.db = await asyncpg.create_pool(DATABASE_URL)
    yield
    await app.state.db.close()

app = FastAPI(title="SIEM Authentication Service", lifespan=lifespan)


class TokenRequest(BaseModel):
    device_id: str

class TokenData(BaseModel):
    token: str


def check_admin(credentials: HTTPBasicCredentials = Depends(security)):
    if credentials.username != ADMIN_USER or credentials.password != ADMIN_PASSWORD:
        raise HTTPException(401, "Forbidden!")
    return credentials.username

def create_jwt(device_id: str) -> str:
    payload = {
        "sub": device_id,
        "exp": datetime.utcnow() + timedelta(days=ACCESS_DAYS)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm="HS256")

def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()

async def store_token(device_id: str, token: str):
    async with app.state.db.acquire() as conn:
        await conn.execute(
            "INSERT INTO tokens(device_id, token, expires_at) VALUES($1,$2,$3)",
            device_id, hash_token(token), datetime.utcnow() + timedelta(days=ACCESS_DAYS)
        )

async def is_token_valid(token: str) -> str | None:
    try:
        device_id = jwt.decode(token, SECRET_KEY, algorithms=["HS256"])["sub"]
    except JWTError:
        return None

    async with app.state.db.acquire() as conn:
        row = await conn.fetchrow(
            "SELECT 1 FROM tokens WHERE token=$1 AND expires_at > NOW()",
            hash_token(token)
        )
        return device_id if row else None

async def revoke_token(token: str):
    async with app.state.db.acquire() as conn:
        await conn.execute("DELETE FROM tokens WHERE token=$1", hash_token(token))

# ROUTES
@app.post("/token/create")
async def create_token(req: TokenRequest, _: str = Depends(check_admin)):
    token = create_jwt(req.device_id)
    await store_token(req.device_id, token)
    return {
        "token": token,
        "expires_at": datetime.utcnow() + timedelta(days=ACCESS_DAYS)
    }

@app.post("/token/validate")
async def validate_token(req: TokenData):
    device = await is_token_valid(req.token)
    if not device:
        raise HTTPException(401, "Invalid token")
    return {"device_id": device}

@app.post("/token/revoke")
async def revoke_token_route(req: TokenData, _: str = Depends(check_admin)):
    await revoke_token(req.token)
    return {"revoked": True}

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
