import os
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Depends
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import jwt, JWTError
from passlib.context import CryptContext
from pydantic import BaseModel, Field
from sqlalchemy import create_engine, text

DATABASE_URL = os.getenv("DATABASE_URL")
JWT_SECRET = os.getenv("JWT_SECRET", "dev-secret")
JWT_ALG = "HS256"

ADMIN_USERNAME = os.getenv("ADMIN_USERNAME", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "CHANGE_ME_ADMIN_PASSWORD")

pwd = CryptContext(schemes=["bcrypt"], deprecated="auto")
engine = create_engine(DATABASE_URL, pool_pre_ping=True)

app = FastAPI(title="PMESP API")
bearer = HTTPBearer(auto_error=False)

class RegisterIn(BaseModel):
    username: str = Field(min_length=3, max_length=50)
    password: str = Field(min_length=6, max_length=200)
    email: Optional[str] = None
    matricula: Optional[str] = None

class LoginIn(BaseModel):
    username: str
    password: str

class ApproveIn(BaseModel):
    days: int = Field(ge=1, le=3650)
    session_limit: int = Field(ge=1, le=999)

def create_tables():
    with engine.begin() as conn:
        conn.execute(text("""
        CREATE TABLE IF NOT EXISTS users (
          id SERIAL PRIMARY KEY,
          username TEXT UNIQUE NOT NULL,
          password_hash TEXT NOT NULL,
          email TEXT,
          matricula TEXT,
          expires_at TIMESTAMP WITH TIME ZONE,
          session_limit INT DEFAULT 1,
          is_active BOOLEAN DEFAULT true,
          is_admin BOOLEAN DEFAULT false,
          created_at TIMESTAMP WITH TIME ZONE DEFAULT now()
        );
        """))

def seed_admin():
    with engine.begin() as conn:
        r = conn.execute(
            text("SELECT id FROM users WHERE username=:u"),
            {"u": ADMIN_USERNAME}
        ).fetchone()
        if not r:
            ph = pwd.hash(ADMIN_PASSWORD)
            conn.execute(text("""
                INSERT INTO users (username, password_hash, expires_at, session_limit, is_active, is_admin)
                VALUES (:u, :p, :e, :l, true, true)
            """), {
                "u": ADMIN_USERNAME,
                "p": ph,
                "e": datetime.now(timezone.utc) + timedelta(days=3650),
                "l": 999,
            })

@app.on_event("startup")
def on_startup():
    if not DATABASE_URL:
        raise RuntimeError("DATABASE_URL não configurada")
    create_tables()
    seed_admin()

def make_token(username: str) -> str:
    now = datetime.now(timezone.utc)
    payload = {
        "sub": username,
        "iat": int(now.timestamp()),
        "exp": int((now + timedelta(hours=8)).timestamp()),
    }
    return jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALG)

def get_current_user(creds: HTTPAuthorizationCredentials = Depends(bearer)):
    if not creds:
        raise HTTPException(status_code=401, detail="Token ausente")
    try:
        payload = jwt.decode(creds.credentials, JWT_SECRET, algorithms=[JWT_ALG])
        username = payload.get("sub")
        if not username:
            raise HTTPException(status_code=401, detail="Token inválido")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token inválido")

    with engine.begin() as conn:
        u = conn.execute(text("""
            SELECT username, expires_at, is_active, is_admin
            FROM users WHERE username=:u
        """), {"u": username}).fetchone()

    if not u:
        raise HTTPException(status_code=401, detail="Usuário não encontrado")
    if not u.is_active:
        raise HTTPException(status_code=403, detail="Conta desativada")

    # PENDENTE => expires_at NULL (validade 0)
    if u.expires_at is None:
        raise HTTPException(status_code=403, detail="Conta pendente")

    if u.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="Conta expirada")

    return {"username": u.username, "is_admin": u.is_admin}

def require_admin(user=Depends(get_current_user)):
    if not user["is_admin"]:
        raise HTTPException(status_code=403, detail="Apenas admin")
    return user

@app.get("/health")
def health():
    return {"ok": True}

@app.post("/public/register")
def public_register(data: RegisterIn):
    ph = pwd.hash(data.password)
    with engine.begin() as conn:
        exists = conn.execute(text("SELECT 1 FROM users WHERE username=:u"), {"u": data.username}).fetchone()
        if exists:
            raise HTTPException(status_code=409, detail="Usuário já existe")

        conn.execute(text("""
            INSERT INTO users (username, password_hash, email, matricula, expires_at, session_limit, is_active, is_admin)
            VALUES (:u, :p, :email, :mat, NULL, 1, true, false)
        """), {"u": data.username, "p": ph, "email": data.email, "mat": data.matricula})

    return {"ok": True, "message": "Solicitação criada como PENDENTE (validade 0). Aguarde aprovação do ADMIN."}

@app.post("/auth/login")
def login(data: LoginIn):
    with engine.begin() as conn:
        u = conn.execute(text("""
            SELECT username, password_hash, expires_at, is_active
            FROM users WHERE username=:u
        """), {"u": data.username}).fetchone()

    if not u or not pwd.verify(data.password, u.password_hash):
        raise HTTPException(status_code=401, detail="Usuário ou senha inválidos")
    if not u.is_active:
        raise HTTPException(status_code=403, detail="Conta desativada")
    if u.expires_at is None:
        raise HTTPException(status_code=403, detail="Conta pendente ou desativada")
    if u.expires_at < datetime.now(timezone.utc):
        raise HTTPException(status_code=403, detail="Conta expirada")

    return {"access_token": make_token(u.username), "token_type": "bearer"}

@app.get("/admin/users", dependencies=[Depends(require_admin)])
def list_users():
    with engine.begin() as conn:
        rows = conn.execute(text("""
            SELECT id, username, email, matricula, expires_at, session_limit, is_active, is_admin, created_at
            FROM users
            ORDER BY id
        """)).mappings().all()
    return {"ok": True, "users": rows}

@app.post("/admin/users/{username}/approve")
def approve_user(username: str, body: ApproveIn, _admin=Depends(require_admin)):
    expires = datetime.now(timezone.utc) + timedelta(days=body.days)
    with engine.begin() as conn:
        r = conn.execute(text("""
            UPDATE users
            SET expires_at=:e, session_limit=:l, is_active=true
            WHERE username=:u AND is_admin=false
            RETURNING username, expires_at
        """), {"u": username, "e": expires, "l": body.session_limit}).fetchone()

    if not r:
        raise HTTPException(status_code=404, detail="Usuário não encontrado (ou é admin)")
    return {"ok": True, "message": f"{r.username} aprovado", "expires_at": str(r.expires_at)}

@app.post("/admin/users/{username}/disable")
def disable_user(username: str, _admin=Depends(require_admin)):
    with engine.begin() as conn:
        r = conn.execute(text("""
            UPDATE users SET is_active=false
            WHERE username=:u AND is_admin=false
            RETURNING username
        """), {"u": username}).fetchone()
    if not r:
        raise HTTPException(status_code=404, detail="Usuário não encontrado (ou é admin)")
    return {"ok": True, "message": f"{r.username} desativado"}
