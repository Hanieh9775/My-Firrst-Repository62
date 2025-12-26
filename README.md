"""
OAuth2 Authentication Server
JWT + Refresh Tokens
Single-file FastAPI application

Features:
- User registration & login
- Secure password hashing
- JWT access tokens
- Refresh token rotation
- Token expiration
- SQLite persistence
- Production-grade auth design

Run:
pip install fastapi uvicorn python-jose passlib[bcrypt]
uvicorn app:app --reload
"""

import sqlite3
import uuid
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from passlib.context import CryptContext
from jose import jwt, JWTError

# -------------------------
# Config
# -------------------------
SECRET_KEY = "CHANGE_THIS_SECRET"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 15
REFRESH_TOKEN_EXPIRE_DAYS = 7
DB_PATH = "auth.db"

app = FastAPI(title="OAuth2 Auth Server")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# -------------------------
# Database
# -------------------------
def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id TEXT PRIMARY KEY,
            username TEXT UNIQUE,
            password_hash TEXT,
            created_at TEXT
        )
    """)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS refresh_tokens (
            token TEXT PRIMARY KEY,
            user_id TEXT,
            expires_at TEXT
        )
    """)
    conn.commit()
    conn.close()

init_db()

def get_db():
    return sqlite3.connect(DB_PATH)

# -------------------------
# Models
# -------------------------
class UserCreate(BaseModel):
    username: str
    password: str

class TokenOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"

# -------------------------
# Security Helpers
# -------------------------
def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(password: str, hashed: str) -> bool:
    return pwd_context.verify(password, hashed)

def create_access_token(user_id: str):
    payload = {
        "sub": user_id,
        "exp": datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)

def create_refresh_token(user_id: str):
    token = str(uuid.uuid4())
    expires = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)

    conn = get_db()
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO refresh_tokens VALUES (?, ?, ?)",
        (token, user_id, expires.isoformat())
    )
    conn.commit()
    conn.close()

    return token

def get_current_user(token: str):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        return payload["sub"]
    except JWTError:
        raise HTTPException(status_code=401, detail="Invalid token")

# -------------------------
# API Routes
# -------------------------
@app.post("/register")
def register(user: UserCreate):
    conn = get_db()
    cur = conn.cursor()
    try:
        cur.execute(
            "INSERT INTO users VALUES (?, ?, ?, ?)",
            (
                str(uuid.uuid4()),
                user.username,
                hash_password(user.password),
                datetime.utcnow().isoformat()
            )
        )
        conn.commit()
    except sqlite3.IntegrityError:
        raise HTTPException(status_code=400, detail="User already exists")
    finally:
        conn.close()

    return {"message": "User registered"}

@app.post("/login", response_model=TokenOut)
def login(user: UserCreate):
    conn = get_db()
    cur = conn.cursor()
    row = cur.execute(
        "SELECT id, password_hash FROM users WHERE username = ?",
        (user.username,)
    ).fetchone()
    conn.close()

    if not row or not verify_password(user.password, row[1]):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    access_token = create_access_token(row[0])
    refresh_token = create_refresh_token(row[0])

    return {
        "access_token": access_token,
        "refresh_token": refresh_token
    }

@app.post("/refresh", response_model=TokenOut)
def refresh(refresh_token: str):
    conn = get_db()
    cur = conn.cursor()
    row = cur.execute(
        "SELECT user_id, expires_at FROM refresh_tokens WHERE token = ?",
        (refresh_token,)
    ).fetchone()

    if not row:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    if datetime.fromisoformat(row[1]) < datetime.utcnow():
        raise HTTPException(status_code=401, detail="Refresh token expired")

    cur.execute("DELETE FROM refresh_tokens WHERE token = ?", (refresh_token,))
    conn.commit()
    conn.close()

    return {
        "access_token": create_access_token(row[0]),
        "refresh_token": create_refresh_token(row[0])
    }

@app.get("/protected")
def protected(token: str):
    user_id = get_current_user(token)
    return {"message": "Access granted", "user_id": user_id}
