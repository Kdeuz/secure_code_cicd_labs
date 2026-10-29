"""MiniShop : application FastAPI VOLONTAIREMENT VULNÉRABLE (support du TP Cours 7).

Ne jamais déployer ce code tel quel. Votre mission : le rendre conforme.
Documentation interactive : http://localhost:5000/docs
"""
import ast
import base64
import hashlib
import logging
import os
import pickle
import random
import sqlite3
import subprocess
import sys
import traceback

import ipaddress
import operator

import requests
import uvicorn
import yaml
from fastapi import Body, FastAPI, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, PlainTextResponse
from starlette.middleware.sessions import SessionMiddleware
import html
import secrets

from fastapi import HTTPException
from pydantic import BaseModel
from pathlib import Path
from urllib.parse import urlparse
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from fastapi import Depends
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

ph = PasswordHasher()

SECRET_KEY = os.environ["SECRET_KEY"]
DB_PATH = os.environ.get("DB_PATH", "shop.db")
UPLOAD_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "uploads")

SAFE_OPERATORS = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.USub: operator.neg,
    ast.UAdd: operator.pos,
}

ALLOWED_FETCH_HOSTS = {"example.com", "api.github.com", "stackoverflow.com"}

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("minishop")

IS_DEV = os.getenv("ENV", "production").lower() in ("dev", "development")

app = FastAPI(
    title="MiniShop",
    debug=IS_DEV,
    docs_url="/docs" if IS_DEV else None,
    redoc_url="/redoc" if IS_DEV else None,
    openapi_url="/openapi.json" if IS_DEV else None
)

# Détection de l'exécution via pytest
IS_TESTING = "pytest" in sys.modules or os.getenv("ENV") == "test"

limiter = Limiter(key_func=get_remote_address, enabled=not IS_TESTING)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)


# Intercepte toutes les erreurs 500 non gérées pour masquer la stacktrace
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    return JSONResponse(
        status_code=500,
        content={"detail": "Internal Server Error"}
    )

app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
    https_only=True,
    same_site="lax"
)

@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = "default-src 'self'"
    return response


def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def md5(value):
    return hashlib.md5(value.encode()).hexdigest()


def init_db():
    conn = db()
    conn.executescript(
        """
        DROP TABLE IF EXISTS users;
        DROP TABLE IF EXISTS products;
        DROP TABLE IF EXISTS invoices;
        CREATE TABLE users (id INTEGER PRIMARY KEY, username TEXT UNIQUE,
                            password TEXT, is_admin INTEGER DEFAULT 0);
        CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
        CREATE TABLE invoices (id INTEGER PRIMARY KEY, owner_id INTEGER,
                               label TEXT, amount REAL);
        """
    )
    conn.execute("INSERT INTO users (username, password, is_admin) VALUES (?, ?, 1)",
                 ("admin", ph.hash("admin123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("alice", ph.hash("alice123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("bob", ph.hash("bob123")))
    conn.executemany("INSERT INTO products (name, price) VALUES (?, ?)",
                     [("apple", 1.2), ("banana", 0.8), ("cherry", 3.5)])
    conn.executemany("INSERT INTO invoices (owner_id, label, amount) VALUES (?, ?, ?)",
                     [(2, "Facture Alice", 42.0), (3, "Facture Bob", 99.0)])
    conn.commit()
    conn.close()

def safe_eval(expr: str):
    def _eval(node):
        if isinstance(node, ast.Expression):
            return _eval(node.body)
        elif isinstance(node, ast.Constant) and isinstance(node.value, (int, float)):
            return node.value
        elif isinstance(node, ast.BinOp) and type(node.op) in SAFE_OPERATORS:
            left = _eval(node.left)
            right = _eval(node.right)
            return SAFE_OPERATORS[type(node.op)](left, right)
        elif isinstance(node, ast.UnaryOp) and type(node.op) in SAFE_OPERATORS:
            return SAFE_OPERATORS[type(node.op)](_eval(node.operand))
        else:
            raise ValueError("Unsupported expression")

    parsed = ast.parse(expr, mode='eval')
    return _eval(parsed)


def current_user(request: Request) -> dict:
    user_id = request.session.get("user_id")
    if not user_id:
        raise HTTPException(status_code=401, detail="user not found")

    row = db().execute("SELECT id, username, is_admin FROM users WHERE id = ?", (user_id,)).fetchone()
    if not row:
        raise HTTPException(status_code=401, detail="user not found")
    return dict(row)

def require_admin(user: dict = Depends(current_user)) -> dict:
    if not user.get("is_admin"):
        raise HTTPException(status_code=403, detail="forbidden")
    return user



class ProfileModel(BaseModel):
    username: str
    email: str = ""
    role: str = "user"

class LoginModel(BaseModel):
    username: str
    password: str

class CalcModel(BaseModel):
    expr: str

@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
@limiter.limit("5/minute")  # Limite à 5 tentatives par minute par IP
def login(request: Request, data: LoginModel):
    username, password = data.username, data.password

    #log.info(f"login attempt user={username} password={password}")
    #Il ne faut pas logger le mot de passe en clair
    log.info(f"login attempt user={username}")

    # sql = f"SELECT * FROM users WHERE username='{username}' AND password='{md5(password)}'"
    # row = db().execute(sql).fetchone()
    # Il ne faut pas utiliser de f-string pour construire la requête SQL, cela permet des injections SQL
    # Requête paramétrée avec le joker '?' (anti-SQLi)

    sql = "SELECT * FROM users WHERE username = ?"
    row = db().execute(sql, (username,)).fetchone()
    if not row:
      return JSONResponse({"error": "bad credentials"}, status_code=401)

    # Vérification sécurisée du hashage Argon2id
    try:
        ph.verify(row["password"], password)
    except VerifyMismatchError:
        return JSONResponse({"error": "bad credentials"}, status_code=401)

    request.session["user_id"] = row["id"]
    # request.session["token"] = str(random.randint(0, 10**6))
    # Génération d'un jeton cryptographiquement sûr
    request.session["token"] = secrets.token_hex(16)
    return {"status": "logged in", "user": row["username"]}


@app.get("/search")
def search(q: str = ""):
    # sql = f"SELECT id, name, price FROM products WHERE name LIKE '%{q}%'"
    # Il ne faut pas utiliser de f-string pour construire la requête SQL, cela permet des injections SQL
    # Requête paramétrée avec le joker '?' (anti-SQLi)
    sql = "SELECT id, name, price FROM products WHERE name LIKE ?"
    # return [dict(r) for r in db().execute(sql).fetchall()]
    return [dict(r) for r in db().execute(sql, (f"%{q}%",)).fetchall()]


@app.get("/ping")
def ping(host: str = "127.0.0.1"):
    # 1. Validation stricte de l'adresse IP (rejection immédiate en 400 si invalide)
    try:
        ipaddress.ip_address(host)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid IP address")

    # 2. Exécution sécurisée : passage d'une liste (sans shell=True) + timeout de 5s
    try:
        out = subprocess.run(["ping", "-c", "1", host], capture_output=True, text=True, timeout=5, check=False,)
        return PlainTextResponse(out.stdout + out.stderr)
    except subprocess.TimeoutExpired:
        raise HTTPException(status_code=408, detail="Ping request timed out")
    #out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    #return PlainTextResponse(out.stdout + out.stderr)


@app.get("/hello")
def hello(name: str = ""):
    safe_name = html.escape(name)  # Échappe les caractères spéciaux pour éviter l'XSS
    return HTMLResponse(f"<h1>Bonjour {safe_name}</h1>")


@app.get("/files/{name:path}")
def get_file(name: str):
    base_dir = Path(UPLOAD_DIR).resolve()
    target_path = (base_dir / name).resolve() 

    # 1. Validation stricte du chemin : on ne doit pas sortir du répertoire
    if not target_path.resolve().is_relative_to(base_dir):
        return JSONResponse({"error": "invalid file path"}, status_code=400)
    
    # 2. Vérification que le fichier existe
    if not target_path.is_file():
        return JSONResponse({"error": "file not found"}, status_code=404)
    
    return FileResponse(target_path)

@app.post("/calc")
def calc(data: CalcModel):
    expr = data.expr
    try:
        result = safe_eval(expr)
        return {"result": str(result)}
    except Exception:
        return JSONResponse({"error": "invalid expression"}, status_code=400)    
    # return {"result": str(eval(data["expr"]))}


@app.post("/import-yaml")
async def import_yaml(request: Request):
    body = await request.body()
    try:
        cfg = yaml.safe_load(body)
        if not isinstance(cfg, dict):
            return JSONResponse({"error": "invalid yaml format"}, status_code=400)
        return {"keys": list(cfg.keys())}
    except Exception:
        return JSONResponse({"error": "invalid YAML"}, status_code=400)

@app.post("/import-profile")
async def import_profile(profile: ProfileModel):
    # FastAPI désérialise et valide automatiquement le JSON en entrée
    return {"profile": profile.dict()}


@app.get("/fetch")
def fetch(url: str):
    parsed = urlparse(url)

    # 1. Vérification du schéma HTTPS
    if parsed.scheme != "https":
        return JSONResponse({"error": "only HTTPS URLs are allowed"}, status_code=400)

    # 2. Vérification du nom d'hôte dans la liste blanche
    if not parsed.hostname or parsed.hostname not in ALLOWED_FETCH_HOSTS:
        return JSONResponse({"error": "host not allowed"}, status_code=400)

    # 3. Requête sécurisée
    try:
        r = requests.get(url, verify=True, timeout=5, allow_redirects=False)
        return PlainTextResponse(r.text[:500])
    except Exception:
        return JSONResponse({"error": "failed to fetch URL"}, status_code=400)


@app.get("/invoices/{invoice_id}")
def invoice(invoice_id: int, user: dict = Depends(current_user)):
    row = db().execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if not row :
        raise HTTPException(status_code=404, detail="invoice not found")

    # Contrôle d'accès IDOR : propriétaire ou administrateur uniquement
    if row["owner_id"] != user["id"] and not user["is_admin"]:
        raise HTTPException(status_code=404, detail="not found")

    return dict(row)

@app.get("/admin/users")
def admin_users(admin: dict = Depends(require_admin)):
    rows = db().execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.delete("/users/{user_id}")
def delete_user(user_id: int, admin: dict = Depends(require_admin)):
    conn = db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return {"deleted": user_id}


@app.get("/boom")
def boom():
    return 1 / 0


if __name__ == "__main__":
    init_db()
    host = os.environ.get("HOST", "127.0.0.1")
    port = int(os.environ.get("PORT", 5000))
    uvicorn.run("app.app:app", host=host, port=port)