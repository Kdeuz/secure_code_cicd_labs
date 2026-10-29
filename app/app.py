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

from fastapi import HTTPException
from pydantic import BaseModel
from pathlib import Path

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

logging.basicConfig(level=logging.DEBUG)
log = logging.getLogger("minishop")

app = FastAPI(title="MiniShop", debug=True)
app.add_middleware(SessionMiddleware, secret_key=SECRET_KEY)


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
                 ("admin", md5("admin123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("alice", md5("alice123")))
    conn.execute("INSERT INTO users (username, password) VALUES (?, ?)", ("bob", md5("bob123")))
    conn.executemany("INSERT INTO products (name, price) VALUES (?, ?)",
                     [("apple", 1.2), ("banana", 0.8), ("cherry", 3.5)])
    conn.executemany("INSERT INTO invoices (owner_id, label, amount) VALUES (?, ?, ?)",
                     [(2, "Facture Alice", 42.0), (3, "Facture Bob", 99.0)])
    conn.commit()
    conn.close()

class ProfileModel(BaseModel):
    username: str
    email: str = ""
    role: str = "user"


@app.exception_handler(Exception)
async def handle_error(request: Request, exc: Exception):
    return HTMLResponse("<pre>" + traceback.format_exc() + "</pre>", status_code=500)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/login")
def login(request: Request, data: dict = Body(...)):
    username, password = data["username"], data["password"]

    #log.info(f"login attempt user={username} password={password}")
    #Il ne faut pas logger le mot de passe en clair
    log.info(f"login attempt user={username}")

    # sql = f"SELECT * FROM users WHERE username='{username}' AND password='{md5(password)}'"
    # row = db().execute(sql).fetchone()
    # Il ne faut pas utiliser de f-string pour construire la requête SQL, cela permet des injections SQL
    # Requête paramétrée avec le joker '?' (anti-SQLi)

    sql = "SELECT * FROM users WHERE username = ? AND password = ?"
    row = db().execute(sql, (username, md5(password))).fetchone()
    if not row:
      return JSONResponse({"error": "bad credentials"}, status_code=401)
    request.session["user_id"] = row["id"]
    request.session["token"] = str(random.randint(0, 10**6))
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

@app.post("/calc")
def calc(data: dict = Body(...)):
    expr = data.get("expr", "")
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
    r = requests.get(url, verify=False)
    return PlainTextResponse(r.text[:500])


@app.get("/invoices/{invoice_id}")
def invoice(invoice_id: int, request: Request):
    if "user_id" not in request.session:
        return JSONResponse({"error": "login required"}, status_code=401)
    row = db().execute("SELECT * FROM invoices WHERE id = ?", (invoice_id,)).fetchone()
    if not row:
        return JSONResponse({"error": "not found"}, status_code=404)
    return dict(row)


@app.get("/admin/users")
def admin_users(request: Request):
    if "user_id" not in request.session:
        return JSONResponse({"error": "login required"}, status_code=401)
    rows = db().execute("SELECT id, username, is_admin FROM users").fetchall()
    return [dict(r) for r in rows]


@app.delete("/users/{user_id}")
def delete_user(user_id: int, request: Request):
    if "user_id" not in request.session:
        return JSONResponse({"error": "login required"}, status_code=401)
    conn = db()
    conn.execute("DELETE FROM users WHERE id = ?", (user_id,))
    conn.commit()
    return {"deleted": user_id}


@app.get("/boom")
def boom():
    return 1 / 0


if __name__ == "__main__":
    init_db()
    uvicorn.run("app:app", host="0.0.0.0", port=5000, reload=True)
