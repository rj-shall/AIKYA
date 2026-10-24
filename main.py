from __future__ import annotations

import hashlib, hmac, json, os, re, secrets, time, uuid
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import psycopg
from psycopg.rows import dict_row
from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

BASE_DIR = Path(__file__).resolve().parent
INDEX_PATH = BASE_DIR / "index.html"
DATABASE_URL = os.environ.get("DATABASE_URL", "")
APP_ENV = os.environ.get("APP_ENV", "production").lower()
SESSION_COOKIE = "aikya_session"
SESSION_TTL_SECONDS = 60 * 60 * 12
PBKDF2_ITERATIONS = 310_000
PUBLIC_KEYS = {"aikya_users_clean", "aikya_posts_clean", "aikya_reviews_clean", "aikya_ver"}
PRIVATE_KEYS = {"aikya_requests_clean", "aikya_messages_clean", "aikya_credit_logs_clean", "aikya_vouchers_clean"}
ALLOWED_KEYS = PUBLIC_KEYS | PRIVATE_KEYS

app = FastAPI(title="AIKYA", docs_url=None, redoc_url=None, openapi_url=None)


def connect():
    if not DATABASE_URL:
        raise HTTPException(status_code=503, detail="Database is not configured. Set DATABASE_URL in the hosting environment.")
    url = DATABASE_URL
    if url.startswith("postgres://"):
        url = "postgresql://" + url[len("postgres://"):]
    return psycopg.connect(url, row_factory=dict_row, connect_timeout=10, sslmode="require")


def init_db():
    with connect() as con:
        con.execute("""CREATE TABLE IF NOT EXISTS aikya_accounts (
            user_id TEXT PRIMARY KEY, email TEXT NOT NULL UNIQUE, password_salt TEXT NOT NULL,
            password_hash TEXT NOT NULL, profile_json JSONB NOT NULL, created_at BIGINT NOT NULL)""")
        con.execute("""CREATE TABLE IF NOT EXISTS aikya_sessions (
            token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL REFERENCES aikya_accounts(user_id) ON DELETE CASCADE,
            expires_at BIGINT NOT NULL, created_at BIGINT NOT NULL)""")
        con.execute("CREATE INDEX IF NOT EXISTS aikya_sessions_expiry_idx ON aikya_sessions(expires_at)")
        con.execute("""CREATE TABLE IF NOT EXISTS aikya_state (
            state_key TEXT PRIMARY KEY, state_json JSONB NOT NULL, updated_at BIGINT NOT NULL)""")


@app.on_event("startup")
def startup():
    init_db()


def safe_profile(profile: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in profile.items() if k.lower() not in {"password", "password_hash", "password_salt", "token", "auth_token", "salt", "passhash"}}


def make_password(password: str) -> tuple[str, str]:
    salt = secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PBKDF2_ITERATIONS)
    return salt.hex(), digest.hex()


def check_password(password: str, salt_hex: str, hash_hex: str) -> bool:
    try:
        actual = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt_hex), PBKDF2_ITERATIONS).hex()
        return hmac.compare_digest(actual, hash_hex)
    except (ValueError, TypeError):
        return False


def session_user(request: Request):
    token = request.cookies.get(SESSION_COOKIE)
    if not token:
        return None
    digest = hashlib.sha256(token.encode()).hexdigest()
    now = int(time.time())
    with connect() as con:
        row = con.execute("""SELECT a.user_id,a.email,a.profile_json,s.expires_at
            FROM aikya_sessions s JOIN aikya_accounts a ON a.user_id=s.user_id
            WHERE s.token_hash=%s AND s.expires_at>%s""", (digest, now)).fetchone()
        con.execute("DELETE FROM aikya_sessions WHERE expires_at<=%s", (now,))
    return row


def require_user(request: Request):
    user = session_user(request)
    if not user:
        raise HTTPException(status_code=401, detail="Please log in to continue.")
    return user


def validate_origin(request: Request):
    origin = request.headers.get("origin")
    if not origin:
        if request.method not in {"GET", "HEAD", "OPTIONS"}:
            raise HTTPException(status_code=403, detail="Origin header is required.")
        return
    allowed = {x.strip().rstrip("/") for x in os.environ.get("ALLOWED_ORIGINS", "").split(",") if x.strip()}
    host = request.headers.get("host", "")
    proto = request.headers.get("x-forwarded-proto", request.url.scheme).split(",")[0].strip()
    expected = f"{proto}://{host}".rstrip("/")
    if origin.rstrip("/") not in (allowed | {expected}):
        raise HTTPException(status_code=403, detail="Cross-origin request blocked.")


def create_session(response: Response, user_id: str):
    raw = secrets.token_urlsafe(32)
    digest = hashlib.sha256(raw.encode()).hexdigest()
    now = int(time.time())
    with connect() as con:
        con.execute("DELETE FROM aikya_sessions WHERE expires_at<=%s", (now,))
        con.execute("INSERT INTO aikya_sessions(token_hash,user_id,expires_at,created_at) VALUES(%s,%s,%s,%s)", (digest, user_id, now + SESSION_TTL_SECONDS, now))
    response.set_cookie(SESSION_COOKIE, raw, httponly=True, secure=True, samesite="lax", max_age=SESSION_TTL_SECONDS, path="/")


class AuthBody(BaseModel):
    email: str = Field(min_length=3, max_length=254)
    password: str = Field(min_length=8, max_length=256)

class RegisterBody(AuthBody):
    name: str = Field(min_length=1, max_length=100)
    college: str = Field(default="Campus", max_length=160)
    branch: str = Field(default="Engineering", max_length=100)

class StateBody(BaseModel):
    value: Any


def read_state(con, keys=None):
    if keys is None:
        rows = con.execute("SELECT state_key,state_json FROM aikya_state").fetchall()
    elif not keys:
        return {}
    else:
        rows = con.execute("SELECT state_key,state_json FROM aikya_state WHERE state_key = ANY(%s)", (list(keys),)).fetchall()
    return {r["state_key"]: r["state_json"] for r in rows}


def save_state(con, key, value):
    if key not in ALLOWED_KEYS:
        raise HTTPException(status_code=400, detail="Unsupported data collection.")
    encoded = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    if len(encoded.encode()) > 1_000_000:
        raise HTTPException(status_code=413, detail="Collection too large.")
    con.execute("""INSERT INTO aikya_state(state_key,state_json,updated_at) VALUES(%s,%s::jsonb,%s)
        ON CONFLICT(state_key) DO UPDATE SET state_json=EXCLUDED.state_json, updated_at=EXCLUDED.updated_at""", (key, encoded, int(time.time())))


def owns(key: str, item: dict, uid: str) -> bool:
    if key == "aikya_users_clean": return item.get("id") == uid
    if key == "aikya_posts_clean": return item.get("userId") == uid
    if key == "aikya_requests_clean": return uid in (item.get("senderId"), item.get("receiverId"))
    if key == "aikya_messages_clean": return item.get("senderId") == uid
    if key == "aikya_reviews_clean": return item.get("reviewerId") == uid
    if key == "aikya_credit_logs_clean": return item.get("userId") == uid
    if key == "aikya_vouchers_clean": return item.get("userId") == uid
    return False


def merge_owned(old: Any, incoming: Any, key: str, uid: str):
    if not isinstance(old, list): old = []
    if not isinstance(incoming, list): raise HTTPException(status_code=422, detail="Expected a list of records.")
    old_by_id = {str(x.get("id")): x for x in old if isinstance(x, dict) and x.get("id") is not None}
    for item in incoming:
        if not isinstance(item, dict) or not owns(key, item, uid):
            continue
        ident = item.get("id")
        if ident is None: continue
        # A user may create/update only records they own. For requests, participant status changes are allowed.
        existing = old_by_id.get(str(ident))
        if existing and key == "aikya_requests_clean" and uid not in (existing.get("senderId"), existing.get("receiverId")):
            continue
        old_by_id[str(ident)] = item
    return list(old_by_id.values())


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "frame-ancestors 'none'; base-uri 'self'; form-action 'self'"
    return response


@app.get("/api/health")
def health():
    with connect() as con: con.execute("SELECT 1")
    return {"status": "ok", "database": "PostgreSQL", "environment": APP_ENV}


@app.get("/api/bootstrap")
def bootstrap(request: Request):
    user = session_user(request)
    with connect() as con:
        state = read_state(con)
    # No client-provided seed data. First launch returns empty collections.
    for key in ALLOWED_KEYS:
        state.setdefault(key, [] if key != "aikya_ver" else "production-v1")
    if not user:
        return {"initialized": True, "authenticated": False, "state": {k: state[k] for k in PUBLIC_KEYS}}
    uid = user["user_id"]
    for key in PRIVATE_KEYS | {"aikya_posts_clean", "aikya_reviews_clean"}:
        val = state.get(key, [])
        if isinstance(val, list):
            if key == "aikya_requests_clean": state[key] = [x for x in val if isinstance(x, dict) and uid in (x.get("senderId"), x.get("receiverId"))]
            elif key == "aikya_messages_clean": state[key] = [x for x in val if isinstance(x, dict) and uid in (x.get("senderId"), x.get("receiverId"))]
            elif key == "aikya_credit_logs_clean": state[key] = [x for x in val if isinstance(x, dict) and x.get("userId") == uid]
            elif key == "aikya_vouchers_clean": state[key] = [x for x in val if isinstance(x, dict) and x.get("userId") == uid]
    profile = safe_profile(user["profile_json"] if isinstance(user["profile_json"], dict) else {})
    users = state.get("aikya_users_clean", [])
    if isinstance(users, list):
        users = [u for u in users if isinstance(u, dict) and u.get("id") != uid]
        users.insert(0, profile)
        state["aikya_users_clean"] = users
    return {"initialized": True, "authenticated": True, "state": state}


@app.put("/api/state/{key}")
def put_state(key: str, body: StateBody, request: Request):
    validate_origin(request)
    user = require_user(request)
    if key not in ALLOWED_KEYS: raise HTTPException(status_code=400, detail="Unsupported data collection.")
    if key == "aikya_ver": return {"ok": True}
    uid = user["user_id"]
    with connect() as con:
        old = read_state(con, {key}).get(key, [])
        if key == "aikya_users_clean":
            incoming = body.value if isinstance(body.value, list) else []
            mine = next((safe_profile(x) for x in incoming if isinstance(x, dict) and x.get("id") == uid), None)
            if mine:
                con.execute("UPDATE aikya_accounts SET profile_json=%s::jsonb WHERE user_id=%s", (json.dumps(mine, ensure_ascii=False), uid))
                value = [x for x in old if not (isinstance(x, dict) and x.get("id") == uid)] if isinstance(old, list) else []
                value.insert(0, mine)
            else:
                value = old if isinstance(old, list) else []
        elif key in PUBLIC_KEYS | PRIVATE_KEYS:
            value = merge_owned(old, body.value, key, uid)
        else: value = old
        save_state(con, key, value)
    return {"ok": True}


@app.post("/api/auth/register")
def register(body: RegisterBody, request: Request, response: Response):
    validate_origin(request)
    email = body.email.strip().lower()
    if not re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+", email): raise HTTPException(status_code=422, detail="Enter a valid email address.")
    if not body.name.strip(): raise HTTPException(status_code=422, detail="Enter your name.")
    uid = "usr_" + uuid.uuid4().hex
    name = body.name.strip()
    profile = {"id": uid, "name": name, "email": email, "college": body.college.strip() or "Campus", "branch": body.branch.strip() or "Engineering", "year": "1st Year", "bio": "Peer eager to exchange skills on campus.", "avatar": "https://ui-avatars.com/api/?name=" + name.replace(" ", "+") + "&background=4F46E5&color=ffffff&bold=true&size=256", "skillsToTeach": [], "skillsToLearn": [], "skillLevel": "Beginner", "category": "Programming", "verified": False, "credits": 10, "rating": 0, "reviewsCount": 0, "badges": ["🎯 Skill Explorer"], "exchangesCompleted": 0}
    salt, digest = make_password(body.password)
    try:
        with connect() as con:
            con.execute("INSERT INTO aikya_accounts(user_id,email,password_salt,password_hash,profile_json,created_at) VALUES(%s,%s,%s,%s,%s::jsonb,%s)", (uid,email,salt,digest,json.dumps(profile,ensure_ascii=False),int(time.time())))
            profiles = con.execute("SELECT profile_json FROM aikya_accounts ORDER BY created_at DESC").fetchall()
            save_state(con, "aikya_users_clean", [r["profile_json"] for r in profiles])
            logs = read_state(con, {"aikya_credit_logs_clean"}).get("aikya_credit_logs_clean", [])
            if not isinstance(logs, list): logs = []
            logs.append({"id":"log_"+uuid.uuid4().hex[:12],"userId":uid,"title":"Welcome Bonus: 10 Free Credits","amount":"+10 🪙","type":"credit","date":"Just now"})
            save_state(con, "aikya_credit_logs_clean", logs)
    except psycopg.errors.UniqueViolation:
        raise HTTPException(status_code=409, detail="An account already exists with this email. Please log in.")
    create_session(response, uid)
    return {"ok": True, "user": profile}


@app.post("/api/auth/login")
def login(body: AuthBody, request: Request, response: Response):
    validate_origin(request)
    with connect() as con:
        row = con.execute("SELECT user_id,email,password_salt,password_hash,profile_json FROM aikya_accounts WHERE email=%s", (body.email.strip().lower(),)).fetchone()
    if not row or not check_password(body.password, row["password_salt"], row["password_hash"]):
        raise HTTPException(status_code=401, detail="Email or password is incorrect.")
    profile = safe_profile(row["profile_json"] if isinstance(row["profile_json"], dict) else {})
    create_session(response, row["user_id"])
    return {"ok": True, "user": profile}


@app.get("/api/auth/me")
def me(request: Request):
    user = session_user(request)
    if not user: raise HTTPException(status_code=401, detail="Not logged in.")
    profile = user["profile_json"] if isinstance(user["profile_json"], dict) else {}
    return {"user": safe_profile(profile), "expires_at": user["expires_at"]}


@app.post("/api/auth/logout")
def logout(request: Request, response: Response):
    validate_origin(request)
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        with connect() as con: con.execute("DELETE FROM aikya_sessions WHERE token_hash=%s", (hashlib.sha256(token.encode()).hexdigest(),))
    response.delete_cookie(SESSION_COOKIE, path="/", httponly=True, secure=True, samesite="lax")
    return {"ok": True}


@app.get("/")
def home(): return FileResponse(INDEX_PATH, media_type="text/html")

@app.get("/index.html")
def index_html(): return FileResponse(INDEX_PATH, media_type="text/html")
