from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator
from urllib.parse import quote

from cryptography.fernet import Fernet, InvalidToken
from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, EmailStr, TypeAdapter


ROOT = Path(__file__).resolve().parent
STATIC_DIR = ROOT / "static"
DEFAULT_DATA_DIR = Path(os.getenv("TRUSTVAULT_DATA_DIR", ROOT / "data"))
DEFAULT_DB_PATH = DEFAULT_DATA_DIR / "trustvault.sqlite3"
MAX_UPLOAD_BYTES = 20 * 1024 * 1024
SESSION_HOURS = 12
PASSWORD_ITERATIONS = 600_000


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def timestamp(value: datetime | None = None) -> str:
    return (value or utc_now()).isoformat(timespec="seconds")


def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or secrets.token_bytes(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, PASSWORD_ITERATIONS)
    return f"{salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        salt_hex, digest_hex = stored.split("$", 1)
        expected = bytes.fromhex(digest_hex)
        actual = hashlib.pbkdf2_hmac(
            "sha256", password.encode(), bytes.fromhex(salt_hex), PASSWORD_ITERATIONS
        )
        return secrets.compare_digest(actual, expected)
    except (ValueError, TypeError):
        return False


def load_fernet(data_dir: Path, encryption_key: bytes | None = None) -> Fernet:
    configured_key = encryption_key or os.getenv("TRUSTVAULT_ENCRYPTION_KEY", "").encode()
    if configured_key:
        return Fernet(configured_key)

    data_dir.mkdir(parents=True, exist_ok=True)
    key_path = data_dir / "master.key"
    try:
        descriptor = os.open(key_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        key = key_path.read_bytes()
    else:
        key = Fernet.generate_key()
        with os.fdopen(descriptor, "wb") as key_file:
            key_file.write(key)
    return Fernet(key)


def canonical_json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)


@contextmanager
def connect(database_path: Path) -> Iterator[sqlite3.Connection]:
    connection = sqlite3.connect(database_path, timeout=10)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def initialize_database(database_path: Path, fernet: Fernet, seed: bool) -> None:
    database_path.parent.mkdir(parents=True, exist_ok=True)
    with connect(database_path) as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
                id TEXT PRIMARY KEY,
                email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                display_name TEXT NOT NULL,
                role TEXT NOT NULL CHECK (role IN ('admin', 'member')),
                password_hash TEXT NOT NULL,
                must_change_password INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY,
                user_id TEXT NOT NULL REFERENCES users(id),
                expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS documents (
                id TEXT PRIMARY KEY,
                title TEXT NOT NULL,
                filename TEXT NOT NULL,
                content_type TEXT NOT NULL,
                byte_size INTEGER NOT NULL,
                owner_id TEXT NOT NULL REFERENCES users(id),
                encrypted_content BLOB NOT NULL,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS shares (
                id TEXT PRIMARY KEY,
                document_id TEXT NOT NULL REFERENCES documents(id),
                user_id TEXT NOT NULL REFERENCES users(id),
                created_by TEXT NOT NULL REFERENCES users(id),
                created_at TEXT NOT NULL,
                expires_at TEXT,
                revoked_at TEXT
            );
            CREATE TABLE IF NOT EXISTS audit_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                actor_id TEXT,
                actor_email TEXT NOT NULL,
                action TEXT NOT NULL,
                document_id TEXT,
                metadata_json TEXT NOT NULL,
                occurred_at TEXT NOT NULL,
                previous_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS shares_user_document ON shares(user_id, document_id);
            CREATE INDEX IF NOT EXISTS audit_events_time ON audit_events(occurred_at DESC);
            CREATE TRIGGER IF NOT EXISTS audit_events_no_update
            BEFORE UPDATE ON audit_events BEGIN
                SELECT RAISE(ABORT, 'audit events are append-only');
            END;
            CREATE TRIGGER IF NOT EXISTS audit_events_no_delete
            BEFORE DELETE ON audit_events BEGIN
                SELECT RAISE(ABORT, 'audit events are append-only');
            END;
            """
        )
        user_columns = {row["name"] for row in connection.execute("PRAGMA table_info(users)")}
        if "must_change_password" not in user_columns:
            connection.execute(
                "ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0"
            )
        if not seed or connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]:
            return

        admin_id = "usr_admin"
        member_id = "usr_maya"
        connection.executemany(
            "INSERT INTO users (id, email, display_name, role, password_hash, created_at) VALUES (?, ?, ?, ?, ?, ?)",
            [
                (
                    admin_id,
                    "admin@trustvault.local",
                    "Jordan Lee",
                    "admin",
                    hash_password("VaultDemo!2026"),
                    timestamp(),
                ),
                (
                    member_id,
                    "maya@northstar.example",
                    "Maya Chen",
                    "member",
                    hash_password("Northstar!2026"),
                    timestamp(),
                ),
            ],
        )
        examples = [
            ("doc_contract", "Northstar · Services agreement", "services-agreement.txt", "Northstar demo agreement.\nAccess is granted to Maya Chen only.\n"),
            ("doc_salary", "2026 compensation letters", "compensation-letters.txt", "Fictional compensation sample.\nThis document is private to its owner.\n"),
            ("doc_drawing", "Orion · Assembly drawing notes", "orion-assembly-notes.txt", "Fictional design notes for the Orion assembly.\n"),
            ("doc_audit", "Q3 controls evidence", "controls-evidence.txt", "Fictional controls evidence index for Q3.\n"),
        ]
        for document_index, (document_id, title, filename, sample_text) in enumerate(examples):
            content = f"TrustVault demo file: {title}\nThis sample is not a real company record.\n{sample_text}".encode()
            connection.execute(
                "INSERT INTO documents VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    document_id,
                    title,
                    filename,
                    "text/plain",
                    len(content),
                    admin_id,
                    fernet.encrypt(content),
                    timestamp(utc_now() - timedelta(days=len(examples) - document_index)),
                ),
            )
        connection.execute(
            "INSERT INTO shares (id, document_id, user_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
            (
                "shr_northstar",
                "doc_contract",
                member_id,
                admin_id,
                timestamp(utc_now() - timedelta(days=2)),
                timestamp(utc_now() + timedelta(days=5)),
            ),
        )


def append_audit(
    connection: sqlite3.Connection,
    actor_id: str | None,
    actor_email: str,
    action: str,
    document_id: str | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    occurred_at = timestamp()
    metadata_json = canonical_json(metadata or {})
    previous = connection.execute(
        "SELECT event_hash FROM audit_events ORDER BY id DESC LIMIT 1"
    ).fetchone()
    previous_hash = previous["event_hash"] if previous else "0" * 64
    event = {
        "actor_email": actor_email,
        "action": action,
        "document_id": document_id,
        "metadata": json.loads(metadata_json),
        "occurred_at": occurred_at,
        "previous_hash": previous_hash,
    }
    event_hash = hashlib.sha256(canonical_json(event).encode()).hexdigest()
    connection.execute(
        "INSERT INTO audit_events (actor_id, actor_email, action, document_id, metadata_json, occurred_at, previous_hash, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (actor_id, actor_email, action, document_id, metadata_json, occurred_at, previous_hash, event_hash),
    )


def verify_audit_chain(connection: sqlite3.Connection) -> tuple[bool, int]:
    previous_hash = "0" * 64
    rows = connection.execute("SELECT * FROM audit_events ORDER BY id").fetchall()
    for row in rows:
        event = {
            "actor_email": row["actor_email"],
            "action": row["action"],
            "document_id": row["document_id"],
            "metadata": json.loads(row["metadata_json"]),
            "occurred_at": row["occurred_at"],
            "previous_hash": previous_hash,
        }
        calculated = hashlib.sha256(canonical_json(event).encode()).hexdigest()
        if row["previous_hash"] != previous_hash or row["event_hash"] != calculated:
            return False, len(rows)
        previous_hash = row["event_hash"]
    return True, len(rows)


def bootstrap_admin(database_path: Path, production_mode: bool) -> None:
    with connect(database_path) as connection:
        existing_admin = connection.execute(
            "SELECT 1 FROM users WHERE role = 'admin' LIMIT 1"
        ).fetchone()
        if existing_admin:
            return
        user_count = connection.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        if not production_mode:
            return
        if user_count:
            raise RuntimeError("Production database has users but no administrator; provision an admin before startup.")

        email = os.getenv("TRUSTVAULT_BOOTSTRAP_ADMIN_EMAIL", "").strip()
        name = os.getenv("TRUSTVAULT_BOOTSTRAP_ADMIN_NAME", "").strip()
        password = os.getenv("TRUSTVAULT_BOOTSTRAP_ADMIN_PASSWORD", "")
        if not email or not name or not password:
            raise RuntimeError(
                "Set TRUSTVAULT_BOOTSTRAP_ADMIN_EMAIL, TRUSTVAULT_BOOTSTRAP_ADMIN_NAME, and "
                "TRUSTVAULT_BOOTSTRAP_ADMIN_PASSWORD for the first production startup."
            )
        if len(password) < 20:
            raise RuntimeError("The bootstrap administrator password must be at least 20 characters.")
        try:
            validated_email = str(TypeAdapter(EmailStr).validate_python(email)).lower()
        except ValueError as error:
            raise RuntimeError("TRUSTVAULT_BOOTSTRAP_ADMIN_EMAIL must be a valid email address.") from error
        user_id = f"usr_{secrets.token_urlsafe(12)}"
        connection.execute(
            "INSERT INTO users (id, email, display_name, role, password_hash, must_change_password, created_at) "
            "VALUES (?, ?, ?, 'admin', ?, 1, ?)",
            (user_id, validated_email, name[:80], hash_password(password), timestamp()),
        )
        append_audit(connection, user_id, validated_email, "auth.admin_bootstrapped")


class ShareRequest(BaseModel):
    email: EmailStr
    expires_at: datetime | None = None


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


def create_app(
    database_path: Path | str = DEFAULT_DB_PATH,
    data_dir: Path | str = DEFAULT_DATA_DIR,
    seed: bool | None = None,
    encryption_key: bytes | None = None,
) -> FastAPI:
    production_mode = os.getenv("TRUSTVAULT_ENV", "development").lower() == "production"
    if seed is None:
        seed = os.getenv("TRUSTVAULT_DEMO", "0") == "1"
    if production_mode:
        if seed or os.getenv("TRUSTVAULT_DEMO", "0") == "1":
            raise RuntimeError("Demo mode must be disabled in production.")
        if os.getenv("TRUSTVAULT_COOKIE_SECURE") != "1":
            raise RuntimeError("Set TRUSTVAULT_COOKIE_SECURE=1 in production.")
        if not os.getenv("TRUSTVAULT_ENCRYPTION_KEY"):
            raise RuntimeError("Set TRUSTVAULT_ENCRYPTION_KEY using a managed secret in production.")

    database_path = Path(database_path)
    data_dir = Path(data_dir)
    fernet = load_fernet(data_dir, encryption_key)
    initialize_database(database_path, fernet, seed)
    if production_mode:
        with connect(database_path) as connection:
            seeded_account = connection.execute(
                "SELECT 1 FROM users WHERE email IN (?, ?) LIMIT 1",
                ("admin@trustvault.local", "maya@northstar.example"),
            ).fetchone()
            if seeded_account:
                raise RuntimeError("Demo accounts exist in the production database; migrate to a clean database first.")
        bootstrap_admin(database_path, production_mode=True)

    app = FastAPI(title="TrustVault", docs_url=None, redoc_url=None)
    app.state.database_path = database_path
    app.state.fernet = fernet
    app.state.demo_mode = seed

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' https://fonts.googleapis.com; "
            "font-src 'self' https://fonts.gstatic.com; img-src 'self' data:; "
            "connect-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'; form-action 'self'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        if production_mode:
            response.headers["Strict-Transport-Security"] = "max-age=31536000"
        if request.url.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        return response

    def csrf_check(request: Request) -> None:
        cookie = request.cookies.get("tv_csrf", "")
        header = request.headers.get("x-csrf-token", "")
        if not cookie or not header or not secrets.compare_digest(cookie, header):
            raise HTTPException(status_code=403, detail="CSRF validation failed")

    def current_user(request: Request) -> dict[str, str]:
        token = request.cookies.get("tv_session")
        if not token:
            raise HTTPException(status_code=401, detail="Sign in required")
        with connect(database_path) as connection:
            row = connection.execute(
                "SELECT u.id, u.email, u.display_name, u.role, u.must_change_password, s.expires_at "
                "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?",
                (hashlib.sha256(token.encode()).hexdigest(),),
            ).fetchone()
            if not row or row["expires_at"] <= timestamp():
                raise HTTPException(status_code=401, detail="Session expired")
            allowed_during_password_change = {"/api/me", "/api/account/password", "/api/logout"}
            if row["must_change_password"] and request.url.path not in allowed_during_password_change:
                raise HTTPException(status_code=403, detail="Change your initial password before continuing")
            return dict(row)

    def require_admin(user: dict[str, str] = Depends(current_user)) -> dict[str, str]:
        if user["role"] != "admin":
            raise HTTPException(status_code=403, detail="Administrator access required")
        return user

    def active_access(connection: sqlite3.Connection, document_id: str, user_id: str) -> bool:
        owner = connection.execute(
            "SELECT 1 FROM documents WHERE id = ? AND owner_id = ?", (document_id, user_id)
        ).fetchone()
        if owner:
            return True
        return connection.execute(
            "SELECT 1 FROM shares WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL "
            "AND (expires_at IS NULL OR expires_at > ?) LIMIT 1",
            (document_id, user_id, timestamp()),
        ).fetchone() is not None

    @app.get("/api/csrf")
    def csrf_token(response: Response) -> dict[str, str]:
        token = secrets.token_urlsafe(32)
        response.set_cookie(
            "tv_csrf", token, httponly=False, secure=os.getenv("TRUSTVAULT_COOKIE_SECURE") == "1",
            samesite="strict", max_age=SESSION_HOURS * 60 * 60, path="/",
        )
        return {"csrf_token": token}

    @app.get("/api/config")
    def public_config() -> dict[str, bool]:
        return {"demo_mode": seed}

    @app.get("/healthz")
    def health_check() -> dict[str, str]:
        with connect(database_path) as connection:
            connection.execute("SELECT 1").fetchone()
        probe = fernet.encrypt(b"health-check")
        fernet.decrypt(probe)
        return {"status": "ok"}

    @app.post("/api/login")
    def login(request: Request, response: Response, payload: dict[str, str]):
        csrf_check(request)
        email = payload.get("email", "").strip().lower()
        password = payload.get("password", "")
        with connect(database_path) as connection:
            user = connection.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
            if not user or not verify_password(password, user["password_hash"]):
                append_audit(connection, None, email or "unknown", "auth.login_failed")
            else:
                token = secrets.token_urlsafe(32)
                expires_at = timestamp(utc_now() + timedelta(hours=SESSION_HOURS))
                connection.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
                connection.execute(
                    "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                    (hashlib.sha256(token.encode()).hexdigest(), user["id"], expires_at),
                )
                append_audit(connection, user["id"], user["email"], "auth.login")
                response.set_cookie(
                    "tv_session", token, httponly=True, secure=os.getenv("TRUSTVAULT_COOKIE_SECURE") == "1",
                    samesite="strict", max_age=SESSION_HOURS * 60 * 60, path="/",
                )
                return {
                    "id": user["id"], "email": user["email"], "name": user["display_name"],
                    "role": user["role"], "must_change_password": bool(user["must_change_password"]),
                }
        raise HTTPException(status_code=401, detail="Email or password is incorrect")

    @app.post("/api/logout")
    def logout(request: Request, response: Response, user: dict[str, str] = Depends(current_user)):
        csrf_check(request)
        token = request.cookies.get("tv_session", "")
        with connect(database_path) as connection:
            connection.execute("DELETE FROM sessions WHERE token_hash = ?", (hashlib.sha256(token.encode()).hexdigest(),))
            append_audit(connection, user["id"], user["email"], "auth.logout")
        secure_cookie = os.getenv("TRUSTVAULT_COOKIE_SECURE") == "1"
        response.delete_cookie("tv_session", path="/", secure=secure_cookie, samesite="strict")
        response.delete_cookie("tv_csrf", path="/", secure=secure_cookie, samesite="strict")
        return {"ok": True}

    @app.get("/api/me")
    def me(user: dict[str, str] = Depends(current_user)):
        return {
            "id": user["id"], "email": user["email"], "name": user["display_name"],
            "role": user["role"], "must_change_password": bool(user["must_change_password"]),
        }

    @app.post("/api/account/password")
    def change_password(
        payload: PasswordChangeRequest,
        request: Request,
        response: Response,
        user: dict[str, str] = Depends(current_user),
    ):
        csrf_check(request)
        if len(payload.new_password) < 20:
            raise HTTPException(status_code=422, detail="New passwords must be at least 20 characters")
        if secrets.compare_digest(payload.current_password, payload.new_password):
            raise HTTPException(status_code=422, detail="New password must differ from the current password")
        token = secrets.token_urlsafe(32)
        expires_at = timestamp(utc_now() + timedelta(hours=SESSION_HOURS))
        with connect(database_path) as connection:
            row = connection.execute("SELECT password_hash FROM users WHERE id = ?", (user["id"],)).fetchone()
            if not row or not verify_password(payload.current_password, row["password_hash"]):
                raise HTTPException(status_code=403, detail="Current password is incorrect")
            connection.execute(
                "UPDATE users SET password_hash = ?, must_change_password = 0 WHERE id = ?",
                (hash_password(payload.new_password), user["id"]),
            )
            connection.execute("DELETE FROM sessions WHERE user_id = ?", (user["id"],))
            connection.execute(
                "INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)",
                (hashlib.sha256(token.encode()).hexdigest(), user["id"], expires_at),
            )
            append_audit(connection, user["id"], user["email"], "auth.password_changed")
        response.set_cookie(
            "tv_session", token, httponly=True, secure=os.getenv("TRUSTVAULT_COOKIE_SECURE") == "1",
            samesite="strict", max_age=SESSION_HOURS * 60 * 60, path="/",
        )
        return {"ok": True}

    @app.get("/api/documents")
    def list_documents(user: dict[str, str] = Depends(current_user)):
        with connect(database_path) as connection:
            rows = connection.execute(
                "SELECT DISTINCT d.id, d.title, d.filename, d.content_type, d.byte_size, d.owner_id, d.created_at, "
                "u.display_name AS owner_name, "
                "(SELECT COUNT(*) FROM shares s2 WHERE s2.document_id = d.id AND s2.revoked_at IS NULL "
                "AND (s2.expires_at IS NULL OR s2.expires_at > ?)) AS shared_count, "
                "(SELECT occurred_at FROM audit_events a WHERE a.document_id = d.id AND a.action = 'document.read' "
                "ORDER BY a.id DESC LIMIT 1) AS last_accessed "
                "FROM documents d JOIN users u ON u.id = d.owner_id "
                "LEFT JOIN shares s ON s.document_id = d.id AND s.user_id = ? AND s.revoked_at IS NULL "
                "AND (s.expires_at IS NULL OR s.expires_at > ?) "
                "WHERE d.owner_id = ? OR s.id IS NOT NULL ORDER BY d.created_at DESC",
                (timestamp(), user["id"], timestamp(), user["id"]),
            ).fetchall()
            return {
                "documents": [
                    {
                        "id": row["id"],
                        "title": row["title"],
                        "filename": row["filename"],
                        "content_type": row["content_type"],
                        "byte_size": row["byte_size"],
                        "owner_id": row["owner_id"],
                        "owner_name": row["owner_name"],
                        "created_at": row["created_at"],
                        "shared_count": row["shared_count"] if row["owner_id"] == user["id"] else None,
                        "last_accessed": row["last_accessed"],
                        "access": "owner" if row["owner_id"] == user["id"] else "shared",
                    }
                    for row in rows
                ]
            }

    @app.post("/api/documents")
    async def upload_document(
        request: Request,
        title: str = Form(...),
        file: UploadFile = File(...),
        user: dict[str, str] = Depends(current_user),
    ):
        csrf_check(request)
        clean_title = title.strip()
        if not clean_title or len(clean_title) > 160:
            raise HTTPException(status_code=422, detail="Title must be between 1 and 160 characters")
        content = await file.read(MAX_UPLOAD_BYTES + 1)
        if not content or len(content) > MAX_UPLOAD_BYTES:
            raise HTTPException(status_code=413, detail="Files must be between 1 byte and 20 MB")
        filename = Path(file.filename or "document").name[:180]
        document_id = f"doc_{secrets.token_urlsafe(12)}"
        with connect(database_path) as connection:
            connection.execute(
                "INSERT INTO documents (id, title, filename, content_type, byte_size, owner_id, encrypted_content, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    document_id,
                    clean_title,
                    filename,
                    file.content_type or "application/octet-stream",
                    len(content),
                    user["id"],
                    request.app.state.fernet.encrypt(content),
                    timestamp(),
                ),
            )
            append_audit(connection, user["id"], user["email"], "document.uploaded", document_id, {"bytes": len(content)})
        return {"id": document_id, "title": clean_title, "filename": filename}

    @app.get("/api/documents/{document_id}/file")
    def read_document(
        document_id: str,
        request: Request,
        user: dict[str, str] = Depends(current_user),
    ):
        denied = False
        with connect(database_path) as connection:
            document = connection.execute("SELECT * FROM documents WHERE id = ?", (document_id,)).fetchone()
            if not document:
                raise HTTPException(status_code=404, detail="Document not found")
            if not active_access(connection, document_id, user["id"]):
                append_audit(
                    connection, user["id"], user["email"], "document.access_denied", document_id,
                    {"remote_address": request.client.host if request.client else "unknown"},
                )
                denied = True
            else:
                try:
                    content = request.app.state.fernet.decrypt(document["encrypted_content"])
                except InvalidToken as error:
                    raise HTTPException(status_code=500, detail="Document integrity check failed") from error
                append_audit(connection, user["id"], user["email"], "document.read", document_id)
        if denied:
            raise HTTPException(status_code=404, detail="Document not found")
        return Response(
            content=content,
            media_type="application/octet-stream",
            headers={
                "Content-Disposition": f"attachment; filename*=UTF-8''{quote(document['filename'])}",
                "Cache-Control": "private, no-store",
                "X-Content-Type-Options": "nosniff",
            },
        )

    @app.get("/api/documents/{document_id}/shares")
    def list_shares(document_id: str, user: dict[str, str] = Depends(current_user)):
        with connect(database_path) as connection:
            document = connection.execute(
                "SELECT id FROM documents WHERE id = ? AND owner_id = ?", (document_id, user["id"])
            ).fetchone()
            if not document:
                raise HTTPException(status_code=404, detail="Document not found")
            rows = connection.execute(
                "SELECT s.id, u.email, u.display_name, s.created_at, s.expires_at, s.revoked_at "
                "FROM shares s JOIN users u ON u.id = s.user_id WHERE s.document_id = ? ORDER BY s.created_at DESC",
                (document_id,),
            ).fetchall()
            return {"shares": [dict(row) for row in rows]}

    @app.post("/api/documents/{document_id}/shares")
    def create_share(
        document_id: str,
        payload: ShareRequest,
        request: Request,
        user: dict[str, str] = Depends(current_user),
    ):
        csrf_check(request)
        with connect(database_path) as connection:
            document = connection.execute(
                "SELECT title FROM documents WHERE id = ? AND owner_id = ?", (document_id, user["id"])
            ).fetchone()
            if not document:
                raise HTTPException(status_code=404, detail="Document not found")
            recipient = connection.execute("SELECT id, email FROM users WHERE email = ?", (str(payload.email),)).fetchone()
            if not recipient:
                raise HTTPException(status_code=404, detail="No account exists for that email")
            if recipient["id"] == user["id"]:
                raise HTTPException(status_code=422, detail="You already own this document")
            expires_at = None
            if payload.expires_at:
                if payload.expires_at.tzinfo is None:
                    raise HTTPException(status_code=422, detail="Expiry must include a timezone")
                expiry = payload.expires_at.astimezone(timezone.utc)
                if expiry <= utc_now() or expiry > utc_now() + timedelta(days=365):
                    raise HTTPException(status_code=422, detail="Expiry must be within the next 365 days")
                expires_at = timestamp(expiry)
            existing = connection.execute(
                "SELECT id FROM shares WHERE document_id = ? AND user_id = ? AND revoked_at IS NULL "
                "AND (expires_at IS NULL OR expires_at > ?)",
                (document_id, recipient["id"], timestamp()),
            ).fetchone()
            if existing:
                raise HTTPException(status_code=409, detail="This person already has access")
            share_id = f"shr_{secrets.token_urlsafe(10)}"
            connection.execute(
                "INSERT INTO shares (id, document_id, user_id, created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?)",
                (share_id, document_id, recipient["id"], user["id"], timestamp(), expires_at),
            )
            append_audit(
                connection, user["id"], user["email"], "document.shared", document_id,
                {"recipient": recipient["email"], "expires_at": expires_at},
            )
        return {"id": share_id, "email": recipient["email"], "expires_at": expires_at}

    @app.delete("/api/documents/{document_id}/shares/{share_id}")
    def revoke_share(
        document_id: str,
        share_id: str,
        request: Request,
        user: dict[str, str] = Depends(current_user),
    ):
        csrf_check(request)
        with connect(database_path) as connection:
            share = connection.execute(
                "SELECT s.id, u.email FROM shares s JOIN users u ON u.id = s.user_id "
                "JOIN documents d ON d.id = s.document_id "
                "WHERE s.id = ? AND s.document_id = ? AND d.owner_id = ? AND s.revoked_at IS NULL",
                (share_id, document_id, user["id"]),
            ).fetchone()
            if not share:
                raise HTTPException(status_code=404, detail="Share not found")
            revoked_at = timestamp()
            connection.execute("UPDATE shares SET revoked_at = ? WHERE id = ?", (revoked_at, share_id))
            append_audit(
                connection, user["id"], user["email"], "document.share_revoked", document_id,
                {"recipient": share["email"], "share_id": share_id},
            )
        return {"ok": True}

    @app.get("/api/audit")
    def list_audit(user: dict[str, str] = Depends(current_user)):
        with connect(database_path) as connection:
            if user["role"] == "admin":
                scope_clause = ""
                parameters: tuple[str, ...] = ()
            else:
                scope_clause = (
                    "WHERE a.actor_id = ? OR (a.document_id IS NOT NULL AND "
                    "(d.owner_id = ? OR EXISTS (SELECT 1 FROM shares s WHERE s.document_id = a.document_id "
                    "AND s.user_id = ? AND s.revoked_at IS NULL AND (s.expires_at IS NULL OR s.expires_at > ?))))"
                )
                parameters = (user["id"], user["id"], user["id"], timestamp())
            rows = connection.execute(
                "SELECT a.id, a.actor_email, a.action, a.document_id, d.title AS document_title, "
                "a.metadata_json, a.occurred_at, a.event_hash "
                f"FROM audit_events a LEFT JOIN documents d ON d.id = a.document_id {scope_clause} "
                "ORDER BY a.id DESC LIMIT 200",
                parameters,
            ).fetchall()
            integrity = None
            if user["role"] == "admin":
                valid, checked = verify_audit_chain(connection)
                integrity = {"valid": valid, "events_checked": checked}
            return {
                "events": [
                    {
                        "id": row["id"],
                        "actor_email": row["actor_email"],
                        "action": row["action"],
                        "document_id": row["document_id"],
                        "document_title": row["document_title"],
                        "metadata": json.loads(row["metadata_json"]),
                        "occurred_at": row["occurred_at"],
                        "event_hash": row["event_hash"],
                    }
                    for row in rows
                ],
                "integrity": integrity,
            }

    @app.get("/api/audit/verify")
    def audit_integrity(user: dict[str, str] = Depends(require_admin)):
        with connect(database_path) as connection:
            valid, checked = verify_audit_chain(connection)
        return {"valid": valid, "events_checked": checked}

    app.mount("/", StaticFiles(directory=STATIC_DIR, html=True), name="static")
    return app


app = create_app()