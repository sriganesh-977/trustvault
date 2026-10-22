from pathlib import Path
from datetime import datetime, timedelta, timezone
import hashlib
import json

import pytest
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient
import pyotp

from app import canonical_json, create_app


ADMIN_EMAIL = "admin@trustvault.local"
ADMIN_PASSWORD = "VaultDemo!2026"
MEMBER_EMAIL = "maya@northstar.example"
MEMBER_PASSWORD = "Northstar!2026"


def login(client: TestClient, email: str, password: str) -> dict[str, object]:
    token = client.get("/api/csrf").json()["csrf_token"]
    response = client.post(
        "/api/login",
        headers={"X-CSRF-Token": token},
        json={"email": email, "password": password},
    )
    assert response.status_code == 200
    return response.json()


def csrf_header(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.get("/api/csrf").json()["csrf_token"]}


def test_exact_document_grant_revocation_and_audit_chain(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "trustvault.sqlite3",
        data_dir=tmp_path / "data",
        seed=True,
    )
    client = TestClient(app)
    assert client.get("/api/config").json() == {"demo_mode": True, "mfa_required": False}
    login(client, MEMBER_EMAIL, MEMBER_PASSWORD)

    inventory = client.get("/api/documents").json()["documents"]
    assert [document["id"] for document in inventory] == ["doc_contract"]

    denied = client.get("/api/documents/doc_salary/file")
    assert denied.status_code == 404
    assert denied.content != (
        b"TrustVault demo file: 2026 compensation letters\n"
        b"This sample is not a real company record.\n"
        b"Fictional compensation sample.\nThis document is private to its owner.\n"
    )

    member_audit = client.get("/api/audit").json()
    assert member_audit["integrity"] is None
    assert all(event["actor_email"] != ADMIN_EMAIL for event in member_audit["events"])
    client.post("/api/logout", headers=csrf_header(client))

    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    grant = client.post(
        "/api/documents/doc_salary/shares",
        headers=csrf_header(client),
        json={"email": MEMBER_EMAIL},
    )
    assert grant.status_code == 200
    share_id = grant.json()["id"]
    client.post("/api/logout", headers=csrf_header(client))
    login(client, MEMBER_EMAIL, MEMBER_PASSWORD)
    downloaded = client.get("/api/documents/doc_salary/file")
    assert downloaded.status_code == 200
    assert b"compensation letters" in downloaded.content
    assert client.get("/api/documents/doc_audit/file").status_code == 404

    client.post("/api/logout", headers=csrf_header(client))
    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    revoked = client.delete(
        f"/api/documents/doc_salary/shares/{share_id}",
        headers=csrf_header(client),
    )
    assert revoked.status_code == 200

    client.post("/api/logout", headers=csrf_header(client))
    login(client, MEMBER_EMAIL, MEMBER_PASSWORD)
    assert client.get("/api/documents/doc_salary/file").status_code == 404

    client.post("/api/logout", headers=csrf_header(client))
    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    audit = client.get("/api/audit").json()
    actions = [event["action"] for event in audit["events"]]
    assert actions.count("document.access_denied") == 3
    assert "document.shared" in actions
    assert "document.share_revoked" in actions
    assert "document.read" in actions
    assert audit["integrity"]["valid"] is True
    assert audit["integrity"]["events_checked"] == len(actions)


def test_audit_events_cannot_be_updated_or_deleted(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "trustvault.sqlite3",
        data_dir=tmp_path / "data",
        seed=True,
    )
    client = TestClient(app)
    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    client.get("/api/audit")

    with app.state.database_path.open("rb") as database_file:
        assert database_file.read(16) == b"SQLite format 3\x00"

    import sqlite3

    connection = sqlite3.connect(app.state.database_path)
    connection.row_factory = sqlite3.Row
    try:
        for statement in (
            "UPDATE audit_events SET actor_email = 'changed@example.com'",
            "DELETE FROM audit_events",
        ):
            try:
                connection.execute(statement)
                connection.commit()
            except sqlite3.IntegrityError as error:
                assert "append-only" in str(error)
                connection.rollback()
            else:
                raise AssertionError("audit mutation unexpectedly succeeded")
        connection.execute("DROP TRIGGER audit_events_no_update")
        row = connection.execute("SELECT * FROM audit_events WHERE id = 1").fetchone()
        event = {
            "actor_id": "forged-actor",
            "actor_email": "changed@example.com",
            "action": row["action"],
            "document_id": row["document_id"],
            "metadata": json.loads(row["metadata_json"]),
            "occurred_at": row["occurred_at"],
            "previous_hash": row["previous_hash"],
        }
        rewritten_hash = hashlib.sha256(canonical_json(event).encode()).hexdigest()
        connection.execute(
            "UPDATE audit_events SET actor_id = ?, actor_email = ?, event_hash = ? WHERE id = 1",
            ("forged-actor", "changed@example.com", rewritten_hash),
        )
        connection.commit()
    finally:
        connection.close()
    assert client.get("/api/audit").json()["integrity"]["valid"] is False


def test_upload_is_encrypted_and_private_to_owner(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "trustvault.sqlite3",
        data_dir=tmp_path / "data",
        seed=True,
    )
    client = TestClient(app)
    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    secret_content = b"new confidential document payload"
    uploaded = client.post(
        "/api/documents",
        headers=csrf_header(client),
        data={"title": "Acquisition plan"},
        files={"file": ("acquisition.txt", secret_content, "text/plain")},
    )
    assert uploaded.status_code == 200
    document_id = uploaded.json()["id"]

    import sqlite3

    connection = sqlite3.connect(app.state.database_path)
    try:
        encrypted = connection.execute(
            "SELECT encrypted_content FROM documents WHERE id = ?", (document_id,)
        ).fetchone()[0]
        assert secret_content not in encrypted
    finally:
        connection.close()
    assert client.get(f"/api/documents/{document_id}/file").content == secret_content

    client.post("/api/logout", headers=csrf_header(client))
    login(client, MEMBER_EMAIL, MEMBER_PASSWORD)
    visible_ids = {item["id"] for item in client.get("/api/documents").json()["documents"]}
    assert document_id not in visible_ids
    assert client.get(f"/api/documents/{document_id}/file").status_code == 404


def test_expired_grant_is_denied(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "trustvault.sqlite3",
        data_dir=tmp_path / "data",
        seed=True,
    )
    client = TestClient(app)
    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    expires_at = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
    grant = client.post(
        "/api/documents/doc_salary/shares",
        headers=csrf_header(client),
        json={"email": MEMBER_EMAIL, "expires_at": expires_at},
    )
    assert grant.status_code == 200

    import sqlite3

    connection = sqlite3.connect(app.state.database_path)
    try:
        connection.execute(
            "UPDATE shares SET expires_at = ? WHERE id = ?",
            ((datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(), grant.json()["id"]),
        )
        connection.commit()
    finally:
        connection.close()

    client.post("/api/logout", headers=csrf_header(client))
    login(client, MEMBER_EMAIL, MEMBER_PASSWORD)
    assert client.get("/api/documents/doc_salary/file").status_code == 404


def test_production_requires_secure_runtime_configuration(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("TRUSTVAULT_ENV", "production")
    monkeypatch.setenv("TRUSTVAULT_DEMO", "0")
    monkeypatch.delenv("TRUSTVAULT_COOKIE_SECURE", raising=False)
    monkeypatch.delenv("TRUSTVAULT_ENCRYPTION_KEY", raising=False)

    with pytest.raises(RuntimeError, match="TRUSTVAULT_COOKIE_SECURE"):
        create_app(
            database_path=tmp_path / "trustvault.sqlite3",
            data_dir=tmp_path / "data",
            seed=False,
        )


def test_production_rejects_seeded_demo_accounts(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    database_path = tmp_path / "trustvault.sqlite3"
    data_dir = tmp_path / "data"
    create_app(database_path=database_path, data_dir=data_dir, seed=True)

    monkeypatch.setenv("TRUSTVAULT_ENV", "production")
    monkeypatch.setenv("TRUSTVAULT_DEMO", "0")
    monkeypatch.setenv("TRUSTVAULT_COOKIE_SECURE", "1")
    monkeypatch.setenv("TRUSTVAULT_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("TRUSTVAULT_AUDIT_KEY", Fernet.generate_key().decode())

    with pytest.raises(RuntimeError, match="Demo accounts exist"):
        create_app(database_path=database_path, data_dir=data_dir, seed=False)


def test_production_bootstraps_unique_admin_without_demo_users(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("TRUSTVAULT_ENV", "production")
    monkeypatch.setenv("TRUSTVAULT_DEMO", "0")
    monkeypatch.setenv("TRUSTVAULT_COOKIE_SECURE", "1")
    monkeypatch.setenv("TRUSTVAULT_ENCRYPTION_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("TRUSTVAULT_AUDIT_KEY", Fernet.generate_key().decode())
    monkeypatch.setenv("TRUSTVAULT_BOOTSTRAP_ADMIN_EMAIL", "security@example.com")
    monkeypatch.setenv("TRUSTVAULT_BOOTSTRAP_ADMIN_NAME", "Security Admin")
    monkeypatch.setenv("TRUSTVAULT_BOOTSTRAP_ADMIN_PASSWORD", "a-long-random-bootstrap-password")

    app = create_app(
        database_path=tmp_path / "trustvault.sqlite3",
        data_dir=tmp_path / "data",
    )
    client = TestClient(app, base_url="https://testserver")
    assert client.get("/api/config").json() == {"demo_mode": False, "mfa_required": True}
    assert client.get("/api/documents").status_code == 401

    login_result = login(client, "security@example.com", "a-long-random-bootstrap-password")
    assert login_result["must_enroll_mfa"] is True
    assert client.get("/api/me").json()["must_change_password"] is True
    assert client.get("/api/documents").status_code == 403
    change = client.post(
        "/api/account/password",
        headers=csrf_header(client),
        json={
            "current_password": "a-long-random-bootstrap-password",
            "new_password": "another-long-random-production-password",
        },
    )
    assert change.status_code == 200
    assert client.get("/api/me").json()["must_change_password"] is False
    assert client.get("/api/me").json()["must_enroll_mfa"] is True
    assert client.get("/api/documents").status_code == 403

    enrollment = client.post("/api/account/mfa/enroll", headers=csrf_header(client))
    assert enrollment.status_code == 200
    secret = enrollment.json()["secret"]
    assert enrollment.json()["provisioning_uri"].startswith("otpauth://totp/")

    import sqlite3

    connection = sqlite3.connect(app.state.database_path)
    try:
        encrypted_secret = connection.execute(
            "SELECT mfa_secret_encrypted FROM users WHERE email = ?", ("security@example.com",)
        ).fetchone()[0]
        assert secret.encode() not in encrypted_secret
    finally:
        connection.close()

    invalid_code = client.post(
        "/api/account/mfa/confirm",
        headers=csrf_header(client),
        json={"code": "000000"},
    )
    assert invalid_code.status_code == 422
    confirmed = client.post(
        "/api/account/mfa/confirm",
        headers=csrf_header(client),
        json={"code": pyotp.TOTP(secret).now()},
    )
    assert confirmed.status_code == 200
    assert client.get("/api/me").json()["must_enroll_mfa"] is False
    assert client.get("/api/documents").json() == {"documents": []}
    assert client.cookies.get("tv_session") is not None

    client.post("/api/logout", headers=csrf_header(client))
    replayed_code = client.post(
        "/api/login",
        headers=csrf_header(client),
        json={
            "email": "security@example.com",
            "password": "another-long-random-production-password",
            "mfa_code": pyotp.TOTP(secret).now(),
        },
    )
    assert replayed_code.status_code == 401
    bad_mfa_login = client.post(
        "/api/login",
        headers=csrf_header(client),
        json={"email": "security@example.com", "password": "another-long-random-production-password", "mfa_code": "000000"},
    )
    assert bad_mfa_login.status_code == 401
    good_mfa_login = client.post(
        "/api/login",
        headers=csrf_header(client),
        json={
            "email": "security@example.com",
            "password": "another-long-random-production-password",
            "mfa_code": pyotp.TOTP(secret).generate_otp(
                pyotp.TOTP(secret).timecode(datetime.now(timezone.utc)) + 1
            ),
        },
    )
    assert good_mfa_login.status_code == 200


def test_password_change_rotates_sessions_and_is_audited(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "trustvault.sqlite3",
        data_dir=tmp_path / "data",
        seed=True,
    )
    client = TestClient(app)
    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    old_session = client.cookies.get("tv_session")

    weak = client.post(
        "/api/account/password",
        headers=csrf_header(client),
        json={"current_password": ADMIN_PASSWORD, "new_password": "too-short"},
    )
    assert weak.status_code == 422

    changed_password = "a-long-random-replacement-password"
    changed = client.post(
        "/api/account/password",
        headers=csrf_header(client),
        json={"current_password": ADMIN_PASSWORD, "new_password": changed_password},
    )
    assert changed.status_code == 200
    assert client.cookies.get("tv_session") != old_session
    assert client.get("/api/me").status_code == 200

    old_client = TestClient(app)
    old_client.cookies.set("tv_session", old_session)
    assert old_client.get("/api/me").status_code == 401
    assert old_client.get("/api/csrf").status_code == 200
    assert old_client.post(
        "/api/login",
        headers=csrf_header(old_client),
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    ).status_code == 401

    actions = [event["action"] for event in client.get("/api/audit").json()["events"]]
    assert "auth.password_changed" in actions


def test_repeated_login_failures_lock_only_the_target_account(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "trustvault.sqlite3",
        data_dir=tmp_path / "data",
        seed=True,
    )
    client = TestClient(app)
    headers = csrf_header(client)
    for _ in range(5):
        response = client.post(
            "/api/login",
            headers=headers,
            json={"email": ADMIN_EMAIL, "password": "incorrect-password"},
        )
        assert response.status_code == 401

    blocked = client.post(
        "/api/login",
        headers=headers,
        json={"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD},
    )
    assert blocked.status_code == 429
    assert blocked.headers["Retry-After"] == "900"

    other_account = client.post(
        "/api/login",
        headers=headers,
        json={"email": MEMBER_EMAIL, "password": MEMBER_PASSWORD},
    )
    assert other_account.status_code == 200


def test_admin_owner_editor_viewer_permissions_and_immediate_revocation(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "trustvault.sqlite3",
        data_dir=tmp_path / "data",
        seed=True,
    )
    client = TestClient(app)
    login(client, "owner@trustvault.local", "OwnerDemo!2026")
    upload = client.post(
        "/api/documents",
        headers=csrf_header(client),
        data={"title": "Private owner notes", "category": "Legal"},
        files={"file": ("notes.txt", b"owner-only content", "text/plain")},
    )
    assert upload.status_code == 200
    private_id = upload.json()["id"]

    seeded_shares = client.get("/api/documents/doc_salary/shares").json()["shares"]
    seed_editor_grant = next(share for share in seeded_shares if share["email"] == "editor@northstar.example")
    assert client.delete(
        f"/api/documents/doc_salary/shares/{seed_editor_grant['id']}",
        headers=csrf_header(client),
    ).status_code == 200

    editor_grant = client.post(
        "/api/documents/doc_salary/shares",
        headers=csrf_header(client),
        json={"email": "editor@northstar.example", "permission": "edit"},
    )
    assert editor_grant.status_code == 200
    editor_share_id = editor_grant.json()["id"]

    login(client, "editor@northstar.example", "EditorDemo!2026")
    editor_ids = {row["id"] for row in client.get("/api/documents").json()["documents"]}
    assert editor_ids == {"doc_salary"}
    assert client.get(f"/api/documents/{private_id}/file").status_code == 404
    assert client.patch(
        f"/api/documents/{private_id}",
        headers=csrf_header(client),
        json={"title": "stolen"},
    ).status_code == 404
    assert client.get("/api/documents/doc_salary/file").status_code == 200
    assert client.patch(
        "/api/documents/doc_salary",
        headers=csrf_header(client),
        json={"title": "Edited with grant", "category": "Compensation"},
    ).status_code == 200
    replaced = client.put(
        "/api/documents/doc_salary/file",
        headers=csrf_header(client),
        files={"file": ("replacement.txt", b"editor replacement", "text/plain")},
    )
    assert replaced.status_code == 200
    assert client.get("/api/documents/doc_salary/file").content == b"editor replacement"
    assert client.delete("/api/documents/doc_salary", headers=csrf_header(client)).status_code == 404
    assert client.get("/api/documents/doc_salary/shares").status_code == 404
    assert client.post(
        "/api/documents/doc_salary/shares",
        headers=csrf_header(client),
        json={"email": MEMBER_EMAIL},
    ).status_code == 404
    assert client.delete(
        f"/api/documents/doc_salary/shares/{editor_share_id}",
        headers=csrf_header(client),
    ).status_code == 404

    login(client, MEMBER_EMAIL, MEMBER_PASSWORD)
    viewer_ids = {row["id"] for row in client.get("/api/documents").json()["documents"]}
    assert viewer_ids == {"doc_contract"}
    assert client.get("/api/documents/doc_contract/file").status_code == 200
    assert client.get("/api/documents/doc_salary/file").status_code == 404
    assert client.patch(
        "/api/documents/doc_contract",
        headers=csrf_header(client),
        json={"title": "viewer escalation"},
    ).status_code == 404
    assert client.put(
        "/api/documents/doc_contract/file",
        headers=csrf_header(client),
        files={"file": ("replacement.txt", b"attempted replacement", "text/plain")},
    ).status_code == 404
    assert client.delete("/api/documents/doc_contract", headers=csrf_header(client)).status_code == 404
    assert client.get("/api/documents/doc_contract/shares").status_code == 404

    login(client, "owner@trustvault.local", "OwnerDemo!2026")
    revoked = client.delete(
        f"/api/documents/doc_salary/shares/{editor_share_id}",
        headers=csrf_header(client),
    )
    assert revoked.status_code == 200
    login(client, "editor@northstar.example", "EditorDemo!2026")
    assert client.get("/api/documents/doc_salary/file").status_code == 404
    assert client.patch(
        "/api/documents/doc_salary",
        headers=csrf_header(client),
        json={"title": "stale grant"},
    ).status_code == 404

    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    admin_ids = {row["id"] for row in client.get("/api/documents").json()["documents"]}
    assert {"doc_contract", "doc_salary", "doc_drawing", "doc_audit", private_id}.issubset(admin_ids)
    assert client.get(f"/api/documents/{private_id}/file").status_code == 200
    assert client.get("/api/documents/doc_salary/shares").status_code == 200
    audit_actions = [event["action"] for event in client.get("/api/audit").json()["events"]]
    assert "document.change_denied" in audit_actions
    assert "document.delete_denied" in audit_actions
    assert "permission.list_denied" in audit_actions
    assert "permission.grant_denied" in audit_actions
    assert "permission.revoke_denied" in audit_actions


def test_unknown_document_access_is_non_disclosing_and_audited(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "trustvault.sqlite3",
        data_dir=tmp_path / "data",
        seed=True,
    )
    client = TestClient(app)
    login(client, MEMBER_EMAIL, MEMBER_PASSWORD)
    missing = client.get("/api/documents/doc_does_not_exist/file")
    assert missing.status_code == 404
    assert missing.json() == {"detail": "Document not found"}

    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    audit = client.get("/api/audit").json()
    denied = next(event for event in audit["events"] if event["action"] == "document.access_denied")
    assert denied["document_id"] == "doc_does_not_exist"
    assert denied["actor_email"] == MEMBER_EMAIL
    assert audit["integrity"]["valid"] is True


def test_document_search_filters_are_server_scoped(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "trustvault.sqlite3",
        data_dir=tmp_path / "data",
        seed=True,
    )
    client = TestClient(app)
    login(client, MEMBER_EMAIL, MEMBER_PASSWORD)

    visible = client.get("/api/documents?q=salary").json()["documents"]
    assert visible == []
    visible = client.get("/api/documents?category=Contracts").json()["documents"]
    assert [item["id"] for item in visible] == ["doc_contract"]
    visible = client.get("/api/documents?owner=Taylor").json()["documents"]
    assert [item["id"] for item in visible] == ["doc_contract"]
    assert client.get("/api/documents?date_from=not-a-date").status_code == 422

    client.post("/api/logout", headers=csrf_header(client))
    login(client, ADMIN_EMAIL, ADMIN_PASSWORD)
    all_docs = client.get("/api/documents?category=Finance").json()["documents"]
    assert [item["id"] for item in all_docs] == ["doc_salary"]
    owner_docs = client.get("/api/documents?owner=Taylor").json()["documents"]
    assert len(owner_docs) == 4


def test_upload_validation_rejects_executables_and_mismatched_content(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "trustvault.sqlite3",
        data_dir=tmp_path / "data",
        seed=True,
    )
    client = TestClient(app)
    login(client, "owner@trustvault.local", "OwnerDemo!2026")
    headers = csrf_header(client)

    executable = client.post(
        "/api/documents",
        headers=headers,
        data={"title": "Executable"},
        files={"file": ("payload.exe", b"MZ fake executable", "application/octet-stream")},
    )
    assert executable.status_code == 415

    spoofed_pdf = client.post(
        "/api/documents",
        headers=headers,
        data={"title": "Spoofed PDF"},
        files={"file": ("document.pdf", b"not a PDF", "application/pdf")},
    )
    assert spoofed_pdf.status_code == 415

    invalid_text = client.post(
        "/api/documents",
        headers=headers,
        data={"title": "Invalid UTF-8"},
        files={"file": ("bad.txt", b"\xff\xfe", "text/plain")},
    )
    assert invalid_text.status_code == 415


def test_demo_seed_is_idempotent_and_provisions_all_roles(tmp_path: Path) -> None:
    database_path = tmp_path / "trustvault.sqlite3"
    data_dir = tmp_path / "data"
    create_app(database_path=database_path, data_dir=data_dir, seed=True)
    create_app(database_path=database_path, data_dir=data_dir, seed=True)

    import sqlite3

    connection = sqlite3.connect(database_path)
    try:
        users = connection.execute(
            "SELECT email, workspace_role FROM users ORDER BY workspace_role"
        ).fetchall()
        assert len(users) == 4
        assert {role for _, role in users} == {"admin", "owner", "editor", "viewer"}
        assert connection.execute("SELECT COUNT(*) FROM documents").fetchone()[0] == 4
        assert connection.execute("SELECT COUNT(*) FROM shares").fetchone()[0] == 2
    finally:
        connection.close()
