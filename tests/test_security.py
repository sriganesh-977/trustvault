from pathlib import Path
from datetime import datetime, timedelta, timezone

from fastapi.testclient import TestClient

from app import create_app


ADMIN_EMAIL = "admin@trustvault.local"
ADMIN_PASSWORD = "VaultDemo!2026"
MEMBER_EMAIL = "maya@northstar.example"
MEMBER_PASSWORD = "Northstar!2026"


def login(client: TestClient, email: str, password: str) -> None:
    token = client.get("/api/csrf").json()["csrf_token"]
    response = client.post(
        "/api/login",
        headers={"X-CSRF-Token": token},
        json={"email": email, "password": password},
    )
    assert response.status_code == 200


def csrf_header(client: TestClient) -> dict[str, str]:
    return {"X-CSRF-Token": client.get("/api/csrf").json()["csrf_token"]}


def test_exact_document_grant_revocation_and_audit_chain(tmp_path: Path) -> None:
    app = create_app(
        database_path=tmp_path / "trustvault.sqlite3",
        data_dir=tmp_path / "data",
        seed=True,
    )
    client = TestClient(app)
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
        connection.execute("UPDATE audit_events SET actor_email = 'changed@example.com' WHERE id = 1")
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
