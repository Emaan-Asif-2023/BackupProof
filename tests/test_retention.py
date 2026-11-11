from datetime import datetime, timedelta, timezone

from app.db import get_db
from app.retention import check_retention


def create_test_backup(operator, asset_id):
    response = operator.upload(
        "retention.sql",
        b"CREATE TABLE retention_test(id INTEGER);",
        asset_id,
        retention_days="30",
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["public_id"]


def test_active_retention(app, operator, asset_id):
    backup_id = create_test_backup(operator, asset_id)

    with app.app_context():
        result = check_retention(backup_id)

    assert result["status"] == "active"
    assert result["retention_days"] == 30


def test_expired_retention(app, operator, asset_id):
    backup_id = create_test_backup(operator, asset_id)

    old_date = (
        datetime.now(timezone.utc) - timedelta(days=60)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    with app.app_context():
        db = get_db()
        db.execute(
            "UPDATE backups SET created_at = ? WHERE public_id = ?",
            (old_date, backup_id),
        )
        db.commit()

        result = check_retention(backup_id)

    assert result["status"] == "expired"


def test_retention_expiry_calculation(app, operator, asset_id):
    backup_id = create_test_backup(operator, asset_id)

    with app.app_context():
        result = check_retention(backup_id)

    created = datetime.fromisoformat(result["created_at"])
    expiry = datetime.fromisoformat(result["expiry_date"])

    assert expiry - created == timedelta(days=30)


def test_retention_not_found(app):
    with app.app_context():
        result = check_retention("nonexistent-backup")

    assert result["status"] == "not_found"


def test_retention_api_authorized(operator, asset_id):
    backup_id = create_test_backup(operator, asset_id)

    response = operator.get(
        f"/api/backups/{backup_id}/retention"
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "active"


def test_retention_api_unauthenticated(client):
    response = client.get(
        "/api/backups/nonexistent/retention"
    )

    assert response.status_code == 401


import pytest
from app import services


def test_active_backup_cannot_be_deleted(
    app, operator, asset_id
):
    backup_id = create_test_backup(operator, asset_id)

    with app.app_context():
        with pytest.raises(services.ValidationError) as exc:
            services.delete_backup(
                backup_id,
                app.config["STORAGE_DIR"]
            )

        assert exc.value.code == "retention_active"

        # Confirm the database record still exists
        backup = get_db().execute(
            "SELECT id FROM backups WHERE public_id = ?",
            (backup_id,)
        ).fetchone()

        assert backup is not None


def test_expired_backup_can_be_deleted(
    app, operator, asset_id
):
    backup_id = create_test_backup(operator, asset_id)

    old_date = (
        datetime.now(timezone.utc) - timedelta(days=60)
    ).strftime("%Y-%m-%dT%H:%M:%SZ")

    with app.app_context():
        db = get_db()

        db.execute(
            "UPDATE backups SET created_at = ? WHERE public_id = ?",
            (old_date, backup_id)
        )
        db.commit()

        services.delete_backup(
            backup_id,
            app.config["STORAGE_DIR"]
        )

        backup = db.execute(
            "SELECT id FROM backups WHERE public_id = ?",
            (backup_id,)
        ).fetchone()

        assert backup is None


def test_admin_cannot_delete_active_backup(
    app, admin, operator, asset_id
):
    backup_id = create_test_backup(operator, asset_id)

    response = admin.delete(
        f"/api/backups/{backup_id}"
    )

    assert response.status_code == 409
    assert response.get_json()["error"]["code"] == "retention_active"

    # Confirm the backup still exists
    with app.app_context():
        backup = get_db().execute(
            "SELECT id FROM backups WHERE public_id = ?",
            (backup_id,)
        ).fetchone()

        assert backup is not None


def test_blocked_deletion_is_audited(
    app, admin, operator, asset_id
):
    backup_id = create_test_backup(operator, asset_id)

    response = admin.delete(
        f"/api/backups/{backup_id}"
    )

    assert response.status_code == 409

    with app.app_context():
        db = get_db()

        audit_entry = db.execute(
            """
            SELECT *
            FROM audit_log
            WHERE action = 'backup_delete'
              AND outcome = 'failure'
              AND target = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (backup_id,)
        ).fetchone()

        assert audit_entry is not None
        assert "retention_active" in audit_entry["detail"]


def test_browser_blocked_deletion_is_audited(
    app, admin, operator, asset_id
):
    backup_id = create_test_backup(operator, asset_id)

    response = admin.post(
        f"/backups/{backup_id}/delete",
        follow_redirects=False
    )

    assert response.status_code == 302

    with app.app_context():
        db = get_db()

        entry = db.execute(
            """
            SELECT *
            FROM audit_log
            WHERE action = 'backup_delete'
              AND outcome = 'failure'
              AND target = ?
            ORDER BY id DESC
            LIMIT 1
            """,
            (backup_id,)
        ).fetchone()

        assert entry is not None
        assert entry["detail"] == "retention_active"

        backup = db.execute(
            "SELECT id FROM backups WHERE public_id = ?",
            (backup_id,)
        ).fetchone()

        assert backup is not None
