from pathlib import Path

from app.integrity import verify_backup


def create_test_backup(operator, asset_id):
    response = operator.upload(
        "sample.sql",
        b"CREATE TABLE students(id INTEGER);",
        asset_id,
        retention_days="30",
    )
    assert response.status_code == 201, response.get_json()
    return response.get_json()["public_id"]


def test_valid_backup(app, operator, asset_id):
    backup_id = create_test_backup(operator, asset_id)

    with app.app_context():
        result = verify_backup(
            backup_id, app.config["STORAGE_DIR"]
        )

    assert result["status"] == "verified"
    assert result["expected_sha256"] == result["actual_sha256"]


def test_corrupted_backup(app, operator, asset_id):
    backup_id = create_test_backup(operator, asset_id)

    with app.app_context():
        from app.db import get_db

        backup = get_db().execute(
            "SELECT stored_filename FROM backups WHERE public_id = ?",
            (backup_id,),
        ).fetchone()

        path = Path(app.config["STORAGE_DIR"]) / backup["stored_filename"]
        path.write_bytes(b"SIMULATED CORRUPTION")

        result = verify_backup(
            backup_id, app.config["STORAGE_DIR"]
        )

    assert result["status"] == "corrupted"
    assert result["expected_sha256"] != result["actual_sha256"]


def test_missing_backup(app, operator, asset_id):
    backup_id = create_test_backup(operator, asset_id)

    with app.app_context():
        from app.db import get_db

        backup = get_db().execute(
            "SELECT stored_filename FROM backups WHERE public_id = ?",
            (backup_id,),
        ).fetchone()

        path = Path(app.config["STORAGE_DIR"]) / backup["stored_filename"]
        path.unlink()

        result = verify_backup(
            backup_id, app.config["STORAGE_DIR"]
        )

    assert result["status"] == "missing"
    assert result["actual_sha256"] is None


def test_integrity_api_authorized(operator, asset_id):
    backup_id = create_test_backup(operator, asset_id)

    response = operator.post(
        f"/api/backups/{backup_id}/verify"
    )

    assert response.status_code == 200
    assert response.get_json()["status"] == "verified"


def test_integrity_api_viewer_denied(viewer, operator, asset_id):
    backup_id = create_test_backup(operator, asset_id)

    response = viewer.post(
        f"/api/backups/{backup_id}/verify"
    )

    assert response.status_code == 403


def test_integrity_api_unauthenticated(client):
    response = client.post(
        "/api/backups/nonexistent/verify"
    )

    assert response.status_code == 401


def test_manifest_api_returns_correct_checksum(
    operator, asset_id
):
    backup_id = create_test_backup(operator, asset_id)

    backup_response = operator.get(
        f"/api/backups/{backup_id}"
    )
    assert backup_response.status_code == 200

    response = operator.get(
        f"/api/backups/{backup_id}/manifest"
    )

    assert response.status_code == 200

    manifest = response.get_json()
    backup = backup_response.get_json()

    assert manifest["backup_id"] == backup_id
    assert manifest["sha256"] == backup["sha256"]
    assert manifest["size_bytes"] == backup["size_bytes"]
    assert manifest["manifest_version"] == "1.0"


def test_manifest_api_viewer_allowed(
    viewer, operator, asset_id
):
    backup_id = create_test_backup(operator, asset_id)

    response = viewer.get(
        f"/api/backups/{backup_id}/manifest"
    )

    assert response.status_code == 200
    assert response.get_json()["backup_id"] == backup_id


def test_manifest_api_unauthenticated(client):
    response = client.get(
        "/api/backups/nonexistent/manifest"
    )

    assert response.status_code == 401


def test_manifest_api_backup_not_found(operator):
    response = operator.get(
        "/api/backups/nonexistent/manifest"
    )

    assert response.status_code == 404
    assert (
        response.get_json()["error"]["code"]
        == "backup_not_found"
    )
