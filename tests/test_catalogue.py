import hashlib
import io
import os
import sqlite3

from app import db


def test_asset_create_validation_and_duplicates(operator):
    assert operator.post("/api/assets", json={"name": "Mail Server"}).status_code == 201
    assert operator.post("/api/assets", json={"name": "mail server"}).status_code == 409
    assert operator.post("/api/assets", json={"name": "<script>"}).status_code == 400
    assert operator.post("/api/assets", json={"name": "ok name", "description": "x" * 501}).status_code == 400


def test_upload_computes_sha256(operator, asset_id):
    data = b"important backup bytes" * 100
    r = operator.upload("db.sql", data, asset_id, retention_days="45", notes="nightly")
    assert r.status_code == 201
    assert r.get_json()["sha256"] == hashlib.sha256(data).hexdigest()
    b = operator.get(f"/api/backups/{r.get_json()['public_id']}").get_json()
    assert b["size_bytes"] == len(data) and b["retention_days"] == 45 and b["source"] == "upload"
    assert "stored_filename" not in b  # internal storage name is not exposed


def test_stored_file_uses_server_generated_name(app, operator, asset_id):
    operator.upload("../../evil name.sql", b"data", asset_id)
    names = os.listdir(app.config["STORAGE_DIR"])
    assert len(names) == 1 and "evil" not in names[0] and ".." not in names[0]


def test_rejects_disallowed_extension(operator, asset_id):
    r = operator.upload("run.exe", b"MZ\x90\x00", asset_id)
    assert r.status_code == 415 and r.get_json()["error"]["code"] == "invalid_file_type"
    assert operator.upload("noext", b"data", asset_id).status_code == 415


def test_rejects_mismatched_content(operator, asset_id):
    assert operator.upload("fake.zip", b"this is not a zip", asset_id).status_code == 415
    assert operator.upload("fake.sql", b"\x00\x01\x02binary", asset_id).status_code == 415
    assert operator.upload("real.zip", b"PK\x03\x04rest", asset_id).status_code == 201


def test_rejects_empty_and_missing_file(operator, asset_id):
    assert operator.upload("e.txt", b"", asset_id).get_json()["error"]["code"] == "empty_file"
    r = operator.post("/api/backups", data={"asset_id": str(asset_id)},
                      content_type="multipart/form-data")
    assert r.status_code == 400


def test_rejects_oversized_upload(operator, asset_id):
    r = operator.upload("big.txt", b"a" * (1024 * 1024 + 10), asset_id)
    assert r.status_code == 413 and "Traceback" not in r.get_data(as_text=True)


def test_rejects_bad_retention_and_asset(operator, asset_id):
    for bad in ("0", "-5", "abc", "99999"):
        assert operator.upload("a.txt", b"x", asset_id, retention_days=bad).status_code == 400
    assert operator.upload("a.txt", b"x", 9999).status_code == 404
    assert operator.upload("a.txt", b"x", "abc").status_code == 400


def test_register_from_source_folder(operator, asset_id):
    r = operator.post("/api/backups/register", json={"source_file": "ok.sql", "asset_id": asset_id})
    assert r.status_code == 201
    assert r.get_json()["sha256"] == hashlib.sha256(b"CREATE TABLE t(a);\n").hexdigest()


def test_register_blocks_path_traversal_and_bad_types(operator, asset_id):
    for name in ("../conftest.py", "/etc/passwd", "..\\x.txt", "bad.exe", "missing.sql"):
        r = operator.post("/api/backups/register", json={"source_file": name, "asset_id": asset_id})
        assert r.status_code == 404, name


def test_sql_injection_in_search_and_fields(app, operator, asset_id):
    operator.upload("a.txt", b"x", asset_id, notes="'; DROP TABLE backups;--")
    r = operator.get("/api/backups", query_string={"q": "' OR 1=1 --"})
    assert r.status_code == 200 and r.get_json()["backups"] == []
    with app.app_context():
        assert db.get_db().execute("SELECT COUNT(*) FROM backups").fetchone()[0] == 1
    assert operator.get("/api/backups", query_string={"asset_id": "1 OR 1=1"}).status_code == 400


def test_search_and_filter(operator, asset_id):
    other = operator.post("/api/assets", json={"name": "Web Server"}).get_json()["id"]
    operator.upload("alpha.txt", b"1", asset_id)
    operator.upload("beta.txt", b"2", other)
    assert len(operator.get("/api/backups", query_string={"q": "alpha"}).get_json()["backups"]) == 1
    assert len(operator.get("/api/backups", query_string={"asset_id": other}).get_json()["backups"]) == 1
    assert len(operator.get("/api/backups").get_json()["backups"]) == 2
    h = hashlib.sha256(b"2").hexdigest()[:12]
    assert len(operator.get("/api/backups", query_string={"q": h}).get_json()["backups"]) == 1
    assert operator.get("/api/backups", query_string={"q": "%"}).get_json()["backups"] == []  # wildcard escaped


def test_backup_id_validation(operator):
    assert operator.get("/api/backups/1").status_code == 404
    assert operator.get("/api/backups/" + "0" * 32).status_code == 404
    assert operator.get("/api/backups/..%2f..%2fetc").status_code == 404


def test_admin_delete_removes_record_and_file(app, admin, operator, asset_id):
    pid = operator.upload("a.txt", b"x", asset_id).get_json()["public_id"]
    assert operator.delete(f"/api/backups/{pid}").status_code == 403
    assert admin.delete(f"/api/backups/{pid}").status_code == 200
    assert os.listdir(app.config["STORAGE_DIR"]) == []
    assert admin.get(f"/api/backups/{pid}").status_code == 404


def test_cannot_delete_asset_with_backups(admin, operator, asset_id):
    operator.upload("a.txt", b"x", asset_id)
    assert admin.delete(f"/api/assets/{asset_id}").status_code == 409


def test_actions_are_audited(app, operator, asset_id):
    operator.upload("a.txt", b"x", asset_id)
    operator.upload("bad.exe", b"MZ..", asset_id)
    with app.app_context():
        actions = [(r["action"], r["outcome"]) for r in db.get_db().execute("SELECT * FROM audit_log")]
    assert ("backup_upload", "success") in actions
    assert ("request_rejected", "failure") in actions


def test_data_persists_across_restart(app, operator, asset_id):
    from app import create_app
    operator.upload("a.txt", b"x", asset_id)
    app2 = create_app({"TESTING": True, "SECRET_KEY": "test-secret", "DATABASE": app.config["DATABASE"],
                       "STORAGE_DIR": app.config["STORAGE_DIR"], "SOURCE_DIR": app.config["SOURCE_DIR"]})
    with app2.app_context():
        assert db.get_db().execute("SELECT COUNT(*) FROM backups").fetchone()[0] == 1


def test_repeated_login_is_rate_limited(app):
    from tests.conftest import Client
    c = Client(app)
    codes = [c.login("nobody", "x").status_code for _ in range(25)]
    assert 429 in codes


def test_html_upload_and_pages(app):
    import re
    from tests.conftest import PW
    c = app.test_client()
    tok = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)
    c.post("/login", data={"username": "op1", "password": PW, "csrf_token": tok})
    page = c.get("/assets").get_data(as_text=True)
    tok = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    c.post("/assets", data={"name": "HTML Asset", "csrf_token": tok})
    r = c.post("/backups/new", data={"mode": "upload", "asset_id": "1", "retention_days": "10",
                                     "csrf_token": tok, "file": (io.BytesIO(b"hello"), "h.txt")},
               content_type="multipart/form-data")
    assert r.status_code == 302
    listing = c.get("/backups").get_data(as_text=True)
    assert "h.txt" in listing and hashlib.sha256(b"hello").hexdigest()[:16] in listing
    # no CSRF token -> rejected
    assert c.post("/assets", data={"name": "Nope Asset"}).status_code == 403


def test_xss_is_escaped_in_pages(app):
    import re
    from tests.conftest import PW
    c = app.test_client()
    tok = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/login").get_data(as_text=True)).group(1)
    c.post("/login", data={"username": "op1", "password": PW, "csrf_token": tok})
    tok = re.search(r'name="csrf_token" value="([^"]+)"', c.get("/assets").get_data(as_text=True)).group(1)
    r = c.post("/assets", data={"name": "Safe Name", "description": "<script>alert(1)</script>", "csrf_token": tok})
    assert r.status_code == 302
    html = c.get("/assets").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in html and "&lt;script&gt;" in html
