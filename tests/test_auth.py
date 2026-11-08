import re

from app import db, services
from .conftest import PW, Client


def audit_rows(app, **where):
    with app.app_context():
        rows = db.get_db().execute("SELECT * FROM audit_log").fetchall()
    return [r for r in rows if all(r[k] == v for k, v in where.items())]


def test_login_success_and_me(client):
    r = client.login("op1")
    assert r.status_code == 200 and r.get_json()["user"]["role"] == "operator"
    assert client.get("/api/me").get_json()["username"] == "op1"


def test_login_wrong_password_generic(client):
    bad = client.login("op1", "WrongPass123")
    unknown = client.login("nobody", "WrongPass123")
    assert bad.status_code == unknown.status_code == 401
    assert bad.get_json() == unknown.get_json()  # no user enumeration


def test_lockout_after_failed_attempts(app, client):
    for _ in range(3):
        client.login("op1", "WrongPass123")
    assert client.login("op1", PW).status_code == 401  # locked even with right password
    assert audit_rows(app, action="login", outcome="failure")


def test_logout_ends_session(operator):
    assert operator.post("/api/logout").status_code == 200
    assert operator.get("/api/me").status_code == 401


def test_unauthenticated_api_is_401(client):
    assert client.get("/api/backups").status_code == 401
    assert client.get("/api/assets").status_code == 401


def test_csrf_required_on_post(app):
    c = app.test_client()
    r = c.post("/api/login", json={"username": "op1", "password": PW})
    assert r.status_code == 403 and r.get_json()["error"]["code"] == "csrf_failed"


def test_csrf_required_for_authenticated_post(app):
    c = Client(app); c.login("op1")
    r = c.c.post("/api/assets", json={"name": "NoToken"})
    assert r.status_code == 403


def test_viewer_cannot_write(viewer, asset_id):
    assert viewer.post("/api/assets", json={"name": "X Asset"}).status_code == 403
    assert viewer.upload("a.txt", b"hello", asset_id).status_code == 403
    assert viewer.get("/api/backups").status_code == 200  # read allowed


def test_operator_cannot_delete_or_admin(operator, asset_id):
    assert operator.delete(f"/api/assets/{asset_id}").status_code == 403
    assert operator.get("/api/users").status_code == 403


def test_denied_attempt_is_logged_without_leaking(app, viewer):
    r = viewer.get("/api/users")
    assert r.status_code == 403
    assert r.get_json()["error"]["code"] == "forbidden"
    assert audit_rows(app, action="access_denied", actor="view1", outcome="denied")


def test_admin_user_management(app, admin):
    r = admin.post("/api/users", json={"username": "new.user", "password": PW, "role": "viewer"})
    assert r.status_code == 201
    assert admin.post("/api/users", json={"username": "new.user", "password": PW,
                                          "role": "viewer"}).status_code == 409
    assert admin.post("/api/users", json={"username": "w", "password": "short",
                                          "role": "viewer"}).status_code == 400
    assert admin.post("/api/users", json={"username": "x" * 5, "password": PW,
                                          "role": "root"}).status_code == 400


def test_role_change_applies_immediately(app, admin, viewer):
    uid = [u for u in admin.get("/api/users").get_json()["users"] if u["username"] == "view1"][0]["id"]
    assert admin.patch(f"/api/users/{uid}", json={"is_active": False}).status_code == 200
    assert viewer.get("/api/me").status_code == 401


def test_cannot_remove_last_admin(admin):
    uid = [u for u in admin.get("/api/users").get_json()["users"] if u["username"] == "admin1"][0]["id"]
    assert admin.patch(f"/api/users/{uid}", json={"role": "viewer"}).status_code == 409
    assert admin.patch(f"/api/users/{uid}", json={"is_active": False}).status_code == 409


def test_passwords_hashed(app):
    with app.app_context():
        h = db.get_db().execute("SELECT password_hash FROM users WHERE username='op1'").fetchone()[0]
    assert PW not in h and re.match(r"^(scrypt|pbkdf2):", h)


def test_audit_log_is_append_only(app):
    import sqlite3
    with app.app_context():
        d = db.get_db()
        d.execute("INSERT INTO audit_log (actor, action, outcome) VALUES ('t','x','success')")
        d.commit()
        for sql in ("UPDATE audit_log SET actor='evil'", "DELETE FROM audit_log"):
            try:
                d.execute(sql)
                raised = False
            except sqlite3.DatabaseError:
                raised = True
            assert raised


def test_audit_never_contains_password(app, client):
    client.login("op1", "SecretWrong123")
    with app.app_context():
        dump = " ".join(str(tuple(r)) for r in db.get_db().execute("SELECT * FROM audit_log"))
    assert "SecretWrong123" not in dump


def test_html_login_flow_and_redirect_safety(app):
    c = app.test_client()
    page = c.get("/login").get_data(as_text=True)
    token = re.search(r'name="csrf_token" value="([^"]+)"', page).group(1)
    r = c.post("/login?next=//evil.example", data={"username": "op1", "password": PW,
                                                  "csrf_token": token})
    assert r.status_code == 302 and "evil.example" not in r.headers["Location"]
    assert c.get("/backups").status_code == 200


def test_html_pages_require_login(app):
    r = app.test_client().get("/backups")
    assert r.status_code == 302 and "/login" in r.headers["Location"]


def test_safe_errors_no_stack_trace(client):
    r = client.get("/api/does-not-exist")
    assert r.status_code == 404 and "Traceback" not in r.get_data(as_text=True)


def test_security_headers(client):
    h = client.get("/api/csrf").headers
    assert h["X-Content-Type-Options"] == "nosniff" and "frame-ancestors" in h["Content-Security-Policy"]


def test_session_cookie_flags(app):
    r = app.test_client().get("/api/csrf")
    cookie = r.headers.get("Set-Cookie", "")
    assert "HttpOnly" in cookie and "SameSite=Lax" in cookie
