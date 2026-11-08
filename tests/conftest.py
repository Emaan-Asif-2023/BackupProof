import io
import os

import pytest

from app import create_app, db, security, services

PW = "Str0ngPass99"


@pytest.fixture()
def app(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    (src / "ok.sql").write_bytes(b"CREATE TABLE t(a);\n")
    (src / "bad.exe").write_bytes(b"MZ....")
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret",
        "DATABASE": str(tmp_path / "t.db"),
        "STORAGE_DIR": str(tmp_path / "storage"),
        "SOURCE_DIR": str(src),
        "MAX_CONTENT_LENGTH": 1024 * 1024,
        "LOGIN_MAX_ATTEMPTS": 3,
    })
    security.limiter.reset()
    with app.app_context():
        db.init_db()
        for name, role in (("admin1", "admin"), ("op1", "operator"), ("view1", "viewer")):
            services.create_user(name, PW, role)
    return app


class Client:
    """Thin JSON-API client that handles the CSRF header."""

    def __init__(self, app):
        self.c = app.test_client()
        self.token = self.c.get("/api/csrf").get_json()["csrf_token"]

    def _h(self):
        return {"X-CSRF-Token": self.token}

    def login(self, user, pw=PW):
        r = self.c.post("/api/login", json={"username": user, "password": pw}, headers=self._h())
        if r.status_code == 200:
            self.token = r.get_json()["csrf_token"]
        return r

    def post(self, url, **kw):
        return self.c.post(url, headers=self._h(), **kw)

    def get(self, url, **kw):
        return self.c.get(url, **kw)

    def delete(self, url):
        return self.c.delete(url, headers=self._h())

    def patch(self, url, **kw):
        return self.c.patch(url, headers=self._h(), **kw)

    def upload(self, name, data, asset_id, **form):
        body = {"file": (io.BytesIO(data), name), "asset_id": str(asset_id), **form}
        return self.post("/api/backups", data=body, content_type="multipart/form-data")


@pytest.fixture()
def client(app):
    return Client(app)


@pytest.fixture()
def admin(app):
    c = Client(app); c.login("admin1"); return c


@pytest.fixture()
def operator(app):
    c = Client(app); c.login("op1"); return c


@pytest.fixture()
def viewer(app):
    c = Client(app); c.login("view1"); return c


@pytest.fixture()
def asset_id(operator):
    return operator.post("/api/assets", json={"name": "Finance DB"}).get_json()["id"]
