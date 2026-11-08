import os
import secrets
from datetime import timedelta

import click
from flask import Flask
from werkzeug.exceptions import HTTPException

from . import api, db, pages, security, services


def create_app(test_config=None):
    app = Flask(__name__, instance_relative_config=True)
    root = os.path.dirname(app.root_path)
    app.config.from_mapping(
        DATABASE=os.path.join(app.instance_path, "backupproof.db"),
        STORAGE_DIR=os.path.join(app.instance_path, "storage"),
        SOURCE_DIR=os.path.join(root, "fixtures"),
        MAX_CONTENT_LENGTH=25 * 1024 * 1024,
        PERMANENT_SESSION_LIFETIME=timedelta(minutes=30),
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Lax",
        SESSION_COOKIE_SECURE=False,  # set True behind HTTPS
        LOGIN_MAX_ATTEMPTS=5,
        LOCKOUT_SECONDS=300,
    )
    if test_config:
        app.config.update(test_config)
    os.makedirs(app.instance_path, exist_ok=True)

    if not app.config.get("SECRET_KEY"):
        app.config["SECRET_KEY"] = os.environ.get("BACKUPPROOF_SECRET_KEY") or _file_secret(app)

    app.teardown_appcontext(db.close_db)
    app.before_request(security.load_user)
    app.before_request(security.check_csrf)
    app.after_request(security.set_security_headers)
    app.register_blueprint(api.bp)
    app.register_blueprint(pages.bp)

    @app.context_processor
    def inject():
        return {"csrf_token": security.csrf_token}

    for code, key, msg in [
        (400, "bad_request", "The request was not valid."),
        (401, "not_authenticated", "Authentication required."),
        (403, "forbidden", "You do not have permission to do that."),
        (404, "not_found", "Not found."),
        (405, "method_not_allowed", "Method not allowed."),
        (413, "payload_too_large", "The upload is too large (limit 25 MB)."),
        (429, "rate_limited", "Too many requests. Try again later."),
    ]:
        app.register_error_handler(code, _make_handler(code, key, msg))

    @app.errorhandler(Exception)
    def _unexpected(exc):  # never leak stack traces
        if isinstance(exc, HTTPException):
            return security.error_response(exc.code, "http_error", "Request failed.")
        app.logger.exception("Unhandled error")
        return security.error_response(500, "internal_error", "Something went wrong.")

    _register_cli(app)
    return app


def _make_handler(code, key, msg):
    def handler(_e):
        return security.error_response(code, key, msg)
    return handler


def _file_secret(app):
    path = os.path.join(app.instance_path, "secret.key")
    if not os.path.exists(path):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(secrets.token_hex(32))
    with open(path) as f:
        return f.read().strip()


def _register_cli(app):
    @app.cli.command("init-db")
    def init_db_cmd():
        """Create tables."""
        db.init_db()
        click.echo("Database initialised.")

    @app.cli.command("create-user")
    @click.argument("username")
    @click.argument("role", type=click.Choice(["admin", "operator", "viewer"]))
    @click.password_option()
    def create_user_cmd(username, role, password):
        """Create a user (use this to make the first admin)."""
        db.init_db()
        try:
            services.create_user(username, password, role)
        except services.ValidationError as e:
            raise click.ClickException(e.message)
        click.echo(f"Created {role} '{username}'.")

    @app.cli.command("seed-demo")
    def seed_demo_cmd():
        """Create demo admin/operator/viewer with random passwords (printed once)."""
        db.init_db()
        for name, role in (("admin", "admin"), ("operator", "operator"), ("viewer", "viewer")):
            pw = secrets.token_urlsafe(9) + "7a"
            try:
                services.create_user(name, pw, role)
                click.echo(f"{role:9s} username={name}  password={pw}")
            except services.ValidationError:
                click.echo(f"{role:9s} already exists, skipped")
