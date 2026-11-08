"""CSRF, rate limiting, current-user loading and server-side authorization."""
import hmac
import secrets
import time
from collections import defaultdict, deque
from functools import wraps

from flask import abort, current_app, g, jsonify, redirect, request, session, url_for

from . import audit
from .db import get_db

ROLES = ("admin", "operator", "viewer")
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}


# ---------- API vs page helpers ----------
def wants_json():
    return request.path.startswith("/api/")


def error_response(status, code, message):
    if wants_json():
        return jsonify({"error": {"code": code, "message": message}}), status
    from flask import render_template
    return render_template("error.html", status=status, message=message), status


# ---------- CSRF ----------
def csrf_token():
    if "csrf_token" not in session:
        session["csrf_token"] = secrets.token_urlsafe(32)
    return session["csrf_token"]


def check_csrf():
    if request.method in SAFE_METHODS:
        return None
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    expected = session.get("csrf_token", "")
    if not expected or not hmac.compare_digest(str(sent), expected):
        audit.log("csrf_rejected", "denied", target=request.path)
        return error_response(403, "csrf_failed", "Request could not be verified.")
    return None


# ---------- Rate limiting (in-memory sliding window) ----------
class RateLimiter:
    def __init__(self):
        self.hits = defaultdict(deque)

    def allow(self, key, limit, window):
        now = time.monotonic()
        q = self.hits[key]
        while q and now - q[0] > window:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True

    def reset(self):
        self.hits.clear()


limiter = RateLimiter()


def rate_limit(name, limit, window):
    """Decorator limiting a sensitive endpoint per client IP."""
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            if not limiter.allow(f"{name}:{request.remote_addr}", limit, window):
                audit.log("rate_limited", "denied", target=name)
                return error_response(429, "rate_limited", "Too many requests. Try again later.")
            return fn(*a, **kw)
        return wrapper
    return deco


# ---------- Current user / authorization ----------
def load_user():
    """Re-read the user on every request so deactivation/role changes apply at once."""
    g.user = None
    uid = session.get("user_id")
    if uid is None:
        return
    row = get_db().execute(
        "SELECT id, username, role, is_active FROM users WHERE id = ?", (uid,)
    ).fetchone()
    if row is None or not row["is_active"]:
        session.clear()
        return
    g.user = row


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if g.user is None:
            if wants_json():
                return error_response(401, "not_authenticated", "Authentication required.")
            return redirect(url_for("pages.login", next=request.path))
        return fn(*a, **kw)
    return wrapper


def roles_required(*roles):
    """Server-side role check. Denials are logged; the response is deliberately generic."""
    def deco(fn):
        @wraps(fn)
        @login_required
        def wrapper(*a, **kw):
            if g.user["role"] not in roles:
                audit.log("access_denied", "denied", target=request.path,
                          detail=f"role={g.user['role']}")
                return error_response(403, "forbidden", "You do not have permission to do that.")
            return fn(*a, **kw)
        return wrapper
    return deco


def set_security_headers(resp):
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "same-origin"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; style-src 'self'; script-src 'self'; "
        "frame-ancestors 'none'; form-action 'self'"
    )
    resp.headers["Cache-Control"] = "no-store"
    return resp
