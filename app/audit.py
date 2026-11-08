"""Append-only audit logging. Never pass passwords, tokens or file contents here."""
from flask import g, has_request_context, request

from .db import get_db

MAX_DETAIL = 500


def log(action, outcome="success", target=None, detail=None, actor=None):
    if actor is None:
        user = getattr(g, "user", None) if has_request_context() else None
        actor = user["username"] if user else "anonymous"
    ip = request.remote_addr if has_request_context() else None
    if detail is not None:
        detail = str(detail)[:MAX_DETAIL]
    db = get_db()
    db.execute(
        "INSERT INTO audit_log (actor, action, target, outcome, detail, ip) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (actor, action, target, outcome, detail, ip),
    )
    db.commit()
