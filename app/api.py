"""JSON API (/api/*). Session-cookie auth + CSRF header; authorization enforced per route."""
from flask import Blueprint, current_app, g, jsonify, request, session

from . import audit, security, services, integrity, retention
from .security import login_required, rate_limit, roles_required

bp = Blueprint("api", __name__, url_prefix="/api")

WRITE = ("admin", "operator")


@bp.errorhandler(services.ValidationError)
def _validation(exc):
    audit.log("request_rejected", "failure", target=request.path, detail=exc.code)
    return jsonify({"error": {"code": exc.code, "message": exc.message}}), exc.status


@bp.get("/csrf")
def csrf():
    return jsonify({"csrf_token": security.csrf_token()})


@bp.post("/login")
@rate_limit("login", 20, 60)
def login():
    data = request.get_json(silent=True) or {}
    user, reason = services.authenticate(
        str(data.get("username", "")), str(data.get("password", "")),
        current_app.config["LOGIN_MAX_ATTEMPTS"], current_app.config["LOCKOUT_SECONDS"])
    if user is None:
        audit.log("login", "failure", actor=str(data.get("username", ""))[:32] or "anonymous",
                  detail=reason)
        return jsonify({"error": {"code": "invalid_credentials",
                                  "message": services.LOCKOUT_MESSAGE}}), 401
    session.clear()
    session["user_id"] = user["id"]
    session.permanent = True
    token = security.csrf_token()
    audit.log("login", "success", actor=user["username"])
    return jsonify({"user": {"username": user["username"], "role": user["role"]},
                    "csrf_token": token})


@bp.post("/logout")
@login_required
def logout():
    audit.log("logout", "success")
    session.clear()
    return jsonify({"status": "logged_out"})


@bp.get("/me")
@login_required
def me():
    return jsonify({"username": g.user["username"], "role": g.user["role"]})


# ---- users (admin) ----
@bp.get("/users")
@roles_required("admin")
def users():
    return jsonify({"users": [services.row_to_dict(u) for u in services.list_users()]})


@bp.post("/users")
@roles_required("admin")
def add_user():
    d = request.get_json(silent=True) or {}
    uid = services.create_user(d.get("username"), d.get("password"), d.get("role"))
    audit.log("user_create", "success", target=str(uid), detail=f"role={d.get('role')}")
    return jsonify({"id": uid}), 201


@bp.patch("/users/<int:user_id>")
@roles_required("admin")
def patch_user(user_id):
    d = request.get_json(silent=True) or {}
    services.update_user(user_id, d.get("role"), d.get("is_active"))
    audit.log("user_update", "success", target=str(user_id),
              detail=f"role={d.get('role')} active={d.get('is_active')}")
    return jsonify({"status": "updated"})


# ---- assets ----
@bp.get("/assets")
@login_required
def assets():
    return jsonify({"assets": [services.row_to_dict(a) for a in services.list_assets()]})


@bp.post("/assets")
@roles_required(*WRITE)
def add_asset():
    d = request.get_json(silent=True) or {}
    aid = services.create_asset(d.get("name"), d.get("description"), g.user["id"])
    audit.log("asset_create", "success", target=str(aid))
    return jsonify({"id": aid}), 201


@bp.delete("/assets/<int:asset_id>")
@roles_required("admin")
def remove_asset(asset_id):
    services.delete_asset(asset_id)
    audit.log("asset_delete", "success", target=str(asset_id))
    return jsonify({"status": "deleted"})


# ---- backups ----
@bp.get("/backups")
@login_required
def backups():
    rows = services.search_backups(request.args.get("q"), request.args.get("asset_id"))
    return jsonify({"backups": [services.row_to_dict(r) for r in rows]})


@bp.get("/backups/<public_id>")
@login_required
def backup(public_id):
    row = services.get_backup(public_id)
    if row is None:
        return jsonify({"error": {"code": "not_found", "message": "Backup not found."}}), 404
    return jsonify(services.row_to_dict(row))


@bp.post("/backups")
@roles_required(*WRITE)
@rate_limit("upload", 30, 60)
def upload():
    pid, digest = services.upload_backup(
        request.files.get("file"), request.form.get("asset_id"), request.form.get("retention_days"),
        request.form.get("notes"), g.user["id"], current_app.config["STORAGE_DIR"])
    audit.log("backup_upload", "success", target=pid, detail=f"sha256={digest}")
    return jsonify({"public_id": pid, "sha256": digest}), 201


@bp.post("/backups/register")
@roles_required(*WRITE)
@rate_limit("register", 30, 60)
def register():
    d = request.get_json(silent=True) or {}
    pid, digest = services.register_backup(
        str(d.get("source_file", "")), d.get("asset_id"), d.get("retention_days"), d.get("notes"),
        g.user["id"], current_app.config["SOURCE_DIR"], current_app.config["STORAGE_DIR"])
    audit.log("backup_register", "success", target=pid, detail=f"sha256={digest}")
    return jsonify({"public_id": pid, "sha256": digest}), 201



@bp.delete("/backups/<public_id>")
@roles_required("admin")
def remove_backup(public_id):
    try:
        row = services.delete_backup(
            public_id,
            current_app.config["STORAGE_DIR"]
        )

        audit.log(
            "backup_delete",
            "success",
            target=row["public_id"]
        )

        return jsonify({"status": "deleted"}), 200

    except services.ValidationError as e:
        audit.log(
            "backup_delete",
            "failure",
            target=public_id,
            detail=e.code
        )

        return jsonify({
            "error": {
                "code": e.code,
                "message": e.message
            }
        }), e.status


@bp.post("/backups/<public_id>/verify")
@roles_required(*WRITE)
@rate_limit("verify", 30, 60)
def verify_backup_integrity(public_id):
    result = integrity.verify_backup(
        public_id,
        current_app.config["STORAGE_DIR"]
    )

    audit.log(
        "backup_integrity_verify",
        "success" if result["status"] == "verified" else "failure",
        target=public_id,
        detail=f"status={result['status']}"
    )

    return jsonify(result), 200


@bp.get("/backups/<public_id>/retention")
@login_required
@rate_limit("retention_check", 30, 60)
def check_backup_retention(public_id):
    result = retention.check_retention(public_id)

    if result["status"] == "not_found":
        audit.log(
            "backup_retention_check",
            "failure",
            target=public_id,
            detail="backup_not_found"
        )
        return jsonify({
            "error": {
                "code": "backup_not_found",
                "message": "Backup not found."
            }
        }), 404

    audit.log(
        "backup_retention_check",
        "success",
        target=public_id,
        detail=f"status={result['status']}"
    )

    return jsonify(result), 200


@bp.get("/backups/<public_id>/manifest")
@login_required
@rate_limit("manifest", 30, 60)
def get_backup_manifest(public_id):
    manifest = integrity.generate_manifest(public_id)

    audit.log(
        "backup_manifest_view",
        "success",
        target=public_id
    )

    return jsonify(manifest), 200

