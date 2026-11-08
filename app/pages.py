"""Server-rendered pages. Same services and authorization rules as the API."""
from flask import (Blueprint, current_app, flash, g, redirect, render_template, request,
                   session, url_for)

from . import audit, security, services
from .security import login_required, rate_limit, roles_required

bp = Blueprint("pages", __name__)
WRITE = ("admin", "operator")


def _safe_next(target):
    if target and target.startswith("/") and not target.startswith("//") and "\\" not in target:
        return target
    return None


@bp.get("/")
def index():
    return redirect(url_for("pages.backups" if g.user else "pages.login"))


@bp.route("/login", methods=["GET", "POST"])
@rate_limit("login", 20, 60)
def login():
    if request.method == "POST":
        username = request.form.get("username", "")
        user, reason = services.authenticate(
            username, request.form.get("password", ""),
            current_app.config["LOGIN_MAX_ATTEMPTS"], current_app.config["LOCKOUT_SECONDS"])
        if user is None:
            audit.log("login", "failure", actor=username[:32] or "anonymous", detail=reason)
            flash(services.LOCKOUT_MESSAGE, "error")
            return render_template("login.html"), 401
        session.clear()
        session["user_id"] = user["id"]
        session.permanent = True
        security.csrf_token()
        audit.log("login", "success", actor=user["username"])
        return redirect(_safe_next(request.args.get("next")) or url_for("pages.backups"))
    return render_template("login.html")


@bp.post("/logout")
@login_required
def logout():
    audit.log("logout", "success")
    session.clear()
    return redirect(url_for("pages.login"))


# ---------- assets ----------
@bp.route("/assets", methods=["GET", "POST"])
@login_required
def assets():
    if request.method == "POST":
        if g.user["role"] not in WRITE:
            audit.log("access_denied", "denied", target=request.path, detail=f"role={g.user['role']}")
            return security.error_response(403, "forbidden", "You do not have permission to do that.")
        try:
            aid = services.create_asset(request.form.get("name"), request.form.get("description"),
                                        g.user["id"])
            audit.log("asset_create", "success", target=str(aid))
            flash("Asset created.", "ok")
        except services.ValidationError as e:
            audit.log("request_rejected", "failure", target=request.path, detail=e.code)
            flash(e.message, "error")
        return redirect(url_for("pages.assets"))
    return render_template("assets.html", assets=services.list_assets())


@bp.post("/assets/<int:asset_id>/delete")
@roles_required("admin")
def asset_delete(asset_id):
    try:
        services.delete_asset(asset_id)
        audit.log("asset_delete", "success", target=str(asset_id))
        flash("Asset deleted.", "ok")
    except services.ValidationError as e:
        audit.log("request_rejected", "failure", target=request.path, detail=e.code)
        flash(e.message, "error")
    return redirect(url_for("pages.assets"))


# ---------- backups ----------
@bp.get("/backups")
@login_required
def backups():
    try:
        rows = services.search_backups(request.args.get("q"), request.args.get("asset_id"))
    except services.ValidationError as e:
        flash(e.message, "error")
        rows = []
    return render_template("backups.html", backups=rows, assets=services.list_assets(),
                           q=request.args.get("q", ""), asset_id=request.args.get("asset_id", ""))


@bp.route("/backups/new", methods=["GET", "POST"])
@roles_required(*WRITE)
@rate_limit("upload", 30, 60)
def backup_new():
    sources = services.list_source_files(current_app.config["SOURCE_DIR"])
    if request.method == "POST":
        mode = request.form.get("mode")
        try:
            if mode == "register":
                pid, digest = services.register_backup(
                    request.form.get("source_file", ""), request.form.get("asset_id"),
                    request.form.get("retention_days"), request.form.get("notes"), g.user["id"],
                    current_app.config["SOURCE_DIR"], current_app.config["STORAGE_DIR"])
                audit.log("backup_register", "success", target=pid, detail=f"sha256={digest}")
            else:
                pid, digest = services.upload_backup(
                    request.files.get("file"), request.form.get("asset_id"),
                    request.form.get("retention_days"), request.form.get("notes"), g.user["id"],
                    current_app.config["STORAGE_DIR"])
                audit.log("backup_upload", "success", target=pid, detail=f"sha256={digest}")
            flash("Backup recorded. SHA-256 baseline stored.", "ok")
            return redirect(url_for("pages.backup_detail", public_id=pid))
        except services.ValidationError as e:
            audit.log("request_rejected", "failure", target=request.path, detail=e.code)
            flash(e.message, "error")
            return render_template("backup_new.html", assets=services.list_assets(),
                                   sources=sources), e.status
    return render_template("backup_new.html", assets=services.list_assets(), sources=sources)


@bp.get("/backups/<public_id>")
@login_required
def backup_detail(public_id):
    row = services.get_backup(public_id)
    if row is None:
        return security.error_response(404, "not_found", "Backup not found.")
    return render_template("backup_detail.html", b=row)


@bp.post("/backups/<public_id>/delete")
@roles_required("admin")
def backup_delete(public_id):
    try:
        row = services.delete_backup(public_id, current_app.config["STORAGE_DIR"])
        audit.log("backup_delete", "success", target=row["public_id"])
        flash("Backup deleted.", "ok")
    except services.ValidationError as e:
        flash(e.message, "error")
    return redirect(url_for("pages.backups"))


# ---------- admin: users ----------
@bp.route("/admin/users", methods=["GET", "POST"])
@roles_required("admin")
def admin_users():
    if request.method == "POST":
        try:
            uid = services.create_user(request.form.get("username"), request.form.get("password"),
                                       request.form.get("role"))
            audit.log("user_create", "success", target=str(uid), detail=f"role={request.form.get('role')}")
            flash("User created.", "ok")
        except services.ValidationError as e:
            audit.log("request_rejected", "failure", target=request.path, detail=e.code)
            flash(e.message, "error")
        return redirect(url_for("pages.admin_users"))
    return render_template("users.html", users=services.list_users())


@bp.post("/admin/users/<int:user_id>")
@roles_required("admin")
def admin_user_update(user_id):
    role = request.form.get("role") or None
    active = request.form.get("is_active")
    active = None if active is None else active == "1"
    try:
        services.update_user(user_id, role, active)
        audit.log("user_update", "success", target=str(user_id), detail=f"role={role} active={active}")
        flash("User updated.", "ok")
    except services.ValidationError as e:
        audit.log("request_rejected", "failure", target=request.path, detail=e.code)
        flash(e.message, "error")
    return redirect(url_for("pages.admin_users"))
