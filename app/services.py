"""Business rules and validation shared by the HTML pages and the JSON API."""
import hashlib
import os
import re
import shutil
import uuid
from datetime import datetime, timedelta, timezone

from werkzeug.security import check_password_hash, generate_password_hash
from werkzeug.utils import secure_filename

from .db import get_db

ALLOWED_EXTENSIONS = {".zip", ".tar", ".gz", ".tgz", ".7z", ".bak", ".sql", ".dump", ".csv", ".txt"}
BINARY_MAGIC = {".zip": b"PK", ".gz": b"\x1f\x8b", ".tgz": b"\x1f\x8b", ".7z": b"7z\xbc\xaf"}
TEXT_EXTENSIONS = {".sql", ".csv", ".txt"}
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
ASSET_RE = re.compile(r"^[A-Za-z0-9 _.\-]{2,64}$")
DEFAULT_RETENTION = 30
LOCKOUT_MESSAGE = "Invalid username or password."

# A valid hash used to equalize timing when the username does not exist.
_DUMMY_HASH = generate_password_hash("not-a-real-password")


class ValidationError(Exception):
    def __init__(self, code, message, status=400):
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


def _now():
    return datetime.now(timezone.utc)


# ---------------- users / auth ----------------
def validate_password(pw):
    if not isinstance(pw, str) or len(pw) < 10 or len(pw) > 128:
        raise ValidationError("weak_password", "Password must be 10-128 characters.")
    if not (re.search(r"[A-Za-z]", pw) and re.search(r"\d", pw)):
        raise ValidationError("weak_password", "Password must contain letters and digits.")


def create_user(username, password, role):
    username = (username or "").strip()
    if not USERNAME_RE.match(username):
        raise ValidationError("invalid_username", "Username must be 3-32 letters, digits, . _ -")
    if role not in ("admin", "operator", "viewer"):
        raise ValidationError("invalid_role", "Role must be admin, operator or viewer.")
    validate_password(password)
    db = get_db()
    try:
        cur = db.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            (username, generate_password_hash(password), role),
        )
        db.commit()
    except Exception as exc:  # sqlite3.IntegrityError
        db.rollback()
        if "UNIQUE" in str(exc):
            raise ValidationError("username_taken", "That username already exists.", 409)
        raise
    return cur.lastrowid


def authenticate(username, password, max_attempts, lockout_seconds):
    """Returns the user row, or None. Same outcome for unknown user / bad password / lockout."""
    db = get_db()
    user = db.execute(
        "SELECT * FROM users WHERE username = ?", ((username or "").strip(),)
    ).fetchone()
    if user is None:
        check_password_hash(_DUMMY_HASH, password or "")
        return None, "unknown_user"
    if not user["is_active"]:
        check_password_hash(_DUMMY_HASH, password or "")
        return None, "inactive"
    if user["locked_until"] and user["locked_until"] > _now().strftime("%Y-%m-%dT%H:%M:%SZ"):
        return None, "locked"
    if check_password_hash(user["password_hash"], password or ""):
        db.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))
        db.commit()
        return user, "ok"
    attempts = user["failed_attempts"] + 1
    locked = None
    if attempts >= max_attempts:
        locked = (_now() + timedelta(seconds=lockout_seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")
        attempts = 0
    db.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
               (attempts, locked, user["id"]))
    db.commit()
    return None, "locked" if locked else "bad_password"


def last_active_admin_guard(user_id, new_role=None, new_active=None):
    """Never allow the system to be left without an active admin."""
    db = get_db()
    target = db.execute("SELECT role, is_active FROM users WHERE id = ?", (user_id,)).fetchone()
    if target is None:
        raise ValidationError("not_found", "User not found.", 404)
    demoting = (new_role is not None and new_role != "admin") or new_active == 0
    if target["role"] == "admin" and target["is_active"] and demoting:
        n = db.execute("SELECT COUNT(*) FROM users WHERE role='admin' AND is_active=1").fetchone()[0]
        if n <= 1:
            raise ValidationError("last_admin", "At least one active admin must remain.", 409)


def update_user(user_id, role=None, is_active=None):
    if role is not None and role not in ("admin", "operator", "viewer"):
        raise ValidationError("invalid_role", "Role must be admin, operator or viewer.")
    if is_active is not None:
        is_active = 1 if is_active else 0
    last_active_admin_guard(user_id, role, is_active)
    db = get_db()
    if role is not None:
        db.execute("UPDATE users SET role = ? WHERE id = ?", (role, user_id))
    if is_active is not None:
        db.execute("UPDATE users SET is_active = ? WHERE id = ?", (is_active, user_id))
    db.commit()


# ---------------- assets ----------------
def create_asset(name, description, user_id):
    name = (name or "").strip()
    description = (description or "").strip()
    if not ASSET_RE.match(name):
        raise ValidationError("invalid_asset_name",
                              "Asset name must be 2-64 letters, digits, spaces, . _ -")
    if len(description) > 500:
        raise ValidationError("invalid_description", "Description is limited to 500 characters.")
    db = get_db()
    try:
        cur = db.execute("INSERT INTO assets (name, description, created_by) VALUES (?, ?, ?)",
                         (name, description, user_id))
        db.commit()
    except Exception as exc:
        db.rollback()
        if "UNIQUE" in str(exc):
            raise ValidationError("asset_exists", "An asset with that name already exists.", 409)
        raise
    return cur.lastrowid


def delete_asset(asset_id):
    db = get_db()
    if db.execute("SELECT 1 FROM assets WHERE id = ?", (asset_id,)).fetchone() is None:
        raise ValidationError("not_found", "Asset not found.", 404)
    if db.execute("SELECT 1 FROM backups WHERE asset_id = ?", (asset_id,)).fetchone():
        raise ValidationError("asset_in_use", "Delete the asset's backups first.", 409)
    db.execute("DELETE FROM assets WHERE id = ?", (asset_id,))
    db.commit()


# ---------------- backups ----------------
def parse_retention(value):
    if value in (None, ""):
        return DEFAULT_RETENTION
    try:
        days = int(value)
    except (TypeError, ValueError):
        raise ValidationError("invalid_retention", "Retention must be a whole number of days.")
    if not 1 <= days <= 3650:
        raise ValidationError("invalid_retention", "Retention must be between 1 and 3650 days.")
    return days


def _check_extension(filename):
    clean = secure_filename(filename or "")
    ext = os.path.splitext(clean)[1].lower()
    if not clean or ext not in ALLOWED_EXTENSIONS:
        raise ValidationError(
            "invalid_file_type",
            "File type not allowed. Allowed: " + ", ".join(sorted(ALLOWED_EXTENSIONS)), 415)
    return clean, ext


def _ingest(stream, filename, storage_dir):
    """Validate type/structure and copy a stream to storage under a server-made name,
    hashing while writing. Returns (clean_name, stored_name, size, sha256)."""
    clean, ext = _check_extension(filename)
    head = stream.read(16)
    if not head:
        raise ValidationError("empty_file", "The file is empty.")
    if ext in BINARY_MAGIC and not head.startswith(BINARY_MAGIC[ext]):
        raise ValidationError("invalid_file_structure",
                              "File contents do not match its extension.", 415)
    if ext in TEXT_EXTENSIONS and b"\x00" in head:
        raise ValidationError("invalid_file_structure",
                              "File contents do not match its extension.", 415)
    os.makedirs(storage_dir, exist_ok=True)
    stored = uuid.uuid4().hex + ext
    path = os.path.join(storage_dir, stored)
    h = hashlib.sha256()
    size = 0
    try:
        with open(path, "xb") as out:
            chunk = head
            while chunk:
                size += len(chunk)
                h.update(chunk)
                out.write(chunk)
                chunk = stream.read(65536)
        os.chmod(path, 0o600)
    except Exception:
        if os.path.exists(path):
            os.remove(path)
        raise
    return clean, stored, size, h.hexdigest()


def _insert_backup(asset_id, clean, stored, size, digest, source, retention, notes, user_id):
    db = get_db()
    if db.execute("SELECT 1 FROM assets WHERE id = ?", (asset_id,)).fetchone() is None:
        raise ValidationError("asset_not_found", "Selected asset does not exist.", 404)
    public_id = uuid.uuid4().hex
    db.execute(
        "INSERT INTO backups (public_id, asset_id, original_filename, stored_filename, size_bytes,"
        " sha256, source, retention_days, notes, created_by) VALUES (?,?,?,?,?,?,?,?,?,?)",
        (public_id, asset_id, clean, stored, size, digest, source, retention, notes, user_id),
    )
    db.commit()
    return public_id


def _clean_notes(notes):
    notes = (notes or "").strip()
    if len(notes) > 500:
        raise ValidationError("invalid_notes", "Notes are limited to 500 characters.")
    return notes


def _parse_asset_id(value):
    try:
        return int(value)
    except (TypeError, ValueError):
        raise ValidationError("invalid_asset", "Choose a valid asset.")


def upload_backup(file_storage, asset_id, retention, notes, user_id, storage_dir):
    if file_storage is None or not file_storage.filename:
        raise ValidationError("no_file", "No file was provided.")
    asset_id = _parse_asset_id(asset_id)
    days = parse_retention(retention)
    notes = _clean_notes(notes)
    if get_db().execute("SELECT 1 FROM assets WHERE id = ?", (asset_id,)).fetchone() is None:
        raise ValidationError("asset_not_found", "Selected asset does not exist.", 404)
    clean, stored, size, digest = _ingest(file_storage.stream, file_storage.filename, storage_dir)
    try:
        pid = _insert_backup(asset_id, clean, stored, size, digest, "upload", days, notes, user_id)
    except Exception:
        os.remove(os.path.join(storage_dir, stored))
        raise
    return pid, digest


def list_source_files(source_dir):
    if not os.path.isdir(source_dir):
        return []
    out = []
    for name in sorted(os.listdir(source_dir)):
        full = os.path.join(source_dir, name)
        if os.path.isfile(full) and not os.path.islink(full) \
                and os.path.splitext(name)[1].lower() in ALLOWED_EXTENSIONS:
            out.append(name)
    return out


def register_backup(source_name, asset_id, retention, notes, user_id, source_dir, storage_dir):
    """Register a file from the approved fixtures folder. Only plain file names that are
    listed in that folder are accepted, so path traversal is impossible."""
    asset_id = _parse_asset_id(asset_id)
    days = parse_retention(retention)
    notes = _clean_notes(notes)
    if source_name not in list_source_files(source_dir):
        raise ValidationError("source_not_found", "That file is not in the approved source folder.", 404)
    full = os.path.join(source_dir, source_name)
    if get_db().execute("SELECT 1 FROM assets WHERE id = ?", (asset_id,)).fetchone() is None:
        raise ValidationError("asset_not_found", "Selected asset does not exist.", 404)
    with open(full, "rb") as f:
        clean, stored, size, digest = _ingest(f, source_name, storage_dir)
    try:
        pid = _insert_backup(asset_id, clean, stored, size, digest, "register", days, notes, user_id)
    except Exception:
        os.remove(os.path.join(storage_dir, stored))
        raise
    return pid, digest


def _like_escape(s):
    return s.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def search_backups(q=None, asset_id=None, limit=100):
    sql = ("SELECT b.public_id, b.original_filename, b.size_bytes, b.sha256, b.source, b.status,"
           " b.retention_days, b.created_at, a.name AS asset_name, a.id AS asset_id, u.username AS created_by"
           " FROM backups b JOIN assets a ON a.id = b.asset_id JOIN users u ON u.id = b.created_by WHERE 1=1")
    params = []
    if q:
        sql += " AND (b.original_filename LIKE ? ESCAPE '\\' OR a.name LIKE ? ESCAPE '\\' OR b.sha256 LIKE ? ESCAPE '\\')"
        like = f"%{_like_escape(q.strip()[:100])}%"
        params += [like, like, like]
    if asset_id:
        try:
            params.append(int(asset_id))
            sql += " AND a.id = ?"
        except ValueError:
            raise ValidationError("invalid_asset", "Invalid asset filter.")
    sql += " ORDER BY b.created_at DESC, b.id DESC LIMIT ?"
    params.append(max(1, min(int(limit), 500)))
    return get_db().execute(sql, params).fetchall()


def get_backup(public_id):
    if not re.fullmatch(r"[0-9a-f]{32}", public_id or ""):
        return None
    return get_db().execute(
        "SELECT b.*, a.name AS asset_name, u.username AS created_by_name FROM backups b"
        " JOIN assets a ON a.id = b.asset_id JOIN users u ON u.id = b.created_by"
        " WHERE b.public_id = ?", (public_id,)).fetchone()



def delete_backup(public_id, storage_dir):
    from .retention import check_retention

    row = get_backup(public_id)

    if row is None:
        raise ValidationError(
            "not_found",
            "Backup not found.",
            404
        )

    # Check retention before deleting anything
    retention_result = check_retention(public_id)

    if retention_result["status"] == "active":
        raise ValidationError(
            "retention_active",
            "Backup cannot be deleted before its retention period expires.",
            409
        )

    # Retention expired: deletion is permitted
    db = get_db()

    db.execute(
        "DELETE FROM backups WHERE id = ?",
        (row["id"],)
    )
    db.commit()

    path = os.path.join(
        storage_dir,
        row["stored_filename"]
    )

    if os.path.isfile(path):
        os.remove(path)

    return row


def list_assets():
    return get_db().execute(
        "SELECT a.id, a.name, a.description, a.created_at,"
        " (SELECT COUNT(*) FROM backups b WHERE b.asset_id = a.id) AS backup_count"
        " FROM assets a ORDER BY a.name").fetchall()


def list_users():
    return get_db().execute(
        "SELECT id, username, role, is_active, created_at FROM users ORDER BY username").fetchall()


def row_to_dict(row):
    return {k: row[k] for k in row.keys() if k not in ("password_hash", "stored_filename")}
