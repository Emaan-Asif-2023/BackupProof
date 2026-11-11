import hashlib
import os
import re

from .db import get_db
from .services import ValidationError


def verify_backup(public_id, storage_dir):
    """Verify a backup against its stored SHA-256 checksum."""

    db = get_db()

    backup = db.execute(
        """
        SELECT public_id, stored_filename, sha256, size_bytes
        FROM backups
        WHERE public_id = ?
        """,
        (public_id,),
    ).fetchone()

    if backup is None:
        raise ValidationError(
            "backup_not_found", "Backup not found.", 404
        )

    stored_name = backup["stored_filename"]

    # Reject unsafe stored paths.
    if (
        not stored_name
        or stored_name in (".", "..")
        or os.path.basename(stored_name) != stored_name
        or not re.fullmatch(r"[A-Za-z0-9_.-]+", stored_name)
    ):
        raise ValidationError(
            "invalid_storage_path", "Invalid backup storage reference.", 400
        )

    path = os.path.join(storage_dir, stored_name)

    result = {
        "backup_id": backup["public_id"],
        "expected_sha256": backup["sha256"],
        "actual_sha256": None,
        "status": None,
        "reason": None,
    }

    if not os.path.isfile(path) or os.path.islink(path):
        result["status"] = "missing"
        result["reason"] = "Backup file is missing or unavailable."
        return result

    hasher = hashlib.sha256()

    try:
        with open(path, "rb") as file:
            while True:
                chunk = file.read(1024 * 1024)
                if not chunk:
                    break
                hasher.update(chunk)
    except OSError:
        raise ValidationError(
            "backup_unreadable",
            "Backup could not be read safely.",
            500,
        )

    actual_hash = hasher.hexdigest()
    result["actual_sha256"] = actual_hash

    if (
        actual_hash == backup["sha256"]
        and os.path.getsize(path) == backup["size_bytes"]
    ):
        result["status"] = "verified"
        result["reason"] = "Backup integrity verified successfully."
    else:
        result["status"] = "corrupted"
        result["reason"] = "Backup checksum or size does not match."

    return result


def generate_manifest(public_id):
    """Generate a checksum manifest from stored backup metadata."""
    db = get_db()

    backup = db.execute(
        """
        SELECT public_id, original_filename,
               stored_filename, size_bytes,
               sha256, created_at
        FROM backups
        WHERE public_id = ?
        """,
        (public_id,)
    ).fetchone()

    if backup is None:
        raise ValidationError(
            "backup_not_found",
            "Backup not found.",
            404
        )

    return {
        "manifest_version": "1.0",
        "backup_id": backup["public_id"],
        "original_filename": backup["original_filename"],
        "stored_filename": backup["stored_filename"],
        "size_bytes": backup["size_bytes"],
        "sha256": backup["sha256"],
        "created_at": backup["created_at"]
    }
