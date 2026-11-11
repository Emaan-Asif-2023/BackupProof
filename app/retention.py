from datetime import datetime, timedelta, timezone
from .db import get_db


def check_retention(public_id):
    """Check whether a backup's retention period has expired."""

    db = get_db()

    backup = db.execute(
        """
        SELECT public_id, created_at, retention_days
        FROM backups
        WHERE public_id = ?
        """,
        (public_id,),
    ).fetchone()

    if backup is None:
        return {
            "status": "not_found",
            "reason": "Backup not found."
        }

    created_at = datetime.fromisoformat(
        backup["created_at"].replace("Z", "+00:00")
    )

    expiry_date = created_at + timedelta(
        days=backup["retention_days"]
    )

    now = datetime.now(timezone.utc)

    expired = now >= expiry_date

    return {
        "backup_id": backup["public_id"],
        "retention_days": backup["retention_days"],
        "created_at": created_at.isoformat(),
        "expiry_date": expiry_date.isoformat(),
        "status": "expired" if expired else "active",
        "reason": (
            "Backup retention period has expired."
            if expired
            else "Backup is within its retention period."
        )
    }