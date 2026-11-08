import os
import sqlite3

from flask import current_app, g


def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(current_app.config["DATABASE"])
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


def close_db(_exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def init_db():
    schema = os.path.join(os.path.dirname(current_app.root_path), "schema.sql")
    with open(schema, encoding="utf-8") as f:
        script = f.read()
    db = get_db()
    db.executescript(script)
    db.commit()
