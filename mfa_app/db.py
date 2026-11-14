"""SQLite connection management and schema."""

from __future__ import annotations

import sqlite3

from flask import Flask, current_app, g


SCHEMA = """
PRAGMA journal_mode = WAL;

CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE,
    password_hash   TEXT NOT NULL,
    is_admin        INTEGER NOT NULL DEFAULT 0,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    REAL,
    created_at      REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS devices (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id           INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name              TEXT NOT NULL,
    secret_ciphertext TEXT NOT NULL,
    last_counter      INTEGER,
    confirmed         INTEGER NOT NULL DEFAULT 0,
    created_at        REAL NOT NULL,
    confirmed_at      REAL,
    UNIQUE (user_id, name)
);

CREATE TABLE IF NOT EXISTS backup_codes (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    code_hash  TEXT NOT NULL UNIQUE,
    used_at    REAL,
    created_at REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_backup_codes_user ON backup_codes(user_id);

CREATE TABLE IF NOT EXISTS audit_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    ts         REAL NOT NULL,
    user_id    INTEGER,
    username   TEXT,
    action     TEXT NOT NULL,
    result     TEXT NOT NULL,
    ip         TEXT,
    device_id  INTEGER,
    detail     TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts);
"""


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        conn = sqlite3.connect(
            current_app.config["DATABASE_PATH"],
            detect_types=sqlite3.PARSE_DECLTYPES,
        )
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(exc: BaseException | None = None) -> None:
    conn = g.pop("db", None)
    if conn is not None:
        # Commit on success so every request's writes are durable; roll back
        # if the view raised. Tests that share the connection keep their own
        # transaction semantics.
        if exc is None:
            conn.commit()
        else:
            conn.rollback()
        conn.close()


def init_db(app: Flask) -> None:
    path = app.config["DATABASE_PATH"]
    import os
    os.makedirs(os.path.dirname(os.path.abspath(path)) or ".", exist_ok=True)
    conn = sqlite3.connect(path)
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


def init_app(app: Flask) -> None:
    app.teardown_appcontext(close_db)
    init_db(app)
