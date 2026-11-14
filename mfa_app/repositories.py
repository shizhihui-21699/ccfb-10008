"""Data-access layer. Thin wrappers over SQLite; all business rules live in
``services`` so repositories stay free of policy decisions."""

from __future__ import annotations

import json
import sqlite3
from typing import Any

from .clock import clock


class UserRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def create(self, username: str, password_hash: str, is_admin: bool = False) -> int:
        cur = self.conn.execute(
            "INSERT INTO users (username, password_hash, is_admin, created_at) "
            "VALUES (?, ?, ?, ?)",
            (username, password_hash, int(is_admin), clock.now()),
        )
        return int(cur.lastrowid)

    def get(self, user_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM users WHERE id = ?", (user_id,)
        ).fetchone()

    def get_by_username(self, username: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM users WHERE username = ?", (username,)
        ).fetchone()

    def list_all(self) -> list[sqlite3.Row]:
        return list(self.conn.execute("SELECT * FROM users ORDER BY id"))

    def set_lock(self, user_id: int, failed_attempts: int,
                 locked_until: float | None) -> None:
        self.conn.execute(
            "UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?",
            (failed_attempts, locked_until, user_id),
        )

    def reset_lock(self, user_id: int) -> None:
        self.conn.execute(
            "UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?",
            (user_id,),
        )

    def set_password(self, user_id: int, password_hash: str) -> None:
        self.conn.execute(
            "UPDATE users SET password_hash = ? WHERE id = ?",
            (password_hash, user_id),
        )


class DeviceRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def create_pending(self, user_id: int, name: str, ciphertext: str) -> int:
        cur = self.conn.execute(
            "INSERT INTO devices (user_id, name, secret_ciphertext, confirmed, "
            "created_at) VALUES (?, ?, ?, 0, ?)",
            (user_id, name, ciphertext, clock.now()),
        )
        return int(cur.lastrowid)

    def get(self, device_id: int) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM devices WHERE id = ?", (device_id,)
        ).fetchone()

    def find(self, user_id: int, name: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM devices WHERE user_id = ? AND name = ?",
            (user_id, name),
        ).fetchone()

    def list_for_user(self, user_id: int, *, confirmed_only: bool = True) -> list[sqlite3.Row]:
        sql = "SELECT * FROM devices WHERE user_id = ?"
        if confirmed_only:
            sql += " AND confirmed = 1"
        sql += " ORDER BY id"
        return list(self.conn.execute(sql, (user_id,)))

    def list_all(self) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT d.*, u.username FROM devices d "
            "JOIN users u ON u.id = d.user_id ORDER BY d.id"))

    def confirm(self, device_id: int, counter: int) -> None:
        self.conn.execute(
            "UPDATE devices SET confirmed = 1, confirmed_at = ?, last_counter = ? "
            "WHERE id = ?",
            (clock.now(), counter, device_id),
        )

    def update_counter(self, device_id: int, counter: int) -> None:
        self.conn.execute(
            "UPDATE devices SET last_counter = ? WHERE id = ?",
            (counter, device_id),
        )

    def delete(self, device_id: int) -> None:
        self.conn.execute("DELETE FROM devices WHERE id = ?", (device_id,))

    def delete_for_user(self, user_id: int) -> None:
        self.conn.execute("DELETE FROM devices WHERE user_id = ?", (user_id,))


class BackupCodeRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def add(self, user_id: int, code_hash: str) -> None:
        self.conn.execute(
            "INSERT INTO backup_codes (user_id, code_hash, created_at) "
            "VALUES (?, ?, ?)",
            (user_id, code_hash, clock.now()),
        )

    def find_unused(self, user_id: int, code_hash: str) -> sqlite3.Row | None:
        return self.conn.execute(
            "SELECT * FROM backup_codes WHERE user_id = ? AND code_hash = ? "
            "AND used_at IS NULL",
            (user_id, code_hash),
        ).fetchone()

    def mark_used(self, code_id: int) -> int:
        """Atomically consume a code. Returns 1 on success, 0 if another
        transaction already spent it (the WHERE guard does the CAS)."""
        cur = self.conn.execute(
            "UPDATE backup_codes SET used_at = ? WHERE id = ? AND used_at IS NULL",
            (clock.now(), code_id),
        )
        return cur.rowcount

    def replace_all(self, user_id: int, hashes: list[str]) -> None:
        self.conn.execute("DELETE FROM backup_codes WHERE user_id = ?", (user_id,))
        now = clock.now()
        self.conn.executemany(
            "INSERT INTO backup_codes (user_id, code_hash, created_at) "
            "VALUES (?, ?, ?)",
            [(user_id, h, now) for h in hashes],
        )

    def counts(self, user_id: int) -> tuple[int, int]:
        row = self.conn.execute(
            "SELECT COUNT(*) AS total, "
            "SUM(CASE WHEN used_at IS NULL THEN 1 ELSE 0 END) AS unused "
            "FROM backup_codes WHERE user_id = ?",
            (user_id,),
        ).fetchone()
        return int(row["total"]), int(row["unused"] or 0)

    def list_for_user(self, user_id: int) -> list[sqlite3.Row]:
        return list(self.conn.execute(
            "SELECT * FROM backup_codes WHERE user_id = ? ORDER BY id",
            (user_id,),
        ))


class AuditRepository:
    def __init__(self, conn: sqlite3.Connection):
        self.conn = conn

    def record(self, action: str, result: str, *, user_id: int | None = None,
               username: str | None = None, ip: str | None = None,
               device_id: int | None = None, detail: dict[str, Any] | None = None) -> None:
        self.conn.execute(
            "INSERT INTO audit_log (ts, user_id, username, action, result, ip, "
            "device_id, detail) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (clock.now(), user_id, username, action, result, ip, device_id,
             json.dumps(detail, sort_keys=True) if detail else None),
        )

    def list_all(self, *, limit: int = 50, offset: int = 0,
                 user_id: int | None = None,
                 action: str | None = None) -> list[sqlite3.Row]:
        sql = "SELECT * FROM audit_log WHERE 1=1"
        params: list[Any] = []
        if user_id is not None:
            sql += " AND user_id = ?"
            params.append(user_id)
        if action:
            sql += " AND action = ?"
            params.append(action)
        sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
        params.extend([limit, offset])
        return list(self.conn.execute(sql, params))

    def count(self, *, user_id: int | None = None,
              action: str | None = None) -> int:
        sql = "SELECT COUNT(*) AS n FROM audit_log WHERE 1=1"
        params: list[Any] = []
        if user_id is not None:
            sql += " AND user_id = ?"
            params.append(user_id)
        if action:
            sql += " AND action = ?"
            params.append(action)
        return int(self.conn.execute(sql, params).fetchone()["n"])
