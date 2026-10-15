"""Argon2id password and opaque-session handling; no browser-side credentials."""

from __future__ import annotations

import hashlib
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError


ROLES = {"super_admin", "security_admin", "approver", "developer", "auditor"}


class AuthStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self.hasher = PasswordHasher()
        with self._connect() as connection:
            connection.execute("""CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY, password_hash TEXT NOT NULL, role TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1, failed_attempts INTEGER NOT NULL DEFAULT 0,
                locked_until TEXT
            )""")
            connection.execute("""CREATE TABLE IF NOT EXISTS sessions (
                token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, role TEXT NOT NULL,
                expires_at TEXT NOT NULL, revoked INTEGER NOT NULL DEFAULT 0
            )""")
            connection.execute("""CREATE TABLE IF NOT EXISTS auth_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT, timestamp TEXT NOT NULL, username TEXT,
                event TEXT NOT NULL, detail TEXT NOT NULL
            )""")

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def provision(self, username: str, password: str, role: str) -> None:
        if not username or len(password) < 12 or role not in ROLES:
            raise ValueError("Username, a 12+ character password, and a valid role are required")
        with self._connect() as connection:
            connection.execute("INSERT OR REPLACE INTO users (username, password_hash, role, enabled, failed_attempts, locked_until) VALUES (?, ?, ?, 1, 0, NULL)", (username, self.hasher.hash(password), role))
        self._event(username, "account_provisioned", role)

    def login(self, username: str, password: str) -> tuple[str, dict[str, str]] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if not row or not row["enabled"] or (row["locked_until"] and row["locked_until"] > datetime.now(UTC).isoformat()):
            self._event(username, "login_failed", "unknown, disabled, or locked account")
            return None
        try:
            self.hasher.verify(row["password_hash"], password)
        except VerifyMismatchError:
            failures = row["failed_attempts"] + 1
            lock = (datetime.now(UTC) + timedelta(minutes=15)).isoformat() if failures >= 5 else None
            with self._connect() as connection:
                connection.execute("UPDATE users SET failed_attempts = ?, locked_until = ? WHERE username = ?", (failures, lock, username))
            self._event(username, "account_locked" if lock else "login_failed", "invalid password")
            return None
        with self._connect() as connection:
            connection.execute("UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE username = ?", (username,))
        token = secrets.token_urlsafe(32)
        expires = datetime.now(UTC) + timedelta(hours=8)
        with self._connect() as connection:
            connection.execute("INSERT INTO sessions VALUES (?, ?, ?, ?, 0)", (self._hash(token), username, row["role"], expires.isoformat()))
        self._event(username, "login_succeeded", row["role"])
        return token, {"username": username, "role": row["role"]}

    def current(self, token: str | None) -> dict[str, str] | None:
        if not token:
            return None
        with self._connect() as connection:
            row = connection.execute("SELECT username, role FROM sessions WHERE token_hash = ? AND revoked = 0 AND expires_at > ?", (self._hash(token), datetime.now(UTC).isoformat())).fetchone()
        return dict(row) if row else None

    def logout(self, token: str | None) -> None:
        if not token:
            return
        identity = self.current(token)
        with self._connect() as connection:
            connection.execute("UPDATE sessions SET revoked = 1 WHERE token_hash = ?", (self._hash(token),))
        if identity:
            self._event(identity["username"], "logout", "session revoked")

    def recent_events(self, limit: int = 50) -> list[dict[str, str]]:
        with self._connect() as connection:
            rows = connection.execute("SELECT timestamp, username, event, detail FROM auth_events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(row) for row in rows]

    def _event(self, username: str | None, event: str, detail: str) -> None:
        with self._connect() as connection:
            connection.execute("INSERT INTO auth_events (timestamp, username, event, detail) VALUES (?, ?, ?, ?)", (datetime.now(UTC).isoformat(), username, event, detail))

    @staticmethod
    def _hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()
