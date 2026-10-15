"""SQLite state for exact-request, one-time security approvals."""

from __future__ import annotations

import hashlib
import json
import secrets
import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any


def canonical_request_hash(tool: str, arguments: dict[str, Any]) -> str:
    payload = json.dumps({"tool": tool, "arguments": arguments}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class ApprovalStore:
    """Approval records are bound to canonical arguments and consumed once."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS approval_requests (
                    id TEXT PRIMARY KEY, requester TEXT NOT NULL, tool TEXT NOT NULL,
                    arguments_json TEXT NOT NULL, request_hash TEXT NOT NULL,
                    status TEXT NOT NULL, created_at TEXT NOT NULL, expires_at TEXT NOT NULL,
                    approver TEXT, justification TEXT, consumed_at TEXT
                )"""
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def create(self, requester: str, tool: str, arguments: dict[str, Any], ttl_seconds: int = 300) -> dict[str, Any]:
        now = datetime.now(UTC)
        request_id = "apr_" + secrets.token_urlsafe(12)
        expires = now + timedelta(seconds=min(max(ttl_seconds, 30), 900))
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO approval_requests VALUES (?, ?, ?, ?, ?, ?, ?, ?, NULL, NULL, NULL)",
                (request_id, requester, tool, json.dumps(arguments, sort_keys=True), canonical_request_hash(tool, arguments), "pending", now.isoformat(), expires.isoformat()),
            )
        return self.get(request_id) or {}

    def get(self, request_id: str) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM approval_requests WHERE id = ?", (request_id,)).fetchone()
        return self._row(row) if row else None

    def pending(self) -> list[dict[str, Any]]:
        self.expire_due()
        with self._connect() as connection:
            rows = connection.execute("SELECT * FROM approval_requests WHERE status = 'pending' ORDER BY created_at DESC").fetchall()
        return [self._row(row) for row in rows]

    def decide(self, request_id: str, approver: str, approve: bool, justification: str = "") -> dict[str, Any] | None:
        self.expire_due()
        status = "approved" if approve else "denied"
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE approval_requests SET status = ?, approver = ?, justification = ? WHERE id = ? AND status = 'pending'",
                (status, approver, justification, request_id),
            )
        return self.get(request_id) if cursor.rowcount else None

    def consume(self, request_id: str, tool: str, arguments: dict[str, Any]) -> bool:
        self.expire_due()
        expected = canonical_request_hash(tool, arguments)
        with self._connect() as connection:
            cursor = connection.execute(
                "UPDATE approval_requests SET status = 'consumed', consumed_at = ? WHERE id = ? AND status = 'approved' AND request_hash = ?",
                (datetime.now(UTC).isoformat(), request_id, expected),
            )
        return bool(cursor.rowcount)

    def expire_due(self) -> None:
        with self._connect() as connection:
            connection.execute("UPDATE approval_requests SET status = 'expired' WHERE status IN ('pending', 'approved') AND expires_at <= ?", (datetime.now(UTC).isoformat(),))

    @staticmethod
    def _row(row: sqlite3.Row) -> dict[str, Any]:
        value = dict(row)
        value["arguments"] = json.loads(value.pop("arguments_json"))
        value.pop("request_hash", None)
        return value
