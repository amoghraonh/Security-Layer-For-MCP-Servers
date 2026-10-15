"""Small SQLite-backed audit log for AIRLOCK gateway decisions."""

from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


SENSITIVE_KEY_PARTS = ("secret", "password", "token", "api_key", "credential")


def sanitize_arguments(arguments: dict[str, Any]) -> dict[str, Any]:
    """Keep useful audit context while redacting common secret-bearing fields."""
    sanitized: dict[str, Any] = {}
    for key, value in arguments.items():
        if any(part in key.lower() for part in SENSITIVE_KEY_PARTS):
            sanitized[key] = "[REDACTED]"
        elif isinstance(value, dict):
            sanitized[key] = sanitize_arguments(value)
        elif isinstance(value, list):
            sanitized[key] = [sanitize_arguments(item) if isinstance(item, dict) else item for item in value]
        else:
            sanitized[key] = value
    return sanitized


class SQLiteAuditLog:
    """Open short-lived connections so stdio handlers do not share SQLite state."""

    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self.database_path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    server_identifier TEXT NOT NULL,
                    tool_identifier TEXT NOT NULL,
                    sanitized_arguments TEXT NOT NULL,
                    decision TEXT NOT NULL,
                    matched_policy TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    fingerprint_status TEXT NOT NULL,
                    response_inspection_outcome TEXT NOT NULL,
                    upstream_executed INTEGER NOT NULL CHECK (upstream_executed IN (0, 1)),
                    risk_score INTEGER NOT NULL DEFAULT 0,
                    risk_category TEXT NOT NULL DEFAULT 'Low',
                    risk_factors TEXT NOT NULL DEFAULT '[]'
                )
                """
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(audit_events)")}
            migrations = {
                "risk_score": "ALTER TABLE audit_events ADD COLUMN risk_score INTEGER NOT NULL DEFAULT 0",
                "risk_category": "ALTER TABLE audit_events ADD COLUMN risk_category TEXT NOT NULL DEFAULT 'Low'",
                "risk_factors": "ALTER TABLE audit_events ADD COLUMN risk_factors TEXT NOT NULL DEFAULT '[]'",
            }
            for column, statement in migrations.items():
                if column not in columns:
                    connection.execute(statement)

    def record_event(
        self,
        *,
        server_identifier: str,
        tool_identifier: str,
        arguments: dict[str, Any],
        decision: str,
        matched_policy: str,
        reason: str,
        fingerprint_status: str,
        response_inspection_outcome: str,
        upstream_executed: bool,
        risk_score: int = 0,
        risk_category: str = "Low",
        risk_factors: list[str] | None = None,
    ) -> int:
        timestamp = datetime.now(UTC).isoformat()
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO audit_events (
                    timestamp, server_identifier, tool_identifier, sanitized_arguments,
                    decision, matched_policy, reason, fingerprint_status,
                    response_inspection_outcome, upstream_executed, risk_score,
                    risk_category, risk_factors
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    timestamp,
                    server_identifier,
                    tool_identifier,
                    json.dumps(sanitize_arguments(arguments), sort_keys=True),
                    decision,
                    matched_policy,
                    reason,
                    fingerprint_status,
                    response_inspection_outcome,
                    int(upstream_executed),
                    risk_score,
                    risk_category,
                    json.dumps(risk_factors or [], sort_keys=True),
                ),
            )
            return int(cursor.lastrowid)

    def events(self, limit: int = 100) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                "SELECT * FROM audit_events ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [self._row_to_event(row) for row in rows]

    def event(self, event_id: int) -> dict[str, Any] | None:
        with self._connect() as connection:
            row = connection.execute("SELECT * FROM audit_events WHERE id = ?", (event_id,)).fetchone()
        return self._row_to_event(row) if row else None

    def summary(self) -> dict[str, int]:
        with self._connect() as connection:
            total = connection.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            allowed = connection.execute("SELECT COUNT(*) FROM audit_events WHERE decision = 'allow'").fetchone()[0]
            denied = connection.execute("SELECT COUNT(*) FROM audit_events WHERE decision = 'deny'").fetchone()[0]
            executed = connection.execute("SELECT COUNT(*) FROM audit_events WHERE upstream_executed = 1").fetchone()[0]
        return {"total_events": total, "allowed": allowed, "denied": denied, "upstream_executed": executed}

    def connections(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT server_identifier, COUNT(*) AS event_count, MAX(timestamp) AS last_seen
                FROM audit_events GROUP BY server_identifier ORDER BY server_identifier
                """
            ).fetchall()
        return [dict(row) for row in rows]

    @staticmethod
    def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
        event = dict(row)
        event["sanitized_arguments"] = json.loads(event["sanitized_arguments"])
        event["risk_factors"] = json.loads(event["risk_factors"])
        event["upstream_executed"] = bool(event["upstream_executed"])
        return event
