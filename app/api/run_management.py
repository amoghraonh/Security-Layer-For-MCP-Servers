"""Run the management API on loopback only by default."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv
import uvicorn

from app.api.management import DEFAULT_AUDIT_PATH, create_management_app


def main() -> None:
    load_dotenv()
    database_path = Path(os.environ.get("SENTRY_X_AUDIT_DATABASE", DEFAULT_AUDIT_PATH))
    host = os.environ.get("SENTRY_X_MANAGEMENT_HOST", "127.0.0.1")
    port = int(os.environ.get("SENTRY_X_MANAGEMENT_PORT", "8000"))
    uvicorn.run(create_management_app(database_path), host=host, port=port)


if __name__ == "__main__":
    main()
