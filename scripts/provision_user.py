"""Create a local AIRLOCK account without placing a password in source or shell history."""

from __future__ import annotations

import argparse
import getpass

from app.api.management import DEFAULT_AUTH_PATH
from app.auth.service import ROLES, AuthStore


def main() -> None:
    parser = argparse.ArgumentParser(description="Provision a local AIRLOCK user")
    parser.add_argument("username")
    parser.add_argument("role", choices=sorted(ROLES))
    args = parser.parse_args()
    password = getpass.getpass("Password (12+ characters): ")
    confirmation = getpass.getpass("Confirm password: ")
    if password != confirmation:
        raise SystemExit("Passwords do not match")
    AuthStore(DEFAULT_AUTH_PATH).provision(args.username, password, args.role)
    print(f"Provisioned {args.username!r} with role {args.role!r}.")


if __name__ == "__main__":
    main()
