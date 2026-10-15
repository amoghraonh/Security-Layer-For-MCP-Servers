"""AIRLOCK Security Lab Example Service."""

import os
import sys

def main() -> None:
    service_name = os.getenv("SERVICE_NAME", "airlock-lab-node")
    print(f"[{service_name}] Zero-Trust verified execution running.")

if __name__ == "__main__":
    main()
