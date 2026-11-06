#!/usr/bin/env python3
"""Allow only the ephemeral benchmark credentials used by the local testbed."""

import json
import os
import sys
from pathlib import Path


def main() -> None:
    credentials = Path(sys.argv[1]).read_text(encoding="utf-8").splitlines()
    username = os.environ.get("username", "")
    if len(credentials) != 2 or username != "vpn" or credentials != ["vpn", "vpn"]:
        raise SystemExit("Benchmark username/password verification failed")

    event = {"username": username, "common_name": os.environ["common_name"]}
    # OpenVPN invokes this script with a sanitized environment. The script's
    # destination inside the private per-run directory needs no custom env.
    audit_log = Path(__file__).with_name("auth.jsonl")
    with audit_log.open("a", encoding="utf-8") as log:
        log.write(json.dumps(event) + "\n")


if __name__ == "__main__":
    main()
