"""Evaluate or connect one profile through the native OpenVPN 3 Core API."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core import (
    VPNConnection,
    evaluate_profile,
    native_crypto_self_test,
    native_platform,
)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("profile", type=Path)
    parser.add_argument("--evaluate-only", action="store_true")
    parser.add_argument("--connect-timeout", type=int, default=30)
    parser.add_argument("--wait-timeout", type=float, default=40)
    parser.add_argument("--device")
    args = parser.parse_args()

    profile = args.profile.read_text(encoding="utf-8")
    print(json.dumps({
        "platform": native_platform(),
        "crypto_self_test": native_crypto_self_test(),
        "evaluation": evaluate_profile(profile, args.connect_timeout).__dict__,
    }, ensure_ascii=False, indent=2))
    if args.evaluate_only:
        return

    connection = VPNConnection(
        profile,
        connect_timeout=args.connect_timeout,
        device=args.device,
    )
    try:
        connection.start()
        info = connection.wait_connected(args.wait_timeout)
        print(json.dumps({"connected": True, "connection": info}, ensure_ascii=False, indent=2))
    except Exception:
        print(json.dumps({
            "connected": False,
            "status": connection.status,
            "events": connection.events,
            "logs": connection.logs[-30:],
        }, ensure_ascii=False, indent=2))
        raise
    finally:
        connection.close()


if __name__ == "__main__":
    main()
