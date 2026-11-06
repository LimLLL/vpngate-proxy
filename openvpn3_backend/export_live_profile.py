"""Export one live/bundled VPNGate candidate for the Go or CLI comparison."""

from __future__ import annotations

import argparse
from pathlib import Path

from .live_vpngate import load_candidates
from .profiles import prepare_profile


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--snapshot", type=Path)
    parser.add_argument("--rank", type=int, default=1)
    parser.add_argument("--device", default="tun0")
    args = parser.parse_args()
    if args.rank < 1:
        raise SystemExit("--rank must be positive")
    candidates = load_candidates(args.rank, args.snapshot)
    label, profile = candidates[args.rank - 1]
    args.output.write_text(prepare_profile(profile, args.device), encoding="utf-8")
    print(f"Exported {label} to {args.output}", flush=True)


if __name__ == "__main__":
    main()
