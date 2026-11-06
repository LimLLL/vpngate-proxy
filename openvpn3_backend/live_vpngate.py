"""GitHub Actions-only live check of a selected backend and the existing proxy."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import subprocess
import threading
import time
import urllib.request
from pathlib import Path
from typing import Any

from proxy_server import start_proxy_server
from snapshot_utils import MAX_SNAPSHOT_BYTES, decode_config, parse_and_validate_snapshot


ROOT = Path(__file__).resolve().parents[1]
API_URL = "https://www.vpngate.net/api/iphone/"
ROUTE_TABLE = 103
RULE_PRIORITY = 32103
PROXY_PORT = 17928


def load_candidates(limit: int) -> list[tuple[str, str]]:
    text = ""
    request = urllib.request.Request(API_URL, headers={"User-Agent": "vpngate-proxy-openvpn3-smoke/1"})
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            payload = response.read(MAX_SNAPSHOT_BYTES + 1)
        if len(payload) > MAX_SNAPSHOT_BYTES:
            raise ValueError("VPNGate response is too large")
        text = payload.decode("utf-8")
        parse_and_validate_snapshot(text, max_rows=1)
        print("Using the live VPNGate API snapshot", flush=True)
    except Exception as exc:
        print(f"Live VPNGate API unavailable, using bundled snapshot: {exc}", flush=True)
        text = (ROOT / "mirror" / "vpngate.csv").read_text(encoding="utf-8")

    rows = parse_and_validate_snapshot(text, max_rows=max(30, limit * 3))
    rows.sort(key=lambda row: int(row.get("Ping") or 999999))
    candidates: list[tuple[str, str]] = []
    for row in rows:
        label = f"{row['CountryShort']}-{row['IP']}"
        candidates.append((label, decode_config(row["OpenVPN_ConfigData_Base64"])))
        if len(candidates) >= limit:
            break
    return candidates


def command_ip(proxy: str | None = None, timeout: int = 10) -> str:
    errors: list[str] = []
    for url in ("http://api.ipify.org", "http://ip.sb"):
        command = ["curl", "--silent", "--show-error", "--fail", "--max-time", str(timeout)]
        if proxy:
            command.extend(["--noproxy", "", "--proxy", proxy])
        else:
            command.extend(["--noproxy", "*"])
        command.append(url)
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout + 2)
        value = result.stdout.strip()
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            errors.append(f"{url}: rc={result.returncode}; {result.stderr.strip()}; body={value[:100]}")
    raise RuntimeError("Public IP request failed: " + " | ".join(errors))


def prepare_policy_routing(device: str) -> None:
    cleanup_policy_routing()
    subprocess.run(
        ["ip", "route", "replace", "default", "dev", device, "table", str(ROUTE_TABLE)],
        check=True,
        timeout=5,
    )
    subprocess.run(
        [
            "ip", "rule", "add", "priority", str(RULE_PRIORITY),
            "oif", device, "table", str(ROUTE_TABLE),
        ],
        check=True,
        timeout=5,
    )
    for name in ("all", "default", device):
        subprocess.run(
            ["sysctl", "-w", f"net.ipv4.conf.{name}.rp_filter=2"],
            check=True,
            capture_output=True,
            timeout=5,
        )


def cleanup_policy_routing() -> None:
    subprocess.run(
        ["ip", "rule", "del", "priority", str(RULE_PRIORITY)],
        capture_output=True,
        timeout=5,
    )
    subprocess.run(
        ["ip", "route", "flush", "table", str(ROUTE_TABLE)],
        capture_output=True,
        timeout=5,
    )


def start_proxy() -> None:
    threading.Thread(
        target=start_proxy_server,
        args=("127.0.0.1", PROXY_PORT),
        name="local-socks5-smoke-proxy",
        daemon=True,
    ).start()
    for _ in range(30):
        try:
            with socket.create_connection(("127.0.0.1", PROXY_PORT), timeout=0.5):
                return
        except OSError:
            time.sleep(0.2)
    raise RuntimeError("Local proxy did not start listening")


def wait_with_progress(label: str, connection: Any, timeout: int) -> dict[str, Any]:
    deadline = time.monotonic() + timeout
    event_cursor = 0
    last_log = ""
    while time.monotonic() < deadline:
        try:
            info = connection.wait_connected(min(1.0, max(0.01, deadline - time.monotonic())))
            print(f"[{label}] CONNECTED: {info}", flush=True)
            return info
        except TimeoutError:
            events = connection.events
            for event in events[event_cursor:]:
                print(f"[{label}] event: {event}", flush=True)
            event_cursor = len(events)
            logs = connection.logs
            if logs and logs[-1] != last_log:
                last_log = logs[-1]
                print(f"[{label}] native: {last_log}", flush=True)
        except Exception:
            print(f"[{label}] native failure events={connection.events} logs={connection.logs[-12:]}", flush=True)
            raise
    raise TimeoutError(f"{label} did not become ready within {timeout}s")


def probe_candidate(
    backend: str,
    label: str,
    profile: str,
    timeout: int,
    direct_ip: str | None,
) -> dict[str, Any]:
    if backend == "core":
        from .core import VPNConnection as Connection
    else:
        from .cli_backend import CLIConnection as Connection
    connection = Connection(profile, connect_timeout=timeout, device="tun0")
    result: dict[str, Any] = {}
    try:
        started = time.monotonic()
        print(f"[{label}] entering {backend} start/eval_config", flush=True)
        connection.start()
        print(f"[{label}] start returned; waiting for CONNECTED", flush=True)
        info = wait_with_progress(label, connection, timeout + 10)
        connect_ms = round((time.monotonic() - started) * 1000)
        if info.get("tunName") != "tun0":
            raise RuntimeError(f"Unexpected TUN name: {info.get('tunName')!r}")
        print(f"[{label}] configuring policy routing and checking proxy", flush=True)
        prepare_policy_routing("tun0")
        proxy_ip = command_ip(f"socks5h://127.0.0.1:{PROXY_PORT}")
        if direct_ip and proxy_ip == direct_ip:
            raise RuntimeError("Proxy IP matches the direct IP; traffic did not use the VPN exit")
        result = {
            "backend": backend,
            "node": label,
            "connected": True,
            "connect_ms": connect_ms,
            "direct_ip": direct_ip,
            "proxy_ip": proxy_ip,
            "connection": info,
            "events": connection.events,
        }
    except Exception as exc:
        result = {
            "backend": backend,
            "node": label,
            "connected": False,
            "error": str(exc),
            "status": connection.status,
            "events": connection.events,
            "logs": connection.logs[-12:],
        }
        # Emit the handshake error before stop(), so a stopping bug cannot hide it.
        print(json.dumps(result, ensure_ascii=False), flush=True)
    finally:
        print(f"[{label}] removing policy routes", flush=True)
        cleanup_policy_routing()
        print(f"[{label}] stopping native connection", flush=True)
        connection.close()
        print(f"[{label}] stop completed", flush=True)
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--attempts", type=int, default=8)
    parser.add_argument("--timeout", type=int, default=20)
    parser.add_argument("--backend", choices=("core", "cli"), default="core")
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("The live test must run as root in the dedicated GitHub Actions runner")
    if args.attempts < 1 or args.timeout < 1:
        raise SystemExit("--attempts and --timeout must be positive")

    direct_ip: str | None
    try:
        direct_ip = command_ip()
        print(f"Direct runner IP: {direct_ip}", flush=True)
    except Exception as exc:
        direct_ip = None
        print(f"Direct IP lookup unavailable; continuing: {exc}", flush=True)

    start_proxy()
    failures: list[dict[str, Any]] = []
    for label, profile in load_candidates(args.attempts):
        print(f"Trying {label} through {args.backend}", flush=True)
        result = probe_candidate(args.backend, label, profile, args.timeout, direct_ip)
        if result["connected"]:
            print(json.dumps({"ok": True, "result": result}, ensure_ascii=False, indent=2), flush=True)
            return
        failures.append(result)
        print(json.dumps(result, ensure_ascii=False), flush=True)

    print(json.dumps({"ok": False, "failures": failures}, ensure_ascii=False, indent=2), flush=True)
    raise SystemExit(f"None of the {len(failures)} attempted VPNGate nodes passed the end-to-end check")


if __name__ == "__main__":
    main()
