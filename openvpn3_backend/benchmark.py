"""Compare real CLI processes and embedded Go/C++ Core on identical profiles."""

from __future__ import annotations

import argparse
import concurrent.futures
import json
import os
import subprocess
import time
from pathlib import Path
from typing import Any

from .cli_backend import CLIConnection
from .live_vpngate import (
    cleanup_policy_routing,
    command_ip,
    load_candidates,
    prepare_policy_routing,
)
from .profiles import prepare_profile


def write_json(path: Path, data: dict[str, Any]) -> None:
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")


def proc_status(pid: int) -> dict[str, int | float]:
    values: dict[str, int | float] = {}
    stat_text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8")
    stat_fields = stat_text.rpartition(") ")[2].split()
    if len(stat_fields) < 13:
        raise ValueError(f"Unexpected /proc/{pid}/stat format")
    ticks = int(stat_fields[11]) + int(stat_fields[12])
    values["cpu_ms"] = round(ticks * 1000 / os.sysconf("SC_CLK_TCK"), 3)
    for line in Path(f"/proc/{pid}/status").read_text(encoding="utf-8").splitlines():
        for key in ("VmRSS", "VmHWM", "Threads"):
            if line.startswith(key + ":"):
                fields = line.split()
                if len(fields) < 2 or (key != "Threads" and fields[-1] != "kB"):
                    raise ValueError(f"Unexpected {key} value: {line}")
                values[key] = int(fields[1])
    missing = {"VmRSS", "VmHWM", "Threads"} - values.keys()
    if missing:
        raise ValueError(f"Missing process metrics for {pid}: {sorted(missing)}")
    return values


def prepare_profiles(workdir: Path, maximum: int) -> tuple[list[str], list[Path], list[dict[str, Any]]]:
    """Select distinct healthy nodes with one throwaway CLI tunnel per node."""
    profile_dir = workdir / "profiles"
    profile_dir.mkdir(parents=True, exist_ok=True)
    attempts: list[dict[str, Any]] = []
    labels: list[str] = []
    paths: list[Path] = []
    seen_nodes: set[str] = set()
    for label, profile in load_candidates(12, workdir / "vpngate.csv"):
        if len(paths) == maximum:
            break
        if label in seen_nodes:
            continue
        seen_nodes.add(label)
        connection = CLIConnection(profile, connect_timeout=15, device="tun9")
        try:
            connection.start()
            connection.wait_connected(25)
            path = profile_dir / f"tun{len(paths)}.ovpn"
            path.write_text(prepare_profile(profile, f"tun{len(paths)}"), encoding="utf-8")
            paths.append(path)
            labels.append(label)
            attempts.append({"node": label, "passed": True, "connect_ms": connection.ready_ms})
            print(f"PRECHECK OK {label}: {connection.ready_ms:.0f} ms", flush=True)
        except Exception as exc:
            attempts.append({
                "node": label,
                "passed": False,
                "error": str(exc),
                "logs": connection.logs[-8:],
            })
            print(f"PRECHECK SKIP {label}: {connection.logs[-1:]}", flush=True)
        finally:
            connection.close()
        write_json(workdir / "selection.json", {"nodes": labels, "attempts": attempts})
    if len(paths) != maximum:
        raise RuntimeError(f"Only {len(paths)} of {maximum} distinct nodes passed the CLI preflight")
    return labels, paths, attempts


def traffic_check(count: int, direct_ip: str) -> list[dict[str, str]]:
    devices = [f"tun{index}" for index in range(count)]
    for device in devices:
        subprocess.run(["ip", "link", "show", "dev", device], check=True, capture_output=True, timeout=5)
    checks: list[dict[str, str]] = []
    try:
        for index, device in enumerate(devices):
            prepare_policy_routing(device, table=110 + index, priority=32110 + index)
        for device in devices:
            exit_ip = command_ip(interface=device)
            if exit_ip == direct_ip:
                raise RuntimeError(f"{device} leaked to the direct runner IP {direct_ip}")
            checks.append({"device": device, "exit_ip": exit_ip})
            print(f"  {device} exit: {exit_ip}", flush=True)
        return checks
    finally:
        for index in reversed(range(count)):
            cleanup_policy_routing(table=110 + index, priority=32110 + index)


def _connect_cli(index: int, profile: str, connection: CLIConnection) -> dict[str, Any]:
    started = time.monotonic()
    try:
        connection.start()
        info = connection.wait_connected(30)
        return {
            "device": f"tun{index}",
            "configure_ms": connection.spawn_ms,
            "connect_ms": connection.ready_ms,
            "observed_ready_ms": round((time.monotonic() - started) * 1000, 3),
            "info": info,
        }
    except Exception as exc:
        # Keep the native error after the higher-level readiness timeout.
        diagnostic = " | ".join(connection.logs[-8:])
        try:
            connection.close()
        except Exception as cleanup_error:
            raise RuntimeError(f"tun{index}: {diagnostic}; cleanup failed: {cleanup_error}") from exc
        raise RuntimeError(f"tun{index}: {diagnostic}") from exc


def cli_connected(profiles: list[Path]) -> tuple[list[CLIConnection], dict[str, Any]]:
    started = time.monotonic()
    connections = [
        CLIConnection(path.read_text(encoding="utf-8"), connect_timeout=20, device=f"tun{index}")
        for index, path in enumerate(profiles)
    ]
    report = base_report("openvpn2-cli", len(connections))
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(connections)) as pool:
            sessions = list(pool.map(lambda item: _connect_cli(item[0], item[1], item[2]),
                                     zip(range(len(connections)), profiles, connections)))
        report["sessions"] = sessions
        report["wall_ready_ms"] = round((time.monotonic() - started) * 1000, 3)
        report["max_ready_ms"] = max(session["connect_ms"] for session in sessions)
        metrics = [proc_status(connection.process_id) for connection in connections if connection.process_id]
        report["threads_after_connect"] = sum(metric["Threads"] for metric in metrics)
        report["current_rss_kb_after_connect"] = sum(metric["VmRSS"] for metric in metrics)
        report["peak_rss_kb"] = sum(metric["VmHWM"] for metric in metrics)
        report["stage"] = "connected"
        return connections, report
    except Exception:
        for connection in connections:
            try:
                connection.close()
            except Exception as exc:
                print(f"Cleanup after failed CLI connect: {exc}", flush=True)
        raise


def cli_closed(connections: list[CLIConnection], sessions: list[dict[str, Any]]) -> None:
    def close(connection: CLIConnection) -> dict[str, Any]:
        started = time.monotonic()
        try:
            connection.close()
            return {"close_ms": round((time.monotonic() - started) * 1000, 3)}
        except Exception as exc:
            return {"error": str(exc), "close_ms": round((time.monotonic() - started) * 1000, 3)}

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(connections)) as pool:
        results = list(pool.map(close, connections))
    for session, result in zip(sessions, results):
        session["close_ms"] = result["close_ms"]
        if "error" in result:
            session["error"] = result["error"]
    errors = [result["error"] for result in results if "error" in result]
    if errors:
        raise RuntimeError("CLI shutdown failed: " + " | ".join(errors))


def base_report(backend: str, count: int) -> dict[str, Any]:
    return {
        "backend": backend,
        "concurrency": count,
        "stage": "starting",
        "engine_process_count": count if backend == "openvpn2-cli" else 1,
        "sessions": [],
        "errors": [],
    }


def run_cli(profiles: list[Path], direct_ip: str) -> dict[str, Any]:
    connections, report = cli_connected(profiles)
    errors: list[str] = []
    try:
        report["interface_checks"] = traffic_check(len(connections), direct_ip)
        report["cpu_ms"] = sum(proc_status(connection.process_id)["cpu_ms"]
                              for connection in connections if connection.process_id)
    except Exception as exc:
        errors.append(str(exc))
    try:
        cli_closed(connections, report["sessions"])
    except Exception as exc:
        errors.append(str(exc))
    if errors:
        report["stage"] = "failed"
        report["errors"].extend(errors)
        raise RuntimeError("; ".join(errors))
    report["stage"] = "stopped"
    return report


def run_go(profiles: list[Path], case_dir: Path, go_binary: Path, direct_ip: str) -> dict[str, Any]:
    ready_file = case_dir / "ready"
    report_file = case_dir / "report.json"
    stop_file = case_dir / "stop"
    for path in (ready_file, report_file, stop_file):
        path.unlink(missing_ok=True)
    log_path = case_dir / "go.log"
    command = [
        "timeout", "--signal=TERM", "--kill-after=5s", "85s", str(go_binary),
        "--profiles", ",".join(str(path) for path in profiles),
        "--ready-file", str(ready_file), "--stop-file", str(stop_file),
        "--report", str(report_file), "--stop-deadline", "55s",
    ]
    errors: list[str] = []
    checks: list[dict[str, str]] = []
    with log_path.open("w", encoding="utf-8") as logs:
        process = subprocess.Popen(command, stdout=logs, stderr=subprocess.STDOUT, text=True)
        try:
            deadline = time.monotonic() + 45
            while not ready_file.exists():
                if process.poll() is not None:
                    raise RuntimeError("Go benchmark exited before all tunnels were ready")
                if time.monotonic() > deadline:
                    raise TimeoutError("Go tunnels did not all become ready within 45s")
                time.sleep(0.25)
            ready_report = json.loads(report_file.read_text(encoding="utf-8"))
            if ready_report.get("stage") != "connected":
                raise RuntimeError(f"Unexpected Go ready stage: {ready_report.get('stage')}")
            checks = traffic_check(len(profiles), direct_ip)
        except Exception as exc:
            errors.append(str(exc))
        finally:
            stop_file.touch()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                errors.append("Go benchmark required SIGKILL during cleanup")
            if process.returncode != 0:
                errors.append(f"Go benchmark exited with {process.returncode}; logs: {log_path}")
    report = json.loads(report_file.read_text(encoding="utf-8")) if report_file.exists() else base_report("go-openvpn3-core", len(profiles))
    report["interface_checks"] = checks
    if errors:
        report["stage"] = "failed"
        report.setdefault("errors", []).extend(errors)
        raise RuntimeError("; ".join(errors))
    return report


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--go-binary", type=Path, required=True)
    parser.add_argument("--concurrency", type=int, action="append", required=True)
    args = parser.parse_args()
    if os.geteuid() != 0:
        raise SystemExit("Benchmark must run as root in the dedicated GitHub Actions runner")
    if not args.go_binary.is_file():
        raise SystemExit(f"Go benchmark binary is missing: {args.go_binary}")
    if not args.concurrency or any(count not in (1, 2, 4) for count in args.concurrency):
        raise SystemExit("Each --concurrency must be 1, 2 or 4")

    workdir = args.workdir
    workdir.mkdir(parents=True, exist_ok=True)
    labels, profile_paths, preflight_attempts = prepare_profiles(workdir, max(args.concurrency))
    direct_ip = command_ip()
    print(f"Selected nodes: {labels}; direct exit: {direct_ip}", flush=True)
    version = subprocess.run(["openvpn", "--version"], check=True, capture_output=True, text=True, timeout=5)
    results: list[dict[str, Any]] = []
    failures = False
    for count in args.concurrency:
        selected = profile_paths[:count]
        for backend in ("go", "cli"):
            case_dir = workdir / f"{backend}-{count}"
            case_dir.mkdir(exist_ok=True)
            print(f"START {backend} with {count} tunnel(s)", flush=True)
            try:
                if backend == "go":
                    report = run_go(selected, case_dir, args.go_binary, direct_ip)
                else:
                    report = run_cli(selected, direct_ip)
                if backend == "cli":
                    report["openvpn_version"] = version.stdout.splitlines()[0]
                    report["ready_time_note"] = "connect_ms includes --route-delay 2 used by the CLI adapter"
                report["profile_nodes"] = labels[:count]
                report["measurement_note"] = "One run per paired VPNGate node; no statistical speedup claim"
                report["stage"] = "stopped"
            except Exception as exc:
                report_file = case_dir / "report.json"
                report = base_report("go-openvpn3-core" if backend == "go" else "openvpn2-cli", count)
                if backend == "go" and report_file.exists():
                    report = json.loads(report_file.read_text(encoding="utf-8"))
                report["stage"] = "failed"
                report.setdefault("errors", []).append(str(exc))
                failures = True
            write_json(case_dir / "final.json", report)
            results.append(report)
            print(json.dumps({
                "backend": backend, "count": count, "stage": report["stage"],
                "wall_ready_ms": report.get("wall_ready_ms"),
                "max_ready_ms": report.get("max_ready_ms"),
                "current_rss_kb_after_connect": report.get("current_rss_kb_after_connect"),
                "peak_rss_kb": report.get("peak_rss_kb"),
                "threads_after_connect": report.get("threads_after_connect"),
                "engine_process_count": report.get("engine_process_count"),
                "errors": report.get("errors"),
            }, ensure_ascii=False), flush=True)

    write_json(workdir / "comparison.json", {
        "nodes": labels,
        "direct_ip": direct_ip,
        "preflight": preflight_attempts,
        "results": results,
    })
    if failures:
        raise SystemExit("At least one benchmark failed; inspect the per-case final.json and go.log artifacts")


if __name__ == "__main__":
    main()
