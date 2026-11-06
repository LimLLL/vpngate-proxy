"""Minimal OpenVPN 2.x CLI adapter for an apples-to-apples comparison."""

from __future__ import annotations

import shutil
import signal
import subprocess
import tempfile
import threading
import time
from collections import deque
from pathlib import Path
from typing import Any

from .profiles import prepare_profile


class CLIConnection:
    """Own one OpenVPN process, its readiness log stream and temporary files."""

    def __init__(
        self,
        profile: str,
        username: str = "vpn",
        password: str = "vpn",
        connect_timeout: int = 30,
        device: str | None = None,
    ) -> None:
        if connect_timeout < 1:
            raise ValueError("connect_timeout must be positive")
        self.profile = prepare_profile(profile, device)
        self.device = device or "tun0"
        self.connect_timeout = connect_timeout
        self._username = username
        self._password = password
        self._workspace = Path(tempfile.mkdtemp(prefix="vpngate-cli-"))
        self._process: subprocess.Popen[str] | None = None
        self._reader: threading.Thread | None = None
        self._connected = threading.Event()
        self._done = threading.Event()
        self._stopping = False
        self._lock = threading.Lock()
        self._logs: deque[str] = deque(maxlen=200)
        self._events: deque[dict[str, Any]] = deque(maxlen=100)
        self._fatal_error = ""
        self.spawn_ms = 0.0
        self.ready_ms = 0.0
        self.shutdown_ms = 0.0
        self._started = 0.0

    @property
    def process_id(self) -> int | None:
        return self._process.pid if self._process else None

    @property
    def logs(self) -> list[str]:
        with self._lock:
            return list(self._logs)

    @property
    def events(self) -> list[dict[str, Any]]:
        with self._lock:
            return list(self._events)

    @property
    def connection_info(self) -> dict[str, Any]:
        return {"tunName": self.device} if self._connected.is_set() else {}

    @property
    def status(self) -> dict[str, Any]:
        process = self._process
        code = process.poll() if process else None
        return {
            "error": bool(code not in (None, 0) and not self._stopping),
            "status": "running" if code is None else f"exit_{code}",
            "message": self._fatal_error,
        }

    def start(self) -> None:
        if self._process is not None:
            raise RuntimeError("A CLIConnection instance cannot be restarted")
        config_path = self._workspace / "profile.ovpn"
        config_path.write_text(self.profile, encoding="utf-8")
        auth_path = self._workspace / "auth.txt"
        auth_path.write_text(f"{self._username}\n{self._password}\n", encoding="utf-8")
        auth_path.chmod(0o600)
        command = [
            "openvpn",
            "--config", str(config_path),
            "--auth-user-pass", str(auth_path),
            "--connect-timeout", str(self.connect_timeout),
            # Measure readiness without an artificial post-TUN sleep. Core
            # likewise considers CONNECTED equivalent to a completed TUN setup.
            "--route-delay", "0",
            "--verb", "4",
        ]
        self._started = time.monotonic()
        spawn_started = self._started
        self._process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
        self.spawn_ms = (time.monotonic() - spawn_started) * 1000
        self._reader = threading.Thread(
            target=self._read_output,
            name=f"openvpn-cli-{self.device}",
            daemon=True,
        )
        self._reader.start()

    def _read_output(self) -> None:
        process = self._process
        if not process or not process.stdout:
            raise RuntimeError("OpenVPN process output is unavailable")
        with process.stdout:
            for raw_line in process.stdout:
                line = raw_line.rstrip("\r\n")
                with self._lock:
                    self._logs.append(line)
                if "Initialization Sequence Completed" in line:
                    self.ready_ms = (time.monotonic() - self._started) * 1000
                    with self._lock:
                        self._events.append({"name": "CONNECTED", "info": line})
                    self._connected.set()
        code = process.wait()
        with self._lock:
            self._events.append({"name": "EXIT", "info": str(code)})
            if code != 0 and not self._stopping:
                self._fatal_error = f"OpenVPN exited with code {code}: " + " | ".join(list(self._logs)[-5:])
        self._done.set()

    def wait_connected(self, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._connected.wait(0.2):
                return self.connection_info
            self._raise_if_failed()
        raise TimeoutError(f"OpenVPN CLI did not connect within {timeout:g}s")

    def _raise_if_failed(self) -> None:
        with self._lock:
            error = self._fatal_error
        if error:
            raise RuntimeError(error)
        if self._done.is_set() and not self._connected.is_set():
            raise RuntimeError("OpenVPN exited before becoming ready")

    def close(self, timeout: float = 10) -> None:
        started = time.monotonic()
        self._stopping = True
        process = self._process
        try:
            if process and process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
                    raise TimeoutError("OpenVPN CLI required SIGKILL during shutdown")
            if self._reader:
                self._reader.join(min(timeout, 2))
        finally:
            self.shutdown_ms = (time.monotonic() - started) * 1000
            shutil.rmtree(self._workspace, ignore_errors=True)

    def __enter__(self) -> CLIConnection:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
