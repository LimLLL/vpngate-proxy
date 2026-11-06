"""Thin adapter around OpenVPN's generated SWIG module, not a protocol implementation."""

from __future__ import annotations

import threading
import time
import weakref
from collections import deque
from dataclasses import dataclass
from typing import Any

from .profiles import prepare_profile

try:
    import ovpncli
except ImportError as exc:
    raise ImportError(
        "The official OpenVPN 3 Core Python binding is unavailable. "
        "Build the pinned ovpnclilib target with the GitHub Actions workflow."
    ) from exc


class OpenVPN3Error(RuntimeError):
    """An OpenVPN profile or native connection operation failed."""


@dataclass(frozen=True)
class ProfileEvaluation:
    error: bool
    message: str
    remote_host: str
    remote_port: str
    remote_proto: str
    autologin: bool
    profile_name: str


def make_config(profile: str, connect_timeout: int) -> Any:
    config = ovpncli.ClientAPI_Config()
    config.content = profile
    config.connTimeout = connect_timeout
    config.tunPersist = False
    # Otherwise a profile without auth-user-pass locks empty default creds,
    # causing submit_creds() to ignore the VPNGate credentials provided below.
    config.autologinSessions = False
    config.compressionMode = "no"
    # VPNGate still publishes legacy AES-CBC profiles alongside modern ones.
    config.enableLegacyAlgorithms = True
    config.enableNonPreferredDCAlgorithms = True
    return config


def _evaluation(result: Any) -> ProfileEvaluation:
    return ProfileEvaluation(
        error=bool(result.error),
        message=str(result.message),
        remote_host=str(result.remoteHost),
        remote_port=str(result.remotePort),
        remote_proto=str(result.remoteProto),
        autologin=bool(result.autologin),
        profile_name=str(result.profileName),
    )


def evaluate_profile(profile: str, connect_timeout: int = 30) -> ProfileEvaluation:
    """Parse a profile using the official C++ ClientAPI helper."""
    helper = ovpncli.ClientAPI_OpenVPNClientHelper()
    return _evaluation(helper.eval_config(make_config(profile, connect_timeout)))


def native_platform() -> str:
    return str(ovpncli.ClientAPI_OpenVPNClientHelper.platform())


def native_crypto_self_test() -> str:
    """Return the upstream self-test output; the OpenSSL path is currently a no-op."""
    return str(ovpncli.ClientAPI_OpenVPNClientHelper().crypto_self_test())


class _NativeClient(ovpncli.ClientAPI_OpenVPNClient):
    """SWIG director that forwards native callbacks to one VPNConnection."""

    def __init__(self, owner: VPNConnection) -> None:
        super().__init__()
        self._owner = weakref.ref(owner)

    def _receive(self) -> VPNConnection | None:
        return self._owner()

    def event(self, event: Any) -> None:
        owner = self._receive()
        if owner:
            owner._on_event(event)

    def acc_event(self, event: Any) -> None:
        owner = self._receive()
        if owner:
            owner._on_acc_event(event)

    def log(self, info: Any) -> None:
        owner = self._receive()
        if owner:
            owner._on_log(str(info.text))

    def pause_on_connection_timeout(self) -> bool:
        return False

    def socket_protect(self, socket: int, remote: str, ipv6: bool) -> bool:
        # route-nopull leaves the physical default route untouched, so no
        # bypass route is needed for the OpenVPN transport socket.
        return True

    def external_pki_cert_request(self, request: Any) -> None:
        request.error = True
        request.errorText = "External PKI is not supported by this prototype"

    def external_pki_sign_request(self, request: Any) -> None:
        request.error = True
        request.errorText = "External PKI is not supported by this prototype"


class VPNConnection:
    """Own one native OpenVPN session; close() releases its thread and TUN."""

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
        self._username = username
        self._password = password
        self._config = make_config(self.profile, connect_timeout)
        self._client = _NativeClient(self)
        self._thread: threading.Thread | None = None
        self._started = False
        self._connected = threading.Event()
        self._done = threading.Event()
        self._state_lock = threading.Lock()
        self._events: deque[dict[str, Any]] = deque(maxlen=100)
        self._logs: deque[str] = deque(maxlen=200)
        self._connection_info: dict[str, Any] = {}
        self._status: dict[str, Any] = {}
        self._fatal_error = ""

    @property
    def events(self) -> list[dict[str, Any]]:
        with self._state_lock:
            return list(self._events)

    @property
    def logs(self) -> list[str]:
        with self._state_lock:
            return list(self._logs)

    @property
    def connection_info(self) -> dict[str, Any]:
        with self._state_lock:
            return dict(self._connection_info)

    @property
    def status(self) -> dict[str, Any]:
        with self._state_lock:
            return dict(self._status)

    def start(self) -> None:
        if self._started:
            raise RuntimeError("A VPNConnection instance cannot be restarted")
        self._started = True
        evaluation = _evaluation(self._client.eval_config(self._config))
        if evaluation.error:
            raise OpenVPN3Error(f"Profile validation failed: {evaluation.message}")

        creds = ovpncli.ClientAPI_ProvideCreds()
        creds.username = self._username
        creds.password = self._password
        status = self._client.provide_creds(creds)
        if status.error:
            raise OpenVPN3Error(self._status_message(status))

        self._thread = threading.Thread(
            target=self._run,
            name="openvpn3-core-connect",
            daemon=True,
        )
        self._thread.start()

    def _run(self) -> None:
        try:
            status = self._client.connect()
            with self._state_lock:
                self._status = {
                    "error": bool(status.error),
                    "status": str(status.status),
                    "message": str(status.message),
                }
                if status.error and not self._fatal_error:
                    self._fatal_error = self._status_message(status)
        except Exception as exc:
            with self._state_lock:
                self._fatal_error = f"Native connect raised: {exc}"
        finally:
            self._done.set()

    @staticmethod
    def _status_message(status: Any) -> str:
        label = str(status.status or "OPENVPN3_ERROR")
        message = str(status.message or "unknown native error")
        return f"{label}: {message}"

    def _on_event(self, event: Any) -> None:
        event_name = str(event.name)
        print(f"[core-callback {threading.get_native_id()}] event enter {event_name}", flush=True)
        item = {
            "name": event_name,
            "info": str(event.info),
            "error": bool(event.error),
            "fatal": bool(event.fatal),
        }
        with self._state_lock:
            self._events.append(item)
            if event.fatal:
                self._fatal_error = f"{event.name}: {event.info}"
        if event_name == "CONNECTED":
            print(f"[core-callback {threading.get_native_id()}] before connection_info", flush=True)
            native_info = self._client.connection_info()
            print(f"[core-callback {threading.get_native_id()}] after connection_info", flush=True)
            with self._state_lock:
                self._connection_info = {
                    key: str(getattr(native_info, key))
                    for key in (
                        "serverHost",
                        "serverPort",
                        "serverProto",
                        "serverIp",
                        "vpnIp4",
                        "vpnIp6",
                        "vpnMtu",
                        "gw4",
                        "gw6",
                        "tunName",
                    )
                }
            self._connected.set()
        print(f"[core-callback {threading.get_native_id()}] event exit {event_name}", flush=True)

    def _on_acc_event(self, event: Any) -> None:
        with self._state_lock:
            self._events.append(
                {"name": "APP_CONTROL", "info": str(event.protocol), "error": False, "fatal": False}
            )

    def _on_log(self, text: str) -> None:
        with self._state_lock:
            self._logs.append(text)

    def wait_connected(self, timeout: float) -> dict[str, Any]:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self._connected.wait(0.2):
                return self.connection_info
            self._raise_if_failed()
        raise TimeoutError(f"OpenVPN 3 Core did not connect within {timeout:g}s")

    def wait_finished(self, timeout: float) -> bool:
        return self._done.wait(timeout)

    def _raise_if_failed(self) -> None:
        with self._state_lock:
            error = self._fatal_error
        if error:
            raise OpenVPN3Error(error)
        if self._done.is_set() and not self._connected.is_set():
            raise OpenVPN3Error("Native connect returned before CONNECTED")

    def close(self, timeout: float = 10) -> None:
        thread = self._thread
        if not thread or not thread.is_alive():
            return
        deadline = time.monotonic() + timeout
        stop_errors: list[Exception] = []

        def request_stop() -> None:
            try:
                self._client.stop()
            except Exception as exc:
                stop_errors.append(exc)

        # SWIG blocks inside some native calls; even the stop request must
        # have a bounded caller instead of hanging the whole Python process.
        stopper = threading.Thread(target=request_stop, name="openvpn3-core-stop", daemon=True)
        stopper.start()
        stopper.join(min(5.0, timeout))
        if stopper.is_alive():
            raise TimeoutError("OpenVPN 3 Core stop request did not return within 5s")
        if stop_errors:
            raise OpenVPN3Error(f"Native stop raised: {stop_errors[0]}")
        thread.join(max(0.0, deadline - time.monotonic()))
        if thread.is_alive():
            raise TimeoutError("OpenVPN 3 Core did not stop within the deadline")

    def __enter__(self) -> VPNConnection:
        self.start()
        return self

    def __exit__(self, exc_type: Any, exc: Any, traceback: Any) -> None:
        self.close()
