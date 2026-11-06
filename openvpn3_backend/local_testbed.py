"""An OpenVPN server with known policy for isolated GitHub Actions benchmarks."""

from __future__ import annotations

import os
import signal
import subprocess
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .profiles import prepare_profile


@dataclass(frozen=True)
class Testbed:
    profiles: tuple[Path, ...]
    target_url: str
    expected_body: str


def stop_process(process: subprocess.Popen[str]) -> None:
    if process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)
        raise TimeoutError("Local test server required SIGKILL during cleanup")


def cleanup_network(namespace: str, physical_link: str, processes: list[subprocess.Popen[str]]) -> None:
    """Remove only the namespace and veth pair owned by this fixture."""
    errors: list[str] = []
    for process in processes:
        try:
            stop_process(process)
        except Exception as exc:
            errors.append(str(exc))
    try:
        # ip-netns(8) explicitly recommends killing these PIDs before delete:
        # killing an exec wrapper need not terminate its descendant server.
        result = subprocess.run(
            ["ip", "netns", "pids", namespace], check=True, capture_output=True, text=True, timeout=5,
        )
        for raw_pid in result.stdout.split():
            try:
                os.kill(int(raw_pid), signal.SIGKILL)
            except ProcessLookupError:
                # An owned worker may exit between enumeration and cleanup.
                continue
        subprocess.run(["ip", "netns", "del", namespace], check=True, capture_output=True, timeout=5)
        # Deleting the namespace can also delete the virtual veth pair, unlike
        # a physical NIC moved back to the root namespace.
        if Path(f"/sys/class/net/{physical_link}").exists():
            result = subprocess.run(
                ["ip", "link", "delete", physical_link], capture_output=True, text=True, timeout=5,
            )
            if result.returncode != 0:
                errors.append(f"Remove veth {physical_link}: {result.stderr.strip()}")
    except Exception as exc:
        errors.append(str(exc))
    if errors:
        raise RuntimeError("Local testbed cleanup failed: " + " | ".join(errors))


def check_server(process: subprocess.Popen[str], log_path: Path) -> None:
    for _ in range(100):
        if log_path.exists() and "Initialization Sequence Completed" in log_path.read_text(encoding="utf-8"):
            return
        if process.poll() is not None:
            log = log_path.read_text(encoding="utf-8") if log_path.exists() else "no server log"
            tail = "\n".join(log.splitlines()[-12:])
            raise RuntimeError(
                f"Local OpenVPN server exited with {process.returncode} before initialization:\n{tail}"
            )
        time.sleep(0.1)
    raise TimeoutError("Local OpenVPN server did not finish initialization")


@contextmanager
def local_testbed(workdir: Path, maximum: int) -> Iterator[Testbed]:
    """Run a real server in an isolated namespace, with distinct client certificates."""
    private = workdir / "private"
    private.mkdir(parents=True, exist_ok=True)
    (private / "web").mkdir(exist_ok=True)
    ca_key, ca_crt = private / "ca.key", private / "ca.crt"
    command = [
        "openssl", "req", "-new", "-x509", "-nodes", "-newkey", "rsa:2048",
        "-days", "1", "-subj", "/CN=vpngate-benchmark-ca",
        "-keyout", str(ca_key), "-out", str(ca_crt),
    ]
    subprocess.run(command, check=True, capture_output=True, timeout=20)
    certificates: dict[str, Path] = {}
    for name, usage in [("server", "serverAuth")] + [(f"client{i}", "clientAuth") for i in range(maximum)]:
        key = private / f"{name}.key"
        request = private / f"{name}.csr"
        certificate = private / f"{name}.crt"
        subprocess.run([
            "openssl", "req", "-new", "-nodes", "-newkey", "rsa:2048",
            "-subj", f"/CN=vpngate-benchmark-{name}", "-keyout", str(key), "-out", str(request),
        ], check=True, capture_output=True, timeout=20)
        extension = private / f"{name}.ext"
        extension.write_text(f"extendedKeyUsage={usage}\n", encoding="utf-8")
        sign = [
            "openssl", "x509", "-req", "-days", "1", "-in", str(request),
            "-CA", str(ca_crt), "-CAkey", str(ca_key), "-out", str(certificate),
            "-extfile", str(extension), "-CAserial", str(private / "ca.srl"),
        ]
        if "server.crt" not in certificates:
            sign.append("-CAcreateserial")
        subprocess.run(sign, check=True, capture_output=True, timeout=20)
        certificates[f"{name}.crt"] = certificate

    tls_key = private / "tls-crypt.key"
    subprocess.run(["openvpn", "--genkey", "secret", str(tls_key)], check=True, capture_output=True, timeout=20)
    auth_log = workdir / "auth.jsonl"
    server_log = workdir / "server.log"
    console_log = workdir / "server-console.log"
    script = Path(__file__).with_name("local_auth.py")
    auth_script = private / "local_auth.py"
    auth_script.write_text(script.read_text(encoding="utf-8"), encoding="utf-8")
    auth_script.chmod(0o700)
    (private / "web" / "health.txt").write_text("vpngate-tunnel-ok\n", encoding="utf-8")
    port = 11946
    http_port = 18080
    # Documentation-only addresses cannot reach public hosts. The client uses
    # this veth for its VPN transport; the private HTTP address exists only in
    # the server namespace, so a client cannot access it without its own TUN.
    namespace = f"vpngate-bench-{os.getpid()}"
    physical_link = f"vpg-h-{os.getpid()}"
    namespace_link = f"vpg-n-{os.getpid()}"
    transport_ip = "192.0.2.2"
    server_ip = "10.66.0.1"
    server_config = workdir / "server.conf"
    server_config.write_text(f"""local {transport_ip}
port {port}
proto udp
dev tun10
topology subnet
server 10.66.0.0 255.255.255.0
dh none
ca {ca_crt}
cert {private / 'server.crt'}
key {private / 'server.key'}
tls-crypt {tls_key}
script-security 2
auth-user-pass-verify {auth_script} via-file
max-clients 4
keepalive 10 120
persist-tun
verb 3
log-append {server_log}
""", encoding="utf-8")

    profiles: list[Path] = []
    profiles_dir = workdir / "profiles"
    profiles_dir.mkdir(exist_ok=True)
    for index in range(maximum):
        profile = f"""client
dev tun{index}
proto udp
remote {transport_ip} {port}
resolv-retry 2
nobind
persist-key
persist-tun
auth-user-pass
auth-nocache
remote-cert-tls server
<ca>
{ca_crt.read_text(encoding='utf-8').strip()}
</ca>
<cert>
{certificates[f'client{index}.crt'].read_text(encoding='utf-8').strip()}
</cert>
<key>
{(private / f'client{index}.key').read_text(encoding='utf-8').strip()}
</key>
<tls-crypt>
{tls_key.read_text(encoding='utf-8').strip()}
</tls-crypt>
"""
        path = profiles_dir / f"tun{index}.ovpn"
        path.write_text(prepare_profile(profile, f"tun{index}"), encoding="utf-8")
        profiles.append(path)

    server: subprocess.Popen[str] | None = None
    web: subprocess.Popen[str] | None = None
    environment = os.environ.copy()
    environment["VPNGATE_AUTH_LOG"] = str(auth_log)
    namespace_created = False
    with console_log.open("w", encoding="utf-8") as console:
        try:
            subprocess.run(["ip", "netns", "add", namespace], check=True, capture_output=True, timeout=5)
            namespace_created = True
            network_commands = [
                ["ip", "link", "add", physical_link, "type", "veth", "peer", "name", namespace_link],
                ["ip", "link", "set", namespace_link, "netns", namespace],
                ["ip", "address", "add", "192.0.2.1/30", "dev", physical_link],
                ["ip", "link", "set", physical_link, "up"],
                ["ip", "netns", "exec", namespace, "ip", "link", "set", "lo", "up"],
                ["ip", "netns", "exec", namespace, "ip", "address", "add", "192.0.2.2/30", "dev", namespace_link],
                ["ip", "netns", "exec", namespace, "ip", "link", "set", namespace_link, "up"],
            ]
            for command in network_commands:
                subprocess.run(command, check=True, capture_output=True, timeout=5)
            server = subprocess.Popen(
                ["ip", "netns", "exec", namespace, "openvpn", "--config", str(server_config)],
                env=environment, stdout=console, stderr=subprocess.STDOUT, text=True,
            )
            check_server(server, server_log)
            web = subprocess.Popen(
                ["ip", "netns", "exec", namespace, "python3", "-m", "http.server",
                 str(http_port), "--bind", server_ip],
                cwd=private / "web", stdout=console, stderr=subprocess.STDOUT, text=True,
            )
            for _ in range(50):
                result = subprocess.run(
                    ["ip", "netns", "exec", namespace, "ss", "-H", "-ltn"],
                    check=True, capture_output=True, text=True, timeout=5,
                )
                if f"{server_ip}:{http_port}" in result.stdout:
                    break
                if server.poll() is not None:
                    raise RuntimeError("Local OpenVPN server exited before clients started")
                if web.poll() is not None:
                    raise RuntimeError("Local HTTP endpoint exited before clients started")
                time.sleep(0.1)
            else:
                raise TimeoutError("Local HTTP endpoint is not listening in the server namespace")
            yield Testbed(tuple(profiles), f"http://{server_ip}:{http_port}/health.txt", "vpngate-tunnel-ok")
        finally:
            if namespace_created:
                processes = [process for process in (web, server) if process is not None]
                cleanup_network(namespace, physical_link, processes)



if __name__ == "__main__":
    raise SystemExit("Local testbed is managed by openvpn3_backend.benchmark")
