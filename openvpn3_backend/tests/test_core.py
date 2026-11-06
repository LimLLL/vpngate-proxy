from __future__ import annotations

import unittest
from pathlib import Path

from openvpn3_backend.core import (
    OpenVPN3Error,
    VPNConnection,
    evaluate_profile,
    make_config,
    native_crypto_self_test,
    native_platform,
    prepare_profile,
)
from snapshot_utils import parse_and_validate_snapshot


ROOT = Path(__file__).resolve().parents[2]


def sample_profile() -> str:
    rows = parse_and_validate_snapshot((ROOT / "mirror" / "vpngate.csv").read_text(encoding="utf-8"), max_rows=1)
    from snapshot_utils import decode_config

    return decode_config(rows[0]["OpenVPN_ConfigData_Base64"])


def loopback_profile(profile: str) -> str:
    lines: list[str] = []
    inline_block = False
    remote_replaced = False
    for raw_line in profile.splitlines():
        stripped = raw_line.strip()
        if inline_block:
            lines.append(raw_line)
            if stripped.startswith("</"):
                inline_block = False
            continue
        if stripped.startswith("<") and not stripped.startswith("</"):
            inline_block = True
            lines.append(raw_line)
            continue
        if stripped.lower().startswith("remote "):
            if not remote_replaced:
                lines.append("remote 127.0.0.1 1 udp")
                remote_replaced = True
            continue
        lines.append(raw_line)
    return "\n".join(lines) + "\n"


class NativeHelperTests(unittest.TestCase):
    def test_native_platform_and_openssl_self_test_contract(self) -> None:
        self.assertTrue(native_platform())
        # openvpn/crypto/selftest.hpp disables the OpenSSL call in this build.
        # Empty output is the upstream contract, not a passing crypto self-test.
        self.assertEqual(native_crypto_self_test(), "")

    def test_autologin_sessions_do_not_hide_external_credentials(self) -> None:
        config = make_config(sample_profile(), connect_timeout=10)
        self.assertFalse(config.autologinSessions)

    def test_cpp_parser_reads_a_real_vpngate_profile(self) -> None:
        result = evaluate_profile(sample_profile())
        self.assertFalse(result.error, result.message)
        self.assertTrue(result.remote_host)
        self.assertTrue(result.remote_port)
        self.assertIn(result.remote_proto, {"udp", "tcp", "tcp-client"})

    def test_cpp_parser_rejects_an_invalid_profile(self) -> None:
        result = evaluate_profile("this is not an OpenVPN profile\n")
        self.assertTrue(result.error)
        self.assertTrue(result.message)


class ProfilePreparationTests(unittest.TestCase):
    def test_route_nopull_and_device_are_added_outside_inline_blocks(self) -> None:
        profile = "client\ndev tun\n<ca>\ndev not-a-directive\n</ca>\n"
        prepared = prepare_profile(profile, "tun7")
        self.assertIn("\ndev tun7\n", prepared)
        self.assertIn("\n<ca>\ndev not-a-directive\n</ca>\n", prepared)
        self.assertTrue(prepared.endswith("route-nopull\n"))


class NativeDirectorTests(unittest.TestCase):
    def test_native_connect_invokes_python_callbacks(self) -> None:
        connection = VPNConnection(loopback_profile(sample_profile()), connect_timeout=2)
        try:
            connection.start()
            self.assertTrue(connection.wait_finished(15), connection.logs)
            self.assertFalse(connection._connected.is_set())
            self.assertTrue(connection.events)
            self.assertTrue(connection.logs)
            with self.assertRaises(OpenVPN3Error):
                connection.wait_connected(0.01)
        finally:
            connection.close()


if __name__ == "__main__":
    unittest.main()
