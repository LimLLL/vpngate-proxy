"""Check actual proxy egress while another process owns the OpenVPN TUN."""

from .live_vpngate import (
    PROXY_PORT,
    cleanup_policy_routing,
    command_ip,
    prepare_policy_routing,
    start_proxy,
)


def main() -> None:
    start_proxy()
    try:
        prepare_policy_routing("tun0")
        exit_ip = command_ip(f"socks5h://127.0.0.1:{PROXY_PORT}")
        print(f"Proxy egress through Go/OpenVPN 3 Core: {exit_ip}", flush=True)
    finally:
        cleanup_policy_routing()


if __name__ == "__main__":
    main()
