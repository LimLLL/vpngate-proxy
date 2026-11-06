"""Profile transformations shared by native and CLI test backends."""


def prepare_profile(profile: str, device: str | None = None) -> str:
    """Keep the host routing table unchanged and optionally pin the TUN name."""
    lines: list[str] = []
    inline_block = False
    route_nopull_seen = False
    dev_seen = False
    for raw_line in profile.replace("\r\n", "\n").splitlines():
        stripped = raw_line.strip()
        lowered = stripped.lower()
        if inline_block:
            lines.append(raw_line)
            if lowered.startswith("</"):
                inline_block = False
            continue
        if lowered.startswith("<") and not lowered.startswith("</"):
            inline_block = True
            lines.append(raw_line)
            continue
        parts = stripped.split()
        directive = parts[0].lower() if parts else ""
        if directive == "route-nopull":
            route_nopull_seen = True
        if device and directive == "dev":
            raw_line = f"dev {device}"
            dev_seen = True
        lines.append(raw_line)
    if device and not dev_seen:
        lines.append(f"dev {device}")
    if not route_nopull_seen:
        lines.append("route-nopull")
    return "\n".join(lines) + "\n"
