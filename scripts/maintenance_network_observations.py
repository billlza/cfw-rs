"""Pure projections for preserving networking during a dormant app update."""

from __future__ import annotations

import json
from pathlib import Path
import re
import stat


class NetworkObservationError(ValueError):
    """A successful OS query did not contain a complete supported observation."""


MANAGED_TUNNEL_BUNDLE = re.compile(
    r"/Library/SystemExtensions/[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}/"
    r"com\.bill\.clashformac\.packet-tunnel\.systemextension"
)


def require_managed_tunnel_location(bundle: Path) -> None:
    """Require an OS-owned installed copy, separate from the app being replaced."""
    if MANAGED_TUNNEL_BUNDLE.fullmatch(str(bundle)) is None:
        raise NetworkObservationError("Packet Tunnel is not an OS-managed installed copy")
    executable = bundle / "Contents/MacOS/CFWPacketTunnel"
    for path in (executable, *executable.parents):
        metadata = path.lstat()
        expected_kind = stat.S_ISREG if path == executable else stat.S_ISDIR
        if not expected_kind(metadata.st_mode) or metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise NetworkObservationError("OS-managed Packet Tunnel path is not protected")


def network_routes(output: str) -> str:
    """Keep route policy, excluding kernel-generated ARP/cloned cache entries."""
    header: list[str] | None = None
    rows: list[list[str]] = []
    for line in output.splitlines():
        fields = line.split()
        if not fields or line.strip() in {"Routing tables", "Internet:", "Internet6:"}:
            continue
        if fields[0] == "Destination":
            if any(fields.count(name) != 1 for name in ("Destination", "Gateway", "Flags", "Netif")):
                raise NetworkObservationError("route table header is unsupported")
            header = fields
            continue
        if header is None:
            raise NetworkObservationError("route rows precede their header")
        indices = [header.index(name) for name in ("Destination", "Gateway", "Flags", "Netif")]
        if len(fields) <= max(indices):
            raise NetworkObservationError("route row is incomplete")
        row = [fields[index] for index in indices]
        if re.fullmatch(r"[A-Za-z!]+", row[2]) is None:
            raise NetworkObservationError("route flags are malformed")
        # RTF_LLINFO and RTF_WASCLONED are defined as generated entries in
        # Apple's net/route.h. Their cache lifetimes are not routing policy.
        if "L" not in row[2] and "W" not in row[2]:
            if fields[-1] == "!" and len(fields) > max(indices) + 1:
                row.append("!")
            rows.append(row)
    if header is None:
        raise NetworkObservationError("route table header is absent")
    return json.dumps(sorted(rows), separators=(",", ":")) + "\n"


def tunnel_interfaces(output: str) -> str:
    """Capture every observed utun; an observed absence is distinct from failure."""
    blocks: dict[str, list[str]] = {}
    current: str | None = None
    observed: set[str] = set()
    for line in output.splitlines():
        if line and not line[0].isspace():
            match = re.match(r"([A-Za-z][A-Za-z0-9_.-]*):\s", line)
            if match is None or match[1] in observed:
                raise NetworkObservationError("interface header is malformed or duplicated")
            observed.add(match[1])
            current = match[1] if re.fullmatch(r"utun[0-9]+", match[1]) else None
            if current is not None:
                blocks[current] = []
        elif line.strip() and not observed:
            raise NetworkObservationError("interface body precedes its header")
        if current is not None:
            blocks[current].append(line.rstrip())
    if not observed:
        raise NetworkObservationError("interface observation is empty")
    return json.dumps(blocks, sort_keys=True, separators=(",", ":")) + "\n"


VPN_HEADER = "Available network connection services in the current set (*=enabled):"
CFM_VPN_OWNERS = frozenset({"com.bill.clashformac", "com.bill.clashformac.packet-tunnel"})
VPN_ROW = re.compile(
    r'^\s*\*?\s*\((Disconnected|Connecting|Connected|Disconnecting|Invalid)\)\s+'
    r'([0-9A-Fa-f]{8}(?:-[0-9A-Fa-f]{4}){3}-[0-9A-Fa-f]{12})\s+'
    r'([A-Za-z0-9_-]+)\s+\(([A-Za-z0-9_.-]+)\)\s+'
    r'"(?:[^"\\]|\\.)*"\s+\[([A-Za-z0-9_-]+):([A-Za-z0-9_.-]+)\]\s*$'
)


def cfm_vpn_services(output: str) -> tuple[tuple[str, str], ...]:
    lines = output.splitlines()
    if not lines or lines[0].strip() != VPN_HEADER:
        raise NetworkObservationError("VPN service-list header is absent")
    services: list[tuple[str, str]] = []
    seen: set[str] = set()
    for line in lines[1:]:
        if not line.strip():
            continue
        match = VPN_ROW.fullmatch(line)
        if match is None:
            raise NetworkObservationError("VPN service row is malformed")
        state, identifier, category, owner, family, subtype = match.groups()
        identifier = identifier.upper()
        if identifier in seen:
            raise NetworkObservationError("VPN service id is duplicated")
        seen.add(identifier)
        if owner in CFM_VPN_OWNERS or subtype in CFM_VPN_OWNERS:
            if category != "VPN" or family != "VPN" or owner != subtype:
                raise NetworkObservationError("CFM VPN service identity is inconsistent")
            services.append((identifier, state))
    return tuple(sorted(services))
