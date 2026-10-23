"""GA runtime acceptance stage of the release driver.

``collect`` is the only multi-hour step of a release and the one that failed
repeatedly before it ever ran traffic. Every precondition the
collector would reject after the app has started is checked here first, before
any collection intent exists, and the evidence instances are started by the
driver and always stopped again, whatever the outcome.

Modes: (none) collect | --recover | --resume-seal | --verify
"""

from __future__ import annotations

from dataclasses import dataclass
import json
from pathlib import Path
import re
import sys
import time
from typing import Final, Sequence

from scripts.release_driver_context import (
    MACHINE,
    NETWORK,
    PREREQUISITE,
    USAGE,
    Context,
    DriverError,
    installed_build,
    path_present,
    require_desktop_terminal,
    run_entry,
)

GCLOUD: Final = "/opt/homebrew/bin/gcloud"
ENDPOINT_REGISTRY: Final = Path("scripts/physical_capture/packet_endpoints.json")
# The GA cases use the primary resolver for DNS and the transport instance for
# TCP and UDP (scripts/ga_runtime_acceptance.py, physical_capture/packet.py).
GA_INSTANCES: Final = ("packet-dns-primary-v040", "packet-transport-v040")
TRANSPORT_PORT: Final = 44333
EVIDENCE_ANSWER: Final = "192.0.2.1"
REACHABILITY_ATTEMPTS: Final = 18
REACHABILITY_INTERVAL_SECONDS: Final = 10
HOST_SUFFIX: Final = "/Contents/MacOS/clash-for-mac"
PACKET_TUNNEL_BUNDLE: Final = "com.bill.clashformac.packet-tunnel"
TEAM_ID: Final = "YKUPL7Z869"
CFW_PROCESSES: Final = (
    "/Applications/Clash for Windows.app/Contents/MacOS/Clash for Windows",
    "/Applications/Clash for Windows.app/Contents/Resources/static/files/darwin/x64/clash-darwin",
)


@dataclass(frozen=True)
class EvidenceInstance:
    name: str
    project: str
    zone: str
    address: str


def evidence_instances(repository: Path) -> tuple[EvidenceInstance, ...]:
    registry = json.loads((repository / ENDPOINT_REGISTRY).read_text(encoding="utf-8"))
    found: dict[str, EvidenceInstance] = {}
    for entry in registry.get("identities", []):
        identity = entry.get("identity", {})
        name = identity.get("instance_name")
        if name in GA_INSTANCES:
            found[name] = EvidenceInstance(
                name=name,
                project=identity["project"],
                zone=identity["zone"],
                address=identity["external_ipv4_address"],
            )
    missing = [name for name in GA_INSTANCES if name not in found]
    if missing:
        raise DriverError(f"{ENDPOINT_REGISTRY} does not register {', '.join(missing)}", PREREQUISITE)
    return tuple(found[name] for name in GA_INSTANCES)


# --- machine observations -------------------------------------------------------


def require_host_absent(context: Context) -> None:
    processes = context.machine.read(["/bin/ps", "-axo", "comm="])
    if processes.status != 0:
        raise DriverError(f"cannot list the running processes: {processes.reason()}", MACHINE)
    if any(line.endswith(HOST_SUFFIX) for line in processes.stdout.splitlines()):
        raise DriverError("Clash for Mac is running; quit it with Cmd-Q in its app menu", MACHINE)


def require_tunnel_disconnected(context: Context) -> None:
    services = context.machine.read(["/usr/sbin/scutil", "--nc", "list"])
    if services.status != 0:
        raise DriverError(f"cannot list the network services: {services.reason()}", MACHINE)
    for line in services.stdout.splitlines():
        if re.search(r"\((com\.bill\.clashformac|com\.bill\.clashformac\.packet-tunnel)\)", line) and "(Disconnected)" not in line:
            raise DriverError("a Clash for Mac VPN is not Disconnected; turn TUN Mode off, then quit with Cmd-Q", MACHINE)


def loopback_proxies(scutil_proxy: str) -> list[str]:
    """Enabled HTTP, HTTPS or SOCKS proxies on a loopback host, in any dictionary.

    ``scutil --proxy`` prints the global settings and, nested, the per-interface
    and supplemental dictionaries; each dictionary is judged on its own keys.
    """

    found: list[str] = []
    stack: list[dict[str, str] | None] = []
    for raw in scutil_proxy.splitlines():
        line = raw.strip()
        if line.endswith("<dictionary> {"):
            stack.append({})
            continue
        if line.endswith("<array> {"):
            stack.append(None)
            continue
        if line == "}":
            current = stack.pop() if stack else None
            if current is not None:
                for kind in ("HTTP", "HTTPS", "SOCKS"):
                    host = current.get(f"{kind}Proxy", "")
                    if current.get(f"{kind}Enable") == "1" and _loopback(host):
                        found.append(f"{kind} {host}:{current.get(f'{kind}Port', '')}")
            continue
        if stack and stack[-1] is not None and " : " in line:
            key, value = line.split(" : ", 1)
            stack[-1][key] = value
    return found


def _loopback(host: str) -> bool:
    lowered = host.lower()
    return (
        lowered == "localhost"
        or lowered.startswith("127.")
        or lowered in ("::1", "0:0:0:0:0:0:0:1")
        or lowered.startswith("::ffff:127.")
    )


def require_no_loopback_system_proxy(context: Context) -> None:
    processes = context.machine.read(["/bin/ps", "-axo", "comm="])
    if processes.status != 0:
        raise DriverError(f"cannot list the running processes: {processes.reason()}", MACHINE)
    if any(process in CFW_PROCESSES for process in processes.stdout.splitlines()):
        # The collector leaves the system proxy to the Clash for Windows guard.
        return
    proxy = context.machine.read(["/usr/sbin/scutil", "--proxy"])
    if proxy.status != 0:
        raise DriverError(f"cannot read the system proxy: {proxy.reason()}", MACHINE)
    found = loopback_proxies(proxy.stdout)
    if found:
        raise DriverError(
            f"a system proxy points at a loopback host ({'; '.join(found)}); open Clash for Mac, "
            "turn System Proxy off and approve the prompt, then quit it with Cmd-Q",
            MACHINE,
        )


def system_extension_problem(listing: str, build: str) -> str | None:
    """Why the collector's system extension check can never pass, if it cannot.

    Before collect the candidate's extension may still await approval and the
    previous one may still be active; the collector judges those rows after
    Tunnel mode is on. Only rows no approval can ever fix end the attempt here.
    """

    for line in listing.splitlines():
        fields = line.split("\t")
        if len(fields) < 6 or not fields[3].startswith(f"{PACKET_TUNNEL_BUNDLE} ("):
            continue
        if fields[2] != TEAM_ID:
            return f"a Packet Tunnel row of another team: {line}"
        version = fields[3][len(PACKET_TUNNEL_BUNDLE) + 2 : -1]
        parts = version.split("/")
        if len(parts) != 2 or not parts[1].isdigit():
            return f"a malformed Packet Tunnel version: {line}"
        row_build, state = int(parts[1]), fields[5].strip()
        if row_build > int(build):
            return f"a later Packet Tunnel build: {line}"
        if row_build == int(build) and ("terminat" in state or "uninstall" in state):
            return f"the candidate's Packet Tunnel is being removed: {line}"
    return None


def require_system_extensions(context: Context) -> None:
    listing = context.machine.read(["/usr/bin/systemextensionsctl", "list"])
    if listing.status != 0:
        raise DriverError(f"cannot list the system extensions: {listing.reason()}", MACHINE)
    problem = system_extension_problem(listing.stdout, context.release.build)
    if problem:
        raise DriverError(f"the collector's system extension check can never pass: {problem}", MACHINE)


def require_mains_power(context: Context) -> None:
    power = context.machine.read(["/usr/bin/pmset", "-g", "batt"])
    first = power.stdout.splitlines()[0] if power.stdout else ""
    if "'AC Power'" not in first:
        raise DriverError(f"connect the Mac to mains power first ({first or power.reason()})", MACHINE)


def require_direct_egress(context: Context, instances: Sequence[EvidenceInstance]) -> None:
    for instance in instances:
        route = context.machine.read(["/sbin/route", "-n", "get", instance.address])
        interface = next(
            (line.split(":", 1)[1].strip() for line in route.stdout.splitlines() if line.strip().startswith("interface:")),
            "",
        )
        if not interface:
            raise DriverError(f"there is no route to {instance.address}: {route.reason()}", NETWORK)
        if interface.startswith(("utun", "ipsec", "ppp")):
            raise DriverError(
                f"traffic to {instance.address} would leave through the tunnel {interface}; disconnect every VPN",
                NETWORK,
            )
        print(f"traffic to {instance.name} ({instance.address}) leaves through {interface}")


def endpoints_reachable(context: Context, instances: Sequence[EvidenceInstance]) -> str | None:
    """None when the evidence resolver answers and the transport accepts TCP."""

    dns, transport = instances
    # The evidence resolver answers only token names under evidence.test, without
    # EDNS and with RD as the only header flag (tools/packet-evidence-endpoint).
    answer = context.machine.read(
        ["/usr/bin/dig", f"@{dns.address}", "cfm-reachability-check.evidence.test", "A",
         "+noedns", "+noadflag", "+time=3", "+tries=2", "+short"],
        timeout=30,
    ).stdout.split()
    if answer != [EVIDENCE_ANSWER]:
        return f"evidence DNS {dns.address}:53 answered {' '.join(answer) or 'nothing'}"
    connected = context.machine.read(
        ["/usr/bin/nc", "-z", "-G", "5", transport.address, str(TRANSPORT_PORT)], timeout=30
    )
    if connected.status != 0:
        return f"evidence transport {transport.address}:{TRANSPORT_PORT}/tcp is unreachable"
    return None


# --- evidence instances ------------------------------------------------------------


def set_instances(context: Context, instances: Sequence[EvidenceInstance], action: str) -> None:
    for instance in instances:
        result = context.machine.read(
            [GCLOUD, "compute", "instances", action, instance.name,
             "--zone", instance.zone, "--project", instance.project, "--quiet"],
            timeout=600,
        )
        if result.status != 0:
            raise DriverError(f"gcloud could not {action} {instance.name}: {result.reason()}", NETWORK)
        print(f"{action}: {instance.name}")


def require_instance_addresses(context: Context, instances: Sequence[EvidenceInstance]) -> None:
    for instance in instances:
        result = context.machine.read(
            [GCLOUD, "compute", "instances", "describe", instance.name, "--zone", instance.zone,
             "--project", instance.project, "--format=value(networkInterfaces[0].accessConfigs[0].natIP)"],
            timeout=120,
        )
        if result.status != 0:
            raise DriverError(f"gcloud could not describe {instance.name}: {result.reason()}", NETWORK)
        address = result.stdout.strip()
        if address != instance.address:
            raise DriverError(
                f"{instance.name} has external address {address or 'none'}, not the registered {instance.address}",
                NETWORK,
            )


def wait_until_reachable(context: Context, instances: Sequence[EvidenceInstance]) -> None:
    problem: str | None = "not checked"
    for _ in range(REACHABILITY_ATTEMPTS):
        problem = endpoints_reachable(context, instances)
        if problem is None:
            return
        time.sleep(REACHABILITY_INTERVAL_SECONDS)
    raise DriverError(
        f"{problem}; this network may block outbound UDP 53 - use one that allows it", NETWORK
    )


# --- the stage -----------------------------------------------------------------


def _confirm_collect() -> None:
    print(
        "Collect (about two hours). Keep this Terminal open, the Mac on mains power and awake, and the\n"
        "network unchanged. When asked:\n"
        "  - 'Authorize bounded CFM packet capture:' -> your administrator password (not echoed);\n"
        "  - 'waiting for macOS approval and Tunnel mode' -> within 10 minutes approve the system\n"
        "    extension if asked and turn on TUN Mode only, then leave the dashboard alone;\n"
        "  - 'waiting for you to quit' -> within 10 minutes press Cmd-Q in Clash for Mac (never the Dock,\n"
        "    Activity Monitor, AppleScript or Force Quit)."
    )
    try:
        answer = input("Type COLLECT to start: ")
    except EOFError as error:
        raise DriverError("collect was not confirmed", USAGE) from error
    if answer != "COLLECT":
        raise DriverError("collect was not confirmed", USAGE)


def run_acceptance(context: Context) -> int:
    arguments = list(context.arguments)
    modes = {(): "collect", ("--recover",): "recover", ("--resume-seal",): "resume-seal", ("--verify",): "verify"}
    mode = modes.get(tuple(arguments))
    if mode is None:
        raise DriverError("acceptance accepts no argument, --recover, --resume-seal or --verify", USAGE)
    acceptance = context.release.acceptance
    if mode == "collect":
        return _collect(context)
    if mode == "recover":
        require_desktop_terminal(context.machine)
        if not path_present(acceptance / "runtime-collection"):
            raise DriverError("there is no runtime-collection to recover", PREREQUISITE)
        for output in ("runtime-evidence", "runtime-acceptance.json"):
            if path_present(acceptance / output):
                raise DriverError(f"{output} exists: never recover published evidence; use --resume-seal", PREREQUISITE)
    if mode == "resume-seal" and not path_present(acceptance / "runtime-evidence"):
        raise DriverError("runtime-evidence does not exist; resume-seal does not apply", PREREQUISITE)
    return run_entry(
        context,
        f"acceptance-{mode}",
        ["./scripts/run_ga_runtime_acceptance.sh", mode],
        attach_terminal=mode == "recover",
    )


def _collect(context: Context) -> int:
    acceptance = context.release.acceptance
    require_desktop_terminal(context.machine)
    if not (acceptance / "migration-journals").is_dir():
        raise DriverError("the journal export has not published migration-journals", PREREQUISITE)
    for output in ("runtime-collection", "runtime-evidence", "runtime-acceptance.json"):
        if path_present(acceptance / output):
            raise DriverError(f"{output} already exists; `next` names the only allowed step", PREREQUISITE)
    if installed_build(context.machine) != context.release.build:
        raise DriverError(f"/Applications does not hold build {context.release.build}", MACHINE)
    require_host_absent(context)
    require_tunnel_disconnected(context)
    require_no_loopback_system_proxy(context)
    require_system_extensions(context)
    require_mains_power(context)
    instances = evidence_instances(context.repository)
    require_direct_egress(context, instances)
    failure: BaseException | None = None
    try:
        set_instances(context, instances, "start")
        require_instance_addresses(context, instances)
        wait_until_reachable(context, instances)
        _confirm_collect()
        return run_entry(
            context,
            "acceptance-collect",
            ["./scripts/run_ga_runtime_acceptance.sh", "collect"],
            attach_terminal=True,
        )
    except BaseException as error:
        failure = error
        raise
    finally:
        # The instances cost money and serve nothing after collect, whatever
        # happened: recover never reaches an evidence endpoint, and a fresh
        # collect starts them again.
        _stop_instances(context, instances, report_only=failure is not None)


def _stop_instances(context: Context, instances: Sequence[EvidenceInstance], *, report_only: bool) -> None:
    try:
        set_instances(context, instances, "stop")
    except DriverError as error:
        commands = "; ".join(
            f"gcloud compute instances stop {item.name} --zone {item.zone} --project {item.project}"
            for item in instances
        )
        print(f"ERROR: {error}. Stop the evidence instances yourself: {commands}", file=sys.stderr)
        if not report_only:
            raise
