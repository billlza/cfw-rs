#!/usr/bin/env python3
"""Crash-safe, dormant installation of the fixed Clash for Mac candidate.

This is an operator-only boundary for one product, one candidate location, and
one installation target.  It deliberately has no caller-selected path API.
It never launches the application, registers or unregisters an SMAppService,
signals any pre-existing product process, or changes proxy, DNS, route, tunnel,
or Network Extension state.  A bounded command child is placed in a new process
group and that newly created group is force-cleaned on every exit path.

An application bundle that owns registered SMAppService jobs cannot be safely
replaced while those jobs remain registered: launchd may resolve the fixed
BundleProgram path after the swap and execute the replacement helper.  The
transaction therefore fails closed unless every known Clash for Mac job is
absent and every known Clash for Mac process has exited.  Clash for Windows is
treated as an immutable network lifeline and is proven unchanged around every
filesystem mutation using read-only process and network observations.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import ctypes
from dataclasses import dataclass
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import shutil
import signal
import stat
import subprocess
import sys
import time
from typing import Any, Callable, Final, Iterator
import uuid

if __package__:
    from .candidate_artifact_binding import (
        CandidateBindingError,
        derive_candidate_toolchain_metadata,
        load_strict_json,
        validate_candidate_app_manifest,
    )
    from .gatekeeper_assessment import (
        GatekeeperEvidenceError,
        validate_evidence as validate_gatekeeper_evidence,
    )
    from .hash_artifact import build_manifest
    from .release_build_identity import (
        BuildIdentityError,
        bundle_build_identity,
        canonical_build_version,
    )
    from .repository_source_identity import SourceIdentityError, current_identity
    from .verify_notary_log import NotaryLogError, validate_files as validate_notary_files
else:
    from candidate_artifact_binding import (
        CandidateBindingError,
        derive_candidate_toolchain_metadata,
        load_strict_json,
        validate_candidate_app_manifest,
    )
    from gatekeeper_assessment import (
        GatekeeperEvidenceError,
        validate_evidence as validate_gatekeeper_evidence,
    )
    from hash_artifact import build_manifest
    from release_build_identity import (
        BuildIdentityError,
        bundle_build_identity,
        canonical_build_version,
    )
    from repository_source_identity import SourceIdentityError, current_identity
    from verify_notary_log import NotaryLogError, validate_files as validate_notary_files


DOCUMENT: Final = "cfw-dormant-app-install-v1"
SCHEMA_VERSION: Final = 1
VERSION: Final = "0.4.0"
BUILD_NUMBER: Final = "40009"
TEAM_ID: Final = "YKUPL7Z869"
TARGET_NAME: Final = "Clash for Mac.app"
PAYLOAD_NAME: Final = TARGET_NAME
PARTIAL_PAYLOAD_NAME: Final = ".Clash for Mac.app.partial"
JOURNAL_NAME: Final = ".com.bill.clashformac.dormant-install.json"
JOURNAL_PENDING_NAME: Final = ".com.bill.clashformac.dormant-install.pending"
LOCK_NAME: Final = ".com.bill.clashformac.dormant-install.lock"
STAGING_PREFIX: Final = ".com.bill.clashformac.dormant-install."
RELEASE_WORKTREE_RELATIVE: Final = Path("target/release-worktrees/40009")
CANDIDATE_RELATIVE: Final = Path(
    "target/candidates/0.4.0/validation/40009/signed"
)
MAX_JOURNAL_BYTES: Final = 1024 * 1024
MAX_GUARD_SEGMENTS: Final = 8
MAX_COMMAND_OUTPUT_BYTES: Final = 8 * 1024 * 1024
COMMAND_POLL_SECONDS: Final = 0.05
RENAME_SWAP: Final = 0x00000002
RENAME_EXCL: Final = 0x00000004
RENAME_NOFOLLOW_ANY: Final = 0x00000010

CFW_ROOT: Final = "/Applications/Clash for Windows.app/"
CFW_GUI: Final = (
    "/Applications/Clash for Windows.app/Contents/MacOS/Clash for Windows"
)
CFW_CORE: Final = (
    "/Applications/Clash for Windows.app/Contents/Resources/static/files/"
    "darwin/x64/clash-darwin"
)
CFW_PROXY_HOST: Final = "127.0.0.1"
CFW_PROXY_PORT: Final = "7890"
CFW_TUN_ADDRESS: Final = "198.18.0.1"
CFW_DNS_SERVER: Final = "8.8.8.8"
CFM_PROCESS_SUFFIXES: Final = (
    "/Contents/MacOS/clash-for-mac",
    "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/MacOS/CFWProxyAgent",
    "Contents/Library/HelperTools/CFWGlobalAuthority",
    "/Contents/MacOS/CFWPacketTunnel",
    "/Library/PrivilegedHelperTools/com.bill.clashformac.helper",
)
BTM_DELIMITER: Final = "=" * 24
BTM_ALLOWED_FIELDS: Final = frozenset(
    {
        "Assoc. Bundle IDs",
        "Bundle Identifier",
        "Developer Name",
        "Disposition",
        "Embedded Item Identifiers",
        "Executable Path",
        "Flags",
        "Generation",
        "Identifier",
        "Last Use",
        "Name",
        "Parent Identifier",
        "Team Identifier",
        "Type",
        "URL",
        "UUID",
    }
)
BTM_REQUIRED_FIELDS: Final = frozenset(
    {
        "Developer Name",
        "Disposition",
        "Flags",
        "Generation",
        "Identifier",
        "Name",
        "Type",
        "URL",
        "UUID",
    }
)
CFM_BTM_IDENTITY_PATTERN: Final = re.compile(
    r"(?<![A-Za-z0-9_.-])(?:[0-9]+\.)?com\.bill\.clashformac"
    r"(?:\.[A-Za-z0-9_-]+)*(?![A-Za-z0-9_.-])"
)
SYSTEM_CFM_LABELS: Final = (
    "com.bill.clashformac.global-authority",
    "com.bill.clashformac.helper",
)
USER_CFM_LABELS: Final = ("com.bill.clashformac.proxy-agent",)
CFM_SYSTEM_EXTENSION_IDENTITY: Final = (
    TEAM_ID,
    "com.bill.clashformac.packet-tunnel",
)
SYSTEM_EXTENSION_HEADER: Final = (
    "enabled\tactive\tteamID\tbundleID (version)\tname\t[state]"
)
MAX_SYSTEM_EXTENSION_COUNT: Final = 4096
PHASES: Final = frozenset(
    {
        "prepared",
        "staged",
        "swapped",
        "installed",
        "rollback-prepared",
        "rollback-swapped",
        "rolled-back",
    }
)


class InstallError(RuntimeError):
    """A fail-closed installation boundary rejected or could not seal a step."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class InstallPaths:
    repository: Path
    candidate_app: Path
    candidate_manifest: Path
    target_parent: Path
    target_name: str = TARGET_NAME
    journal_name: str = JOURNAL_NAME
    journal_pending_name: str = JOURNAL_PENDING_NAME
    lock_name: str = LOCK_NAME

    @classmethod
    def production(cls) -> "InstallPaths":
        operator_repository = Path(__file__).resolve().parent.parent
        repository = operator_repository / RELEASE_WORKTREE_RELATIVE
        signed = repository / CANDIDATE_RELATIVE
        return cls(
            repository=repository,
            candidate_app=signed / TARGET_NAME,
            candidate_manifest=signed / f"{TARGET_NAME}.manifest.json",
            target_parent=Path("/Applications"),
        )

    @property
    def target_app(self) -> Path:
        return self.target_parent / self.target_name

    @property
    def journal(self) -> Path:
        return self.target_parent / self.journal_name


@dataclass(frozen=True)
class AppIdentity:
    version: str
    build_number: str
    tree_sha256: str

    def document(self) -> dict[str, str]:
        return {
            "build_number": self.build_number,
            "tree_sha256": self.tree_sha256,
            "version": self.version,
        }


@dataclass(frozen=True)
class CandidateIdentity:
    app: AppIdentity
    manifest_sha256: str
    repository_commit: str
    release_source_sha256: str

    def document(self) -> dict[str, str]:
        return {
            **self.app.document(),
            "manifest_sha256": self.manifest_sha256,
            "release_source_sha256": self.release_source_sha256,
            "repository_commit": self.repository_commit,
        }


@dataclass(frozen=True)
class CommandResult:
    returncode: int
    stdout: str
    stderr: str


CommandRunner = Callable[[tuple[str, ...]], CommandResult]
GuardCapture = Callable[[], dict[str, Any]]
DormantCheck = Callable[[dict[str, Any]], None]
CfmProcessCheck = Callable[[], list[dict[str, Any]]]
CandidateAdmitter = Callable[[InstallPaths], CandidateIdentity]
IdentityReader = Callable[[Path], AppIdentity]
Copier = Callable[[Path, Path], None]
TreeSyncer = Callable[[Path], None]
Swapper = Callable[[int, str, int, str], None]
BundleVerifier = Callable[[Path, AppIdentity], None]


@dataclass(frozen=True)
class InstallRuntime:
    capture_guard: GuardCapture
    require_cfm_dormant: DormantCheck
    require_cfm_process_absent: CfmProcessCheck
    admit_candidate: CandidateAdmitter
    read_identity: IdentityReader
    copy_candidate: Copier
    sync_tree: TreeSyncer
    swap: Swapper
    verify_bundle: BundleVerifier

    @classmethod
    def production(cls) -> "InstallRuntime":
        runner = production_command_runner
        return cls(
            capture_guard=lambda: capture_cfw_guard(runner),
            require_cfm_dormant=lambda guard: require_cfm_dormant(guard, runner),
            require_cfm_process_absent=lambda: require_cfm_process_absent(runner),
            admit_candidate=lambda paths: admit_fixed_candidate(paths, runner),
            read_identity=read_app_identity,
            copy_candidate=lambda source, destination: copy_candidate_with_ditto(
                source, destination, runner
            ),
            sync_tree=fsync_tree,
            swap=swap_names,
            verify_bundle=lambda path, identity: verify_dormant_bundle(
                path, identity, runner
            ),
        )


def _canonical_json(value: object) -> bytes:
    return (
        json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        + "\n"
    ).encode("utf-8")


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _hash_regular(path: Path, label: str) -> str:
    try:
        before = path.lstat()
    except OSError as error:
        raise InstallError("identity_unavailable", f"cannot inspect {label}") from error
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or path.is_symlink():
        raise InstallError("unsafe_identity_input", f"{label} is not a single-link file")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise InstallError("identity_unavailable", f"cannot open {label}") from error
    try:
        opened = os.fstat(descriptor)
        if (opened.st_dev, opened.st_ino) != (before.st_dev, before.st_ino):
            raise InstallError("identity_drift", f"{label} changed while opening")
        digest = hashlib.sha256()
        size = 0
        while True:
            chunk = os.read(descriptor, 1024 * 1024)
            if not chunk:
                break
            size += len(chunk)
            digest.update(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (
        size != opened.st_size
        or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise InstallError("identity_drift", f"{label} changed while hashing")
    return digest.hexdigest()


def _tree_sha256(path: Path, label: str) -> str:
    try:
        manifest = build_manifest(path, algorithm="sha256-tree-v2")
    except (OSError, ValueError) as error:
        raise InstallError("tree_identity_unavailable", f"cannot identify {label}") from error
    digest = manifest.get("sha256")
    if not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise InstallError("tree_identity_invalid", f"{label} has no canonical tree digest")
    return digest


def read_app_identity(path: Path) -> AppIdentity:
    try:
        identity = bundle_build_identity(path)
    except (OSError, BuildIdentityError, ValueError) as error:
        raise InstallError("app_identity_invalid", f"invalid application identity: {path}") from error
    return AppIdentity(
        version=identity.product_version,
        build_number=identity.build_version,
        tree_sha256=_tree_sha256(path, "application bundle"),
    )


def production_command_runner(arguments: tuple[str, ...]) -> CommandResult:
    _require_fixed_command(arguments)
    timeout = 600.0 if arguments[0] == "/usr/bin/ditto" else 120.0
    if arguments[0] in {
        "/bin/launchctl",
        "/bin/ps",
        "/sbin/ifconfig",
        "/usr/bin/sfltool",
        "/usr/bin/systemextensionsctl",
        "/usr/sbin/netstat",
        "/usr/sbin/scutil",
    }:
        timeout = 30.0
    if arguments == ("/usr/bin/sfltool", "dumpbtm"):
        timeout = 120.0
    return _run_bounded_process(arguments, timeout=timeout)


def _fixed_bundle_command_path(value: str) -> bool:
    path = Path(value)
    production = InstallPaths.production()
    if path in {production.candidate_app, production.target_app}:
        return True
    if not path.is_absolute() or path.parent.parent != Path("/Applications"):
        return False
    container = path.parent.name
    if not container.startswith(STAGING_PREFIX):
        return False
    transaction_id = container.removeprefix(STAGING_PREFIX)
    try:
        canonical = str(uuid.UUID(transaction_id))
    except (ValueError, AttributeError):
        return False
    return canonical == transaction_id and path.name in {
        PAYLOAD_NAME,
        PARTIAL_PAYLOAD_NAME,
    }


def _require_fixed_command(arguments: tuple[str, ...]) -> None:
    fixed = {
        ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="),
        ("/sbin/ifconfig",),
        ("/usr/bin/sfltool", "dumpbtm"),
        ("/usr/bin/systemextensionsctl", "list"),
        ("/usr/sbin/netstat", "-rn", "-f", "inet"),
        ("/usr/sbin/netstat", "-rn", "-f", "inet6"),
        ("/usr/sbin/scutil", "--dns"),
        ("/usr/sbin/scutil", "--proxy"),
    }
    if arguments in fixed:
        return
    if len(arguments) == 3 and arguments[:2] == ("/bin/launchctl", "print"):
        domain = arguments[2]
        allowed_system = {
            f"system/{label}" for label in SYSTEM_CFM_LABELS
        }
        if domain in allowed_system or re.fullmatch(
            r"gui/[1-9][0-9]*/com\.bill\.clashformac\.proxy-agent", domain
        ):
            return
    if len(arguments) >= 2 and _fixed_bundle_command_path(arguments[-1]):
        path = arguments[-1]
        if arguments[:-1] in {
            ("/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=4"),
            ("/usr/bin/codesign", "--display", "--verbose=4"),
            ("/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4"),
            ("/usr/bin/xcrun", "stapler", "validate"),
        }:
            return
        production = InstallPaths.production()
        if (
            arguments[:2] == ("/usr/bin/ditto", "--noqtn")
            and len(arguments) == 4
            and Path(arguments[2]) == production.candidate_app
            and _fixed_bundle_command_path(path)
            and Path(path).name == PARTIAL_PAYLOAD_NAME
        ):
            return
    raise InstallError(
        "command_not_allowed", "installer attempted an unreviewed command or argument shape"
    )


def _terminate_process_group(
    process: subprocess.Popen[bytes], group: int
) -> InstallError | None:
    failure: InstallError | None = None
    try:
        os.killpg(group, signal.SIGKILL)
    except ProcessLookupError:
        if process.poll() is None:
            failure = InstallError(
                "command_termination_failed",
                "spawned command group disappeared while its leader remained",
            )
    except OSError:
        failure = InstallError(
            "command_termination_failed", "spawned command group could not be signalled"
        )
        try:
            process.kill()
        except ProcessLookupError:
            if process.poll() is None:
                failure = InstallError(
                    "command_termination_failed",
                    "spawned command could not be terminated",
                )
        except OSError:
            failure = InstallError(
                "command_termination_failed", "spawned command could not be terminated"
            )
    deadline = time.monotonic() + 5
    while process.poll() is None:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            failure = InstallError(
                "command_termination_failed",
                "fixed command process group did not terminate",
            )
            break
        try:
            process.wait(timeout=remaining)
        except subprocess.TimeoutExpired:
            failure = InstallError(
                "command_termination_failed",
                "fixed command process group did not terminate",
            )
            break
        except BaseException:
            # Cleanup is an integrity boundary: record the interruption, issue
            # SIGKILL again, and keep waiting until the bounded deadline.
            failure = InstallError(
                "command_cleanup_interrupted",
                "command cleanup was interrupted before termination was proven",
            )
            try:
                os.killpg(group, signal.SIGKILL)
            except ProcessLookupError:
                if process.poll() is not None:
                    break
            except OSError:
                try:
                    process.kill()
                except OSError:
                    continue
    return failure


def _run_bounded_process(
    arguments: tuple[str, ...], *, timeout: float = 600
) -> CommandResult:
    if not arguments or timeout <= 0:
        raise InstallError("command_invalid", "bounded command arguments are invalid")
    try:
        account = pwd.getpwuid(os.geteuid())
        home = Path(account.pw_dir)
        home_metadata = home.lstat()
    except (KeyError, OSError) as error:
        raise InstallError(
            "command_environment_invalid", "cannot derive the invoking user's home"
        ) from error
    if (
        not home.is_absolute()
        or home.is_symlink()
        or not stat.S_ISDIR(home_metadata.st_mode)
        or home_metadata.st_uid != os.geteuid()
    ):
        raise InstallError(
            "command_environment_invalid", "the invoking user's home is unsafe"
        )
    environment = {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "LOGNAME": account.pw_name,
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        "USER": account.pw_name,
    }
    try:
        process = subprocess.Popen(
            arguments,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
            start_new_session=True,
            bufsize=0,
        )
    except OSError as error:
        raise InstallError("command_failed", "fixed installer command could not start") from error
    group = process.pid
    primary: BaseException | None = None
    cleanup_failure: InstallError | None = None
    result: CommandResult | None = None
    stdout = bytearray()
    stderr = bytearray()
    selector = selectors.DefaultSelector()
    try:
        if process.stdout is None or process.stderr is None:
            raise InstallError("command_failed", "fixed command pipes are unavailable")
        for stream, destination in ((process.stdout, stdout), (process.stderr, stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, destination)
        deadline = time.monotonic() + timeout
        leader_cleanup_attempted = False
        while selector.get_map() or process.poll() is None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise InstallError("command_timeout", "fixed installer command timed out")
            if selector.get_map():
                for key, _mask in selector.select(
                    min(COMMAND_POLL_SECONDS, remaining)
                ):
                    stream = key.fileobj
                    destination = key.data
                    try:
                        chunk = os.read(stream.fileno(), 65536)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(stream)
                        continue
                    destination.extend(chunk)
                    if len(stdout) + len(stderr) > MAX_COMMAND_OUTPUT_BYTES:
                        raise InstallError(
                            "command_output_oversized",
                            "fixed installer command exceeded its output bound",
                        )
            else:
                try:
                    process.wait(timeout=min(COMMAND_POLL_SECONDS, remaining))
                except subprocess.TimeoutExpired:
                    continue
            if process.poll() is not None and not leader_cleanup_attempted:
                leader_cleanup_attempted = True
                cleanup_failure = _terminate_process_group(process, group)
        returncode = process.poll()
        if returncode is None:
            raise InstallError("command_timeout", "fixed installer command timed out")
        try:
            decoded_stdout = bytes(stdout).decode("utf-8", errors="strict")
            decoded_stderr = bytes(stderr).decode("utf-8", errors="strict")
        except UnicodeError as error:
            raise InstallError(
                "command_output_invalid", "fixed installer command output is not UTF-8"
            ) from error
        result = CommandResult(returncode, decoded_stdout, decoded_stderr)
    except BaseException as error:
        primary = error
    finally:
        close_failure: InstallError | None = None
        try:
            selector.close()
        except OSError:
            close_failure = InstallError(
                "command_cleanup_failed", "command selector could not be closed"
            )
        finally:
            try:
                if process.stdout is not None:
                    process.stdout.close()
                if process.stderr is not None:
                    process.stderr.close()
            except OSError:
                close_failure = InstallError(
                    "command_cleanup_failed", "command pipes could not be closed"
                )
            finally:
                final_cleanup = _terminate_process_group(process, group)
                if cleanup_failure is None:
                    cleanup_failure = final_cleanup
        if cleanup_failure is None:
            cleanup_failure = close_failure
    if cleanup_failure is not None:
        if primary is not None:
            raise cleanup_failure from primary
        raise cleanup_failure
    if primary is not None:
        raise primary
    if result is not None:
        return result
    raise InstallError("command_failed", "fixed installer command ended without a result")


def _require_command_success(result: CommandResult, label: str) -> str:
    if result.returncode != 0:
        raise InstallError("command_failed", f"{label} failed")
    return result.stdout + result.stderr


def _parse_processes(output: str) -> list[dict[str, Any]]:
    processes: list[dict[str, Any]] = []
    seen: set[int] = set()
    for raw in output.splitlines():
        match = re.fullmatch(
            r"\s*([1-9][0-9]*)\s+(-?[0-9]+)\s+"
            r"([A-Z][a-z]{2} [A-Z][a-z]{2} [ 0-9][0-9] "
            r"[0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4})\s+(.+?)\s*",
            raw,
        )
        if match is None:
            if raw.strip():
                raise InstallError("process_observation_invalid", "ps output is malformed")
            continue
        pid = int(match.group(1))
        if pid in seen:
            raise InstallError("process_observation_invalid", "ps returned a duplicate pid")
        seen.add(pid)
        processes.append(
            {
                "pid": pid,
                "uid": int(match.group(2)),
                "started_at": match.group(3),
                "path": match.group(4),
            }
        )
    return processes


def _normalize_routes(output: str, interface: str) -> str:
    lines = []
    for line in output.splitlines():
        if re.search(rf"\b{re.escape(interface)}\b", line) is None:
            continue
        # Neighbor-cache expiry is a timer, not route identity.  Preserve the
        # permanent/reject marker "!" while removing only a final decimal timer.
        # Non-tunnel neighbor-cache entries are outside this transaction's CFW
        # route boundary and may age independently during a long bundle copy.
        lines.append(re.sub(r"[ \t]+[0-9]+[ \t]*$", "", line).rstrip())
    return "\n".join(lines) + ("\n" if lines else "")


def _normalize_dns(output: str) -> str:
    lines = [line.rstrip() for line in output.splitlines() if not re.match(r"\s*reach\s+:", line)]
    return "\n".join(lines) + "\n"


def _utun_projection(output: str, interface: str) -> str:
    selected: list[str] = []
    include = False
    for line in output.splitlines():
        if line and not line[0].isspace():
            include = line.startswith(f"{interface}:")
        if include:
            selected.append(line.rstrip())
    return "\n".join(selected) + ("\n" if selected else "")


def _find_cfw_tun_interface(output: str) -> str:
    """Resolve the one utun interface carrying CFW's fixed point-to-point IP."""
    candidates: list[str] = []
    current: str | None = None
    for line in output.splitlines():
        if line and not line[0].isspace():
            name, separator, _ = line.partition(":")
            current = name if separator and re.fullmatch(r"utun[0-9]+", name) else None
        if current is not None and re.search(
            rf"^\s*inet {re.escape(CFW_TUN_ADDRESS)} --> {re.escape(CFW_TUN_ADDRESS)}(?:\s|$)",
            line,
        ):
            candidates.append(current)
    if len(candidates) != 1:
        raise InstallError(
            "cfw_tunnel_identity_invalid",
            "the CFW point-to-point tunnel address is not bound to exactly one utun interface",
        )
    return candidates[0]


def _observation_digest(value: str) -> str:
    return _sha256_bytes(value.encode("utf-8"))


def _require_exact_cfw_proxy(output: str) -> None:
    observed: dict[str, str] = {}
    for line in output.splitlines():
        match = re.fullmatch(r"\s*([A-Za-z]+)\s+:\s+([^\s]+)\s*", line)
        if match is None:
            continue
        key, value = match.groups()
        if key in observed:
            raise InstallError("cfw_proxy_invalid", "system proxy has a duplicate field")
        observed[key] = value
    expected = {
        "HTTPEnable": "1",
        "HTTPPort": CFW_PROXY_PORT,
        "HTTPProxy": CFW_PROXY_HOST,
        "HTTPSEnable": "1",
        "HTTPSPort": CFW_PROXY_PORT,
        "HTTPSProxy": CFW_PROXY_HOST,
        "SOCKSEnable": "1",
        "SOCKSPort": CFW_PROXY_PORT,
        "SOCKSProxy": CFW_PROXY_HOST,
    }
    if any(observed.get(key) != value for key, value in expected.items()):
        raise InstallError(
            "cfw_proxy_invalid",
            "system proxy is not the exact Clash for Windows 127.0.0.1:7890 binding",
        )


def _required_btm_uids(gui_uid: int) -> set[int]:
    try:
        accounts = pwd.getpwall()
    except OSError as error:
        raise InstallError(
            "cfm_background_item_observation_failed",
            "cannot enumerate local users for the BTM absence proof",
        ) from error
    required = {-2, 0, gui_uid}
    required.update(
        account.pw_uid
        for account in accounts
        if 500 <= account.pw_uid < 2**31 and account.pw_name != "nobody"
    )
    return required


def _parse_btm_values(output: str, required_uids: set[int]) -> set[str]:
    invalid = "Clash for Mac BTM output is incomplete or has an unknown format"
    if (
        not output
        or not output.endswith("\n\n\n\n")
        or output.endswith("\n\n\n\n\n")
    ):
        raise InstallError("cfm_background_item_observation_invalid", invalid)
    lines = output.splitlines()
    index = 0
    observed_uids: set[int] = set()
    observed_uid_order: list[int] = []
    values: set[str] = set()

    def skip_blank_lines() -> None:
        nonlocal index
        while index < len(lines) and lines[index] == "":
            index += 1

    while True:
        skip_blank_lines()
        if index == len(lines):
            break
        if lines[index] != BTM_DELIMITER or index + 2 >= len(lines):
            raise InstallError("cfm_background_item_observation_invalid", invalid)
        header = re.fullmatch(
            r" Records for UID (-2|0|[1-9][0-9]*) : "
            r"([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})",
            lines[index + 1],
        )
        if header is None or lines[index + 2] != BTM_DELIMITER:
            raise InstallError("cfm_background_item_observation_invalid", invalid)
        uid = int(header.group(1))
        try:
            section_uuid = str(uuid.UUID(header.group(2))).upper()
        except ValueError as error:
            raise InstallError(
                "cfm_background_item_observation_invalid", invalid
            ) from error
        if section_uuid != header.group(2) or uid in observed_uids:
            raise InstallError("cfm_background_item_observation_invalid", invalid)
        observed_uids.add(uid)
        observed_uid_order.append(uid)
        index += 3
        skip_blank_lines()
        if index + 2 >= len(lines):
            raise InstallError("cfm_background_item_observation_invalid", invalid)
        if re.fullmatch(
            r" ServiceManagement migrated: (?:true|false)", lines[index]
        ) is None or re.fullmatch(
            r" LaunchServices registered: (?:true|false)", lines[index + 1]
        ) is None:
            raise InstallError("cfm_background_item_observation_invalid", invalid)
        index += 2
        skip_blank_lines()
        if index >= len(lines) or lines[index] != " Items:":
            raise InstallError("cfm_background_item_observation_invalid", invalid)
        index += 1
        expected_item = 1

        while True:
            skip_blank_lines()
            if index == len(lines) or lines[index] == BTM_DELIMITER:
                break
            item = re.fullmatch(r" #([1-9][0-9]*):", lines[index])
            if item is None or int(item.group(1)) != expected_item:
                raise InstallError("cfm_background_item_observation_invalid", invalid)
            expected_item += 1
            index += 1
            fields: dict[str, str] = {}
            embedded_expected: int | None = None
            record_closed = False

            while index < len(lines):
                line = lines[index]
                if line == "":
                    skip_blank_lines()
                    record_closed = True
                    if index < len(lines) and lines[index] != BTM_DELIMITER and re.fullmatch(
                        r" #[1-9][0-9]*:", lines[index]
                    ) is None:
                        raise InstallError(
                            "cfm_background_item_observation_invalid", invalid
                        )
                    break
                if line == BTM_DELIMITER or re.fullmatch(r" #[1-9][0-9]*:", line):
                    raise InstallError("cfm_background_item_observation_invalid", invalid)
                if embedded_expected is not None:
                    embedded = re.fullmatch(r"    #([1-9][0-9]*): (\S.*)", line)
                    if embedded is None or int(embedded.group(1)) != embedded_expected:
                        raise InstallError(
                            "cfm_background_item_observation_invalid", invalid
                        )
                    values.add(embedded.group(2))
                    embedded_expected += 1
                    index += 1
                    continue
                field = re.fullmatch(r" +([A-Za-z][A-Za-z0-9. ]*):(?: (.*))?", line)
                if field is None:
                    raise InstallError("cfm_background_item_observation_invalid", invalid)
                name = field.group(1)
                value = field.group(2) or ""
                if name not in BTM_ALLOWED_FIELDS or name in fields:
                    raise InstallError("cfm_background_item_observation_invalid", invalid)
                if name == "Embedded Item Identifiers":
                    if value:
                        raise InstallError(
                            "cfm_background_item_observation_invalid", invalid
                        )
                    fields[name] = value
                    embedded_expected = 1
                else:
                    if not value or any(ord(character) < 32 for character in value):
                        raise InstallError(
                            "cfm_background_item_observation_invalid", invalid
                        )
                    fields[name] = value
                    values.add(value)
                index += 1

            if (
                not record_closed
                or embedded_expected == 1
                or not BTM_REQUIRED_FIELDS.issubset(fields)
            ):
                raise InstallError("cfm_background_item_observation_invalid", invalid)
            try:
                item_uuid = str(uuid.UUID(fields["UUID"])).upper()
            except ValueError as error:
                raise InstallError(
                    "cfm_background_item_observation_invalid", invalid
                ) from error
            if (
                item_uuid != fields["UUID"]
                or re.fullmatch(r"\S.* \(0x[0-9a-f]+\)", fields["Type"]) is None
                or re.fullmatch(
                    r"\[(?:enabled|disabled), (?:allowed|disallowed), "
                    r"(?:notified|not notified)(?:, alerted)?\] "
                    r"\((?:0|0x[0-9a-f]+)\)",
                    fields["Disposition"],
                )
                is None
                or re.fullmatch(r"[0-9]+", fields["Generation"]) is None
                or (
                    "Assoc. Bundle IDs" in fields
                    and re.fullmatch(r"\[.*\]", fields["Assoc. Bundle IDs"])
                    is None
                )
            ):
                raise InstallError("cfm_background_item_observation_invalid", invalid)

    if (
        len(observed_uid_order) < 2
        or observed_uid_order[:2] != [-2, 0]
        or observed_uid_order[2:] != sorted(observed_uid_order[2:])
        or any(uid <= 0 for uid in observed_uid_order[2:])
        or not required_uids.issubset(observed_uids)
    ):
        raise InstallError("cfm_background_item_observation_invalid", invalid)
    return values


def _parse_system_extension_identities(output: str) -> set[tuple[str, str]]:
    invalid = "system extension output has an unknown or inconsistent format"
    if not output or not output.endswith("\n") or "\r" in output or "\x00" in output:
        raise InstallError("cfm_system_extension_observation_invalid", invalid)
    lines = output.splitlines()
    summary = re.fullmatch(r"(0|[1-9][0-9]{0,4}) extension\(s\)", lines[0])
    if summary is None:
        raise InstallError("cfm_system_extension_observation_invalid", invalid)
    expected_count = int(summary.group(1))
    if expected_count > MAX_SYSTEM_EXTENSION_COUNT:
        raise InstallError("cfm_system_extension_observation_invalid", invalid)
    if expected_count == 0:
        if lines != ["0 extension(s)"]:
            raise InstallError("cfm_system_extension_observation_invalid", invalid)
        return set()

    identities: set[tuple[str, str]] = set()
    categories: set[str] = set()
    index = 1
    while index < len(lines):
        section = re.fullmatch(
            r"--- (com\.apple\.system_extension\.[a-z0-9_]+)(?: \(([\x20-\x7e]{1,512})\))?",
            lines[index],
        )
        if section is None or section.group(1) in categories:
            raise InstallError("cfm_system_extension_observation_invalid", invalid)
        categories.add(section.group(1))
        index += 1
        if index >= len(lines) or lines[index] != SYSTEM_EXTENSION_HEADER:
            raise InstallError("cfm_system_extension_observation_invalid", invalid)
        index += 1
        section_count = 0
        while index < len(lines) and not lines[index].startswith("--- "):
            fields = lines[index].split("\t")
            if len(fields) != 6 or fields[0] not in {"", "*"} or fields[1] not in {"", "*"}:
                raise InstallError("cfm_system_extension_observation_invalid", invalid)
            _, _, team_id, bundle_version, name, state = fields
            bundle_match = re.fullmatch(
                r"([A-Za-z0-9](?:[A-Za-z0-9.-]{0,253}[A-Za-z0-9])?) \(([^()\t]{1,128})\)",
                bundle_version,
            )
            if (
                re.fullmatch(r"[A-Z0-9]{10}", team_id) is None
                or bundle_match is None
                or not name
                or len(name) > 512
                or any(ord(character) < 32 or ord(character) == 127 for character in name)
                or re.fullmatch(r"\[[^\[\]\t\r\n]{1,256}\]", state) is None
            ):
                raise InstallError("cfm_system_extension_observation_invalid", invalid)
            identity = (team_id, bundle_match.group(1))
            if identity in identities:
                raise InstallError("cfm_system_extension_observation_invalid", invalid)
            identities.add(identity)
            section_count += 1
            index += 1
        if section_count == 0:
            raise InstallError("cfm_system_extension_observation_invalid", invalid)

    if len(identities) != expected_count:
        raise InstallError("cfm_system_extension_observation_invalid", invalid)
    return identities


def _require_no_cfm_processes(processes: list[dict[str, Any]]) -> None:
    if any(
        any(process["path"].endswith(suffix) for suffix in CFM_PROCESS_SUFFIXES)
        for process in processes
    ):
        raise InstallError(
            "cfm_process_running",
            "Clash for Mac or one of its helpers is still running; dormant install refused",
        )


def capture_cfw_guard(runner: CommandRunner) -> dict[str, Any]:
    process_output = _require_command_success(
        runner(("/bin/ps", "-axo", "pid=,uid=,lstart=,comm=")),
        "CFW process observation",
    )
    observed = _parse_processes(process_output)
    _require_no_cfm_processes(observed)
    required = []
    for path in (CFW_GUI, CFW_CORE):
        matches = [process for process in observed if process["path"] == path]
        if len(matches) != 1:
            raise InstallError(
                "cfw_process_identity_invalid",
                f"required Clash for Windows process is not unique: {path}",
            )
        process = matches[0]
        binary = Path(path)
        required.append(
            {
                **process,
                "binary_sha256": _hash_regular(binary, "Clash for Windows executable"),
            }
        )
    if required[0]["uid"] == 0 or required[1]["uid"] != 0:
        raise InstallError("cfw_identity_invalid", "Clash for Windows GUI/core uid contract changed")

    proxy = _require_command_success(
        runner(("/usr/sbin/scutil", "--proxy")), "system proxy observation"
    )
    _require_exact_cfw_proxy(proxy)
    dns = _require_command_success(
        runner(("/usr/sbin/scutil", "--dns")), "DNS observation"
    )
    routes4 = _require_command_success(
        runner(("/usr/sbin/netstat", "-rn", "-f", "inet")), "IPv4 route observation"
    )
    routes6 = _require_command_success(
        runner(("/usr/sbin/netstat", "-rn", "-f", "inet6")), "IPv6 route observation"
    )
    interfaces = _require_command_success(
        runner(("/sbin/ifconfig",)), "tunnel interface observation"
    )
    tun_interface = _find_cfw_tun_interface(interfaces)
    tun = _utun_projection(interfaces, tun_interface)
    routes4_projection = _normalize_routes(routes4, tun_interface)
    routes6_projection = _normalize_routes(routes6, tun_interface)
    if not routes4_projection or CFW_TUN_ADDRESS not in routes4_projection:
        raise InstallError("cfw_routes_absent", "no CFW tunnel routes are available to protect")
    if f"nameserver[0] : {CFW_DNS_SERVER}" not in dns:
        raise InstallError("cfw_dns_invalid", "the exact Clash for Windows DNS binding is absent")
    return {
        "cfw_processes": required,
        "dns_sha256": _observation_digest(_normalize_dns(dns)),
        "proxy_sha256": _observation_digest(proxy),
        "routes_ipv4_sha256": _observation_digest(routes4_projection),
        "routes_ipv6_sha256": _observation_digest(routes6_projection),
        "tun_sha256": _observation_digest(tun),
    }


def require_cfm_process_absent(runner: CommandRunner) -> list[dict[str, Any]]:
    processes = _parse_processes(
        _require_command_success(
            runner(("/bin/ps", "-axo", "pid=,uid=,lstart=,comm=")),
            "Clash for Mac process observation",
        )
    )
    _require_no_cfm_processes(processes)
    return processes


def require_cfm_dormant(guard: dict[str, Any], runner: CommandRunner) -> None:
    processes = require_cfm_process_absent(runner)
    cfw_processes = guard.get("cfw_processes")
    if not isinstance(cfw_processes, list) or not cfw_processes:
        raise InstallError("cfw_identity_invalid", "CFW guard has no GUI identity")
    gui_uid = cfw_processes[0].get("uid")
    if type(gui_uid) is not int or gui_uid <= 0:
        raise InstallError("cfw_identity_invalid", "CFW GUI uid is invalid")
    gui_uids = {gui_uid}
    gui_uids.update(
        process["uid"]
        for process in processes
        if process["uid"] > 0
        and process["path"].endswith(
            "/loginwindow.app/Contents/MacOS/loginwindow"
        )
    )
    domains = [
        *(f"system/{label}" for label in SYSTEM_CFM_LABELS),
        *(
            f"gui/{uid}/{label}"
            for uid in sorted(gui_uids)
            for label in USER_CFM_LABELS
        ),
    ]
    for domain in domains:
        result = runner(("/bin/launchctl", "print", domain))
        combined = result.stdout + result.stderr
        if result.returncode == 0:
            raise InstallError(
                "cfm_service_registered",
                f"Clash for Mac service remains registered: {domain}",
            )
        if result.returncode != 113 or "Could not find service" not in combined:
            raise InstallError(
                "cfm_service_observation_failed",
                f"cannot prove Clash for Mac service absence: {domain}",
            )
    background_items = runner(("/usr/bin/sfltool", "dumpbtm"))
    if background_items.returncode != 0:
        raise InstallError(
            "cfm_background_item_observation_failed",
            "cannot prove cross-user Clash for Mac background-item absence",
        )
    if background_items.stderr:
        raise InstallError(
            "cfm_background_item_observation_invalid",
            "Clash for Mac BTM observation produced unexpected diagnostic output",
        )
    background_values = _parse_btm_values(
        background_items.stdout, _required_btm_uids(gui_uid)
    )
    if any(CFM_BTM_IDENTITY_PATTERN.search(value) for value in background_values):
        raise InstallError(
            "cfm_background_item_registered",
            "Clash for Mac background-item registration remains in the BTM database",
        )
    extensions = runner(("/usr/bin/systemextensionsctl", "list"))
    if extensions.returncode != 0:
        raise InstallError(
            "cfm_system_extension_observation_failed",
            "cannot prove Clash for Mac system extension absence",
        )
    if extensions.stderr:
        raise InstallError(
            "cfm_system_extension_observation_invalid",
            "system extension observation produced unexpected diagnostic output",
        )
    extension_identities = _parse_system_extension_identities(extensions.stdout)
    if CFM_SYSTEM_EXTENSION_IDENTITY in extension_identities:
        raise InstallError(
            "cfm_system_extension_registered",
            "Clash for Mac packet-tunnel system extension remains registered",
        )


def _assert_guard_unchanged(before: dict[str, Any], after: dict[str, Any]) -> None:
    if after != before:
        raise InstallError(
            "cfw_guard_changed",
            "Clash for Windows identity or proxy/TUN/routes/DNS changed during installation",
        )


def admit_fixed_candidate(paths: InstallPaths, runner: CommandRunner) -> CandidateIdentity:
    expected_repository = (
        Path(__file__).resolve().parent.parent / RELEASE_WORKTREE_RELATIVE
    ).resolve(strict=True)
    if paths.repository.resolve(strict=True) != expected_repository:
        raise InstallError("candidate_path_invalid", "production repository path is not fixed")
    expected_signed = expected_repository / CANDIDATE_RELATIVE
    if paths.candidate_app != expected_signed / TARGET_NAME or paths.candidate_manifest != expected_signed / f"{TARGET_NAME}.manifest.json":
        raise InstallError("candidate_path_invalid", "candidate path is not the fixed signed output")
    try:
        source = current_identity(paths.repository, require_clean=True)
        manifest = load_strict_json(paths.candidate_manifest, "signed candidate manifest")
        metadata = manifest.get("metadata")
        if not isinstance(metadata, dict):
            raise CandidateBindingError("signed candidate metadata is absent")
        build_number = canonical_build_version(
            metadata.get("buildNumber"), "signed candidate build number"
        )
        if build_number != BUILD_NUMBER:
            raise CandidateBindingError("signed candidate is not fixed build 40009")
        toolchain = derive_candidate_toolchain_metadata(paths.repository)
        validated = validate_candidate_app_manifest(
            paths.candidate_manifest,
            paths.candidate_app,
            artifact_kind="notarized-validation-candidate-v1",
            build_number=build_number,
            source_identity=source,
            toolchain_metadata=toolchain,
            team_id=TEAM_ID,
        )
        bundle = bundle_build_identity(paths.candidate_app)
    except (
        CandidateBindingError,
        SourceIdentityError,
        BuildIdentityError,
        KeyError,
        OSError,
        ValueError,
    ) as error:
        raise InstallError("candidate_binding_invalid", "candidate source/build binding failed") from error
    if bundle.product_version != VERSION or bundle.build_version != build_number:
        raise InstallError("candidate_binding_invalid", "candidate bundle identity differs from its manifest")

    signed_root = paths.candidate_app.parent
    archive_name = f"Clash.for.Mac_{VERSION}_{build_number}_notary.zip"
    archive = signed_root / archive_name
    try:
        validate_notary_files(
            signed_root / "notarization.json",
            signed_root / "notarization-log.json",
            archive,
        )
        gatekeeper = validate_gatekeeper_evidence(
            load_strict_json(signed_root / "gatekeeper.json", "Gatekeeper evidence"),
            expected_assessment_type="execute",
            expected_primary_signature_context=False,
        )
    except (
        CandidateBindingError,
        GatekeeperEvidenceError,
        NotaryLogError,
        OSError,
        ValueError,
    ) as error:
        raise InstallError("candidate_notarization_invalid", "candidate notarization evidence failed") from error
    tree_sha256 = validated.get("sha256")
    if tree_sha256 != gatekeeper.get("target_signed_app_tree_sha256"):
        raise InstallError("candidate_gatekeeper_mismatch", "Gatekeeper evidence targets other bytes")

    native_products = (
        paths.repository
        / f"target/candidates/0.4.0/validation/{build_number}/native-products"
    )
    verifier = paths.repository / "scripts/verify_release_app.sh"
    _require_command_success(
        _run_fixed_release_verifier(
            paths.repository, verifier, paths.candidate_app, native_products
        ),
        "release application verification",
    )
    _require_command_success(
        runner(("/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=4", str(paths.candidate_app))),
        "candidate code-signature verification",
    )
    _require_command_success(
        runner(("/usr/bin/xcrun", "stapler", "validate", str(paths.candidate_app))),
        "candidate stapling verification",
    )
    assessment = _require_command_success(
        runner(("/usr/sbin/spctl", "--assess", "--type", "execute", "--verbose=4", str(paths.candidate_app))),
        "candidate Gatekeeper assessment",
    )
    if "accepted" not in assessment or "Notarized Developer ID" not in assessment:
        raise InstallError("candidate_gatekeeper_invalid", "live Gatekeeper result is not notarized acceptance")

    # Close every read/command TOCTOU window before returning the admitted bytes.
    if _tree_sha256(paths.candidate_app, "signed candidate") != tree_sha256:
        raise InstallError("candidate_identity_drift", "candidate changed during admission")
    if current_identity(paths.repository, require_clean=True) != source:
        raise InstallError("candidate_source_drift", "release source changed during admission")
    return CandidateIdentity(
        app=AppIdentity(VERSION, build_number, tree_sha256),
        manifest_sha256=_hash_regular(paths.candidate_manifest, "candidate manifest"),
        repository_commit=source["repositoryCommit"],
        release_source_sha256=source["releaseSourceSha256"],
    )


def _run_fixed_release_verifier(
    repository: Path, verifier: Path, app: Path, native_products: Path
) -> CommandResult:
    expected = repository / "scripts/verify_release_app.sh"
    if verifier != expected or not verifier.is_file() or verifier.is_symlink():
        raise InstallError("release_verifier_invalid", "release verifier path is not fixed")
    metadata = verifier.lstat()
    if (
        metadata.st_uid != os.geteuid()
        or metadata.st_nlink != 1
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise InstallError(
            "release_verifier_invalid",
            "release verifier ownership or mode is unsafe",
        )
    return _run_bounded_process((str(verifier), str(app), str(native_products)))


def verify_dormant_bundle(
    app: Path, expected: AppIdentity, runner: CommandRunner
) -> None:
    if read_app_identity(app) != expected:
        raise InstallError("bundle_identity_mismatch", "application bundle identity changed")
    _require_command_success(
        runner(
            (
                "/usr/bin/codesign",
                "--verify",
                "--deep",
                "--strict",
                "--verbose=4",
                str(app),
            )
        ),
        "dormant bundle code-signature verification",
    )
    identity = _require_command_success(
        runner(("/usr/bin/codesign", "--display", "--verbose=4", str(app))),
        "dormant bundle signing identity",
    )
    if (
        "Identifier=com.bill.clashformac" not in identity
        or f"TeamIdentifier={TEAM_ID}" not in identity
    ):
        raise InstallError(
            "bundle_signing_identity_invalid",
            "application bundle is not the fixed Team ID and bundle identifier",
        )
    _require_command_success(
        runner(("/usr/bin/xcrun", "stapler", "validate", str(app))),
        "dormant bundle stapling verification",
    )
    assessment = _require_command_success(
        runner(
            (
                "/usr/sbin/spctl",
                "--assess",
                "--type",
                "execute",
                "--verbose=4",
                str(app),
            )
        ),
        "dormant bundle Gatekeeper assessment",
    )
    if "accepted" not in assessment or "Notarized Developer ID" not in assessment:
        raise InstallError(
            "bundle_gatekeeper_invalid",
            "application bundle lacks live notarized Gatekeeper acceptance",
        )
    if read_app_identity(app) != expected:
        raise InstallError(
            "bundle_identity_drift", "application bundle changed during verification"
        )


def copy_candidate_with_ditto(source: Path, destination: Path, runner: CommandRunner) -> None:
    result = runner(("/usr/bin/ditto", "--noqtn", str(source), str(destination)))
    _require_command_success(result, "candidate staging copy")


def _fsync_open_file(path: Path, before: os.stat_result) -> None:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
            != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns)
        ):
            raise InstallError("staging_identity_drift", "staged file changed before fsync")
        os.fsync(descriptor)
        after = os.fstat(descriptor)
        if (opened.st_size, opened.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
            raise InstallError("staging_identity_drift", "staged file changed during fsync")
    finally:
        os.close(descriptor)


def fsync_tree(root: Path) -> None:
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        raise InstallError("staging_unsafe", "staged application is not a real directory")
    directories: list[Path] = []
    for current, directory_names, file_names in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        directories.append(current_path)
        for name in directory_names + file_names:
            path = current_path / name
            metadata = path.lstat()
            kind = stat.S_IFMT(metadata.st_mode)
            if kind == stat.S_IFREG:
                if metadata.st_nlink != 1:
                    raise InstallError("staging_unsafe", "staged file has hard links")
                _fsync_open_file(path, metadata)
            elif kind not in (stat.S_IFDIR, stat.S_IFLNK):
                raise InstallError("staging_unsafe", "staged application contains a special file")
    for directory in reversed(directories):
        descriptor = os.open(
            directory,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            if not stat.S_ISDIR(os.fstat(descriptor).st_mode):
                raise InstallError("staging_unsafe", "staged directory identity changed")
            os.fsync(descriptor)
        finally:
            os.close(descriptor)


def remove_partial_staged_payload(container: Path, payload: Path) -> None:
    if payload.parent != container or payload.name != PARTIAL_PAYLOAD_NAME:
        raise InstallError("staging_path_invalid", "partial staging path is not fixed")
    container_metadata = container.lstat()
    if (
        not stat.S_ISDIR(container_metadata.st_mode)
        or container.is_symlink()
        or stat.S_IMODE(container_metadata.st_mode) != 0o700
        or container_metadata.st_uid != os.geteuid()
    ):
        raise InstallError("staging_unsafe", "transaction staging container is not private")
    try:
        metadata = payload.lstat()
    except FileNotFoundError:
        return
    kind = stat.S_IFMT(metadata.st_mode)
    try:
        if kind == stat.S_IFDIR:
            shutil.rmtree(payload)
        elif kind in (stat.S_IFREG, stat.S_IFLNK):
            payload.unlink()
        else:
            raise InstallError("staging_unsafe", "partial staging payload is a special file")
    except OSError as error:
        raise InstallError("staging_cleanup_failed", "partial staging payload cannot be removed") from error
    descriptor = _open_directory(container)
    try:
        _fsync_directory_fd(descriptor)
    finally:
        os.close(descriptor)


def swap_names(first_fd: int, first_name: str, second_fd: int, second_name: str) -> None:
    if sys.platform != "darwin":
        raise InstallError("unsupported_platform", "RENAME_SWAP requires macOS")
    if first_name != TARGET_NAME or second_name != PAYLOAD_NAME:
        raise InstallError("unsafe_swap_name", "bundle swap names are not fixed")
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renameatx_np
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    result = rename(
        first_fd,
        os.fsencode(first_name),
        second_fd,
        os.fsencode(second_name),
        RENAME_SWAP | RENAME_NOFOLLOW_ANY,
    )
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EXDEV:
            raise InstallError("cross_device_swap", "bundle swap crossed volumes")
        raise InstallError("atomic_swap_failed", "atomic application bundle swap failed")


def publish_staged_payload(container_fd: int) -> None:
    if sys.platform != "darwin":
        raise InstallError("unsupported_platform", "RENAME_EXCL requires macOS")
    library = ctypes.CDLL(None, use_errno=True)
    rename = library.renameatx_np
    rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
    rename.restype = ctypes.c_int
    result = rename(
        container_fd,
        os.fsencode(PARTIAL_PAYLOAD_NAME),
        container_fd,
        os.fsencode(PAYLOAD_NAME),
        RENAME_EXCL | RENAME_NOFOLLOW_ANY,
    )
    if result != 0:
        code = ctypes.get_errno()
        if code == errno.EEXIST:
            raise InstallError("staging_publish_exists", "staged payload already exists")
        raise InstallError("staging_publish_failed", "staged payload publication failed")
    _fsync_directory_fd(container_fd)


def _open_directory(path: Path) -> int:
    try:
        before = path.lstat()
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_DIRECTORY", 0)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
        )
        opened = os.fstat(descriptor)
    except OSError as error:
        raise InstallError("directory_unavailable", f"cannot open directory: {path}") from error
    if (
        not stat.S_ISDIR(opened.st_mode)
        or (before.st_dev, before.st_ino) != (opened.st_dev, opened.st_ino)
    ):
        os.close(descriptor)
        raise InstallError("directory_identity_drift", f"directory changed while opening: {path}")
    return descriptor


def _fsync_directory_fd(descriptor: int) -> None:
    try:
        os.fsync(descriptor)
    except OSError as error:
        raise InstallError("directory_fsync_failed", "installation directory durability is unknown") from error


def _require_private_container(descriptor: int) -> None:
    metadata = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or stat.S_IMODE(metadata.st_mode) != 0o700
        or metadata.st_uid != os.geteuid()
    ):
        raise InstallError("staging_unsafe", "transaction staging container is not private")


def _read_fd_bytes(descriptor: int, maximum: int) -> bytes:
    output = bytearray()
    while len(output) <= maximum:
        chunk = os.read(descriptor, min(65536, maximum + 1 - len(output)))
        if not chunk:
            break
        output.extend(chunk)
    if len(output) > maximum:
        raise InstallError("journal_invalid", "installation journal is oversized")
    return bytes(output)


def _strict_dict(value: object, fields: set[str], label: str) -> dict[str, Any]:
    if not isinstance(value, dict) or set(value) != fields:
        raise InstallError("journal_invalid", f"{label} has an unexpected field set")
    return value


def _validate_sha256(value: object, label: str) -> str:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise InstallError("journal_invalid", f"{label} is not a SHA-256")
    return value


def _validate_app_document(value: object, label: str) -> dict[str, str]:
    document = _strict_dict(value, {"build_number", "tree_sha256", "version"}, label)
    if document["version"] != VERSION:
        raise InstallError("journal_invalid", f"{label} has the wrong version")
    try:
        build_number = canonical_build_version(
            document["build_number"], f"{label} build number"
        )
    except BuildIdentityError as error:
        raise InstallError("journal_invalid", f"{label} build number is invalid") from error
    tree_sha256 = _validate_sha256(document["tree_sha256"], f"{label} tree digest")
    return {
        "build_number": build_number,
        "tree_sha256": tree_sha256,
        "version": VERSION,
    }


def _validate_guard(value: object) -> dict[str, Any]:
    guard = _strict_dict(
        value,
        {
            "cfw_processes",
            "dns_sha256",
            "proxy_sha256",
            "routes_ipv4_sha256",
            "routes_ipv6_sha256",
            "tun_sha256",
        },
        "CFW guard",
    )
    processes = guard["cfw_processes"]
    if not isinstance(processes, list) or len(processes) != 2:
        raise InstallError("journal_invalid", "CFW guard process set is invalid")
    paths = []
    for process in processes:
        process = _strict_dict(
            process,
            {"binary_sha256", "path", "pid", "started_at", "uid"},
            "CFW process",
        )
        if type(process["pid"]) is not int or process["pid"] <= 0 or type(process["uid"]) is not int:
            raise InstallError("journal_invalid", "CFW process identity is invalid")
        paths.append(process["path"])
        if not isinstance(process["started_at"], str) or re.fullmatch(
            r"[A-Z][a-z]{2} [A-Z][a-z]{2} [ 0-9][0-9] "
            r"[0-9]{2}:[0-9]{2}:[0-9]{2} [0-9]{4}",
            process["started_at"],
        ) is None:
            raise InstallError("journal_invalid", "CFW process start time is invalid")
        _validate_sha256(process["binary_sha256"], "CFW executable digest")
    if paths != [CFW_GUI, CFW_CORE]:
        raise InstallError("journal_invalid", "CFW process paths are not fixed")
    for key in guard.keys() - {"cfw_processes"}:
        _validate_sha256(guard[key], f"CFW guard {key}")
    return guard


def validate_journal(value: object) -> dict[str, Any]:
    document = _strict_dict(
        value,
        {
            "candidate",
            "document",
            "guards",
            "phase",
            "previous",
            "schema_version",
            "sequence",
            "staging_name",
            "transaction_id",
        },
        "installation journal",
    )
    if document["document"] != DOCUMENT or document["schema_version"] != SCHEMA_VERSION:
        raise InstallError("journal_invalid", "installation journal schema is unsupported")
    if type(document["sequence"]) is not int or document["sequence"] <= 0:
        raise InstallError("journal_invalid", "installation journal sequence is invalid")
    if document["phase"] not in PHASES:
        raise InstallError("journal_invalid", "installation journal phase is invalid")
    try:
        transaction_id = str(uuid.UUID(document["transaction_id"]))
    except (ValueError, TypeError, AttributeError) as error:
        raise InstallError("journal_invalid", "transaction id is invalid") from error
    if transaction_id != document["transaction_id"]:
        raise InstallError("journal_invalid", "transaction id is not canonical")
    expected_staging = f"{STAGING_PREFIX}{transaction_id}"
    if document["staging_name"] != expected_staging:
        raise InstallError("journal_invalid", "staging directory is not transaction-bound")
    candidate = _strict_dict(
        document["candidate"],
        {
            "build_number",
            "manifest_sha256",
            "release_source_sha256",
            "repository_commit",
            "tree_sha256",
            "version",
        },
        "candidate identity",
    )
    candidate_app = _validate_app_document(
        {key: candidate[key] for key in ("build_number", "tree_sha256", "version")},
        "candidate identity",
    )
    _validate_sha256(candidate["manifest_sha256"], "candidate manifest digest")
    _validate_sha256(candidate["release_source_sha256"], "candidate source digest")
    if not isinstance(candidate["repository_commit"], str) or re.fullmatch(r"[0-9a-f]{40}", candidate["repository_commit"]) is None:
        raise InstallError("journal_invalid", "candidate repository commit is invalid")
    previous_app = _validate_app_document(document["previous"], "previous application")
    if int(candidate_app["build_number"]) <= int(previous_app["build_number"]):
        raise InstallError("journal_invalid", "candidate build is not newer than previous build")
    guards = document["guards"]
    if not isinstance(guards, list) or not 1 <= len(guards) <= MAX_GUARD_SEGMENTS:
        raise InstallError("journal_invalid", "CFW guard segment count is invalid")
    operations: list[str] = []
    for index, segment in enumerate(guards):
        segment = _strict_dict(segment, {"after", "before", "operation"}, "CFW guard segment")
        if segment["operation"] not in {"install", "recover", "rollback"}:
            raise InstallError("journal_invalid", "CFW guard operation is invalid")
        operations.append(segment["operation"])
        before = _validate_guard(segment["before"])
        if segment["after"] is not None:
            after = _validate_guard(segment["after"])
            if after != before:
                raise InstallError("journal_invalid", "CFW guard records network drift")
        elif index != len(guards) - 1:
            raise InstallError("journal_invalid", "only the active CFW guard may be incomplete")
    if operations[0] != "install" or "install" in operations[1:]:
        raise InstallError("journal_invalid", "CFW guard must begin with one install operation")
    rollback_count = operations.count("rollback")
    rollback_phase = document["phase"] in {
        "rollback-prepared",
        "rollback-swapped",
        "rolled-back",
    }
    if rollback_count != (1 if rollback_phase else 0):
        raise InstallError("journal_invalid", "CFW rollback guard differs from journal phase")
    terminal = document["phase"] in {"installed", "rolled-back"}
    last_incomplete = guards[-1]["after"] is None
    if terminal == last_incomplete:
        raise InstallError("journal_invalid", "CFW guard completion differs from journal phase")
    minimum_sequence = {
        "prepared": 1,
        "staged": 2,
        "swapped": 3,
        "installed": 4,
        "rollback-prepared": 5,
        "rollback-swapped": 6,
        "rolled-back": 7,
    }[document["phase"]]
    if document["sequence"] < minimum_sequence:
        raise InstallError("journal_invalid", "journal sequence is impossible for its phase")
    return document


def _require_journal_successor(
    current: dict[str, Any] | None, pending: dict[str, Any]
) -> None:
    if current is None:
        if not (
            pending["sequence"] == 1
            and pending["phase"] == "prepared"
            and len(pending["guards"]) == 1
            and pending["guards"][0]["operation"] == "install"
            and pending["guards"][0]["after"] is None
        ):
            raise InstallError(
                "journal_recovery_ambiguous",
                "orphan pending journal is not the initial prepared generation",
            )
        return
    immutable = {
        "candidate",
        "document",
        "previous",
        "schema_version",
        "staging_name",
        "transaction_id",
    }
    if any(current[field] != pending[field] for field in immutable):
        raise InstallError(
            "journal_recovery_ambiguous",
            "pending journal changed immutable transaction identity",
        )
    if pending["sequence"] != current["sequence"] + 1:
        raise InstallError(
            "journal_recovery_ambiguous", "pending journal lineage is invalid"
        )
    direct_transitions = {
        "prepared": "staged",
        "staged": "swapped",
        "swapped": "installed",
        "rollback-prepared": "rollback-swapped",
        "rollback-swapped": "rolled-back",
    }
    if pending["phase"] == direct_transitions.get(current["phase"]):
        if pending["guards"] == current["guards"]:
            return
        if current["phase"] in {"swapped", "rollback-swapped"} and (
            len(pending["guards"]) == len(current["guards"])
            and pending["guards"][:-1] == current["guards"][:-1]
            and current["guards"][-1]["after"] is None
            and pending["guards"][-1]
            == {
                **current["guards"][-1],
                "after": current["guards"][-1]["before"],
            }
        ):
            return
    if current["phase"] == "installed" and pending["phase"] == "rollback-prepared":
        if (
            pending["guards"][:-1] == current["guards"]
            and pending["guards"][-1]["operation"] == "rollback"
            and pending["guards"][-1]["after"] is None
        ):
            return
    if pending["phase"] == current["phase"] and len(pending["guards"]) == len(
        current["guards"]
    ) + 1:
        prior = pending["guards"][-2]
        active = pending["guards"][-1]
        if (
            pending["guards"][:-2] == current["guards"][:-1]
            and current["guards"][-1]["after"] is None
            and prior["operation"] == current["guards"][-1]["operation"]
            and prior["before"] == current["guards"][-1]["before"]
            and prior["after"] == prior["before"]
            and active
            == {
                "after": None,
                "before": prior["after"],
                "operation": "recover",
            }
        ):
            return
    raise InstallError(
        "journal_recovery_ambiguous",
        "pending journal is not a permitted next transaction generation",
    )


class JournalStore:
    def __init__(self, paths: InstallPaths) -> None:
        self.paths = paths
        self.parent_fd = _open_directory(paths.target_parent)

    def close(self) -> None:
        if self.parent_fd >= 0:
            os.close(self.parent_fd)
            self.parent_fd = -1

    def __enter__(self) -> "JournalStore":
        return self

    def __exit__(self, _type: object, _value: object, _traceback: object) -> None:
        self.close()

    @contextmanager
    def locked(self) -> Iterator[None]:
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        try:
            descriptor = os.open(self.paths.lock_name, flags, 0o600, dir_fd=self.parent_fd)
        except OSError as error:
            raise InstallError("install_lock_unavailable", "cannot open installation lock") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
            ):
                raise InstallError("install_lock_unsafe", "installation lock is not a single-link file")
            if stat.S_IMODE(metadata.st_mode) != 0o600:
                raise InstallError("install_lock_unsafe", "installation lock mode is not 0600")
            try:
                fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError as error:
                raise InstallError("install_busy", "another installation transaction is active") from error
            rebound = os.stat(
                self.paths.lock_name,
                dir_fd=self.parent_fd,
                follow_symlinks=False,
            )
            if (rebound.st_dev, rebound.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise InstallError("install_lock_unsafe", "installation lock path changed")
            yield
        finally:
            os.close(descriptor)

    def _load_name(self, name: str) -> dict[str, Any] | None:
        try:
            descriptor = os.open(
                name,
                os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=self.parent_fd,
            )
        except FileNotFoundError:
            return None
        except OSError as error:
            raise InstallError("journal_unavailable", "cannot open installation journal") from error
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_uid != os.geteuid()
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size <= 0
                or metadata.st_size > MAX_JOURNAL_BYTES
            ):
                raise InstallError("journal_invalid", "installation journal file is unsafe")
            data = _read_fd_bytes(descriptor, MAX_JOURNAL_BYTES)
            after = os.fstat(descriptor)
            rebound = os.stat(name, dir_fd=self.parent_fd, follow_symlinks=False)
        finally:
            os.close(descriptor)
        if (
            (metadata.st_size, metadata.st_mtime_ns)
            != (after.st_size, after.st_mtime_ns)
            or (metadata.st_dev, metadata.st_ino) != (rebound.st_dev, rebound.st_ino)
        ):
            raise InstallError("journal_identity_drift", "installation journal changed while reading")
        try:
            value = json.loads(data.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys)
        except (UnicodeError, json.JSONDecodeError, ValueError) as error:
            raise InstallError("journal_invalid", "installation journal is not strict JSON") from error
        if data != _canonical_json(value):
            raise InstallError("journal_invalid", "installation journal is not canonical JSON")
        return validate_journal(value)

    def load(self) -> dict[str, Any] | None:
        current = self._load_name(self.paths.journal_name)
        pending = self._load_name(self.paths.journal_pending_name)
        if pending is None:
            return current
        _require_journal_successor(current, pending)
        self._rename_pending()
        return pending

    def _rename_pending(self) -> None:
        library = ctypes.CDLL(None, use_errno=True)
        rename = library.renameatx_np
        rename.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint]
        rename.restype = ctypes.c_int
        result = rename(
            self.parent_fd,
            os.fsencode(self.paths.journal_pending_name),
            self.parent_fd,
            os.fsencode(self.paths.journal_name),
            RENAME_NOFOLLOW_ANY,
        )
        if result != 0:
            raise InstallError("journal_publish_failed", "cannot publish installation journal")
        _fsync_directory_fd(self.parent_fd)

    def write(self, document: dict[str, Any]) -> None:
        validated = validate_journal(document)
        data = _canonical_json(validated)
        if len(data) > MAX_JOURNAL_BYTES:
            raise InstallError("journal_invalid", "installation journal is oversized")
        flags = (
            os.O_WRONLY
            | os.O_CREAT
            | os.O_EXCL
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(
                self.paths.journal_pending_name,
                flags,
                0o600,
                dir_fd=self.parent_fd,
            )
        except OSError as error:
            raise InstallError("journal_pending_exists", "pending installation journal exists") from error
        try:
            offset = 0
            while offset < len(data):
                written = os.write(descriptor, data[offset:])
                if written <= 0:
                    raise InstallError(
                        "journal_write_failed", "installation journal write was short"
                    )
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        self._rename_pending()


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _next(document: dict[str, Any], *, phase: str | None = None) -> dict[str, Any]:
    updated = json.loads(json.dumps(document))
    updated["sequence"] += 1
    if phase is not None:
        updated["phase"] = phase
    return updated


def _candidate_from_journal(document: dict[str, Any]) -> CandidateIdentity:
    value = document["candidate"]
    return CandidateIdentity(
        app=AppIdentity(value["version"], value["build_number"], value["tree_sha256"]),
        manifest_sha256=value["manifest_sha256"],
        repository_commit=value["repository_commit"],
        release_source_sha256=value["release_source_sha256"],
    )


def _previous_from_journal(document: dict[str, Any]) -> AppIdentity:
    value = document["previous"]
    return AppIdentity(value["version"], value["build_number"], value["tree_sha256"])


def _same_app(actual: AppIdentity, expected: AppIdentity) -> bool:
    return actual == expected


def _identity_if_present(path: Path, reader: IdentityReader) -> AppIdentity | None:
    try:
        path.lstat()
    except FileNotFoundError:
        return None
    return reader(path)


class DormantInstallTransaction:
    def __init__(self, paths: InstallPaths, runtime: InstallRuntime) -> None:
        self.paths = paths
        self.runtime = runtime

    def _capture_stable_dormant_guard(
        self, expected: dict[str, Any] | None = None
    ) -> dict[str, Any]:
        initial = self.runtime.capture_guard()
        if expected is not None:
            _assert_guard_unchanged(expected, initial)
        self.runtime.require_cfm_dormant(initial)
        self.runtime.require_cfm_process_absent()
        final = self.runtime.capture_guard()
        _assert_guard_unchanged(initial, final)
        if expected is not None:
            _assert_guard_unchanged(expected, final)
        self.runtime.require_cfm_process_absent()
        return final

    def preflight(self) -> tuple[CandidateIdentity, AppIdentity]:
        before = self._capture_stable_dormant_guard()
        candidate = self.runtime.admit_candidate(self.paths)
        previous = self.runtime.read_identity(self.paths.target_app)
        self.runtime.verify_bundle(self.paths.target_app, previous)
        if int(candidate.app.build_number) <= int(previous.build_number):
            raise InstallError("candidate_not_newer", "candidate build is not newer than installed build")
        after = self._capture_stable_dormant_guard(before)
        return candidate, previous

    def install(self) -> dict[str, Any]:
        # The first gate is deliberately outside JournalStore: when an old CFM
        # job is present, even creating the persistent transaction lock would
        # violate the zero-write dormant-preflight contract.
        candidate, previous = self.preflight()
        with JournalStore(self.paths) as store:
            with store.locked():
                opening_guard = self._capture_stable_dormant_guard()
                if store.load() is not None:
                    raise InstallError("journal_exists", "recover or roll back the existing transaction")
                before = self._capture_stable_dormant_guard(opening_guard)
                transaction_id = str(uuid.uuid4())
                staging_name = f"{STAGING_PREFIX}{transaction_id}"
                document: dict[str, Any] = {
                    "candidate": candidate.document(),
                    "document": DOCUMENT,
                    "guards": [{"after": None, "before": before, "operation": "install"}],
                    "phase": "prepared",
                    "previous": previous.document(),
                    "schema_version": SCHEMA_VERSION,
                    "sequence": 1,
                    "staging_name": staging_name,
                    "transaction_id": transaction_id,
                }
                store.write(document)
                return self._resume(store, document)

    def recover(self) -> dict[str, Any]:
        before_open = self._capture_stable_dormant_guard()
        with JournalStore(self.paths) as store:
            with store.locked():
                before = self._capture_stable_dormant_guard(before_open)
                document = store.load()
                if document is None:
                    raise InstallError("journal_absent", "there is no installation transaction")
                if document["phase"] in {"installed", "rolled-back"}:
                    self._verify_terminal(document)
                    return document
                if len(document["guards"]) >= MAX_GUARD_SEGMENTS:
                    raise InstallError("guard_capacity", "installation recovery guard capacity is exhausted")
                original_before = document["guards"][-1]["before"]
                _assert_guard_unchanged(original_before, before)
                updated = _next(document)
                updated["guards"][-1]["after"] = before
                updated["guards"].append(
                    {"after": None, "before": before, "operation": "recover"}
                )
                store.write(updated)
                return self._resume(store, updated)

    def rollback(self) -> dict[str, Any]:
        before_open = self._capture_stable_dormant_guard()
        with JournalStore(self.paths) as store:
            with store.locked():
                before = self._capture_stable_dormant_guard(before_open)
                document = store.load()
                if document is None or document["phase"] != "installed":
                    raise InstallError("rollback_unavailable", "only an installed transaction can roll back")
                if len(document["guards"]) >= MAX_GUARD_SEGMENTS:
                    raise InstallError("guard_capacity", "installation rollback guard capacity is exhausted")
                self._require_layout(document, target="candidate", staged="previous")
                self.runtime.verify_bundle(
                    self.paths.target_app, _candidate_from_journal(document).app
                )
                self.runtime.verify_bundle(
                    self.paths.target_parent
                    / document["staging_name"]
                    / PAYLOAD_NAME,
                    _previous_from_journal(document),
                )
                updated = _next(document, phase="rollback-prepared")
                updated["guards"].append(
                    {"after": None, "before": before, "operation": "rollback"}
                )
                store.write(updated)
                return self._resume(store, updated)

    def _resume(self, store: JournalStore, document: dict[str, Any]) -> dict[str, Any]:
        candidate = _candidate_from_journal(document)
        parent_fd = _open_directory(self.paths.target_parent)
        container_path = self.paths.target_parent / document["staging_name"]
        try:
            if document["phase"] in {"rollback-prepared", "rollback-swapped"}:
                return self._resume_rollback(store, document)
            if document["phase"] == "prepared":
                self._capture_stable_dormant_guard(
                    document["guards"][-1]["before"]
                )
                if self.runtime.read_identity(self.paths.target_app) != _previous_from_journal(
                    document
                ):
                    raise InstallError(
                        "recovery_layout_ambiguous",
                        "prepared transaction no longer has the previous target",
                    )
                try:
                    container_path.lstat()
                    container_exists = True
                except FileNotFoundError:
                    container_exists = False
                if not container_exists:
                    os.mkdir(document["staging_name"], 0o700, dir_fd=parent_fd)
                    _fsync_directory_fd(parent_fd)
                container_fd = _open_directory(container_path)
                try:
                    _require_private_container(container_fd)
                    staged = container_path / PAYLOAD_NAME
                    partial = container_path / PARTIAL_PAYLOAD_NAME
                    inventory = set(os.listdir(container_fd))
                    if not inventory <= {PAYLOAD_NAME, PARTIAL_PAYLOAD_NAME}:
                        raise InstallError(
                            "staging_inventory_invalid",
                            "transaction staging container has unexpected entries",
                        )
                    try:
                        staged_identity = _identity_if_present(
                            staged, self.runtime.read_identity
                        )
                    except InstallError as error:
                        raise InstallError(
                            "staging_identity_mismatch",
                            "published staged application is invalid",
                        ) from error
                    if staged_identity is not None and staged_identity != candidate.app:
                        raise InstallError(
                            "staging_identity_mismatch",
                            "published staged application differs from candidate",
                        )
                    if staged_identity is not None and partial.exists():
                        raise InstallError(
                            "staging_inventory_invalid",
                            "published staging has an unexpected partial payload",
                        )
                    if staged_identity is None:
                        try:
                            partial_identity = _identity_if_present(
                                partial, self.runtime.read_identity
                            )
                        except InstallError:
                            remove_partial_staged_payload(container_path, partial)
                            partial_identity = None
                        if partial_identity is not None and partial_identity != candidate.app:
                            remove_partial_staged_payload(container_path, partial)
                            partial_identity = None
                        if partial_identity is None:
                            admitted = self.runtime.admit_candidate(self.paths)
                            if admitted != candidate:
                                raise InstallError(
                                    "candidate_identity_drift",
                                    "candidate differs from installation journal",
                                )
                            self.runtime.copy_candidate(self.paths.candidate_app, partial)
                        partial_identity = self.runtime.read_identity(partial)
                        if partial_identity != candidate.app:
                            raise InstallError(
                                "staging_identity_mismatch",
                                "partial staged application differs from candidate",
                            )
                        self.runtime.verify_bundle(partial, candidate.app)
                        self.runtime.sync_tree(partial)
                        publish_staged_payload(container_fd)
                    staged_identity = self.runtime.read_identity(staged)
                    if not _same_app(staged_identity, candidate.app):
                        raise InstallError("staging_identity_mismatch", "staged application differs from candidate")
                    self.runtime.verify_bundle(staged, candidate.app)
                    self.runtime.sync_tree(staged)
                    _fsync_directory_fd(container_fd)
                    _fsync_directory_fd(parent_fd)
                finally:
                    os.close(container_fd)
                document = _next(document, phase="staged")
                store.write(document)

            if document["phase"] == "staged":
                swap_parent_fd, container_fd = self._open_transaction_directories(document)
                try:
                    target = self.runtime.read_identity(self.paths.target_app)
                    staged = self.runtime.read_identity(container_path / PAYLOAD_NAME)
                    candidate_expected = _candidate_from_journal(document).app
                    previous_expected = _previous_from_journal(document)
                    if _same_app(target, previous_expected) and _same_app(staged, candidate_expected):
                        self.runtime.verify_bundle(self.paths.target_app, previous_expected)
                        self.runtime.verify_bundle(
                            container_path / PAYLOAD_NAME, candidate_expected
                        )
                        self._capture_stable_dormant_guard(
                            document["guards"][-1]["before"]
                        )
                        self._require_layout(
                            document, target="previous", staged="candidate"
                        )
                        self.runtime.swap(
                            swap_parent_fd,
                            self.paths.target_name,
                            container_fd,
                            PAYLOAD_NAME,
                        )
                        _fsync_directory_fd(container_fd)
                        _fsync_directory_fd(swap_parent_fd)
                    elif not (
                        _same_app(target, candidate_expected)
                        and _same_app(staged, previous_expected)
                    ):
                        raise InstallError("recovery_layout_ambiguous", "staged transaction has unknown bundle identities")
                finally:
                    os.close(container_fd)
                    os.close(swap_parent_fd)
                self._require_layout(document, target="candidate", staged="previous")
                document = _next(document, phase="swapped")
                store.write(document)

            if document["phase"] == "swapped":
                self._require_layout(document, target="candidate", staged="previous")
                self.runtime.verify_bundle(
                    self.paths.target_app, _candidate_from_journal(document).app
                )
                self.runtime.verify_bundle(
                    container_path / PAYLOAD_NAME, _previous_from_journal(document)
                )
                after = self._capture_stable_dormant_guard(
                    document["guards"][-1]["before"]
                )
                self._require_layout(
                    document, target="candidate", staged="previous"
                )
                document["guards"][-1]["after"] = after
                document = _next(document, phase="installed")
                store.write(document)
                self._verify_terminal(document)
                return document
            raise InstallError("journal_phase_invalid", "transaction did not reach a terminal phase")
        finally:
            os.close(parent_fd)

    def _resume_rollback(
        self, store: JournalStore, document: dict[str, Any]
    ) -> dict[str, Any]:
        if document["phase"] == "rollback-prepared":
            parent_fd, container_fd = self._open_transaction_directories(document)
            try:
                target = self.runtime.read_identity(self.paths.target_app)
                staged = self.runtime.read_identity(
                    self.paths.target_parent / document["staging_name"] / PAYLOAD_NAME
                )
                candidate = _candidate_from_journal(document).app
                previous = _previous_from_journal(document)
                if _same_app(target, candidate) and _same_app(staged, previous):
                    self.runtime.verify_bundle(self.paths.target_app, candidate)
                    self.runtime.verify_bundle(
                        self.paths.target_parent
                        / document["staging_name"]
                        / PAYLOAD_NAME,
                        previous,
                    )
                    self._capture_stable_dormant_guard(
                        document["guards"][-1]["before"]
                    )
                    self._require_layout(
                        document, target="candidate", staged="previous"
                    )
                    self.runtime.swap(
                        parent_fd, self.paths.target_name, container_fd, PAYLOAD_NAME
                    )
                    _fsync_directory_fd(container_fd)
                    _fsync_directory_fd(parent_fd)
                elif not (
                    _same_app(target, previous) and _same_app(staged, candidate)
                ):
                    raise InstallError(
                        "recovery_layout_ambiguous",
                        "rollback transaction has unknown bundle identities",
                    )
            finally:
                os.close(container_fd)
                os.close(parent_fd)
            self._require_layout(document, target="previous", staged="candidate")
            document = _next(document, phase="rollback-swapped")
            store.write(document)

        if document["phase"] == "rollback-swapped":
            self._require_layout(document, target="previous", staged="candidate")
            after = self._capture_stable_dormant_guard(
                document["guards"][-1]["before"]
            )
            self._require_layout(
                document, target="previous", staged="candidate"
            )
            document["guards"][-1]["after"] = after
            document = _next(document, phase="rolled-back")
            store.write(document)
            self._verify_terminal(document)
            return document
        raise InstallError("journal_phase_invalid", "rollback did not reach a terminal phase")

    def _open_transaction_directories(self, document: dict[str, Any]) -> tuple[int, int]:
        parent_fd = _open_directory(self.paths.target_parent)
        try:
            container_fd = _open_directory(self.paths.target_parent / document["staging_name"])
            _require_private_container(container_fd)
        except InstallError:
            os.close(parent_fd)
            raise
        if os.fstat(parent_fd).st_dev != os.fstat(container_fd).st_dev:
            os.close(container_fd)
            os.close(parent_fd)
            raise InstallError("cross_device_swap", "staging directory is on another volume")
        return parent_fd, container_fd

    def _require_layout(self, document: dict[str, Any], *, target: str, staged: str) -> None:
        identities = {
            "candidate": _candidate_from_journal(document).app,
            "previous": _previous_from_journal(document),
        }
        actual_target = self.runtime.read_identity(self.paths.target_app)
        actual_staged = self.runtime.read_identity(
            self.paths.target_parent / document["staging_name"] / PAYLOAD_NAME
        )
        if actual_target != identities[target] or actual_staged != identities[staged]:
            raise InstallError("recovery_layout_ambiguous", "bundle layout differs from journal")

    def _verify_terminal(self, document: dict[str, Any]) -> None:
        if document["phase"] == "installed":
            self._require_layout(document, target="candidate", staged="previous")
            self.runtime.verify_bundle(
                self.paths.target_app, _candidate_from_journal(document).app
            )
            self.runtime.verify_bundle(
                self.paths.target_parent
                / document["staging_name"]
                / PAYLOAD_NAME,
                _previous_from_journal(document),
            )
        elif document["phase"] == "rolled-back":
            self._require_layout(document, target="previous", staged="candidate")
            self.runtime.verify_bundle(
                self.paths.target_app, _previous_from_journal(document)
            )
            self.runtime.verify_bundle(
                self.paths.target_parent
                / document["staging_name"]
                / PAYLOAD_NAME,
                _candidate_from_journal(document).app,
            )
        else:
            raise InstallError("journal_phase_invalid", "journal is not terminal")
        for segment in document["guards"]:
            if segment["after"] is None:
                raise InstallError("guard_incomplete", "terminal CFW guard is incomplete")
            _assert_guard_unchanged(segment["before"], segment["after"])


def _transaction() -> DormantInstallTransaction:
    if os.geteuid() == 0:
        raise InstallError(
            "root_execution_refused",
            "dormant install must run as the owning administrator, never through sudo",
        )
    return DormantInstallTransaction(InstallPaths.production(), InstallRuntime.production())


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--install", action="store_true")
    mode.add_argument("--recover", action="store_true")
    mode.add_argument("--rollback", action="store_true")
    arguments = parser.parse_args()
    try:
        transaction = _transaction()
        if arguments.preflight:
            candidate, previous = transaction.preflight()
            print(
                f"dormant install preflight passed: {previous.build_number} -> "
                f"{candidate.app.build_number}; no application or service was changed"
            )
            return
        if arguments.install:
            result = transaction.install()
        elif arguments.recover:
            result = transaction.recover()
        else:
            result = transaction.rollback()
    except (InstallError, OSError, ValueError) as error:
        code = error.code if isinstance(error, InstallError) else "unexpected_install_error"
        raise SystemExit(f"error: {code}: {error}") from error
    print(
        f"dormant install transaction {result['phase']}: "
        f"0.4.0 ({result['candidate']['build_number']}); application was not launched"
    )


if __name__ == "__main__":
    main()
