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
    from . import ga_acceptance_environment as ga_environment
    from .hash_artifact import build_manifest
    from .macos_durability import full_fsync
    from .release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        BuildIdentityError,
        bundle_build_identity,
        canonical_build_version,
        ga_signed_native_products_root,
        ga_signed_root,
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
    import ga_acceptance_environment as ga_environment
    from hash_artifact import build_manifest
    from macos_durability import full_fsync
    from release_build_identity import (
        ACTIVE_RELEASE_IDENTITY,
        BuildIdentityError,
        bundle_build_identity,
        canonical_build_version,
        ga_signed_native_products_root,
        ga_signed_root,
    )
    from repository_source_identity import SourceIdentityError, current_identity
    from verify_notary_log import NotaryLogError, validate_files as validate_notary_files


DOCUMENT: Final = "cfw-dormant-app-install-v2"
SCHEMA_VERSION: Final = 2
VERSION: Final = ACTIVE_RELEASE_IDENTITY.product_version
BUILD_NUMBER: Final = ACTIVE_RELEASE_IDENTITY.ga_build
TEAM_ID: Final = "YKUPL7Z869"
TARGET_NAME: Final = "Clash for Mac.app"
PAYLOAD_NAME: Final = TARGET_NAME
PARTIAL_PAYLOAD_NAME: Final = ".Clash for Mac.app.partial"
JOURNAL_NAME: Final = ".com.bill.clashformac.dormant-install.json"
JOURNAL_PENDING_NAME: Final = ".com.bill.clashformac.dormant-install.pending"
LOCK_NAME: Final = ".com.bill.clashformac.dormant-install.lock"
MAINTENANCE_LOCK_NAME: Final = ".com.bill.clashformac.release-maintenance-v1.lock"
STAGING_PREFIX: Final = ".com.bill.clashformac.dormant-install."
REPOSITORY_RELATIVE: Final = Path(".")
CANDIDATE_RELATIVE: Final = ga_signed_root(REPOSITORY_RELATIVE)
NATIVE_PRODUCTS_RELATIVE: Final = ga_signed_native_products_root(
    REPOSITORY_RELATIVE
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
SYSTEM_CFM_LABELS: Final = ("com.bill.clashformac.global-authority",)
USER_CFM_LABELS: Final = ("com.bill.clashformac.proxy-agent",)
LEGACY_TOMBSTONE_LABEL: Final = "com.bill.clashformac.helper"
LEGACY_TOMBSTONE_PROGRAM: Final = (
    "Contents/Library/HelperTools/cfw-helper-tombstone"
)
SERVICE_MAINTENANCE_FLAG: Final = "--service-maintenance-v2"
SERVICE_MAINTENANCE_DOCUMENT: Final = "cfw-current-service-maintenance-v2"
SERVICE_TRANSACTION_DOCUMENT: Final = "cfw-current-service-transaction-v3"
SERVICE_TRANSACTION_SCHEMA_VERSION: Final = 3
SERVICE_ENVIRONMENT_NAME: Final = "environment.json"
RETIRED_SERVICE_TRANSACTION_NAMES: Final = (
    ".com.bill.clashformac.service-transaction-v2",
    ".com.bill.clashformac.service-transaction-v2.pending",
    ".com.bill.clashformac.service-transaction-v2.lock",
)
INSTALLED_40019_OFF_PROOF_PROFILE: Final = (
    "installed_40019_engine_v5_authority_v1_0"
)
INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE: Final = (
    "installed_40019_recovery_current_authority_v1_1"
)
INSTALLED_40019_RECOVERY_ACTION: Final = (
    "recover-installed-40019-global-authority"
)
AUTHORITY_RECOVERY_INTENT_DOCUMENT: Final = (
    "cfw-current-service-authority-recovery-intent-v1"
)
AUTHORITY_RECOVERY_INTENT_NAME: Final = "authority-recovery-intent.json"
AUTHORITY_RECOVERY_PENDING_INTENT_NAME: Final = (
    ".authority-recovery-intent.json.pending"
)
AUTHORITY_RECOVERY_INTENT_SCHEMA_VERSION: Final = 1
CURRENT_OFF_PROOF_PROFILE: Final = "current_engine_v6_authority_v1_1"
SERVICE_DECOMMISSION_PHASES: Final = (
    "prepared",
    "proxy_unregistered",
    "authority_unregistered",
    "decommissioned",
)
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
    }
)


class InstallError(RuntimeError):
    """A fail-closed installation boundary rejected or could not seal a step."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class InstallProfile:
    name: str
    build_number: str
    previous_build_number: str
    repository_relative: Path
    candidate_relative: Path
    native_products_relative: Path
    artifact_kind: str
    journal_name: str
    journal_pending_name: str
    lock_name: str
    staging_prefix: str
    service_transaction_directory: str
    off_proof_profile: str
    prove_off_action: str
    unregister_proxy_action: str
    unregister_authority_action: str

    @property
    def service_pending_directory(self) -> str:
        return f"{self.service_transaction_directory}.pending"

    @property
    def service_lock_name(self) -> str:
        return f"{self.service_transaction_directory}.lock"

    @property
    def service_actions(self) -> tuple[str, ...]:
        return (
            "prepare",
            self.unregister_proxy_action,
            self.unregister_authority_action,
            "verify-dormant",
            "register-global-authority",
            "register-proxy-agent",
            "prove-off",
        )

    @property
    def service_event_proof_profiles(self) -> tuple[str, ...]:
        return (
            self.off_proof_profile,
            self.off_proof_profile,
            self.off_proof_profile,
            self.off_proof_profile,
            CURRENT_OFF_PROOF_PROFILE,
            CURRENT_OFF_PROOF_PROFILE,
            CURRENT_OFF_PROOF_PROFILE,
        )

    @property
    def service_event_allowed_proof_profiles(self) -> tuple[frozenset[str], ...]:
        profiles = tuple(
            frozenset({profile}) for profile in self.service_event_proof_profiles
        )
        if self.unregister_authority_action != (
            "unregister-installed-40019-global-authority"
        ):
            return profiles
        recovery_index = self.service_actions.index(self.unregister_authority_action)
        mutable = list(profiles)
        mutable[recovery_index] = frozenset(
            {
                INSTALLED_40019_OFF_PROOF_PROFILE,
                INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE,
            }
        )
        return tuple(mutable)

    @property
    def service_event_allowed_actions(self) -> tuple[frozenset[str], ...]:
        actions = tuple(frozenset({action}) for action in self.service_actions)
        if self.unregister_authority_action != (
            "unregister-installed-40019-global-authority"
        ):
            return actions
        recovery_index = self.service_actions.index(self.unregister_authority_action)
        mutable = list(actions)
        mutable[recovery_index] = frozenset(
            {
                self.unregister_authority_action,
                INSTALLED_40019_RECOVERY_ACTION,
            }
        )
        return tuple(mutable)

    def service_event_contract(
        self,
        sequence: int,
        *,
        authority_recovery_prepared: bool,
    ) -> tuple[frozenset[str], frozenset[str]]:
        if not 0 <= sequence < len(self.service_actions):
            raise InstallError(
                "service_journal_invalid",
                "service event contract sequence is out of range",
            )
        actions = self.service_event_allowed_actions[sequence]
        proof_profiles = self.service_event_allowed_proof_profiles[sequence]
        if self.unregister_authority_action != (
            "unregister-installed-40019-global-authority"
        ):
            if authority_recovery_prepared:
                raise InstallError(
                    "service_journal_invalid",
                    "Authority recovery intent is forbidden for this install profile",
                )
            return actions, proof_profiles

        authority_sequence = self.service_actions.index(
            self.unregister_authority_action
        )
        if sequence == authority_sequence:
            if authority_recovery_prepared:
                return (
                    frozenset({INSTALLED_40019_RECOVERY_ACTION}),
                    frozenset({INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE}),
                )
            return (
                frozenset({self.unregister_authority_action}),
                frozenset({INSTALLED_40019_OFF_PROOF_PROFILE}),
            )
        if sequence == authority_sequence + 1:
            return (
                actions,
                frozenset(
                    {
                        INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE
                        if authority_recovery_prepared
                        else INSTALLED_40019_OFF_PROOF_PROFILE
                    }
                ),
            )
        return actions, proof_profiles


GA_INSTALL_PROFILE: Final = InstallProfile(
    name="ga",
    build_number=BUILD_NUMBER,
    previous_build_number="40019",
    repository_relative=REPOSITORY_RELATIVE,
    candidate_relative=CANDIDATE_RELATIVE,
    native_products_relative=NATIVE_PRODUCTS_RELATIVE,
    artifact_kind="notarized-ga-candidate-v1",
    journal_name=JOURNAL_NAME,
    journal_pending_name=JOURNAL_PENDING_NAME,
    lock_name=LOCK_NAME,
    staging_prefix=STAGING_PREFIX,
    service_transaction_directory=".com.bill.clashformac.service-transaction-v3",
    off_proof_profile=INSTALLED_40019_OFF_PROOF_PROFILE,
    prove_off_action="prove-installed-40019-off",
    unregister_proxy_action="unregister-installed-40019-proxy-agent",
    unregister_authority_action="unregister-installed-40019-global-authority",
)


@dataclass(frozen=True)
class InstallPaths:
    repository: Path
    candidate_app: Path
    candidate_manifest: Path
    target_parent: Path
    operator_repository: Path | None = None
    target_name: str = TARGET_NAME
    profile: InstallProfile = GA_INSTALL_PROFILE

    @classmethod
    def production(cls) -> "InstallPaths":
        profile = GA_INSTALL_PROFILE
        operator_repository = Path(__file__).resolve().parent.parent
        repository = operator_repository / profile.repository_relative
        signed = repository / profile.candidate_relative
        return cls(
            repository=repository,
            candidate_app=signed / TARGET_NAME,
            candidate_manifest=signed / f"{TARGET_NAME}.manifest.json",
            target_parent=Path("/Applications"),
            operator_repository=operator_repository,
            profile=profile,
        )

    @property
    def target_app(self) -> Path:
        return self.target_parent / self.target_name

    @property
    def candidate_executable(self) -> Path:
        return self.candidate_app / "Contents/MacOS/clash-for-mac"

    @property
    def release_toolchain_root(self) -> Path:
        return self.repository / "target/toolchains"

    @property
    def journal_name(self) -> str:
        return self.profile.journal_name

    @property
    def journal_pending_name(self) -> str:
        return self.profile.journal_pending_name

    @property
    def lock_name(self) -> str:
        return self.profile.lock_name

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
class TerminalInstallJournalSnapshot:
    """One stable, validated terminal install journal read under its lock."""

    document: dict[str, Any]
    data: bytes
    metadata: os.stat_result


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
ServiceDecommissionVerifier = Callable[
    [InstallPaths, CandidateIdentity, AppIdentity, dict[str, Any]], dict[str, Any]
]


@dataclass(frozen=True)
class InstallRuntime:
    capture_guard: GuardCapture
    observe_environment: ga_environment.EnvironmentObserver
    require_cfm_dormant: DormantCheck
    require_cfm_process_absent: CfmProcessCheck
    admit_candidate: CandidateAdmitter
    read_identity: IdentityReader
    copy_candidate: Copier
    sync_tree: TreeSyncer
    swap: Swapper
    verify_bundle: BundleVerifier
    require_service_decommissioned: ServiceDecommissionVerifier

    @classmethod
    def production(cls, paths: InstallPaths | None = None) -> "InstallRuntime":
        runner = production_command_runner
        selected_paths = paths or InstallPaths.production()
        return cls(
            capture_guard=lambda: capture_cfw_guard(runner),
            observe_environment=ga_environment.observe_environment,
            require_cfm_dormant=lambda guard: require_cfm_dormant(
                guard,
                runner,
                executable=selected_paths.candidate_executable,
            ),
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
            require_service_decommissioned=require_decommissioned_service_transaction,
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
        "/usr/bin/dscl",
        "/usr/bin/systemextensionsctl",
        "/usr/sbin/netstat",
        "/usr/sbin/scutil",
    }:
        timeout = 30.0
    if _fixed_host_executable_path(arguments[0]):
        timeout = 60.0
    return _run_bounded_process(arguments, timeout=timeout)


def _fixed_bundle_command_path(value: str) -> bool:
    path = Path(value)
    production = InstallPaths.production()
    if path in {
        production.candidate_app,
        production.target_app,
    }:
        return True
    if not path.is_absolute() or path.parent.parent != Path("/Applications"):
        return False
    container = path.parent.name
    if not container.startswith(GA_INSTALL_PROFILE.staging_prefix):
        return False
    transaction_id = container.removeprefix(GA_INSTALL_PROFILE.staging_prefix)
    try:
        canonical = str(uuid.UUID(transaction_id))
    except (ValueError, AttributeError):
        return False
    return canonical == transaction_id and path.name in {
        PAYLOAD_NAME,
        PARTIAL_PAYLOAD_NAME,
    }


def _fixed_host_executable_path(value: str) -> bool:
    path = Path(value)
    if path.name != "clash-for-mac" or path.parent.name != "MacOS":
        return False
    contents = path.parent.parent
    return contents.name == "Contents" and _fixed_bundle_command_path(
        str(contents.parent)
    )


def _require_fixed_command(arguments: tuple[str, ...]) -> None:
    fixed = {
        ("/bin/ps", "-axo", "pid=,uid=,lstart=,comm="),
        (
            "/usr/bin/dscl",
            ".",
            "-readall",
            "/Users",
            "UniqueID",
            "NFSHomeDirectory",
            "UserShell",
            "AuthenticationAuthority",
        ),
        ("/sbin/ifconfig",),
        ("/usr/bin/systemextensionsctl", "list"),
        ("/usr/sbin/netstat", "-rn", "-f", "inet"),
        ("/usr/sbin/netstat", "-rn", "-f", "inet6"),
        ("/usr/sbin/scutil", "--dns"),
        ("/usr/sbin/scutil", "--proxy"),
    }
    if arguments in fixed:
        return
    if (
        len(arguments) == 3
        and _fixed_host_executable_path(arguments[0])
        and arguments[1] == SERVICE_MAINTENANCE_FLAG
        and arguments[2]
        in {
            "prove-off",
            "prove-installed-40019-off",
            "status",
            "unregister-proxy-agent",
            "unregister-installed-40019-proxy-agent",
            "unregister-global-authority",
            "unregister-installed-40019-global-authority",
            INSTALLED_40019_RECOVERY_ACTION,
            "register-global-authority",
            "register-proxy-agent",
        }
    ):
        return
    if len(arguments) == 3 and arguments[:2] == ("/bin/launchctl", "print"):
        domain = arguments[2]
        allowed_system = {
            *(f"system/{label}" for label in SYSTEM_CFM_LABELS),
            f"system/{LEGACY_TOMBSTONE_LABEL}",
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
        if (
            arguments[:2] == ("/usr/bin/ditto", "--noqtn")
            and len(arguments) == 4
            and Path(arguments[2]) == InstallPaths.production().candidate_app
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
    except PermissionError:
        # macOS can transiently report EPERM for an already-killed orphaned
        # group while its descendants are being reparented and reaped.  Keep
        # the bounded absence proof below armed; a live leader is still an
        # unambiguous termination failure.
        if process.poll() is None:
            failure = InstallError(
                "command_termination_failed",
                "spawned command group could not be signalled",
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
    while failure is None:
        group_visibility_restricted = False
        try:
            os.killpg(group, 0)
        except ProcessLookupError:
            break
        except PermissionError:
            group_visibility_restricted = True
        except OSError:
            failure = InstallError(
                "command_termination_failed",
                "spawned command group absence could not be observed",
            )
            break
        if time.monotonic() >= deadline:
            failure = InstallError(
                "command_termination_failed",
                (
                    "spawned command group absence could not be observed"
                    if group_visibility_restricted
                    else "spawned command group did not disappear after SIGKILL"
                ),
            )
            break
        try:
            os.killpg(group, signal.SIGKILL)
        except ProcessLookupError:
            break
        except PermissionError:
            if not group_visibility_restricted:
                failure = InstallError(
                    "command_termination_failed",
                    "spawned command group could not be re-signalled",
                )
                break
        except OSError:
            failure = InstallError(
                "command_termination_failed",
                "spawned command group could not be re-signalled",
            )
            break
        time.sleep(0.01)
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
    selector: selectors.BaseSelector | None = None
    leader_cleanup_attempted = False
    try:
        try:
            selector = selectors.DefaultSelector()
        except OSError as error:
            raise InstallError(
                "command_io_unavailable",
                "fixed command output selector is unavailable",
            ) from error
        if process.stdout is None or process.stderr is None:
            raise InstallError("command_failed", "fixed command pipes are unavailable")
        for stream, destination in ((process.stdout, stdout), (process.stderr, stderr)):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, destination)
        deadline = time.monotonic() + timeout
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
    except OSError as error:
        primary = InstallError(
            "command_io_unavailable",
            "fixed command process I/O failed",
        )
        primary.__cause__ = error
    except BaseException as error:
        primary = error
    finally:
        close_failure: InstallError | None = None
        if selector is not None:
            try:
                selector.close()
            except OSError:
                close_failure = InstallError(
                    "command_cleanup_failed", "command selector could not be closed"
                )
        for stream in (process.stdout, process.stderr):
            if stream is None:
                continue
            try:
                stream.close()
            except OSError:
                if close_failure is None:
                    close_failure = InstallError(
                        "command_cleanup_failed", "command pipes could not be closed"
                    )
        if not leader_cleanup_attempted:
            cleanup_failure = _terminate_process_group(process, group)
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


def capture_cfw_guard(
    runner: CommandRunner, *, require_cfm_absent: bool = True
) -> dict[str, Any]:
    process_output = _require_command_success(
        runner(("/bin/ps", "-axo", "pid=,uid=,lstart=,comm=")),
        "CFW process observation",
    )
    observed = _parse_processes(process_output)
    if require_cfm_absent:
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


def require_single_interactive_local_user(
    runner: CommandRunner, expected_uid: int
) -> None:
    if type(expected_uid) is not int or expected_uid <= 0 or expected_uid != os.geteuid():
        raise InstallError(
            "cfm_user_inventory_invalid",
            "maintenance owner is not the effective local user",
        )
    result = runner(
        (
            "/usr/bin/dscl",
            ".",
            "-readall",
            "/Users",
            "UniqueID",
            "NFSHomeDirectory",
            "UserShell",
            "AuthenticationAuthority",
        )
    )
    if result.returncode != 0 or result.stderr or not result.stdout.endswith("\n"):
        raise InstallError(
            "cfm_user_inventory_invalid",
            "cannot enumerate local interactive user registrations",
        )
    records = result.stdout.rstrip("\n").split("\n-\n")
    if not records or len(records) > 4096:
        raise InstallError(
            "cfm_user_inventory_invalid", "local user inventory size is invalid"
        )
    interactive_uids: set[int] = set()
    seen_uids: set[int] = set()
    for record in records:
        values: dict[str, str] = {}
        for line in record.splitlines():
            key, separator, value = line.partition(": ")
            if separator and key in {
                "AuthenticationAuthority",
                "NFSHomeDirectory",
                "UniqueID",
                "UserShell",
            }:
                if key in values or not value:
                    raise InstallError(
                        "cfm_user_inventory_invalid",
                        "local user record contains duplicate or empty fields",
                    )
                values[key] = value
        if not {"NFSHomeDirectory", "UniqueID", "UserShell"} <= set(values):
            raise InstallError(
                "cfm_user_inventory_invalid",
                "local user record omits a required identity field",
            )
        try:
            uid = int(values["UniqueID"])
        except ValueError as error:
            raise InstallError(
                "cfm_user_inventory_invalid", "local user uid is malformed"
            ) from error
        if uid in seen_uids:
            raise InstallError(
                "cfm_user_inventory_invalid", "local user inventory repeats a uid"
            )
        seen_uids.add(uid)
        shell = values["UserShell"]
        home = values["NFSHomeDirectory"]
        authenticated = "AuthenticationAuthority" in values
        if (
            uid >= 500
            and shell not in {"/bin/false", "/usr/bin/false", "/usr/sbin/nologin"}
            and (authenticated or home.startswith("/Users/"))
        ):
            interactive_uids.add(uid)
    if interactive_uids != {expected_uid}:
        raise InstallError(
            "cfm_multi_user_registration_unproven",
            "another persistent local user could retain a ProxyAgent registration",
        )


def _require_launchctl_service_absent(result: CommandResult, domain: str) -> None:
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


def _require_legacy_tombstone_absent_or_inactive(result: CommandResult) -> None:
    domain = f"system/{LEGACY_TOMBSTONE_LABEL}"
    if result.returncode == 113 and "Could not find service" in result.stdout + result.stderr:
        return
    if result.returncode != 0 or result.stderr:
        raise InstallError(
            "cfm_legacy_tombstone_observation_failed",
            "cannot prove the legacy migration tombstone state",
        )
    lines = result.stdout.splitlines()
    if not lines or lines[0] != f"{domain} = {{" or lines[-1] != "}":
        raise InstallError(
            "cfm_legacy_tombstone_invalid",
            "legacy migration tombstone launchd output is malformed",
        )
    stripped = [line.strip() for line in lines]
    required = {
        "active count = 0",
        "managed_by = com.apple.xpc.ServiceManagement",
        "state = not running",
        f"program identifier = {LEGACY_TOMBSTONE_PROGRAM} (mode: 2)",
        "parent bundle identifier = com.bill.clashformac",
        "\"team-identifier\" => \"YKUPL7Z869\"",
        "domain = system",
    }
    if any(stripped.count(value) != 1 for value in required):
        raise InstallError(
            "cfm_legacy_tombstone_invalid",
            "legacy migration tombstone is active, ambiguous, or has the wrong identity",
        )


def parse_service_maintenance_receipt(
    result: CommandResult, expected_action: str
) -> dict[str, Any]:
    if result.returncode != 0 or result.stderr or not result.stdout.endswith("\n"):
        raise InstallError(
            "cfm_service_status_failed",
            "signed Host could not prove current SMAppService registration state",
        )
    try:
        receipt = json.loads(
            result.stdout,
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except (json.JSONDecodeError, RecursionError, ValueError) as error:
        raise InstallError(
            "cfm_service_status_invalid",
            "signed Host returned a malformed service status receipt",
        ) from error
    try:
        canonical_receipt = _canonical_json(receipt)
    except RecursionError as error:
        raise InstallError(
            "cfm_service_status_invalid",
            "signed Host returned a noncanonical service maintenance receipt",
        ) from error
    expected_keys = {
        "action",
        "document",
        "engine_status",
        "global_authority",
        "off_proof_profile",
        "proxy_agent",
    }
    proof_profiles: dict[str, frozenset[str | None]] = {
        "status": frozenset({None}),
        "prove-off": frozenset({CURRENT_OFF_PROOF_PROFILE}),
        "unregister-proxy-agent": frozenset({CURRENT_OFF_PROOF_PROFILE}),
        "unregister-global-authority": frozenset({CURRENT_OFF_PROOF_PROFILE}),
        "register-global-authority": frozenset({CURRENT_OFF_PROOF_PROFILE}),
        "register-proxy-agent": frozenset({CURRENT_OFF_PROOF_PROFILE}),
        "prove-installed-40019-off": frozenset(
            {INSTALLED_40019_OFF_PROOF_PROFILE}
        ),
        "unregister-installed-40019-proxy-agent": frozenset(
            {INSTALLED_40019_OFF_PROOF_PROFILE}
        ),
        "unregister-installed-40019-global-authority": frozenset(
            {INSTALLED_40019_OFF_PROOF_PROFILE}
        ),
        INSTALLED_40019_RECOVERY_ACTION: frozenset(
            {INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE}
        ),
    }
    if expected_action not in proof_profiles:
        raise InstallError(
            "cfm_service_status_invalid",
            "service maintenance action is outside the fixed receipt contract",
        )
    if (
        not isinstance(receipt, dict)
        or set(receipt) != expected_keys
        or receipt.get("action") != expected_action.replace("-", "_")
        or receipt.get("document") != SERVICE_MAINTENANCE_DOCUMENT
        or receipt.get("engine_status")
        != (None if expected_action == "status" else "off")
        or all(
            receipt.get("off_proof_profile") != profile
            for profile in proof_profiles[expected_action]
        )
        or receipt.get("global_authority")
        not in {
            "enabled",
            "requires_approval",
            "not_registered",
            "not_found",
            "unknown",
        }
        or receipt.get("proxy_agent")
        not in {
            "enabled",
            "requires_approval",
            "not_registered",
            "not_found",
            "unknown",
        }
        or result.stdout.encode("utf-8") != canonical_receipt
    ):
        raise InstallError(
            "cfm_service_status_invalid",
            "signed Host returned a noncanonical service maintenance receipt",
        )
    return receipt


def _require_current_services_unregistered(
    runner: CommandRunner,
    *,
    executable: Path | None = None,
) -> None:
    service_host = executable or InstallPaths.production().candidate_executable
    receipt = parse_service_maintenance_receipt(
        runner((str(service_host), SERVICE_MAINTENANCE_FLAG, "status")),
        "status",
    )
    if (
        receipt["global_authority"] != "not_registered"
        or receipt["proxy_agent"] != "not_registered"
    ):
        raise InstallError(
            "cfm_service_status_invalid",
            "signed Host did not prove both current SMAppServices unregistered",
        )


def require_cfm_dormant(
    guard: dict[str, Any],
    runner: CommandRunner,
    *,
    executable: Path | None = None,
) -> None:
    processes = require_cfm_process_absent(runner)
    cfw_processes = guard.get("cfw_processes")
    if not isinstance(cfw_processes, list) or not cfw_processes:
        raise InstallError("cfw_identity_invalid", "CFW guard has no GUI identity")
    gui_uid = cfw_processes[0].get("uid")
    if type(gui_uid) is not int or gui_uid <= 0:
        raise InstallError("cfw_identity_invalid", "CFW GUI uid is invalid")
    require_single_interactive_local_user(runner, gui_uid)
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
        _require_launchctl_service_absent(
            runner(("/bin/launchctl", "print", domain)), domain
        )
    _require_legacy_tombstone_absent_or_inactive(
        runner(("/bin/launchctl", "print", f"system/{LEGACY_TOMBSTONE_LABEL}"))
    )
    # BTM records are not a launchability boundary: Apple documents that an
    # unregistered item may remain visible until later system maintenance, and
    # `sfltool dumpbtm` is not a bounded API. The signed Host SMAppService
    # statuses plus exact launchd job/process absence are authoritative here.
    _require_current_services_unregistered(runner, executable=executable)
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


def _matching_clean_source_identity(
    operator_repository: Path, release_worktree: Path
) -> dict[str, str]:
    operator_source = current_identity(operator_repository, require_clean=True)
    worktree_source = current_identity(release_worktree, require_clean=True)
    if worktree_source != operator_source:
        raise CandidateBindingError(
            "operator and candidate worktree source identities differ"
        )
    return worktree_source


def _clean_profile_source_identity(
    operator_repository: Path, release_repository: Path
) -> dict[str, str]:
    if release_repository == operator_repository:
        return current_identity(operator_repository, require_clean=True)
    return _matching_clean_source_identity(operator_repository, release_repository)


def admit_fixed_candidate(paths: InstallPaths, runner: CommandRunner) -> CandidateIdentity:
    if "CFW_TOOLCHAIN_ROOT" in os.environ:
        raise InstallError(
            "candidate_toolchain_override",
            "dormant installation refuses a caller-selected release toolchain root",
        )
    operator_repository = Path(__file__).resolve().parent.parent
    profile = paths.profile
    expected_repository = operator_repository / profile.repository_relative
    if paths.operator_repository != operator_repository or paths.repository != expected_repository:
        raise InstallError("candidate_path_invalid", "production repository path is not fixed")
    try:
        worktree_metadata = expected_repository.lstat()
        toolchain_metadata = paths.release_toolchain_root.lstat()
    except OSError as error:
        raise InstallError(
            "candidate_worktree_invalid",
            "fixed release worktree or its local toolchain is unavailable",
        ) from error
    if (
        expected_repository.is_symlink()
        or not stat.S_ISDIR(worktree_metadata.st_mode)
        or paths.release_toolchain_root.is_symlink()
        or not stat.S_ISDIR(toolchain_metadata.st_mode)
    ):
        raise InstallError(
            "candidate_worktree_invalid",
            "fixed release worktree and local toolchain must be real directories",
        )
    expected_signed = expected_repository / profile.candidate_relative
    if (
        paths.candidate_app != expected_signed / TARGET_NAME
        or paths.candidate_manifest != expected_signed / f"{TARGET_NAME}.manifest.json"
    ):
        raise InstallError("candidate_path_invalid", "candidate path is not the fixed signed output")
    try:
        source = _clean_profile_source_identity(
            operator_repository, paths.repository
        )
        manifest = load_strict_json(paths.candidate_manifest, "signed candidate manifest")
        metadata = manifest.get("metadata")
        if not isinstance(metadata, dict):
            raise CandidateBindingError("signed candidate metadata is absent")
        build_number = canonical_build_version(
            metadata.get("buildNumber"), "signed candidate build number"
        )
        if build_number != profile.build_number:
            raise CandidateBindingError(
                f"signed candidate is not fixed build {profile.build_number}"
            )
        toolchain = derive_candidate_toolchain_metadata(paths.repository)
        validated = validate_candidate_app_manifest(
            paths.candidate_manifest,
            paths.candidate_app,
            artifact_kind=profile.artifact_kind,
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

    native_products = paths.repository / profile.native_products_relative
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
    if (
        _clean_profile_source_identity(operator_repository, paths.repository) != source
    ):
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
    return _run_bounded_process(
        (
            str(verifier),
            str(app),
            str(native_products),
            "--context",
            "canonical-native-content",
        )
    )


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
            try:
                if directory == root:
                    full_fsync(descriptor)
                else:
                    os.fsync(descriptor)
            except OSError as error:
                raise InstallError(
                    "directory_fsync_failed",
                    "staged directory stable-storage durability is unknown",
                ) from error
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
        full_fsync(descriptor)
    except OSError as error:
        raise InstallError(
            "directory_fsync_failed",
            "installation directory stable-storage durability is unknown",
        ) from error


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


def _journal_metadata_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


@contextmanager
def exclusive_release_maintenance_lock(
    target_parent: Path,
    *,
    require_existing: bool = False,
) -> Iterator[None]:
    """Serialize every service-registration and application-swap mutation."""

    parent_fd = _open_directory(target_parent)
    descriptor = -1
    flags = (
        (os.O_RDONLY if require_existing else os.O_RDWR | os.O_CREAT)
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        try:
            descriptor = os.open(
                MAINTENANCE_LOCK_NAME,
                flags,
                0o600,
                dir_fd=parent_fd,
            )
        except OSError as error:
            raise InstallError(
                "maintenance_lock_unavailable",
                "cannot open the release maintenance lock",
            ) from error
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise InstallError(
                "maintenance_lock_unsafe",
                "release maintenance lock ownership, type, link count, or mode is unsafe",
            )
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError as error:
            raise InstallError(
                "maintenance_busy",
                "another release maintenance transaction is active",
            ) from error

        def require_identity() -> None:
            try:
                visible = os.stat(
                    MAINTENANCE_LOCK_NAME,
                    dir_fd=parent_fd,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise InstallError(
                    "maintenance_lock_identity_drift",
                    "release maintenance lock path is unavailable",
                ) from error
            opened = os.fstat(descriptor)
            if (opened.st_dev, opened.st_ino) != (visible.st_dev, visible.st_ino):
                raise InstallError(
                    "maintenance_lock_identity_drift",
                    "release maintenance lock path was rebound",
                )

        require_identity()
        try:
            yield
        finally:
            require_identity()
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        os.close(parent_fd)


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


def _read_private_service_document(
    directory_fd: int,
    name: str,
    label: str,
) -> tuple[dict[str, Any], bytes]:
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        descriptor = os.open(name, flags, dir_fd=directory_fd)
    except OSError as error:
        raise InstallError(
            "service_decommission_evidence_invalid",
            f"cannot open {label}",
        ) from error
    try:
        try:
            opened = os.fstat(descriptor)
            if (
                not stat.S_ISREG(opened.st_mode)
                or opened.st_nlink != 1
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o600
                or opened.st_size <= 0
                or opened.st_size > MAX_JOURNAL_BYTES
            ):
                raise InstallError(
                    "service_decommission_evidence_invalid",
                    f"{label} metadata is unsafe",
                )
            data = _read_fd_bytes(descriptor, MAX_JOURNAL_BYTES)
            after = os.fstat(descriptor)
            visible = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        except OSError as error:
            raise InstallError(
                "service_decommission_evidence_invalid",
                f"{label} changed or became unavailable while reading",
            ) from error
    finally:
        try:
            os.close(descriptor)
        except OSError as error:
            raise InstallError(
                "service_decommission_evidence_invalid",
                f"{label} descriptor could not be closed",
            ) from error
    if (
        (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
            opened.st_mtime_ns,
        )
        != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        )
        or (after.st_dev, after.st_ino) != (visible.st_dev, visible.st_ino)
    ):
        raise InstallError(
            "service_decommission_evidence_invalid",
            f"{label} changed while reading",
        )
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise InstallError(
            "service_decommission_evidence_invalid",
            f"{label} is not strict JSON",
        ) from error
    if not isinstance(value, dict):
        raise InstallError(
            "service_decommission_evidence_invalid",
            f"{label} is not canonical JSON",
        )
    try:
        encoded = _canonical_json(value)
    except RecursionError as error:
        raise InstallError(
            "service_decommission_evidence_invalid",
            f"{label} is not canonical JSON",
        ) from error
    if data != encoded:
        raise InstallError(
            "service_decommission_evidence_invalid",
            f"{label} is not canonical JSON",
        )
    return value, data


def require_retired_service_transaction_names_absent(parent_fd: int) -> None:
    """Prove every retired service-transaction name is absent beneath one fd."""

    for name in RETIRED_SERVICE_TRANSACTION_NAMES:
        try:
            os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        except FileNotFoundError:
            continue
        except OSError as error:
            raise InstallError(
                "service_retired_journal_unavailable",
                "cannot prove the retired service transaction namespace is absent",
            ) from error
        raise InstallError(
            "service_retired_journal_present",
            "retired service transaction evidence must be reviewed separately",
        )


def require_decommissioned_service_transaction(
    paths: InstallPaths,
    candidate: CandidateIdentity,
    previous: AppIdentity,
    expected_guard: dict[str, Any],
) -> dict[str, Any]:
    """Verify the exact append-only service journal before any bundle swap."""

    parent_fd = _open_directory(paths.target_parent)
    directory_fd = -1
    directory_name = paths.profile.service_transaction_directory
    try:
        require_retired_service_transaction_names_absent(parent_fd)
        try:
            directory_fd = os.open(
                directory_name,
                os.O_RDONLY
                | getattr(os, "O_DIRECTORY", 0)
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_fd,
            )
        except OSError as error:
            raise InstallError(
                "service_decommission_evidence_invalid",
                "fixed service transaction is unavailable",
            ) from error
        directory_metadata = os.fstat(directory_fd)
        visible_directory = os.stat(
            directory_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        if (
            not stat.S_ISDIR(directory_metadata.st_mode)
            or directory_metadata.st_uid != os.geteuid()
            or stat.S_IMODE(directory_metadata.st_mode) != 0o700
            or (directory_metadata.st_dev, directory_metadata.st_ino)
            != (visible_directory.st_dev, visible_directory.st_ino)
        ):
            raise InstallError(
                "service_decommission_evidence_invalid",
                "fixed service transaction directory is unsafe",
            )

        event_names = [
            f"event-{sequence:08d}.json"
            for sequence in range(len(SERVICE_DECOMMISSION_PHASES))
        ]
        inventory = set(os.listdir(directory_fd))
        authority_recovery_prepared = AUTHORITY_RECOVERY_INTENT_NAME in inventory
        expected_inventory = {
            SERVICE_ENVIRONMENT_NAME,
            "intent.json",
            *event_names,
        }
        if authority_recovery_prepared:
            expected_inventory.add(AUTHORITY_RECOVERY_INTENT_NAME)
        if (
            AUTHORITY_RECOVERY_PENDING_INTENT_NAME in inventory
            or inventory != expected_inventory
        ):
            raise InstallError(
                "service_decommission_evidence_invalid",
                "service transaction is not exactly at the decommissioned phase",
            )

        intent, intent_data = _read_private_service_document(
            directory_fd,
            "intent.json",
            "service intent",
        )
        if set(intent) != {
            "candidate",
            "document",
            "ga_environment_sha256",
            "off_proof_profile",
            "previous",
            "schema_version",
            "transaction_id",
        }:
            raise InstallError(
                "service_decommission_evidence_invalid",
                "service intent shape is invalid",
            )

        environment_document, environment_data = _read_private_service_document(
            directory_fd,
            SERVICE_ENVIRONMENT_NAME,
            "GA environment identity",
        )
        try:
            normalized_environment = ga_environment.validate_environment(
                environment_document
            )
            environment_sha256 = ga_environment.environment_sha256(
                normalized_environment
            )
        except ga_environment.GAAcceptanceEnvironmentError as error:
            raise InstallError(
                "service_decommission_evidence_invalid",
                "service GA environment identity is invalid",
            ) from error
        if environment_data != ga_environment.canonical_json(normalized_environment):
            raise InstallError(
                "service_decommission_evidence_invalid",
                "service GA environment identity is not canonical",
            )
        try:
            transaction_id = str(uuid.UUID(intent["transaction_id"]))
        except (TypeError, ValueError, AttributeError) as error:
            raise InstallError(
                "service_decommission_evidence_invalid",
                "service transaction id is invalid",
            ) from error
        if (
            intent["document"] != SERVICE_TRANSACTION_DOCUMENT
            or type(intent["schema_version"]) is not int
            or intent["schema_version"] != SERVICE_TRANSACTION_SCHEMA_VERSION
            or transaction_id != intent["transaction_id"]
            or intent["candidate"] != candidate.document()
            or intent["previous"] != previous.document()
            or intent["ga_environment_sha256"] != environment_sha256
            or intent["off_proof_profile"] != paths.profile.off_proof_profile
        ):
            raise InstallError(
                "service_decommission_evidence_invalid",
                "service intent does not bind the fixed GA installation identity",
            )

        intent_sha256 = _sha256_bytes(intent_data)
        previous_event_sha256: str | None = None
        baseline_guard: dict[str, Any] | None = None
        validated_events: list[dict[str, Any]] = []
        event_documents: list[bytes] = []
        for sequence, name in enumerate(event_names):
            event, event_bytes = _read_private_service_document(
                directory_fd,
                name,
                f"service event {sequence}",
            )
            if set(event) != {
                "action",
                "document",
                "guard_after",
                "guard_before",
                "intent_sha256",
                "off_proof_profile",
                "phase",
                "previous_event_sha256",
                "schema_version",
                "sequence",
            }:
                raise InstallError(
                    "service_decommission_evidence_invalid",
                    "service event shape is invalid",
                )
            before = _validate_guard(event["guard_before"])
            after = _validate_guard(event["guard_after"])
            allowed_actions, allowed_profiles = paths.profile.service_event_contract(
                sequence,
                authority_recovery_prepared=authority_recovery_prepared,
            )
            if (
                not isinstance(event["action"], str)
                or event["action"] not in allowed_actions
                or event["document"] != SERVICE_TRANSACTION_DOCUMENT
                or event["intent_sha256"] != intent_sha256
                or event["phase"] != SERVICE_DECOMMISSION_PHASES[sequence]
                or event["previous_event_sha256"] != previous_event_sha256
                or type(event["schema_version"]) is not int
                or event["schema_version"]
                != SERVICE_TRANSACTION_SCHEMA_VERSION
                or type(event["sequence"]) is not int
                or event["sequence"] != sequence
                or not isinstance(event["off_proof_profile"], str)
                or event["off_proof_profile"]
                not in allowed_profiles
                or before != after
                or (baseline_guard is not None and before != baseline_guard)
            ):
                raise InstallError(
                    "service_decommission_evidence_invalid",
                    "service event lineage or CFW guard is invalid",
                )
            if baseline_guard is None:
                baseline_guard = after
            previous_event_sha256 = _sha256_bytes(event_bytes)
            validated_events.append(event)
            event_documents.append(event_bytes)

        if authority_recovery_prepared:
            recovery, _recovery_data = _read_private_service_document(
                directory_fd,
                AUTHORITY_RECOVERY_INTENT_NAME,
                "Authority recovery intent",
            )
            if set(recovery) != {
                "action",
                "document",
                "guard",
                "intent_sha256",
                "off_proof_profile",
                "previous_event_sha256",
                "schema_version",
                "sequence",
                "transaction_id",
            }:
                raise InstallError(
                    "service_decommission_evidence_invalid",
                    "Authority recovery intent shape is invalid",
                )
            recovery_guard = _validate_guard(recovery["guard"])
            if (
                len(validated_events) < 3
                or recovery["action"] != INSTALLED_40019_RECOVERY_ACTION
                or recovery["document"] != AUTHORITY_RECOVERY_INTENT_DOCUMENT
                or recovery["intent_sha256"] != intent_sha256
                or recovery["off_proof_profile"]
                != INSTALLED_40019_RECOVERY_OFF_PROOF_PROFILE
                or recovery["previous_event_sha256"]
                != _sha256_bytes(event_documents[1])
                or type(recovery["schema_version"]) is not int
                or recovery["schema_version"]
                != AUTHORITY_RECOVERY_INTENT_SCHEMA_VERSION
                or type(recovery["sequence"]) is not int
                or recovery["sequence"] != 2
                or recovery["transaction_id"] != intent["transaction_id"]
                or recovery_guard != baseline_guard
            ):
                raise InstallError(
                    "service_decommission_evidence_invalid",
                    "Authority recovery intent lineage is invalid",
                )

        visible_after = os.stat(
            directory_name,
            dir_fd=parent_fd,
            follow_symlinks=False,
        )
        opened_after = os.fstat(directory_fd)
        if (opened_after.st_dev, opened_after.st_ino) != (
            visible_after.st_dev,
            visible_after.st_ino,
        ):
            raise InstallError(
                "service_decommission_evidence_invalid",
                "service transaction directory was rebound",
            )
        if baseline_guard is None:
            raise InstallError(
                "service_decommission_evidence_invalid",
                "service transaction has no CFW guard baseline",
            )
        _assert_guard_unchanged(baseline_guard, expected_guard)
        return normalized_environment
    except InstallError as error:
        if error.code == "journal_invalid":
            raise InstallError(
                "service_decommission_evidence_invalid",
                "service transaction contains an invalid CFW guard",
            ) from error
        raise
    except OSError as error:
        raise InstallError(
            "service_decommission_evidence_invalid",
            "service transaction evidence changed or became unavailable",
        ) from error
    finally:
        close_error: OSError | None = None
        if directory_fd >= 0:
            try:
                os.close(directory_fd)
            except OSError as error:
                close_error = error
        try:
            os.close(parent_fd)
        except OSError as error:
            if close_error is None:
                close_error = error
        if close_error is not None:
            raise InstallError(
                "service_decommission_evidence_invalid",
                "service transaction descriptors could not be closed",
            ) from close_error


def validate_journal(
    value: object,
    profile: InstallProfile = GA_INSTALL_PROFILE,
) -> dict[str, Any]:
    document = _strict_dict(
        value,
        {
            "candidate",
            "document",
            "ga_environment_sha256",
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
    if (
        document["document"] != DOCUMENT
        or type(document["schema_version"]) is not int
        or document["schema_version"] != SCHEMA_VERSION
    ):
        raise InstallError("journal_invalid", "installation journal schema is unsupported")
    try:
        ga_environment_digest = document["ga_environment_sha256"]
        if (
            not isinstance(ga_environment_digest, str)
            or re.fullmatch(r"[0-9a-f]{64}", ga_environment_digest) is None
        ):
            raise ValueError
    except (KeyError, ValueError) as error:
        raise InstallError(
            "journal_invalid", "installation journal GA environment digest is invalid"
        ) from error
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
    expected_staging = f"{profile.staging_prefix}{transaction_id}"
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
    if (
        candidate_app["build_number"] != profile.build_number
        or previous_app["build_number"] != profile.previous_build_number
    ):
        raise InstallError(
            "journal_invalid",
            "installation journal is not for the fixed GA identity",
        )
    if int(candidate_app["build_number"]) <= int(previous_app["build_number"]):
        raise InstallError("journal_invalid", "candidate build is not newer than previous build")
    guards = document["guards"]
    if not isinstance(guards, list) or not 1 <= len(guards) <= MAX_GUARD_SEGMENTS:
        raise InstallError("journal_invalid", "CFW guard segment count is invalid")
    operations: list[str] = []
    for index, segment in enumerate(guards):
        segment = _strict_dict(segment, {"after", "before", "operation"}, "CFW guard segment")
        if segment["operation"] not in {"install", "recover"}:
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
    terminal = document["phase"] == "installed"
    last_incomplete = guards[-1]["after"] is None
    if terminal == last_incomplete:
        raise InstallError("journal_invalid", "CFW guard completion differs from journal phase")
    minimum_sequence = {
        "prepared": 1,
        "staged": 2,
        "swapped": 3,
        "installed": 4,
    }[document["phase"]]
    if document["sequence"] < minimum_sequence:
        raise InstallError("journal_invalid", "journal sequence is impossible for its phase")
    return document


def validate_journal_bytes(
    data: bytes,
    profile: InstallProfile = GA_INSTALL_PROFILE,
) -> dict[str, Any]:
    """Parse canonical producer bytes through the one install-journal validator."""

    if not isinstance(data, bytes) or not data or len(data) > MAX_JOURNAL_BYTES:
        raise InstallError("journal_invalid", "installation journal size is invalid")
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_constant,
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError, ValueError) as error:
        raise InstallError(
            "journal_invalid", "installation journal is not strict JSON"
        ) from error
    try:
        encoded = _canonical_json(value)
    except RecursionError as error:
        raise InstallError(
            "journal_invalid", "installation journal is not canonical JSON"
        ) from error
    if data != encoded:
        raise InstallError(
            "journal_invalid", "installation journal is not canonical JSON"
        )
    return validate_journal(value, profile)


def validate_terminal_journal_bytes(
    data: bytes,
    profile: InstallProfile = GA_INSTALL_PROFILE,
) -> dict[str, Any]:
    """Validate one exact installed producer journal for downstream export."""

    document = validate_journal_bytes(data, profile)
    if document["phase"] != "installed":
        raise InstallError(
            "journal_not_terminal",
            "installation journal is not at the installed phase",
        )
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
                "orphan pending journal is not the initial prepared revision",
            )
        return
    immutable = {
        "candidate",
        "document",
        "ga_environment_sha256",
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
    }
    if pending["phase"] == direct_transitions.get(current["phase"]):
        if pending["guards"] == current["guards"]:
            return
        if current["phase"] == "swapped" and (
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
        "pending journal is not a permitted next transaction revision",
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
    def locked(self, *, require_existing: bool = False) -> Iterator[None]:
        flags = (
            (os.O_RDONLY if require_existing else os.O_RDWR | os.O_CREAT)
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
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
            try:
                rebound = os.stat(
                    self.paths.lock_name,
                    dir_fd=self.parent_fd,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise InstallError(
                    "install_lock_unsafe",
                    "installation lock path is unavailable",
                ) from error
            if (rebound.st_dev, rebound.st_ino) != (metadata.st_dev, metadata.st_ino):
                raise InstallError("install_lock_unsafe", "installation lock path changed")
            try:
                yield
            finally:
                try:
                    rebound_after = os.stat(
                        self.paths.lock_name,
                        dir_fd=self.parent_fd,
                        follow_symlinks=False,
                    )
                except OSError as error:
                    raise InstallError(
                        "install_lock_unsafe",
                        "installation lock path is unavailable",
                    ) from error
                if (rebound_after.st_dev, rebound_after.st_ino) != (
                    metadata.st_dev,
                    metadata.st_ino,
                ):
                    raise InstallError(
                        "install_lock_unsafe",
                        "installation lock path changed",
                    )
        finally:
            os.close(descriptor)

    def _read_name(
        self,
        name: str,
    ) -> TerminalInstallJournalSnapshot | None:
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
            _journal_metadata_identity(metadata) != _journal_metadata_identity(after)
            or _journal_metadata_identity(metadata)
            != _journal_metadata_identity(rebound)
        ):
            raise InstallError("journal_identity_drift", "installation journal changed while reading")
        return TerminalInstallJournalSnapshot(
            document=validate_journal_bytes(data, self.paths.profile),
            data=data,
            metadata=metadata,
        )

    def _load_name(self, name: str) -> dict[str, Any] | None:
        snapshot = self._read_name(name)
        return None if snapshot is None else snapshot.document

    def terminal_snapshot(self) -> TerminalInstallJournalSnapshot:
        """Read the exact installed journal; the caller must hold ``locked``."""

        current = self._read_name(self.paths.journal_name)
        pending = self._read_name(self.paths.journal_pending_name)
        if pending is not None:
            raise InstallError(
                "journal_pending",
                "terminal installation snapshot refuses a pending journal",
            )
        if current is None:
            raise InstallError(
                "journal_missing",
                "terminal installation journal is absent",
            )
        validate_terminal_journal_bytes(current.data, self.paths.profile)
        return current

    def peek(self) -> dict[str, Any] | None:
        current = self._load_name(self.paths.journal_name)
        pending = self._load_name(self.paths.journal_pending_name)
        if pending is None:
            return current
        _require_journal_successor(current, pending)
        return pending

    def load(
        self,
        authorize: Callable[[dict[str, Any]], None],
    ) -> dict[str, Any] | None:
        current = self._load_name(self.paths.journal_name)
        pending = self._load_name(self.paths.journal_pending_name)
        document = pending if pending is not None else current
        if pending is not None:
            _require_journal_successor(current, pending)
        if document is None:
            return None
        authorize(document)
        if pending is None:
            return current
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
        validated = validate_journal(document, self.paths.profile)
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


def _reject_nonfinite_constant(token: str) -> object:
    raise ValueError(f"non-finite JSON constant: {token}")


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

    def _observe_environment(self) -> dict[str, Any]:
        try:
            return ga_environment.validate_environment(
                self.runtime.observe_environment()
            )
        except ga_environment.GAAcceptanceEnvironmentError as error:
            raise InstallError(
                "install_environment_invalid",
                "current GA environment cannot be observed",
            ) from error

    def _require_service_environment(
        self,
        expected: object,
    ) -> dict[str, Any]:
        observed = self._observe_environment()
        try:
            return ga_environment.require_same_environment(
                expected,
                observed,
                label="dormant install GA environment",
            )
        except ga_environment.GAAcceptanceEnvironmentError as error:
            raise InstallError(
                "install_environment_drift",
                "current GA environment differs from the service transaction",
            ) from error

    def _require_journal_environment(
        self,
        document: dict[str, Any],
    ) -> dict[str, Any]:
        observed = self._observe_environment()
        try:
            digest = ga_environment.environment_sha256(observed)
        except ga_environment.GAAcceptanceEnvironmentError as error:
            raise InstallError(
                "install_environment_invalid",
                "current GA environment is invalid",
            ) from error
        if digest != document["ga_environment_sha256"]:
            raise InstallError(
                "install_environment_drift",
                "current GA environment differs from the installation journal",
            )
        return observed

    def preflight(self) -> tuple[CandidateIdentity, AppIdentity]:
        before = self._capture_stable_dormant_guard()
        candidate = self.runtime.admit_candidate(self.paths)
        previous = self.runtime.read_identity(self.paths.target_app)
        self.runtime.verify_bundle(self.paths.target_app, previous)
        if int(candidate.app.build_number) <= int(previous.build_number):
            raise InstallError(
                "candidate_not_newer", "candidate build is not newer than installed build"
            )
        if (
            candidate.app.build_number != self.paths.profile.build_number
            or previous.build_number != self.paths.profile.previous_build_number
        ):
            raise InstallError(
                "install_identity_mismatch",
                "candidate and installed application do not match the fixed GA identity",
            )
        service_environment = self.runtime.require_service_decommissioned(
            self.paths,
            candidate,
            previous,
            before,
        )
        self._require_service_environment(service_environment)
        after = self._capture_stable_dormant_guard(before)
        return candidate, previous

    def install(self) -> dict[str, Any]:
        # The first gate is deliberately outside JournalStore: when an old CFM
        # job is present, even creating the persistent transaction lock would
        # violate the zero-write dormant-preflight contract.
        candidate, previous = self.preflight()
        with exclusive_release_maintenance_lock(self.paths.target_parent):
            with JournalStore(self.paths) as store:
                with store.locked():
                    opening_guard = self._capture_stable_dormant_guard()
                    service_environment = self.runtime.require_service_decommissioned(
                        self.paths,
                        candidate,
                        previous,
                        opening_guard,
                    )
                    observed_environment = self._require_service_environment(
                        service_environment
                    )
                    if store.peek() is not None:
                        raise InstallError(
                            "journal_exists",
                            "recover the existing installation transaction",
                        )
                    before = self._capture_stable_dormant_guard(opening_guard)
                    transaction_id = str(uuid.uuid4())
                    staging_name = (
                        f"{self.paths.profile.staging_prefix}{transaction_id}"
                    )
                    document: dict[str, Any] = {
                        "candidate": candidate.document(),
                        "document": DOCUMENT,
                        "ga_environment_sha256": (
                            ga_environment.environment_sha256(
                                observed_environment
                            )
                        ),
                        "guards": [
                            {
                                "after": None,
                                "before": before,
                                "operation": "install",
                            }
                        ],
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
        with exclusive_release_maintenance_lock(self.paths.target_parent):
            with JournalStore(self.paths) as store:
                with store.locked():
                    before = self._capture_stable_dormant_guard(before_open)
                    def authorize(selected: dict[str, Any]) -> None:
                        service_environment = self.runtime.require_service_decommissioned(
                            self.paths,
                            _candidate_from_journal(selected),
                            _previous_from_journal(selected),
                            before,
                        )
                        observed = self._require_service_environment(
                            service_environment
                        )
                        if (
                            ga_environment.environment_sha256(observed)
                            != selected["ga_environment_sha256"]
                        ):
                            raise InstallError(
                                "install_environment_drift",
                                "service and installation journals bind different GA environments",
                            )

                    document = store.load(authorize)
                    if document is None:
                        raise InstallError(
                            "journal_absent", "there is no installation transaction"
                        )
                    if document["phase"] == "installed":
                        self._verify_terminal(document)
                        return document
                    if len(document["guards"]) >= MAX_GUARD_SEGMENTS:
                        raise InstallError(
                            "guard_capacity",
                            "installation recovery guard capacity is exhausted",
                        )
                    original_before = document["guards"][-1]["before"]
                    _assert_guard_unchanged(original_before, before)
                    updated = _next(document)
                    updated["guards"][-1]["after"] = before
                    updated["guards"].append(
                        {"after": None, "before": before, "operation": "recover"}
                    )
                    store.write(updated)
                    return self._resume(store, updated)

    def _resume(self, store: JournalStore, document: dict[str, Any]) -> dict[str, Any]:
        self._require_journal_environment(document)
        candidate = _candidate_from_journal(document)
        parent_fd = _open_directory(self.paths.target_parent)
        container_path = self.paths.target_parent / document["staging_name"]
        try:
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
                    self._require_journal_environment(document)
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
                            self._require_journal_environment(document)
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
                        self._require_journal_environment(document)
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
                self._require_journal_environment(document)
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
                        self._require_journal_environment(document)
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
                self._require_journal_environment(document)
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
                self._require_journal_environment(document)
                store.write(document)
                self._verify_terminal(document)
                return document
            raise InstallError("journal_phase_invalid", "transaction did not reach a terminal phase")
        finally:
            os.close(parent_fd)

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
        self._require_journal_environment(document)
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
    paths = InstallPaths.production()
    return DormantInstallTransaction(paths, InstallRuntime.production(paths))


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    mode = parser.add_mutually_exclusive_group(required=True)
    mode.add_argument("--preflight", action="store_true")
    mode.add_argument("--install", action="store_true")
    mode.add_argument("--recover", action="store_true")
    if "--final" in sys.argv[1:]:
        parser.error(
            f"--final is retired; {VERSION} has exactly one GA build ({BUILD_NUMBER})"
        )
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
            result = transaction.recover()
    except (InstallError, OSError, ValueError) as error:
        code = error.code if isinstance(error, InstallError) else "unexpected_install_error"
        raise SystemExit(f"error: {code}: {error}") from error
    print(
        f"dormant install transaction {result['phase']}: "
        f"0.4.0 ({result['candidate']['build_number']}); application was not launched"
    )


if __name__ == "__main__":
    from release_python_runtime import (
        ReleasePythonRuntimeError,
        require_closed_release_runtime,
    )

    try:
        require_closed_release_runtime()
    except ReleasePythonRuntimeError as error:
        raise SystemExit(f"error: dormant-install runtime admission: {error}") from error
    main()
