"""Deterministic unsigned-CI lane collection and the single toolchain binding.

This module is the collector behind the ``unsigned_ci`` gate of the sealed outer
Evidence Manifest (``publication.sealed_manifest``). It adds no competing
framework: the lane identifiers come from
:data:`publication.sealed_manifest.REQUIRED_CI_LANES`, the lane *commands* are
transcribed from ``.github/workflows/ci.yml`` (the source of truth audited by
``scripts/verify_ci_no_masking.py``), the toolchain identity is derived from the
already-authoritative pinned-input graph
(``publication.sealed_closure.derive_supply_chain``), and the assembled document
is validated by the gate's own validator before it is written.

The one toolchain digest
------------------------
Every lane must be bound to exactly one commit *and* one toolchain digest
(Requirements 4.1, 5.1). ``toolchain_sha256`` is therefore content-addressed
over the pinned toolchain set plus the toolchain actually resolved on this
machine:

``toolchain_sha256 = sha256(canonical_json(identity))`` where ``identity`` binds

* ``pins_sha256`` - the SHA-256 of ``scripts/dependency_pins.env`` itself, so any
  change to any pin (including tool archive digests such as
  ``SHELLCHECK_DARWIN_ARM64_SHA256``) changes the toolchain digest;
* ``toolchain_versions`` / ``toolchain_digests`` - the pinned tool identities
  extracted by ``derive_supply_chain``, which first runs the fail-closed
  ``scripts/verify_pinned_build_inputs.py`` verifier, so a drifted or partial pin
  set can never produce a digest at all;
* ``apple_toolchain`` - the pinned Xcode marketing/build version and the pinned
  macOS deployment target; and
* ``resolved`` - the exact identity strings reported by the tools that actually
  execute the lanes (``rustc``, ``cargo``, ``cargo-deny``, ``cargo-tauri``,
  ``xcodebuild``, ``swift``, and the pinned ``node``/``npm``/``go``/``gomobile``/
  ``govulncheck``). Each resolved identity is checked against its pin; a missing
  tool or a version mismatch raises :class:`PublicationError` and no digest is
  produced, so a lane set can never be recorded against an unknown toolchain.

The digest is not hand-picked, is reproducible from the repository plus the
installed toolchain, and changes if either side moves.

Fail-closed recording
---------------------
* ``passed`` is written only for exit status 0; a nonzero exit is ``failed``.
* A lane that exceeds its fixed wall-clock bound is ``timeout`` with exit code
  124 - a non-passing result - and is never retried into a pass.
* A lane killed by a signal is recorded with the shell's ``128 + signal``
  convention, which is nonzero and therefore non-passing.
* The assembled document is passed through
  ``publication.sealed_manifest._ci_lane_document`` (the gate's own validator)
  before it is written, so a document this collector emits is exactly a document
  the gate accepts - and a masked record (``passed`` with a nonzero exit, a
  missing lane, an unknown lane, a foreign commit, or a foreign toolchain) is
  rejected here as well.
* Nothing in this module can convert an unavailable input into success: there is
  no ``|| true``, no skip, and no override flag.
"""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .common import (
    PublicationError,
    canonical_json,
    read_regular,
    require_sha256,
    sha256_bytes,
    sha256_file,
    write_new,
)
from .sealed_closure import derive_supply_chain
from .sealed_manifest import REQUIRED_CI_LANES, _ci_lane_document, _require_command
from .release_toolchains import verified_release_toolchain_trees


SCHEMA_VERSION = 1
DOCUMENT_KIND = "unsigned-ci-lane-record-v1"
LANE_SCHEMA_VERSION = 2
LANE_DOCUMENT_KIND = "unsigned-ci-lanes-v2"
TOOLCHAIN_BINDING_KIND = "unsigned-ci-toolchain-binding-v1"

PASSED = "passed"
FAILED = "failed"
TIMEOUT = "timeout"
TIMEOUT_EXIT_CODE = 124

PINS_RELATIVE = "scripts/dependency_pins.env"
MAX_LOG_BYTES = 64 * 1024 * 1024

# Where the pinned Node/Go toolchains are staged by
# ``scripts/bootstrap_release_toolchain.sh``.
TOOLCHAIN_ROOT_RELATIVE = "target/toolchains"

# The patched sing-box tree the libbox lanes consume. The CI workflow
# materializes it from the pinned upstream commit in a separate step; locally it
# is the tree produced by ``scripts/materialize_libbox_source.sh``, which the
# libbox scripts re-validate against the pinned patch/diff digests on every run.
DEFAULT_LIBBOX_SOURCE_TEMPLATE = "target/sources/sing-box-{version}-patched"
# The libbox build lane never overwrites the authoritative XCFramework that the
# unsigned-candidate lane binds by manifest digest; it writes its own output.
DEFAULT_LIBBOX_OUTPUT = "target/native-dependencies-ci-lane/Libbox.xcframework"


@dataclass(frozen=True)
class Lane:
    """One deterministic unsigned-CI lane, transcribed from the CI workflow."""

    identifier: str
    command: str
    # Workflow ``working-directory`` for the step, relative to the repository.
    cwd: str = "."
    # Fixed wall-clock bound. Exceeding it is recorded as ``timeout``.
    timeout: int = 1800
    # Put the pinned Node.js toolchain first on PATH (the workflow's
    # ``setup-node`` / pinned-node steps).
    pinned_node: bool = False
    # Bind ``SING_BOX_SOURCE`` (the workflow exports it from the materialize
    # step through ``GITHUB_ENV``).
    libbox_source: bool = False
    # Bind ``LIBBOX_OUTPUT`` so an existing artifact is never replaced.
    libbox_output: bool = False
    # Provide a fresh ``RUNNER_TEMP`` (the workflow relies on the runner's).
    runner_temp: bool = False


# The 26 required lanes, in dependency order: the UI install lane precedes the
# lanes that consume ``node_modules``, the libbox module lane precedes the scan
# and build lanes, and the unsigned candidate lane runs last because it consumes
# the UI dependency tree and the native products.
LANES: tuple[Lane, ...] = (
    Lane("build-script-boundary", "./scripts/verify_build_boundaries.sh", timeout=1800),
    Lane(
        "ci-no-masking",
        "PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/verify_ci_no_masking.py",
        timeout=600,
    ),
    Lane("evidence-manifest-lane", "./scripts/verify_evidence_manifest_lane.sh", timeout=1800),
    Lane(
        "version-contract",
        "PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/verify_version_contract.py",
        timeout=600,
    ),
    Lane("rust-fmt", "cargo fmt --all -- --check", timeout=900),
    Lane(
        "rust-locked-metadata",
        "cargo metadata --locked --filter-platform aarch64-apple-darwin --format-version 1 >/dev/null",
        timeout=900,
    ),
    Lane(
        "rust-clippy",
        "cargo clippy --locked --workspace --all-targets --all-features -- -D warnings",
        timeout=5400,
    ),
    Lane("rust-test", "cargo test --locked --workspace --all-targets", timeout=7200),
    Lane(
        "rust-target-audit",
        "PYTHONDONTWRITEBYTECODE=1 python3 -B scripts/audit_rust_target.py",
        timeout=1800,
    ),
    Lane("cargo-deny", "cargo deny --locked --target aarch64-apple-darwin check", timeout=1800),
    Lane("node-install", "./scripts/prepare_ui_dependencies.sh", timeout=1800),
    Lane("node-test", "./scripts/build_ui_with_pinned_node.sh --test", timeout=1800),
    Lane("node-build", "./scripts/build_ui_with_pinned_node.sh", timeout=1800),
    Lane(
        "node-audit",
        "./scripts/build_ui_with_pinned_node.sh --audit",
        timeout=900,
    ),
    Lane(
        "swift-format-lint",
        "swift format lint --recursive --strict native/macos/Sources "
        "native/macos/SystemExtension native/macos/Tests",
        timeout=1800,
    ),
    Lane("swift-package-test", "swift test --package-path native/macos", timeout=5400),
    Lane("xcode-project-verify", "./scripts/verify_xcode_project.sh", timeout=1800),
    Lane(
        "xcode-unsigned-test",
        "xcodebuild test -project native/macos/CFWNative.xcodeproj -scheme CFWNativeTests "
        "-destination 'platform=macOS,arch=arm64' CODE_SIGNING_ALLOWED=NO",
        timeout=5400,
    ),
    Lane(
        "xcode-analyze",
        "for scheme in CFWNativeTests CFWPacketTunnelExtension CFWProxyAgent CFWNativeBridge; "
        "do xcodebuild analyze -project native/macos/CFWNative.xcodeproj -scheme \"$scheme\" "
        "-destination 'platform=macOS,arch=arm64' CODE_SIGNING_ALLOWED=NO; done",
        timeout=7200,
    ),
    Lane(
        "libbox-module-verify",
        'SING_BOX_SOURCE="$SING_BOX_SOURCE" ./scripts/test_libbox_source.sh',
        timeout=7200,
        libbox_source=True,
        runner_temp=True,
    ),
    Lane(
        "libbox-govulncheck",
        'SING_BOX_SOURCE="$SING_BOX_SOURCE" ./scripts/scan_libbox_vulnerabilities.sh',
        timeout=3600,
        libbox_source=True,
    ),
    Lane(
        "libbox-build",
        'LIBBOX_OUTPUT="$LIBBOX_OUTPUT" SING_BOX_SOURCE="$SING_BOX_SOURCE" '
        "./scripts/build_libbox.sh",
        timeout=7200,
        libbox_source=True,
        libbox_output=True,
    ),
    Lane(
        "release-tooling-tests",
        "PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest discover -s scripts/tests "
        "-p 'test_*.py'; "
        'while IFS= read -r test_script; do bash "$test_script"; done '
        "< <(find scripts/tests -type f -name '*_test.sh' | sort)",
        timeout=7200,
    ),
    Lane(
        "shell-syntax",
        'while IFS= read -r script; do bash -n "$script"; zsh -n "$script"; done '
        "< <(find scripts -type f -name '*.sh' | sort)",
        timeout=900,
    ),
    Lane(
        "shellcheck",
        "source scripts/dependency_pins.env; "
        'archive="$RUNNER_TEMP/shellcheck-v$SHELLCHECK_VERSION.darwin.aarch64.tar.gz"; '
        "curl --fail --location --proto '=https' --tlsv1.2 "
        '"https://github.com/koalaman/shellcheck/releases/download/v$SHELLCHECK_VERSION/'
        'shellcheck-v$SHELLCHECK_VERSION.darwin.aarch64.tar.gz" --output "$archive"; '
        "printf '%s  %s\\n' \"$SHELLCHECK_DARWIN_ARM64_SHA256\" \"$archive\" "
        "| shasum -a 256 --check; "
        'tar -xzf "$archive" -C "$RUNNER_TEMP"; '
        '"$RUNNER_TEMP/shellcheck-v$SHELLCHECK_VERSION/shellcheck" -x scripts/*.sh '
        "scripts/tests/*.sh",
        timeout=1800,
        runner_temp=True,
    ),
    Lane("unsigned-candidate", "./scripts/build_unsigned_candidate.sh", timeout=7200),
)

LANE_INDEX: dict[str, Lane] = {lane.identifier: lane for lane in LANES}


def self_check() -> None:
    """Verify the lane table matches the gate's required lane set exactly."""
    if len(LANES) != len(LANE_INDEX):
        raise PublicationError("unsigned CI lane table repeats a lane identifier")
    if set(LANE_INDEX) != set(REQUIRED_CI_LANES):
        missing = sorted(set(REQUIRED_CI_LANES) - set(LANE_INDEX))
        unknown = sorted(set(LANE_INDEX) - set(REQUIRED_CI_LANES))
        raise PublicationError(
            f"unsigned CI lane table does not match the gate: missing={missing} unknown={unknown}"
        )
    for lane in LANES:
        # The gate only accepts bounded single-line commands.
        _require_command(lane.command, f"unsigned CI lane {lane.identifier!r} command")
        if lane.timeout <= 0:
            raise PublicationError(f"unsigned CI lane {lane.identifier!r} has no wall-clock bound")


# --------------------------------------------------------------------------
# The one toolchain binding
# --------------------------------------------------------------------------

if __package__ and __package__.startswith("scripts."):
    from scripts import verify_pinned_build_inputs as pinned
else:  # pragma: no cover - exercised via both invocation styles
    import verify_pinned_build_inputs as pinned


IDENTITY_TIMEOUT_SECONDS = 120

# Pins that the Apple/tool identity checks below are compared against.
APPLE_PIN_KEYS = ("XCODE_VERSION", "XCODE_BUILD_VERSION", "MACOS_DEPLOYMENT_TARGET")


def _pins(repository: Path) -> dict[str, str]:
    try:
        return pinned._parse_env(
            pinned._read_text(repository / PINS_RELATIVE, "dependency_pins.env")
        )
    except pinned.PinnedInputError as error:
        raise PublicationError(f"cannot read the pinned toolchain set: {error}") from error


def _identity_output(
    argv: list[str], repository: Path, label: str, env: dict[str, str], maximum: int = 512
) -> str:
    """Return one tool's normalized identity string, or fail closed."""
    try:
        completed = subprocess.run(
            argv,
            cwd=str(repository),
            capture_output=True,
            check=False,
            env=env,
            timeout=IDENTITY_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.SubprocessError) as error:
        raise PublicationError(f"cannot resolve the {label} toolchain identity: {error}") from error
    if completed.returncode != 0:
        raise PublicationError(
            f"cannot resolve the {label} toolchain identity: exit {completed.returncode}"
        )
    text = (completed.stdout + completed.stderr).decode("utf-8", "replace")
    identity = "; ".join(line.strip() for line in text.splitlines() if line.strip())
    if not identity or len(identity) > maximum:
        raise PublicationError(f"the {label} toolchain identity is empty or unbounded")
    return identity


def _expect(identity: str, expected: str, label: str) -> str:
    if identity != expected:
        raise PublicationError(
            f"resolved {label} toolchain {identity!r} does not match the pinned {expected!r}"
        )
    return identity


def _expect_field(identity: str, index: int, expected: str, label: str) -> str:
    fields = identity.split()
    if len(fields) <= index or fields[index] != expected:
        raise PublicationError(
            f"resolved {label} toolchain {identity!r} does not match the pinned {expected!r}"
        )
    return identity


def _go_module_identity(
    repository: Path, go_bin: Path, binary: Path, module: str, version: str, module_sum: str, env: dict[str, str]
) -> str:
    """Bind one pinned Go tool by module path, version, and module checksum."""
    if not binary.is_file() or binary.is_symlink() or not os.access(binary, os.X_OK):
        raise PublicationError(f"pinned Go tool is missing or not executable: {binary}")
    identity = _identity_output(
        [str(go_bin), "version", "-m", str(binary)],
        repository,
        f"{module} tool",
        env,
        maximum=64 * 1024,
    )
    for record in identity.split("; "):
        fields = record.split()
        if len(fields) == 4 and fields[0] == "mod" and fields[1] == module:
            if fields[2] != version or fields[3] != module_sum:
                raise PublicationError(
                    f"pinned {module} identity {fields[2]}/{fields[3]} does not match the pinned "
                    f"{version}/{module_sum}"
                )
            return f"{fields[1]} {fields[2]} {fields[3]}"
    raise PublicationError(f"pinned Go tool does not report its {module} module identity: {binary}")


def _resolved_toolchain(
    repository: Path,
    pins: dict[str, str],
    toolchain_root: Path | None = None,
) -> dict[str, str]:
    """Resolve the identity of every tool that actually executes a lane."""
    if toolchain_root is None:
        toolchain_root, _tree_digests = verified_release_toolchain_trees(repository, pins)
    node_bin_dir = toolchain_root / f"node-{pins['NODE_VERSION']}" / "bin"
    go_bin = toolchain_root / f"go-{pins['GO_VERSION']}" / "bin" / "go"
    go_workspace_bin = toolchain_root / "go-workspace" / "bin"
    xcodegen_bin = toolchain_root / f"xcodegen-{pins['XCODEGEN_VERSION']}" / "bin/xcodegen"
    tauri_bin = toolchain_root / f"tauri-cli-{pins['TAURI_CLI_VERSION']}" / "bin/cargo-tauri"

    base = dict(os.environ)
    base["PYTHONDONTWRITEBYTECODE"] = "1"
    node_env = dict(base)
    node_env["PATH"] = f"{node_bin_dir}:{base.get('PATH', '')}"

    resolved: dict[str, str] = {}
    resolved["rustc"] = _expect_field(
        _identity_output(["rustc", "--version"], repository, "rustc", base),
        1,
        pins["RUST_VERSION"],
        "rustc",
    )
    resolved["cargo"] = _expect_field(
        _identity_output(["cargo", "--version"], repository, "cargo", base),
        1,
        pins["RUST_VERSION"],
        "cargo",
    )
    resolved["cargo-deny"] = _expect_field(
        _identity_output(["cargo", "deny", "--version"], repository, "cargo-deny", base),
        1,
        pins["CARGO_DENY_VERSION"],
        "cargo-deny",
    )
    resolved["cargo-tauri"] = _expect_field(
        _identity_output([str(tauri_bin), "--version"], repository, "tauri-cli", base),
        1,
        pins["TAURI_CLI_VERSION"],
        "tauri-cli",
    )
    resolved["xcodegen"] = _expect(
        _identity_output([str(xcodegen_bin), "--version"], repository, "XcodeGen", base),
        f"Version: {pins['XCODEGEN_VERSION']}",
        "XcodeGen",
    )
    resolved["xcodebuild"] = _expect(
        _identity_output(["xcodebuild", "-version"], repository, "Xcode", base),
        f"Xcode {pins['XCODE_VERSION']}; Build version {pins['XCODE_BUILD_VERSION']}",
        "Xcode",
    )
    # The workflow only asserts that the Swift driver reports an identity; there
    # is no separate Swift pin (it ships inside the pinned Xcode).
    resolved["swift"] = _identity_output(["swift", "--version"], repository, "Swift", base)
    resolved["node"] = _expect(
        _identity_output([str(node_bin_dir / "node"), "--version"], repository, "Node.js", node_env),
        f"v{pins['NODE_VERSION']}",
        "Node.js",
    )
    resolved["npm"] = _identity_output(
        [str(node_bin_dir / "npm"), "--version"], repository, "npm", node_env
    )
    resolved["go"] = _expect(
        _identity_output([str(go_bin), "version"], repository, "Go", base),
        f"go version go{pins['GO_VERSION']} darwin/arm64",
        "Go",
    )
    resolved["gomobile"] = _go_module_identity(
        repository,
        go_bin,
        go_workspace_bin / "gomobile",
        "github.com/sagernet/gomobile",
        pins["GOMOBILE_VERSION"],
        pins["GOMOBILE_MODULE_SUM"],
        base,
    )
    resolved["govulncheck"] = _go_module_identity(
        repository,
        go_bin,
        go_workspace_bin / "govulncheck",
        "golang.org/x/vuln",
        pins["GOVULNCHECK_VERSION"],
        pins["GOVULNCHECK_MODULE_SUM"],
        base,
    )
    return resolved


def derive_toolchain_identity(repository: Path) -> dict[str, Any]:
    """Derive the canonical toolchain identity the CI lanes are bound to.

    Fail closed: ``derive_supply_chain`` first runs the pinned-input verifier, and
    every resolved tool identity must match its pin. No digest exists for an
    unverified or drifted toolchain.
    """
    supply = derive_supply_chain(repository)
    pins = _pins(repository)
    toolchain_root, tree_digests = verified_release_toolchain_trees(repository, pins)
    for key in APPLE_PIN_KEYS:
        if key not in pins:
            raise PublicationError(f"dependency_pins.env is missing required pin {key}")
    resolved = _resolved_toolchain(repository, pins, toolchain_root)
    _verified_root_after, tree_digests_after = verified_release_toolchain_trees(
        repository, pins
    )
    if _verified_root_after != toolchain_root or tree_digests_after != tree_digests:
        raise PublicationError("release toolchain changed while resolving its identity")
    return {
        "document": TOOLCHAIN_BINDING_KIND,
        "pins_path": PINS_RELATIVE,
        "pins_sha256": sha256_file(repository / PINS_RELATIVE),
        "toolchain_versions": supply["toolchain_versions"],
        "toolchain_digests": supply["toolchain_digests"],
        "release_tree_sha256": tree_digests,
        "apple_toolchain": {
            "xcode_version": pins["XCODE_VERSION"],
            "xcode_build_version": pins["XCODE_BUILD_VERSION"],
            "macos_deployment_target": pins["MACOS_DEPLOYMENT_TARGET"],
        },
        "resolved": resolved,
    }


def toolchain_sha256(identity: dict[str, Any]) -> str:
    """Content-address one toolchain identity into the single toolchain digest."""
    return sha256_bytes(canonical_json(identity))


def derive_toolchain_binding(repository: Path) -> tuple[str, dict[str, Any]]:
    identity = derive_toolchain_identity(repository)
    return toolchain_sha256(identity), identity


# --------------------------------------------------------------------------
# Lane execution and fail-closed recording
# --------------------------------------------------------------------------


JOURNAL_FIELDS = {
    "schema_version",
    "document",
    "id",
    "command",
    "cwd",
    "status",
    "exit_code",
    "log_sha256",
    "log_name",
    "log_bytes",
    "commit",
    "release_source_sha256",
    "toolchain_sha256",
    "timeout_seconds",
    "duration_seconds",
    "started_at",
}

# The exact key set the sealed manifest's unsigned-CI gate accepts per lane.
DOCUMENT_LANE_FIELDS = (
    "id",
    "command",
    "status",
    "exit_code",
    "log_sha256",
    "commit",
    "release_source_sha256",
    "toolchain_sha256",
)


def _normalized_exit(exit_code: int | None, timed_out: bool) -> tuple[str, int]:
    """Map a real process outcome onto (status, exit_code). Never masks."""
    if timed_out:
        # A lane that exceeded its wall-clock bound is non-passing evidence.
        return TIMEOUT, TIMEOUT_EXIT_CODE
    if exit_code is None:
        raise PublicationError("a completed lane must report an exit status")
    if exit_code == 0:
        return PASSED, 0
    if exit_code < 0:
        # Killed by a signal: the shell's 128 + signal convention, clamped.
        return FAILED, min(128 - exit_code, 255)
    return FAILED, min(exit_code, 255)


def record_lane(
    lane: Lane,
    commit: str,
    release_source_sha256: str,
    toolchain: str,
    output: bytes,
    exit_code: int | None,
    timed_out: bool,
    duration: float,
    started_at: int,
) -> dict[str, Any]:
    """Build one journal record from a real lane run. Fail closed."""
    status, normalized = _normalized_exit(exit_code, timed_out)
    if (status == PASSED) != (normalized == 0):
        # Defense in depth: a pass must have exit 0 and exit 0 must be a pass.
        raise PublicationError(f"lane {lane.identifier!r} would record a masked result")
    return {
        "schema_version": SCHEMA_VERSION,
        "document": DOCUMENT_KIND,
        "id": lane.identifier,
        "command": lane.command,
        "cwd": lane.cwd,
        "status": status,
        "exit_code": normalized,
        "log_sha256": hashlib.sha256(output).hexdigest(),
        "log_name": f"{lane.identifier}.log",
        "log_bytes": len(output),
        "commit": commit,
        "release_source_sha256": require_sha256(
            release_source_sha256, "release source SHA-256"
        ),
        "toolchain_sha256": toolchain,
        "timeout_seconds": lane.timeout,
        "duration_seconds": round(duration, 3),
        "started_at": started_at,
    }


def lane_environment(
    repository: Path,
    lane: Lane,
    pins: dict[str, str],
    libbox_source: Path,
    libbox_output: Path,
    runner_temp: Path,
    toolchain_root: Path,
) -> dict[str, str]:
    """Build the lane's environment: the pinned toolchain and nothing masking."""
    environment = dict(os.environ)
    environment["PYTHONDONTWRITEBYTECODE"] = "1"
    environment["MACOSX_DEPLOYMENT_TARGET"] = pins["MACOS_DEPLOYMENT_TARGET"]
    environment["CFW_TOOLCHAIN_ROOT"] = str(toolchain_root)
    for key in ("SING_BOX_SOURCE", "LIBBOX_OUTPUT", "RUNNER_TEMP"):
        environment.pop(key, None)
    if lane.pinned_node:
        node_bin = toolchain_root / f"node-{pins['NODE_VERSION']}" / "bin"
        environment["PATH"] = f"{node_bin}:{environment.get('PATH', '')}"
    if lane.libbox_source:
        environment["SING_BOX_SOURCE"] = str(libbox_source)
    if lane.libbox_output:
        environment["LIBBOX_OUTPUT"] = str(libbox_output)
    if lane.runner_temp:
        runner_temp.mkdir(parents=True, exist_ok=True)
        environment["RUNNER_TEMP"] = str(runner_temp)
    return environment


def execute_lane(
    repository: Path, lane: Lane, environment: dict[str, str]
) -> tuple[bytes, int | None, bool, float]:
    """Run one lane with the workflow's shell and a fixed wall-clock bound."""
    working_directory = (repository / lane.cwd).resolve()
    if not working_directory.is_dir():
        raise PublicationError(f"lane {lane.identifier!r} working directory is missing")
    started = time.monotonic()
    # GitHub Actions runs ``run:`` steps with ``bash -e -o pipefail``; the lanes
    # are executed with the same fail-fast shell.
    process = subprocess.Popen(
        ["bash", "-euo", "pipefail", "-c", lane.command],
        cwd=str(working_directory),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
    )
    timed_out = False
    try:
        output, _ = process.communicate(timeout=lane.timeout)
        exit_code: int | None = process.returncode
    except subprocess.TimeoutExpired:
        timed_out = True
        exit_code = None
        try:
            os.killpg(os.getpgid(process.pid), 9)
        except (ProcessLookupError, PermissionError):
            process.kill()
        try:
            output, _ = process.communicate(timeout=120)
        except subprocess.TimeoutExpired:
            output = b""
    return output, exit_code, timed_out, time.monotonic() - started


# --------------------------------------------------------------------------
# Journal (one real run per lane, replayable without re-running)
# --------------------------------------------------------------------------


def _journal_paths(journal: Path, lane: Lane) -> tuple[Path, Path]:
    return journal / f"{lane.identifier}.json", journal / f"{lane.identifier}.log"


def write_journal_record(journal: Path, lane: Lane, record: dict[str, Any], output: bytes) -> None:
    if set(record) != JOURNAL_FIELDS:
        raise PublicationError(f"lane {lane.identifier!r} journal record has an unexpected shape")
    journal.mkdir(parents=True, exist_ok=True)
    record_path, log_path = _journal_paths(journal, lane)
    for path in (record_path, log_path):
        if path.is_symlink():
            raise PublicationError(f"refusing to write through a symlink: {path}")
        path.unlink(missing_ok=True)
    write_new(log_path, output)
    write_new(record_path, canonical_json(record))


def read_journal_record(
    journal: Path,
    lane: Lane,
    commit: str,
    release_source_sha256: str,
    toolchain: str,
) -> dict[str, Any] | None:
    """Return the lane's recorded run, or None when it is absent or stale.

    A record is stale - and therefore unusable - when it was captured at another
    commit or source tree, against another toolchain, for a different command,
    or when its log no longer hashes to the recorded digest.
    """
    record_path, log_path = _journal_paths(journal, lane)
    if record_path.is_symlink() or not record_path.is_file():
        return None
    try:
        record = json.loads(read_regular(record_path).decode("utf-8"))
    except (PublicationError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError(f"lane {lane.identifier!r} journal record is unreadable: {error}")
    if not isinstance(record, dict) or set(record) != JOURNAL_FIELDS:
        raise PublicationError(f"lane {lane.identifier!r} journal record has an unexpected shape")
    if (
        record["id"] != lane.identifier
        or record["command"] != lane.command
        or record["cwd"] != lane.cwd
        or record["commit"] != commit
        or record["release_source_sha256"] != release_source_sha256
        or record["toolchain_sha256"] != toolchain
    ):
        return None
    if log_path.is_symlink() or not log_path.is_file():
        raise PublicationError(f"lane {lane.identifier!r} journal log is missing: {log_path}")
    digest = hashlib.sha256()
    with log_path.open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    if digest.hexdigest() != record["log_sha256"]:
        raise PublicationError(f"lane {lane.identifier!r} journal log digest changed on disk")
    # Re-derive the status from the recorded exit code so a hand-edited journal
    # cannot promote a failure.
    status, normalized = _normalized_exit(
        record["exit_code"], record["status"] == TIMEOUT and record["exit_code"] == TIMEOUT_EXIT_CODE
    )
    if (status, normalized) != (record["status"], record["exit_code"]):
        raise PublicationError(
            f"lane {lane.identifier!r} journal record status does not match its exit code"
        )
    return record


# --------------------------------------------------------------------------
# Canonical document assembly
# --------------------------------------------------------------------------


def assemble_document(
    records: dict[str, dict[str, Any]],
    commit: str,
    release_source_sha256: str,
    toolchain: str,
) -> tuple[dict[str, Any], list[str]]:
    """Assemble and validate the canonical unsigned-CI lane document.

    The assembled document is validated by the sealed manifest's own unsigned-CI
    validator, so anything this function returns is exactly what the gate accepts.
    """
    missing = sorted(set(REQUIRED_CI_LANES) - set(records))
    if missing:
        raise PublicationError(f"unsigned CI lane records are missing: {missing}")
    document = {
        "schema_version": LANE_SCHEMA_VERSION,
        "document": LANE_DOCUMENT_KIND,
        "release_source_sha256": require_sha256(
            release_source_sha256, "unsigned CI release source SHA-256"
        ),
        "toolchain_sha256": toolchain,
        "lanes": sorted(
            ({field: records[lane][field] for field in DOCUMENT_LANE_FIELDS} for lane in records),
            key=lambda entry: entry["id"],
        ),
    }
    validated, failures = _ci_lane_document(document, commit, release_source_sha256)
    return validated, failures


# --------------------------------------------------------------------------
# Collection driver
# --------------------------------------------------------------------------


Runner = Callable[[Path, Lane, dict[str, str]], tuple[bytes, int | None, bool, float]]


def collect_ci_lanes(
    repository: Path,
    *,
    commit: str,
    release_source_sha256: str,
    output: Path,
    journal: Path,
    only: frozenset[str] = frozenset(),
    rerun: frozenset[str] = frozenset(),
    assemble_only: bool = False,
    libbox_source: Path | None = None,
    libbox_output: Path | None = None,
    runner: Runner = execute_lane,
    report: Callable[[str], None] = print,
    toolchain: tuple[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Run the required unsigned-CI lanes and write the canonical document.

    Lanes already recorded in the journal against this commit, source tree, and
    toolchain are replayed instead of re-run; ``rerun`` forces a fresh run,
    ``only`` restricts which lanes may run at all. Nothing is fabricated: a lane
    that is neither recorded nor run stays missing and the document is refused.
    """
    self_check()
    release_source_sha256 = require_sha256(
        release_source_sha256, "unsigned CI release source SHA-256"
    )
    unknown = sorted((only | rerun) - set(LANE_INDEX))
    if unknown:
        raise PublicationError(f"unknown unsigned CI lane selection: {unknown}")
    pins = _pins(repository)
    if toolchain is None:
        digest, identity = derive_toolchain_binding(repository)
        execution_toolchain_root, execution_tree_digests = verified_release_toolchain_trees(
            repository, pins
        )
        if identity.get("release_tree_sha256") != execution_tree_digests:
            raise PublicationError(
                "CI lane execution toolchain differs from the canonical binding"
            )
    else:
        digest, identity = toolchain
        configured_root = Path(
            os.environ.get("CFW_TOOLCHAIN_ROOT", repository / TOOLCHAIN_ROOT_RELATIVE)
        )
        selected_root = (
            configured_root if configured_root.is_absolute() else repository / configured_root
        )
        try:
            if not selected_root.is_dir() or selected_root.is_symlink():
                raise PublicationError(
                    "CI lane execution toolchain root is missing, not a directory, or a symlink"
                )
            execution_toolchain_root = selected_root.resolve(strict=True)
        except OSError as error:
            raise PublicationError(
                f"cannot resolve the CI lane execution toolchain root: {error}"
            ) from error
    source = (
        repository / DEFAULT_LIBBOX_SOURCE_TEMPLATE.format(version=pins["SING_BOX_VERSION"])
        if libbox_source is None
        else libbox_source
    )
    artifact = repository / DEFAULT_LIBBOX_OUTPUT if libbox_output is None else libbox_output

    if output.exists() or output.is_symlink():
        raise PublicationError(f"refusing to replace an unsigned CI lane record: {output}")
    journal.mkdir(parents=True, exist_ok=True)
    binding_path = journal / "toolchain-binding.json"
    if binding_path.is_symlink():
        raise PublicationError(f"refusing to write through a symlink: {binding_path}")
    binding_path.unlink(missing_ok=True)
    write_new(binding_path, canonical_json(identity))

    report(
        "unsigned CI lanes: "
        f"commit={commit} release_source_sha256={release_source_sha256} "
        f"toolchain_sha256={digest}"
    )
    records: dict[str, dict[str, Any]] = {}
    for lane in LANES:
        existing = read_journal_record(
            journal, lane, commit, release_source_sha256, digest
        )
        if existing is not None and lane.identifier not in rerun:
            records[lane.identifier] = existing
            report(
                f"  {lane.identifier}: replayed {existing['status']} "
                f"(exit {existing['exit_code']}, {existing['duration_seconds']}s)"
            )
            continue
        if assemble_only or (only and lane.identifier not in only):
            report(f"  {lane.identifier}: not recorded")
            continue
        environment = lane_environment(
            repository,
            lane,
            pins,
            source,
            artifact,
            journal / "runner-temp" / lane.identifier,
            execution_toolchain_root,
        )
        report(f"  {lane.identifier}: running (bound to {lane.timeout}s) $ {lane.command}")
        started_at = int(time.time())
        output_bytes, exit_code, timed_out, duration = runner(repository, lane, environment)
        record = record_lane(
            lane,
            commit,
            release_source_sha256,
            digest,
            output_bytes,
            exit_code,
            timed_out,
            duration,
            started_at,
        )
        write_journal_record(journal, lane, record, output_bytes)
        records[lane.identifier] = record
        report(
            f"  {lane.identifier}: {record['status']} (exit {record['exit_code']}, "
            f"{record['duration_seconds']}s, log {record['log_sha256'][:12]})"
        )

    document, failures = assemble_document(
        records, commit, release_source_sha256, digest
    )
    write_new(output, canonical_json(document))
    report(f"unsigned CI lane record written: {output}")
    report(f"lanes={len(document['lanes'])} failed={failures}")
    return {
        "document": document,
        "failures": failures,
        "toolchain_sha256": digest,
        "release_source_sha256": release_source_sha256,
        "toolchain_identity": identity,
        "records": records,
        "output": str(output),
        "journal": str(journal),
    }
