"""Deterministic local unsigned-lane collection and toolchain binding.

This module records a local reproduction of the commands used by the
``unsigned_ci`` gate of the sealed outer Evidence Manifest
(``publication.sealed_manifest``).  It is not GitHub-hosted evidence and cannot
satisfy ``github_hosted_ci_receipt``. It adds no competing
framework: the lane identifiers come from
:data:`publication.sealed_manifest.REQUIRED_CI_LANES`, the lane *commands* are
transcribed from ``.github/workflows/ci.yml`` (the source of truth audited by
``scripts/verify_ci_no_masking.py``), except that ``unsigned-candidate`` is its
production-local release-evidence counterpart and deliberately uses the fixed
Cellar Python rather than the hosted runner's setup-python selection. The
toolchain identity is derived from the
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
  extracted by ``derive_supply_chain``, which first runs the fail-closed static
  pinned source-contract verifier, so a drifted or partial pin set can never
  produce a digest at all;
* ``apple_toolchain`` - the pinned Xcode marketing/build version and the pinned
  macOS deployment target; and
* ``resolved`` - the exact identity strings reported by the tools that actually
  execute the lanes (``rustc``, ``cargo``, ``cargo-deny``, ``cargo-tauri``,
  ``xcodebuild``, ``swift``, and the pinned ``node``/``npm``/``go``/``gomobile``/
  ``govulncheck``). Python binds its launcher, framework runtime, and complete
  standard-library tree; every Python lane disables ``site`` initialization.
  Each resolved identity is checked against its pin; a missing
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
import math
import os
import re
import selectors
import signal
import stat
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable

from .common import (
    PublicationError,
    canonical_json,
    open_regular,
    read_regular,
    require_sha256,
    sha256_bytes,
    sha256_file,
)
from .sealed_closure import derive_supply_chain
from .durable_file import (
    exclusive_directory_lock,
    fsync_directory,
    fsync_locked_directory,
    promote_private_pending,
    read_private_pending,
    write_private_pending,
)
from .sealed_manifest import REQUIRED_CI_LANES, _ci_lane_document, _require_command
from .release_toolchains import verified_release_toolchain_trees
from .release_environment import (
    APPLE_XCODEBUILD,
    SYSTEM_PATH,
    identity_output,
    release_tool_environment,
    swift_toolchain_identity,
)
if __package__ and __package__.startswith("scripts."):
    from scripts.release_rust_toolchain import (
        ReleaseRustToolchainError,
        verify_pinned_toolchain,
    )
else:
    from release_rust_toolchain import (
        ReleaseRustToolchainError,
        verify_pinned_toolchain,
    )


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
MAX_EXECUTABLE_BYTES = 512 * 1024 * 1024
MAX_CI_ATTEMPTS = 9999
LANE_PROCESS_UMASK = 0o022
ATTEMPT_NAME = re.compile(r"attempt-([0-9]{4})\Z")
ATTEMPT_INTENT_KIND = "unsigned-ci-lane-attempt-intent-v1"
ATTEMPT_RESULT_KIND = "unsigned-ci-lane-attempt-result-v1"

# The patched sing-box tree the libbox lanes consume. The CI workflow
# materializes it from the pinned upstream commit in a separate step; locally it
# is the tree produced by ``scripts/materialize_libbox_source.sh``, which the
# libbox scripts re-validate against the pinned patch/diff digests on every run.
DEFAULT_LIBBOX_SOURCE_TEMPLATE = "target/sources/sing-box-{version}-patched"
# The libbox build lane never overwrites the authoritative XCFramework that the
# unsigned-candidate lane binds by manifest digest; it writes its own output.
DEFAULT_LIBBOX_OUTPUT = "target/native-dependencies-ci-lane/Libbox.xcframework"
AUTHORITATIVE_LIBBOX_OUTPUT = "target/native-dependencies/Libbox.xcframework"


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


# The 27 required lanes, in dependency order: the UI install lane precedes the
# lanes that consume ``node_modules``, the libbox module lane precedes the scan
# and build lanes, the packet LAN peer lane independently proves its generated
# Linux/arm64 artifact, and the unsigned candidate lane runs last because it
# consumes the UI dependency tree and the native products.
LANES: tuple[Lane, ...] = (
    Lane(
        "build-script-boundary",
        "./scripts/run_release_ci_gate.sh build-script-boundary",
        timeout=1800,
    ),
    Lane(
        "ci-no-masking",
        "./scripts/run_release_ci_gate.sh ci-no-masking",
        timeout=600,
    ),
    Lane(
        "evidence-manifest-lane",
        "./scripts/run_release_ci_gate.sh evidence-manifest-lane",
        timeout=1800,
    ),
    Lane(
        "version-contract",
        "./scripts/run_release_ci_gate.sh version-contract",
        timeout=600,
    ),
    Lane("rust-fmt", "./scripts/run_release_ci_gate.sh rust-fmt", timeout=900),
    Lane(
        "rust-locked-metadata",
        "./scripts/run_release_ci_gate.sh rust-metadata",
        timeout=900,
    ),
    Lane(
        "rust-clippy",
        "./scripts/run_release_ci_gate.sh rust-clippy",
        timeout=5400,
    ),
    Lane("rust-test", "./scripts/run_release_ci_gate.sh rust-test", timeout=7200),
    Lane(
        "rust-target-audit",
        "./scripts/run_release_ci_gate.sh rust-target-audit",
        timeout=1800,
    ),
    Lane("cargo-deny", "./scripts/run_release_ci_gate.sh cargo-deny", timeout=1800),
    Lane(
        "packet-lan-peer",
        "./scripts/run_release_ci_gate.sh packet-lan-peer",
        timeout=1800,
    ),
    Lane(
        "node-install",
        "./scripts/run_release_ci_gate.sh prepare-ui-dependencies",
        timeout=1800,
    ),
    Lane("node-test", "./scripts/run_release_ci_gate.sh ui-test", timeout=1800),
    Lane("node-build", "./scripts/run_release_ci_gate.sh ui-build", timeout=1800),
    Lane(
        "node-audit",
        "./scripts/run_release_ci_gate.sh ui-audit",
        timeout=900,
    ),
    Lane(
        "swift-format-lint",
        "./scripts/run_release_ci_gate.sh swift-format-lint",
        timeout=1800,
    ),
    Lane(
        "swift-package-test",
        "./scripts/run_release_ci_gate.sh swift-package-test",
        timeout=5400,
    ),
    Lane(
        "xcode-project-verify",
        "./scripts/run_release_ci_gate.sh verify-xcode-project",
        timeout=1800,
    ),
    Lane(
        "xcode-unsigned-test",
        "./scripts/run_release_ci_gate.sh xcode-unsigned-test",
        timeout=5400,
    ),
    Lane(
        "xcode-analyze",
        "./scripts/run_release_ci_gate.sh xcode-analyze",
        timeout=7200,
    ),
    Lane(
        "libbox-module-verify",
        './scripts/run_release_ci_gate.sh libbox-source-tests "$SING_BOX_SOURCE"',
        timeout=7200,
        libbox_source=True,
        runner_temp=True,
    ),
    Lane(
        "libbox-govulncheck",
        './scripts/run_release_ci_gate.sh libbox-vulnerability-scan "$SING_BOX_SOURCE"',
        timeout=3600,
        libbox_source=True,
    ),
    Lane(
        "libbox-build",
        './scripts/run_release_ci_gate.sh build-libbox "$SING_BOX_SOURCE" "$LIBBOX_OUTPUT"',
        timeout=7200,
        libbox_source=True,
        libbox_output=True,
    ),
    Lane(
        "release-tooling-tests",
        "./scripts/run_release_ci_gate.sh release-tool-tests",
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
    from scripts.hash_artifact import build_manifest
    from scripts.repository_source_identity import (
        SourceIdentityError,
        current_identity,
    )
else:  # pragma: no cover - exercised via both invocation styles
    import verify_pinned_build_inputs as pinned
    from hash_artifact import build_manifest
    from repository_source_identity import SourceIdentityError, current_identity


class _DuplicateManifestFieldError(ValueError):
    pass


def _strict_manifest_object(
    pairs: list[tuple[str, Any]],
) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateManifestFieldError(f"duplicate manifest field: {key}")
        result[key] = value
    return result


def _libbox_manifest_metadata(
    pins: dict[str, str], toolchain_trees: dict[str, str]
) -> dict[str, str]:
    def pin(name: str) -> str:
        value = pins.get(name)
        if not isinstance(value, str) or not value:
            raise PublicationError(f"Libbox metadata pin is unavailable: {name}")
        return value

    return {
        "sourceTag": pin("SING_BOX_VERSION"),
        "sourceCommit": pin("SING_BOX_COMMIT"),
        "goVersion": pin("GO_VERSION"),
        "goToolchainTreeSha256": require_sha256(
            toolchain_trees.get("go"), "verified Go toolchain tree digest"
        ),
        "goToolsTreeSha256": require_sha256(
            toolchain_trees.get("go-release-tools"),
            "verified Go release-tools tree digest",
        ),
        "goModuleCacheTreeSha256": require_sha256(
            toolchain_trees.get("go-module-cache"),
            "verified Go module-cache tree digest",
        ),
        "gomobileVersion": pin("GOMOBILE_VERSION"),
        "gomobileCommit": pin("GOMOBILE_COMMIT"),
        "gomobileModuleSum": pin("GOMOBILE_MODULE_SUM"),
        "archiveDeterminism": "zeroArDate-v1",
        "headerNormalization": "angleBracketFrameworkImports-v1",
        "platform": pin("LIBBOX_APPLE_PLATFORM"),
        "buildTags": pin("LIBBOX_BUILD_TAGS"),
        "nonMacOsTags": pin("LIBBOX_NON_MACOS_TAGS"),
        "upstreamGoModSha256": pin("SING_BOX_UPSTREAM_GO_MOD_SHA256"),
        "upstreamGoSumSha256": pin("SING_BOX_UPSTREAM_GO_SUM_SHA256"),
        "securityPatchSha256": pin("SING_BOX_SECURITY_PATCH_SHA256"),
        "rawPacketPatchSha256": pin("SING_BOX_RAW_PACKET_PATCH_SHA256"),
        "dnsFailoverPatchSha256": pin("SING_BOX_DNS_FAILOVER_PATCH_SHA256"),
        "endpointConflictPatchSha256": pin(
            "SING_BOX_ENDPOINT_CONFLICT_PATCH_SHA256"
        ),
        "patchedDiffSha256": pin("SING_BOX_PATCHED_DIFF_SHA256"),
        "combinedDiffSha256": pin("SING_BOX_COMBINED_DIFF_SHA256"),
        "patchedGoModSha256": pin("SING_BOX_PATCHED_GO_MOD_SHA256"),
        "patchedGoSumSha256": pin("SING_BOX_PATCHED_GO_SUM_SHA256"),
    }


def _verified_libbox_manifest(
    artifact: Path,
    manifest: Path,
    expected_metadata: dict[str, str],
) -> tuple[bytes, dict[str, Any]]:
    encoded = read_regular(manifest)
    try:
        document = json.loads(
            encoded.decode("utf-8"), object_pairs_hook=_strict_manifest_object
        )
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        _DuplicateManifestFieldError,
    ) as error:
        raise PublicationError(f"Libbox artifact manifest is invalid: {manifest}") from error
    expected_fields = {"algorithm", "entries", "metadata", "root", "sha256"}
    if not isinstance(document, dict) or set(document) != expected_fields:
        raise PublicationError("Libbox artifact manifest has an unexpected shape")
    if (
        document.get("algorithm") != "sha256-tree-v1"
        or document.get("root") != "Libbox.xcframework"
        or document.get("metadata") != expected_metadata
    ):
        raise PublicationError("Libbox artifact manifest identity or metadata drifted")
    try:
        actual = build_manifest(artifact, algorithm="sha256-tree-v1")
    except (OSError, RuntimeError, ValueError) as error:
        raise PublicationError(f"cannot verify Libbox artifact tree: {artifact}") from error
    for field in ("algorithm", "entries", "root", "sha256"):
        if document.get(field) != actual.get(field):
            raise PublicationError(f"Libbox artifact manifest {field} drifted")
    if read_regular(manifest) != encoded:
        raise PublicationError("Libbox artifact manifest changed during verification")
    return encoded, document


def verify_libbox_reproduction(
    repository: Path,
    rebuilt_artifact: Path,
    pins: dict[str, str],
    toolchain_trees: dict[str, str],
) -> str:
    """Prove the fresh CI build is byte-identical to the consumed artifact."""

    repository = repository.resolve(strict=True)
    authoritative_input = repository / AUTHORITATIVE_LIBBOX_OUTPUT
    if not rebuilt_artifact.is_absolute():
        raise PublicationError("rebuilt Libbox artifact path must be absolute")
    try:
        authoritative = authoritative_input.resolve(strict=True)
        rebuilt = rebuilt_artifact.resolve(strict=True)
    except OSError as error:
        raise PublicationError("both Libbox reproduction artifacts are required") from error
    if authoritative != authoritative_input:
        raise PublicationError("authoritative Libbox artifact path is not canonical")
    if rebuilt != rebuilt_artifact or rebuilt == authoritative:
        raise PublicationError(
            "rebuilt Libbox artifact must be an independent canonical path"
        )
    expected_metadata = _libbox_manifest_metadata(pins, toolchain_trees)
    authoritative_manifest = authoritative.parent / (
        authoritative.name + ".manifest.json"
    )
    rebuilt_manifest = rebuilt.parent / (rebuilt.name + ".manifest.json")
    authoritative_bytes, authoritative_document = _verified_libbox_manifest(
        authoritative, authoritative_manifest, expected_metadata
    )
    rebuilt_bytes, rebuilt_document = _verified_libbox_manifest(
        rebuilt, rebuilt_manifest, expected_metadata
    )
    if (
        rebuilt_bytes != authoritative_bytes
        or rebuilt_document != authoritative_document
    ):
        raise PublicationError(
            "fresh Libbox build is not byte-identical to the consumed artifact"
        )
    return require_sha256(
        authoritative_document.get("sha256"),
        "reproduced Libbox tree digest",
    )


# Pins that the Apple/tool identity checks below are compared against.
APPLE_PIN_KEYS = ("XCODE_VERSION", "XCODE_BUILD_VERSION", "MACOS_DEPLOYMENT_TARGET")
PYTHON_STDLIB_MANIFEST_ALGORITHM = "sha256-tree-v1"


def _pins(repository: Path) -> dict[str, str]:
    try:
        return pinned._parse_env(
            pinned._read_text(repository, PINS_RELATIVE, "dependency_pins.env")
        )
    except pinned.PinnedInputError as error:
        raise PublicationError(f"cannot read the pinned toolchain set: {error}") from error


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


def _bound_executable_identity(
    executable: Path,
    arguments: list[str],
    repository: Path,
    label: str,
    environment: dict[str, str],
    maximum: int = 4096,
) -> tuple[str, str]:
    try:
        resolved = executable.resolve(strict=True)
        metadata = resolved.stat()
    except OSError as error:
        raise PublicationError(f"cannot resolve the {label} executable: {error}") from error
    if (
        not resolved.is_file()
        or not os.access(resolved, os.X_OK)
        or metadata.st_size <= 0
    ):
        raise PublicationError(f"the {label} executable is unavailable or unsafe")
    identity = identity_output(
        [str(resolved), *arguments],
        repository,
        label,
        environment,
        maximum=maximum,
    )
    binding = f"path={resolved}; sha256={_executable_sha256(resolved)}; identity={identity}"
    return identity, binding


def _executable_sha256(path: Path) -> str:
    try:
        before = path.lstat()
    except OSError as error:
        raise PublicationError(f"cannot inspect executable {path}: {error}") from error
    if (
        not stat.S_ISREG(before.st_mode)
        or before.st_size <= 0
        or before.st_size > MAX_EXECUTABLE_BYTES
    ):
        raise PublicationError(f"executable size or type is unsafe: {path}")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise PublicationError(f"cannot open executable {path}: {error}") from error
    digest = hashlib.sha256()
    try:
        opened = os.fstat(descriptor)
        if (before.st_dev, before.st_ino, before.st_size) != (
            opened.st_dev,
            opened.st_ino,
            opened.st_size,
        ):
            raise PublicationError(f"executable changed while opening: {path}")
        remaining = opened.st_size
        while remaining:
            chunk = os.read(descriptor, min(1024 * 1024, remaining))
            if not chunk:
                raise PublicationError(f"executable ended before its observed size: {path}")
            digest.update(chunk)
            remaining -= len(chunk)
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    if (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns) != (
        after.st_dev,
        after.st_ino,
        after.st_size,
        after.st_mtime_ns,
    ):
        raise PublicationError(f"executable changed while hashing: {path}")
    return digest.hexdigest()


def _python_stdlib_binding(stdlib: Path) -> str:
    try:
        resolved = stdlib.resolve(strict=True)
        if resolved != stdlib or not stdlib.is_dir() or stdlib.is_symlink():
            raise ValueError("standard-library root is not canonical")
        manifest = build_manifest(
            stdlib,
            algorithm=PYTHON_STDLIB_MANIFEST_ALGORITHM,
        )
        digest = manifest.get("sha256")
        if not isinstance(digest, str):
            raise ValueError("standard-library manifest omitted its digest")
        require_sha256(digest, "Python standard-library tree SHA-256")
    except (OSError, RuntimeError, ValueError) as error:
        raise PublicationError(
            f"cannot bind the Python standard-library tree: {error}"
        ) from error
    return (
        f"stdlib_path={stdlib}; "
        f"stdlib_algorithm={PYTHON_STDLIB_MANIFEST_ALGORITHM}; "
        f"stdlib_sha256={digest}"
    )


def _go_module_identity(
    repository: Path, go_bin: Path, binary: Path, module: str, version: str, module_sum: str, env: dict[str, str]
) -> str:
    """Bind one pinned Go tool by module path, version, and module checksum."""
    if not binary.is_file() or binary.is_symlink() or not os.access(binary, os.X_OK):
        raise PublicationError(f"pinned Go tool is missing or not executable: {binary}")
    identity = identity_output(
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
    release_environment: dict[str, str] | None = None,
) -> dict[str, str]:
    """Resolve the identity of every tool that actually executes a lane."""
    base = (
        release_tool_environment(repository, pins)
        if release_environment is None
        else dict(release_environment)
    )
    if toolchain_root is None:
        toolchain_root, _tree_digests = verified_release_toolchain_trees(
            repository, pins, environment=base
        )
    node_bin_dir = toolchain_root / f"node-{pins['NODE_VERSION']}" / "bin"
    go_bin = toolchain_root / f"go-{pins['GO_VERSION']}" / "bin" / "go"
    go_workspace_bin = toolchain_root / "go-workspace" / "bin"
    xcodegen_bin = toolchain_root / f"xcodegen-{pins['XCODEGEN_VERSION']}" / "bin/xcodegen"
    tauri_bin = toolchain_root / f"tauri-cli-{pins['TAURI_CLI_VERSION']}" / "bin/cargo-tauri"

    try:
        rustc_bin = Path(base["CFW_RELEASE_RUSTC_EXECUTABLE"])
        cargo_bin = Path(base["CFW_RELEASE_CARGO_EXECUTABLE"])
        cargo_audit_bin = Path(base["CFW_RELEASE_CARGO_AUDIT_EXECUTABLE"])
        cargo_deny_bin = Path(base["CFW_RELEASE_CARGO_DENY_EXECUTABLE"])
        python_bin = Path(base["CFW_RELEASE_PYTHON_EXECUTABLE"])
        python_runtime = Path(base["CFW_RELEASE_PYTHON_RUNTIME"])
        python_stdlib = Path(base["CFW_RELEASE_PYTHON_STDLIB"])
    except KeyError as error:
        raise PublicationError("release environment omitted an executable identity") from error
    node_env = dict(base)
    node_env["PATH"] = f"{node_bin_dir}:{base['PATH']}"

    resolved: dict[str, str] = {}
    try:
        rust_toolchain = verify_pinned_toolchain(
            repository, rustc_bin.parent.parent.resolve(strict=True)
        )
    except (OSError, ReleaseRustToolchainError) as error:
        raise PublicationError("Rust release toolchain surface is invalid") from error
    surface = rust_toolchain.surface
    resolved["rust-toolchain-surface"] = (
        f"root={rust_toolchain.root}; algorithm={surface['algorithm']}; "
        f"components={','.join(surface['components'])}; "
        f"file_count={surface['file_count']}; sha256={surface['sha256']}; "
        f"total_size={surface['total_size']}"
    )
    rustc_identity, resolved["rustc"] = _bound_executable_identity(
        rustc_bin, ["--version"], repository, "rustc", base
    )
    _expect_field(rustc_identity, 1, pins["RUST_VERSION"], "rustc")
    cargo_identity, resolved["cargo"] = _bound_executable_identity(
        cargo_bin, ["--version"], repository, "cargo", base
    )
    _expect_field(cargo_identity, 1, pins["RUST_VERSION"], "cargo")
    cargo_audit_identity, resolved["cargo-audit"] = _bound_executable_identity(
        cargo_audit_bin,
        ["--version"],
        repository,
        "cargo-audit",
        base,
    )
    _expect_field(
        cargo_audit_identity, 1, pins["CARGO_AUDIT_VERSION"], "cargo-audit"
    )
    cargo_deny_identity, resolved["cargo-deny"] = _bound_executable_identity(
        cargo_deny_bin,
        ["--version"],
        repository,
        "cargo-deny",
        base,
    )
    _expect_field(cargo_deny_identity, 1, pins["CARGO_DENY_VERSION"], "cargo-deny")
    python_identity, python_binding = _bound_executable_identity(
        python_bin, ["--version"], repository, "Python", base
    )
    _expect(python_identity, f"Python {pins['PYTHON_VERSION']}", "Python")
    if (
        not python_runtime.is_file()
        or python_runtime.is_symlink()
        or python_runtime.stat().st_nlink != 1
    ):
        raise PublicationError(
            "the pinned Python framework runtime is unavailable or unsafe"
        )
    resolved["python3"] = (
        f"{python_binding}; runtime_path={python_runtime}; "
        f"runtime_sha256={sha256_file(python_runtime)}; "
        f"{_python_stdlib_binding(python_stdlib)}"
    )
    for name, executable, arguments in (
        ("git", Path("/usr/bin/git"), ["--version"]),
        ("bash", Path("/bin/bash"), ["--version"]),
        ("zsh", Path("/bin/zsh"), ["--version"]),
    ):
        _identity, resolved[name] = _bound_executable_identity(
            executable,
            arguments,
            repository,
            name,
            base,
            maximum=16 * 1024,
        )
    resolved["cargo-tauri"] = _expect_field(
        identity_output([str(tauri_bin), "--version"], repository, "tauri-cli", base),
        1,
        pins["TAURI_CLI_VERSION"],
        "tauri-cli",
    )
    resolved["xcodegen"] = _expect(
        identity_output([str(xcodegen_bin), "--version"], repository, "XcodeGen", base),
        f"Version: {pins['XCODEGEN_VERSION']}",
        "XcodeGen",
    )
    resolved["xcodebuild"] = _expect(
        identity_output([APPLE_XCODEBUILD, "-version"], repository, "Xcode", base),
        f"Xcode {pins['XCODE_VERSION']}; Build version {pins['XCODE_BUILD_VERSION']}",
        "Xcode",
    )
    # Swift ships inside the pinned Xcode. Its structured target identity is
    # projected without the machine-local Xcode installation prefix.
    resolved["swift"] = swift_toolchain_identity(
        repository,
        base,
        pins["MACOS_DEPLOYMENT_TARGET"],
    ).canonical
    resolved["node"] = _expect(
        identity_output([str(node_bin_dir / "node"), "--version"], repository, "Node.js", node_env),
        f"v{pins['NODE_VERSION']}",
        "Node.js",
    )
    resolved["npm"] = identity_output(
        [str(node_bin_dir / "npm"), "--version"], repository, "npm", node_env
    )
    resolved["go"] = _expect(
        identity_output([str(go_bin), "version"], repository, "Go", base),
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


def derive_toolchain_identity(
    repository: Path,
    release_environment: dict[str, str] | None = None,
) -> dict[str, Any]:
    """Derive the canonical toolchain identity the CI lanes are bound to.

    Fail closed: ``derive_supply_chain`` first runs the static pinned
    source-contract verifier, and every resolved tool identity must match its
    pin. No digest exists for an unverified or drifted toolchain.
    """
    supply = derive_supply_chain(repository)
    pins = _pins(repository)
    for key in APPLE_PIN_KEYS:
        if key not in pins:
            raise PublicationError(f"dependency_pins.env is missing required pin {key}")
    environment = (
        release_tool_environment(repository, pins)
        if release_environment is None
        else dict(release_environment)
    )
    toolchain_root, tree_digests = verified_release_toolchain_trees(
        repository, pins, environment=environment
    )
    resolved = _resolved_toolchain(
        repository, pins, toolchain_root, release_environment=environment
    )
    _verified_root_after, tree_digests_after = verified_release_toolchain_trees(
        repository, pins, environment=environment
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


def derive_toolchain_binding(
    repository: Path,
    release_environment: dict[str, str] | None = None,
) -> tuple[str, dict[str, Any]]:
    identity = derive_toolchain_identity(repository, release_environment)
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
    if len(output) > MAX_LOG_BYTES:
        raise PublicationError(
            f"lane {lane.identifier!r} output exceeded {MAX_LOG_BYTES} bytes"
        )
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
    release_environment: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build the lane's environment: the pinned toolchain and nothing masking."""
    environment = (
        release_tool_environment(repository, pins)
        if release_environment is None
        else dict(release_environment)
    )
    environment["MACOSX_DEPLOYMENT_TARGET"] = pins["MACOS_DEPLOYMENT_TARGET"]
    environment["CFW_TOOLCHAIN_ROOT"] = str(toolchain_root)
    for key in ("SING_BOX_SOURCE", "LIBBOX_OUTPUT", "RUNNER_TEMP"):
        environment.pop(key, None)
    if lane.pinned_node:
        node_bin = toolchain_root / f"node-{pins['NODE_VERSION']}" / "bin"
        environment["PATH"] = f"{node_bin}:{environment['PATH']}"
    if lane.libbox_source:
        environment["SING_BOX_SOURCE"] = str(libbox_source)
    if lane.libbox_output:
        environment["LIBBOX_OUTPUT"] = str(libbox_output)
    if lane.runner_temp:
        runner_temp.mkdir(parents=True, exist_ok=True)
        environment["RUNNER_TEMP"] = str(runner_temp)
    return environment


def _lane_process_group_exists(group: int) -> bool:
    try:
        os.killpg(group, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _terminate_lane_process_group(
    process: subprocess.Popen[bytes], lane_identifier: str
) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        if process.poll() is None:
            process.kill()
    try:
        process.wait(timeout=5)
    except subprocess.TimeoutExpired as error:
        raise PublicationError(
            f"lane {lane_identifier!r} leader did not terminate after SIGKILL"
        ) from error
    cleanup_deadline = time.monotonic() + 5
    while _lane_process_group_exists(process.pid):
        if time.monotonic() >= cleanup_deadline:
            raise PublicationError(
                f"lane {lane_identifier!r} descendants did not terminate after SIGKILL"
            )
        time.sleep(0.01)


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
        ["/bin/bash", "-p", "-euo", "pipefail", "-c", lane.command],
        cwd=str(working_directory),
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        start_new_session=True,
        umask=LANE_PROCESS_UMASK,
    )
    if process.stdout is None:
        process.kill()
        raise PublicationError(f"lane {lane.identifier!r} has no output pipe")

    descriptor = -1
    selector: selectors.BaseSelector | None = None
    output = bytearray()
    termination_reason: str | None = None
    termination_deadline: float | None = None

    def terminate(reason: str) -> None:
        nonlocal termination_reason, termination_deadline
        if termination_reason is not None:
            return
        termination_reason = reason
        termination_deadline = time.monotonic() + 120
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            if process.poll() is None:
                process.kill()

    try:
        descriptor = process.stdout.fileno()
        os.set_blocking(descriptor, False)
        selector = selectors.DefaultSelector()
        selector.register(descriptor, selectors.EVENT_READ)
        while selector.get_map() or process.poll() is None:
            now = time.monotonic()
            if termination_reason is None and now - started >= lane.timeout:
                terminate("timeout")
            if termination_deadline is not None and now >= termination_deadline:
                raise PublicationError(
                    f"lane {lane.identifier!r} did not terminate after SIGKILL"
                )
            active_deadline = (
                termination_deadline
                if termination_deadline is not None
                else started + lane.timeout
            )
            wait_seconds = max(0.0, min(0.25, active_deadline - now))
            try:
                events = selector.select(wait_seconds)
            except InterruptedError:
                continue
            for _key, _mask in events:
                while True:
                    try:
                        chunk = os.read(descriptor, min(1024 * 1024, MAX_LOG_BYTES + 1))
                    except BlockingIOError:
                        break
                    if not chunk:
                        selector.unregister(descriptor)
                        break
                    if termination_reason is not None:
                        continue
                    remaining = MAX_LOG_BYTES - len(output)
                    if len(chunk) > remaining:
                        output.extend(chunk[:remaining])
                        terminate("output-limit")
                    else:
                        output.extend(chunk)
            if process.poll() is not None and not selector.get_map():
                break
        if process.poll() is None:
            process.wait(timeout=1)
    except BaseException:
        _terminate_lane_process_group(process, lane.identifier)
        raise
    finally:
        try:
            if selector is not None:
                selector.close()
        finally:
            process.stdout.close()

    group_remained = _lane_process_group_exists(process.pid)
    descendant_remained = termination_reason is None and group_remained
    if group_remained:
        _terminate_lane_process_group(process, lane.identifier)
    if descendant_remained:
        raise PublicationError(
            f"lane {lane.identifier!r} left a descendant process running"
        )
    if termination_reason == "output-limit":
        raise PublicationError(
            f"lane {lane.identifier!r} output exceeded {MAX_LOG_BYTES} bytes"
        )
    timed_out = termination_reason == "timeout"
    exit_code: int | None = None if timed_out else process.returncode
    return bytes(output), exit_code, timed_out, time.monotonic() - started


# --------------------------------------------------------------------------
# Journal (immutable attempts, with explicit references to prior lane runs)
# --------------------------------------------------------------------------


def _journal_paths(journal: Path, lane: Lane) -> tuple[Path, Path]:
    return journal / f"{lane.identifier}.json", journal / f"{lane.identifier}.log"


def write_journal_record(journal: Path, lane: Lane, record: dict[str, Any], output: bytes) -> None:
    if set(record) != JOURNAL_FIELDS:
        raise PublicationError(f"lane {lane.identifier!r} journal record has an unexpected shape")
    record_path, log_path = _journal_paths(journal, lane)
    for path in (record_path, log_path):
        if os.path.lexists(path):
            raise PublicationError(f"refusing to replace a CI lane journal file: {path}")
    _write_attempt_file(log_path, output)
    _write_attempt_file(record_path, canonical_json(record))


def _write_attempt_file(path: Path, payload: bytes) -> None:
    pending = path.with_name(f".{path.name}.pending")
    if os.path.lexists(path) or os.path.lexists(pending):
        raise PublicationError(f"CI lane evidence destination is already occupied: {path}")
    write_private_pending(pending, payload)
    promote_private_pending(pending, path)


def _read_journal_output(
    journal: Path, lane: Lane, record: dict[str, Any]
) -> bytes:
    _record_path, log_path = _journal_paths(journal, lane)
    if (
        record.get("log_name") != log_path.name
        or type(record.get("log_bytes")) is not int
        or not 0 <= record["log_bytes"] <= MAX_LOG_BYTES
    ):
        raise PublicationError(
            f"lane {lane.identifier!r} journal log metadata is invalid"
        )
    stream, opened = open_regular(log_path)
    with stream:
        output = stream.read(MAX_LOG_BYTES + 1)
        after = os.fstat(stream.fileno())
    if (
        len(output) > MAX_LOG_BYTES
        or len(output) != record["log_bytes"]
        or opened.st_size != record["log_bytes"]
        or (opened.st_dev, opened.st_ino, opened.st_size, opened.st_mtime_ns)
        != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
    ):
        raise PublicationError(
            f"lane {lane.identifier!r} journal log digest changed on disk"
        )
    if hashlib.sha256(output).hexdigest() != record["log_sha256"]:
        raise PublicationError(
            f"lane {lane.identifier!r} journal log digest changed on disk"
        )
    return output


def _publish_toolchain_binding(journal: Path, identity: dict[str, Any]) -> None:
    binding_path = journal / "toolchain-binding.json"
    payload = canonical_json(identity)
    if binding_path.is_symlink():
        raise PublicationError(f"refusing to write through a symlink: {binding_path}")
    if binding_path.exists():
        if read_regular(binding_path) == payload:
            return
        raise PublicationError("CI lane toolchain binding differs from its immutable record")
    _write_attempt_file(binding_path, payload)


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
    if not os.path.lexists(record_path):
        if os.path.lexists(log_path):
            raise PublicationError(f"lane {lane.identifier!r} has an incomplete journal record")
        return None
    try:
        payload = read_regular(record_path)
        record = json.loads(payload.decode("utf-8"))
    except (PublicationError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError(f"lane {lane.identifier!r} journal record is unreadable: {error}")
    if not isinstance(record, dict) or set(record) != JOURNAL_FIELDS:
        raise PublicationError(f"lane {lane.identifier!r} journal record has an unexpected shape")
    if (
        canonical_json(record) != payload
        or type(record["schema_version"]) is not int
        or record["schema_version"] != SCHEMA_VERSION
        or record["document"] != DOCUMENT_KIND
        or type(record["exit_code"]) is not int
        or not 0 <= record["exit_code"] <= 255
        or type(record["started_at"]) is not int
        or record["started_at"] < 0
        or type(record["duration_seconds"]) not in {int, float}
        or not math.isfinite(record["duration_seconds"])
        or record["duration_seconds"] < 0
        or type(record["timeout_seconds"]) is not int
        or record["timeout_seconds"] != lane.timeout
        or type(record["commit"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", record["commit"]) is None
    ):
        raise PublicationError(f"lane {lane.identifier!r} journal record is malformed")
    require_sha256(record["release_source_sha256"], "lane release source")
    require_sha256(record["toolchain_sha256"], "lane toolchain")
    _read_journal_output(journal, lane, record)
    status, normalized = _normalized_exit(
        record["exit_code"], record["status"] == TIMEOUT and record["exit_code"] == TIMEOUT_EXIT_CODE
    )
    if (status, normalized) != (record["status"], record["exit_code"]):
        raise PublicationError(
            f"lane {lane.identifier!r} journal record status does not match its exit code"
        )
    if (
        record["id"] != lane.identifier
        or record["command"] != lane.command
        or record["cwd"] != lane.cwd
        or record["commit"] != commit
        or record["release_source_sha256"] != release_source_sha256
        or record["toolchain_sha256"] != toolchain
    ):
        return None
    return record


@dataclass(frozen=True)
class _LaneSelection:
    attempt_number: int
    directory: Path
    record: dict[str, Any]
    record_sha256: str

    def reference(self) -> dict[str, Any]:
        return {
            "attempt_number": self.attempt_number,
            "record_sha256": self.record_sha256,
        }


@dataclass(frozen=True)
class _CiHistory:
    count: int
    selected: dict[str, _LaneSelection]
    snapshot: dict[str, str]


def _read_ci_json(path: Path) -> dict[str, Any]:
    payload = read_regular(path)
    try:
        value = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError(f"CI lane journal JSON is unreadable: {path}") from error
    if type(value) is not dict or canonical_json(value) != payload:
        raise PublicationError(f"CI lane journal JSON is not canonical: {path}")
    return value


def _require_ci_directory(path: Path) -> None:
    metadata = path.lstat()
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
    ):
        raise PublicationError(f"CI lane journal is not an owned real directory: {path}")


def canonical_ci_evidence_path(path: Path, label: str) -> Path:
    """Admit an explicit evidence location without following ancestor symlinks."""
    if "\x00" in os.fspath(path) or ".." in path.parts:
        raise PublicationError(f"{label} must use a canonical path without symlink ancestors")
    absolute = Path(os.path.abspath(path))
    try:
        resolved = absolute.resolve(strict=False)
    except (OSError, RuntimeError) as error:
        raise PublicationError(f"{label} ancestry cannot be resolved") from error
    if resolved != absolute:
        raise PublicationError(f"{label} must use a canonical path without symlink ancestors")
    return absolute


def _stored_lane(directory: Path, lane: Lane, number: int) -> _LaneSelection:
    path, _log = _journal_paths(directory, lane)
    value = _read_ci_json(path)
    if set(value) != JOURNAL_FIELDS:
        raise PublicationError(f"lane {lane.identifier!r} journal record has an unexpected shape")
    command = _require_command(value["command"], "historical CI lane command")
    cwd = value["cwd"]
    if (
        type(cwd) is not str or not cwd or len(cwd) > 1024
        or Path(cwd).is_absolute() or ".." in Path(cwd).parts
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in cwd)
        or type(value["timeout_seconds"]) is not int
        or not 0 < value["timeout_seconds"] <= 24 * 60 * 60
    ):
        raise PublicationError("historical CI lane execution bounds are malformed")
    # This passive shape is used only to validate retained evidence. Execution
    # always receives the current source-owned Lane, never a journal command.
    recorded_lane = Lane(lane.identifier, command, cwd=cwd, timeout=value["timeout_seconds"])
    record = read_journal_record(
        directory, recorded_lane, value["commit"], value["release_source_sha256"], value["toolchain_sha256"]
    )
    if record is None:
        raise PublicationError(f"lane {lane.identifier!r} journal command differs from its contract")
    return _LaneSelection(number, directory, record, sha256_bytes(canonical_json(record)))


def _matches_selection(
    selection: _LaneSelection, commit: str, source: str, toolchain: str
) -> bool:
    lane = LANE_INDEX[selection.record["id"]]
    return (
        _matches_source_binding(selection, commit, source, toolchain)
        and selection.record["command"] == lane.command
        and selection.record["cwd"] == lane.cwd
        and selection.record["timeout_seconds"] == lane.timeout
    )


def _matches_source_binding(
    selection: _LaneSelection, commit: str, source: str, toolchain: str
) -> bool:
    record = selection.record
    return (
        record["commit"] == commit
        and record["release_source_sha256"] == source
        and record["toolchain_sha256"] == toolchain
    )


def _resolve_selections(
    value: object,
    available: dict[tuple[int, str], _LaneSelection],
    *,
    before: int,
) -> dict[str, _LaneSelection]:
    if type(value) is not dict or not set(value) <= set(LANE_INDEX):
        raise PublicationError("CI lane attempt selection has an unexpected lane set")
    selected: dict[str, _LaneSelection] = {}
    for identifier, reference in value.items():
        if (
            type(reference) is not dict
            or set(reference) != {"attempt_number", "record_sha256"}
            or type(reference["attempt_number"]) is not int
            or not 0 <= reference["attempt_number"] < before
        ):
            raise PublicationError("CI lane attempt selection is malformed or points forward")
        selection = available.get((reference["attempt_number"], identifier))
        if selection is None or reference["record_sha256"] != selection.record_sha256:
            raise PublicationError("CI lane attempt selection does not match an immutable record")
        selected[identifier] = selection
    return selected


def _read_ci_history(
    journal: Path,
    commit: str,
    source: str,
    toolchain: str,
    *,
    active_attempt: Path | None = None,
) -> _CiHistory:
    """Read legacy records and every closed attempt without modifying either."""
    _require_ci_directory(journal)
    legacy_names = {"toolchain-binding.json"} | {
        f"{lane.identifier}.{extension}" for lane in LANES for extension in ("json", "log")
    }
    entries = {entry.name: entry for entry in journal.iterdir()}
    attempts: dict[int, Path] = {}
    for name, path in entries.items():
        if path == active_attempt:
            continue
        match = ATTEMPT_NAME.fullmatch(name)
        if match is not None:
            number = int(match[1])
            if not 1 <= number <= MAX_CI_ATTEMPTS:
                raise PublicationError("CI lane attempt number is outside its fixed bound")
            _require_ci_directory(path)
            attempts[number] = path
        elif name not in legacy_names:
            raise PublicationError(f"CI lane journal contains an unknown entry: {name}")
    if sorted(attempts) != list(range(1, len(attempts) + 1)):
        raise PublicationError("CI lane journal attempt numbering has a gap")
    if active_attempt is not None and active_attempt.name != f"attempt-{len(attempts) + 1:04d}":
        raise PublicationError("CI lane journal active attempt changed")

    snapshot: dict[str, str] = {}
    available: dict[tuple[int, str], _LaneSelection] = {}
    selected: dict[str, _LaneSelection] = {}

    def remember(selection: _LaneSelection) -> None:
        identifier = selection.record["id"]
        available[(selection.attempt_number, identifier)] = selection
        relative = selection.directory.relative_to(journal)
        snapshot[(relative / f"{identifier}.json").as_posix()] = selection.record_sha256
        snapshot[(relative / f"{identifier}.log").as_posix()] = selection.record["log_sha256"]

    legacy_binding = entries.get("toolchain-binding.json")
    if legacy_binding is not None:
        legacy_identity = _read_ci_json(legacy_binding)
        if legacy_identity.get("document") != TOOLCHAIN_BINDING_KIND:
            raise PublicationError("legacy CI toolchain binding has an unexpected document kind")
        snapshot[legacy_binding.name] = sha256_bytes(canonical_json(legacy_identity))
    for lane in LANES:
        record_path, log_path = _journal_paths(journal, lane)
        exists = (os.path.lexists(record_path), os.path.lexists(log_path))
        if exists == (False, False):
            continue
        if exists != (True, True) or legacy_binding is None:
            raise PublicationError(f"legacy CI lane {lane.identifier!r} has incomplete evidence")
        selection = _stored_lane(journal, lane, 0)
        if selection.record["toolchain_sha256"] != snapshot["toolchain-binding.json"]:
            raise PublicationError("legacy CI lane toolchain differs from its binding document")
        remember(selection)
        if _matches_selection(selection, commit, source, toolchain):
            selected[lane.identifier] = selection

    for number, directory in sorted(attempts.items()):
        names = {path.name for path in directory.iterdir()}
        if not {"intent.json", "result.json", "toolchain-binding.json"} <= names:
            raise PublicationError(f"CI lane attempt {number:04d} is incomplete; preserve it for review")
        intent = _read_ci_json(directory / "intent.json")
        result = _read_ci_json(directory / "result.json")
        expected_intent = {
            "document", "schema_version", "attempt_number", "repository_commit",
            "release_source_sha256", "toolchain_sha256", "toolchain_binding_sha256",
            "executor_source", "only", "rerun", "assemble_only", "selected",
            "lane_process_umask",
        }
        if (
            set(intent) != expected_intent
            or intent["document"] != ATTEMPT_INTENT_KIND
            or type(intent["schema_version"]) is not int or intent["schema_version"] != 1
            or type(intent["attempt_number"]) is not int or intent["attempt_number"] != number
            or type(intent["repository_commit"]) is not str
            or re.fullmatch(r"[0-9a-f]{40}", intent["repository_commit"]) is None
            or type(intent["assemble_only"]) is not bool
            or type(intent["lane_process_umask"]) is not int
            or intent["lane_process_umask"] != LANE_PROCESS_UMASK
        ):
            raise PublicationError("CI lane attempt intent has an unexpected shape")
        for key in ("release_source_sha256", "toolchain_sha256", "toolchain_binding_sha256"):
            require_sha256(intent[key], f"CI lane attempt {key}")
        for key in ("only", "rerun"):
            value = intent[key]
            if type(value) is not list or any(type(item) is not str for item in value):
                raise PublicationError("CI lane attempt request is malformed")
            if value != sorted(set(value)) or not set(value) <= set(LANE_INDEX):
                raise PublicationError("CI lane attempt request contains unknown or repeated lanes")
        _validate_executor_identity(intent["executor_source"])
        binding = canonical_json(_read_ci_json(directory / "toolchain-binding.json"))
        if (
            sha256_bytes(binding) != intent["toolchain_binding_sha256"]
            or intent["toolchain_binding_sha256"] != intent["toolchain_sha256"]
        ):
            raise PublicationError("CI lane attempt toolchain binding changed")
        inherited = _resolve_selections(intent["selected"], available, before=number)
        if set(inherited) & set(intent["rerun"]):
            raise PublicationError("CI lane attempt replays a lane it requested to rerun")
        if any(
            not _matches_source_binding(item, intent["repository_commit"], intent["release_source_sha256"], intent["toolchain_sha256"])
            for item in inherited.values()
        ):
            raise PublicationError("CI lane attempt selected a different source or toolchain")
        expected_result = {
            "document", "schema_version", "attempt_number", "outcome", "phase",
            "records", "selected", "document_sha256", "reproduction_sha256",
            "observed_reproduction_sha256s",
        }
        if (
            set(result) != expected_result
            or result["document"] != ATTEMPT_RESULT_KIND
            or type(result["schema_version"]) is not int or result["schema_version"] != 1
            or type(result["attempt_number"]) is not int or result["attempt_number"] != number
            or type(result["outcome"]) is not str
            or result["outcome"] not in {"completed", "partial", "verification-failed"}
            or type(result["phase"]) is not str
            or result["phase"] not in CI_COLLECTION_PHASES
            or type(result["records"]) is not dict
            or not set(result["records"]) <= set(LANE_INDEX)
        ):
            raise PublicationError("CI lane attempt result has an unexpected shape")
        observations = result["observed_reproduction_sha256s"]
        if type(observations) is not list or len(observations) > 2:
            raise PublicationError("CI lane reproduction observations exceed their fixed bound")
        for observed in observations:
            require_sha256(observed, "CI lane observed reproduction")
        expected_names = {"intent.json", "result.json", "toolchain-binding.json"}
        own: dict[str, _LaneSelection] = {}
        for identifier, digest in result["records"].items():
            if (
                identifier in inherited or intent["assemble_only"]
                or (intent["only"] and identifier not in intent["only"])
            ):
                raise PublicationError("CI lane attempt ran an unrequested lane")
            selection = _stored_lane(directory, LANE_INDEX[identifier], number)
            if digest != selection.record_sha256 or not _matches_source_binding(
                selection, intent["repository_commit"], intent["release_source_sha256"], intent["toolchain_sha256"]
            ):
                raise PublicationError("CI lane attempt record differs from its bound result")
            remember(selection)
            own[identifier] = selection
            expected_names.update({f"{identifier}.json", f"{identifier}.log"})
        resolved = _resolve_selections(result["selected"], available, before=number + 1)
        if resolved != {**inherited, **own}:
            raise PublicationError("CI lane attempt result changed its explicit selection")
        if "runner-temp" in names:
            _require_ci_directory(directory / "runner-temp")
            expected_names.add("runner-temp")
        records = {identifier: item.record for identifier, item in resolved.items()}
        if result["outcome"] == "completed":
            if result["phase"] != "complete":
                raise PublicationError("completed CI lane attempt has an unfinished phase")
            document, failures = assemble_document(
                records, intent["repository_commit"], intent["release_source_sha256"], intent["toolchain_sha256"]
            )
            document_raw = canonical_json(_read_ci_json(directory / "document.json"))
            if document_raw != canonical_json(document) or sha256_bytes(document_raw) != result["document_sha256"]:
                raise PublicationError("CI lane attempt document differs from its validated records")
            if failures:
                if result["reproduction_sha256"] is not None or observations:
                    raise PublicationError("failed CI lanes claim a Libbox reproduction")
            else:
                require_sha256(result["reproduction_sha256"], "CI lane reproduction")
                if observations != [result["reproduction_sha256"]] * 2:
                    raise PublicationError("CI lane reproduction lacks two identical observations")
            expected_names.add("document.json")
        elif result["document_sha256"] is not None or result["reproduction_sha256"] is not None:
            raise PublicationError("unverified CI lane attempt claims a completed document")
        if result["outcome"] == "partial" and (
            result["phase"] != "assembly" or set(records) == set(REQUIRED_CI_LANES)
        ):
            raise PublicationError("partial CI lane attempt has no explicit missing-lane boundary")
        if names != expected_names:
            if names == expected_names | {"admission-failure.json"} and result["outcome"] == "completed":
                failure = _read_ci_json(directory / "admission-failure.json")
                if (
                    set(failure) != {"document", "attempt_number", "document_sha256", "phase", "code"}
                    or failure["document"] != "unsigned-ci-lane-admission-failure-v1"
                    or type(failure["attempt_number"]) is not int
                    or failure["attempt_number"] != number
                    or failure["document_sha256"] != result["document_sha256"]
                    or type(failure["phase"]) is not str
                    or failure["phase"] not in {"environment", "source", "toolchain", "executor"}
                    or failure["code"] != f"{failure['phase']}_admission_failed"
                ):
                    raise PublicationError("CI lane admission failure has an unexpected binding")
                expected_names.add("admission-failure.json")
            else:
                raise PublicationError(f"CI lane attempt {number:04d} contains unknown or incomplete files")
        for name in ("intent.json", "result.json", "toolchain-binding.json", "document.json", "admission-failure.json"):
            if name in expected_names:
                snapshot[f"{directory.name}/{name}"] = sha256_file(directory / name)
        if result["outcome"] in {"completed", "partial"} and "admission-failure.json" not in names:
            for identifier, selection in resolved.items():
                if _matches_selection(selection, commit, source, toolchain):
                    selected[identifier] = selection
        else:
            for identifier in own:
                del available[(number, identifier)]
    return _CiHistory(len(attempts), selected, snapshot)


def _validate_executor_identity(value: object) -> None:
    if value is None:
        return
    if (
        type(value) is not dict
        or set(value) != {"repositoryCommit", "releaseSourceSha256"}
        or type(value["repositoryCommit"]) is not str
        or re.fullmatch(r"[0-9a-f]{40}", value["repositoryCommit"]) is None
    ):
        raise PublicationError("CI lane executor source identity is malformed")
    require_sha256(value["releaseSourceSha256"], "CI lane executor source")


CI_COLLECTION_PHASES = frozenset({
    "lanes", "environment", "source", "toolchain", "reproduction", "history", "assembly", "complete",
})


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
LibboxReproductionVerifier = Callable[
    [Path, Path, dict[str, str], dict[str, str]], str
]


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
    reproduction_verifier: LibboxReproductionVerifier = verify_libbox_reproduction,
    report: Callable[[str], None] = print,
    executor_source: dict[str, str] | None = None,
    source_recheck: Callable[[], None] | None = None,
) -> dict[str, Any]:
    """Append one real collection attempt; promote only a fully passing document.

    Legacy root-level records are read-only seeds. Each later selection names
    the exact immutable attempt and record it reuses. Interrupted attempts are
    retained and rejected; verification failures cannot seed later evidence.
    """
    self_check()
    release_source_sha256 = require_sha256(release_source_sha256, "unsigned CI release source SHA-256")
    unknown = sorted((only | rerun) - set(LANE_INDEX))
    if unknown:
        raise PublicationError(f"unknown unsigned CI lane selection: {unknown}")
    if assemble_only and rerun:
        raise PublicationError("assemble-only cannot request lane reruns")
    _validate_executor_identity(executor_source)
    if executor_source is not None and source_recheck is None:
        raise PublicationError("CI lane executor identity requires source revalidation")
    pins = _pins(repository)
    execution_environment = release_tool_environment(repository, pins)
    expected_source_identity = {"repositoryCommit": commit, "releaseSourceSha256": release_source_sha256}
    try:
        starting_source_identity = current_identity(repository, require_clean=True, environment=execution_environment)
    except (OSError, SourceIdentityError) as error:
        raise PublicationError("local deterministic CI lanes require one clean release source identity") from error
    if starting_source_identity != expected_source_identity:
        raise PublicationError("unsigned CI lane inputs differ from the current release source identity")
    digest, identity = derive_toolchain_binding(repository, release_environment=execution_environment)
    if sha256_bytes(canonical_json(identity)) != digest:
        raise PublicationError("CI lane toolchain digest differs from its canonical identity")
    execution_toolchain_root, execution_tree_digests = verified_release_toolchain_trees(
        repository, pins, environment=execution_environment
    )
    if identity.get("release_tree_sha256") != execution_tree_digests:
        raise PublicationError("CI lane execution toolchain differs from the canonical binding")
    source = repository / DEFAULT_LIBBOX_SOURCE_TEMPLATE.format(version=pins["SING_BOX_VERSION"]) if libbox_source is None else libbox_source
    artifact = repository / DEFAULT_LIBBOX_OUTPUT if libbox_output is None else libbox_output
    output = canonical_ci_evidence_path(output, "CI lane output")
    journal = canonical_ci_evidence_path(journal, "CI lane journal")
    if journal.absolute() == output.absolute() or journal.absolute() in output.absolute().parents:
        raise PublicationError("CI lane canonical output must be outside its attempt journal")
    _require_ci_directory(output.parent)
    _require_ci_directory(journal.parent)
    if os.path.lexists(output):
        raise PublicationError(f"refusing to replace an unsigned CI lane record: {output}")
    journal.mkdir(exist_ok=True, mode=0o700)
    _require_ci_directory(journal)
    report(f"local deterministic CI lanes: commit={commit} release_source_sha256={release_source_sha256} toolchain_sha256={digest}")

    with exclusive_directory_lock(journal) as journal_descriptor:
        history = _read_ci_history(journal, commit, release_source_sha256, digest)
        if history.count >= MAX_CI_ATTEMPTS:
            raise PublicationError("CI lane journal exhausted its bounded attempt sequence")
        if any(item.attempt_number == 0 for item in history.selected.values()):
            if read_regular(journal / "toolchain-binding.json") != canonical_json(identity):
                raise PublicationError("legacy CI lane toolchain binding differs from the current toolchain")
        selected = {identifier: item for identifier, item in history.selected.items() if identifier not in rerun}
        number = history.count + 1
        attempt = journal / f"attempt-{number:04d}"
        attempt.mkdir(mode=0o700)
        fsync_locked_directory(journal_descriptor, journal)
        intent = {
            "document": ATTEMPT_INTENT_KIND, "schema_version": 1, "attempt_number": number,
            "repository_commit": commit, "release_source_sha256": release_source_sha256,
            "toolchain_sha256": digest, "toolchain_binding_sha256": sha256_bytes(canonical_json(identity)),
            "executor_source": executor_source, "only": sorted(only), "rerun": sorted(rerun),
            "assemble_only": assemble_only,
            "lane_process_umask": LANE_PROCESS_UMASK,
            "selected": {identifier: item.reference() for identifier, item in selected.items()},
        }
        _write_attempt_file(attempt / "intent.json", canonical_json(intent))
        _publish_toolchain_binding(attempt, identity)
        own: dict[str, _LaneSelection] = {}
        phase = "lanes"
        reproduction_digest: str | None = None
        reproduction_observations: list[str] = []

        def close_attempt(outcome: str, document: dict[str, Any] | None = None) -> None:
            payload = None if document is None else canonical_json(document)
            if payload is not None:
                _write_attempt_file(attempt / "document.json", payload)
            result = {
                "document": ATTEMPT_RESULT_KIND, "schema_version": 1,
                "attempt_number": number, "outcome": outcome, "phase": phase,
                "records": {identifier: item.record_sha256 for identifier, item in own.items()},
                "selected": {identifier: item.reference() for identifier, item in selected.items()},
                "document_sha256": None if payload is None else sha256_bytes(payload),
                "reproduction_sha256": reproduction_digest if document is not None else None,
                "observed_reproduction_sha256s": list(reproduction_observations),
            }
            _write_attempt_file(attempt / "result.json", canonical_json(result))
            fsync_locked_directory(journal_descriptor, journal)

        try:
            for lane in LANES:
                if lane.identifier in selected:
                    record = selected[lane.identifier].record
                    report(f"  {lane.identifier}: replayed {record['status']} (exit {record['exit_code']})")
                    continue
                if assemble_only or (only and lane.identifier not in only):
                    report(f"  {lane.identifier}: not recorded")
                    continue
                environment = lane_environment(
                    repository, lane, pins, source, artifact,
                    attempt / "runner-temp" / lane.identifier, execution_toolchain_root,
                    release_environment=execution_environment,
                )
                report(f"  {lane.identifier}: running (bound to {lane.timeout}s) $ {lane.command}")
                started_at = int(time.time())
                output_bytes, exit_code, timed_out, duration = runner(repository, lane, environment)
                record = record_lane(lane, commit, release_source_sha256, digest, output_bytes, exit_code, timed_out, duration, started_at)
                write_journal_record(attempt, lane, record, output_bytes)
                selection = _LaneSelection(number, attempt, record, sha256_bytes(canonical_json(record)))
                own[lane.identifier] = selection
                selected[lane.identifier] = selection
                report(f"  {lane.identifier}: {record['status']} (exit {record['exit_code']}, {record['duration_seconds']}s, log {record['log_sha256'][:12]})")

            phase = "environment"
            try:
                ending_environment = release_tool_environment(repository, pins, execution_environment)
            except PublicationError as error:
                raise PublicationError("release tool environment changed while CI lanes were executing") from error
            if ending_environment != execution_environment:
                raise PublicationError("release tool environment changed while CI lanes were executing")
            phase = "source"
            try:
                ending_source_identity = current_identity(repository, require_clean=True, environment=ending_environment)
            except (OSError, SourceIdentityError) as error:
                raise PublicationError("release source changed or became unreadable while CI lanes were executing") from error
            if ending_source_identity != starting_source_identity:
                raise PublicationError("release source changed while CI lanes were executing")
            if source_recheck is not None:
                source_recheck()
            phase = "toolchain"
            ending_digest, ending_identity = derive_toolchain_binding(repository, release_environment=ending_environment)
            ending_root, ending_trees = verified_release_toolchain_trees(repository, pins, environment=ending_environment)
            if (
                ending_digest != digest or ending_identity != identity
                or ending_root != execution_toolchain_root or ending_trees != execution_tree_digests
                or ending_identity.get("release_tree_sha256") != ending_trees
            ):
                raise PublicationError("release toolchain changed while CI lanes were executing")
            records = {identifier: item.record for identifier, item in selected.items()}
            phase = "reproduction"
            if set(records) == set(REQUIRED_CI_LANES) and all(record["status"] == PASSED for record in records.values()):
                reproduction_digest = require_sha256(reproduction_verifier(repository, artifact, pins, ending_trees), "verified Libbox reproduction tree digest")
                reproduction_observations.append(reproduction_digest)
                repeated = require_sha256(reproduction_verifier(repository, artifact, pins, ending_trees), "repeated Libbox reproduction tree digest")
                reproduction_observations.append(repeated)
                if repeated != reproduction_digest:
                    raise PublicationError("Libbox reproduction changed while CI evidence was being published")
                phase = "source"
                if current_identity(repository, require_clean=True, environment=ending_environment) != starting_source_identity:
                    raise PublicationError("release source changed before CI evidence publication")
            phase = "history"
            if _read_ci_history(journal, commit, release_source_sha256, digest, active_attempt=attempt) != history:
                raise PublicationError("CI lane journal changed while lanes were executing")
            if _read_ci_json(attempt / "intent.json") != intent or read_regular(attempt / "toolchain-binding.json") != canonical_json(identity):
                raise PublicationError("CI lane attempt inputs changed while lanes were executing")
            for identifier, selection in own.items():
                if _stored_lane(attempt, LANE_INDEX[identifier], number) != selection:
                    raise PublicationError("CI lane attempt record changed before publication")
            phase = "assembly"
            if set(records) != set(REQUIRED_CI_LANES):
                close_attempt("partial")
                missing = sorted(set(REQUIRED_CI_LANES) - set(records))
                raise PublicationError(f"unsigned CI lane records are missing: {missing}")
            document, failures = assemble_document(records, commit, release_source_sha256, digest)
            if not failures and source_recheck is not None:
                phase = "source"
                source_recheck()
            phase = "complete"
            close_attempt("completed", document)
        except BaseException:
            try:
                if not os.path.lexists(attempt / "result.json"):
                    close_attempt("verification-failed")
            except Exception as journal_error:
                raise PublicationError(
                    f"CI lane attempt {number:04d} failed and its terminal evidence could not be made durable"
                ) from journal_error
            raise

        # Reopen the durable result and every selected record before promotion.
        verified = _read_ci_history(journal, commit, release_source_sha256, digest)
        if verified.count != number:
            raise PublicationError("CI lane attempt history changed before promotion")
        if not failures:
            admission_phase = "environment"
            try:
                admitted_environment = release_tool_environment(repository, pins, execution_environment)
                if admitted_environment != execution_environment:
                    raise PublicationError("release tool environment changed before CI publication")
                admission_phase = "source"
                if current_identity(repository, require_clean=True, environment=admitted_environment) != starting_source_identity:
                    raise PublicationError("release source changed before canonical CI publication")
                admission_phase = "toolchain"
                admitted_digest, admitted_identity = derive_toolchain_binding(repository, release_environment=admitted_environment)
                admitted_root, admitted_trees = verified_release_toolchain_trees(repository, pins, environment=admitted_environment)
                if (
                    admitted_digest != digest or admitted_identity != identity
                    or admitted_root != execution_toolchain_root or admitted_trees != execution_tree_digests
                ):
                    raise PublicationError("release toolchain changed before canonical CI publication")
                admission_phase = "executor"
                if source_recheck is not None:
                    source_recheck()
            except BaseException:
                observation = {
                    "document": "unsigned-ci-lane-admission-failure-v1", "attempt_number": number,
                    "document_sha256": sha256_bytes(canonical_json(document)),
                    "phase": admission_phase, "code": f"{admission_phase}_admission_failed",
                }
                _write_attempt_file(attempt / "admission-failure.json", canonical_json(observation))
                raise
            payload = read_regular(attempt / "document.json")
            if payload != canonical_json(document):
                raise PublicationError("CI lane passing attempt changed before promotion")
            pending = output.with_name(f".{output.name}.pending")
            if os.path.lexists(pending):
                if read_private_pending(pending, len(payload)) != payload:
                    raise PublicationError("CI lane canonical pending file differs from the passing attempt")
            else:
                canonical_ci_evidence_path(output, "CI lane output")
                write_private_pending(pending, payload)
            canonical_ci_evidence_path(output, "CI lane output")
            promote_private_pending(pending, output)
            if read_regular(output) != payload:
                raise PublicationError("CI lane canonical output changed while publishing")
            fsync_directory(output.parent)
            report(f"local deterministic CI lane record written: {output}")
        report(f"CI lane attempt retained: {attempt} lanes={len(document['lanes'])} failed={failures}")
        return {
            "document": document, "failures": failures, "toolchain_sha256": digest,
            "release_source_sha256": release_source_sha256, "toolchain_identity": identity,
            "records": records, "output": str(output) if not failures else None,
            "attempt": str(attempt), "journal": str(journal),
        }
