"""Deterministic unsigned-CI lane collection and the single toolchain binding.

This module is the collector behind the ``unsigned_ci`` gate of the sealed outer
Evidence Manifest (``publication.sealed_manifest``). It adds no competing
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
import os
import selectors
import signal
import stat
import subprocess
import tempfile
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
    write_new,
)
from .sealed_closure import derive_supply_chain
from .sealed_manifest import REQUIRED_CI_LANES, _ci_lane_document, _require_command
from .release_toolchains import verified_release_toolchain_trees
from .release_environment import (
    APPLE_SWIFT,
    APPLE_XCODEBUILD,
    APPLE_XCRUN,
    SYSTEM_PATH,
    identity_output,
    release_tool_environment,
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
    # The workflow only asserts that the Swift driver reports an identity; there
    # is no separate Swift pin (it ships inside the pinned Xcode).
    resolved["swift"] = identity_output(
        [APPLE_SWIFT, "--version"], repository, "Swift", base
    )
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
        binding_path.unlink()
    write_new(binding_path, payload)


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
    record_path, _log_path = _journal_paths(journal, lane)
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
    _read_journal_output(journal, lane, record)
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
    execution_environment = release_tool_environment(repository, pins)
    expected_source_identity = {
        "repositoryCommit": commit,
        "releaseSourceSha256": release_source_sha256,
    }
    try:
        starting_source_identity = current_identity(
            repository,
            require_clean=True,
            environment=execution_environment,
        )
    except (OSError, SourceIdentityError) as error:
        raise PublicationError(
            "unsigned CI lanes require one clean release source identity"
        ) from error
    if starting_source_identity != expected_source_identity:
        raise PublicationError(
            "unsigned CI lane inputs differ from the current release source identity"
        )
    digest, identity = derive_toolchain_binding(
        repository, release_environment=execution_environment
    )
    execution_toolchain_root, execution_tree_digests = verified_release_toolchain_trees(
        repository, pins, environment=execution_environment
    )
    if identity.get("release_tree_sha256") != execution_tree_digests:
        raise PublicationError(
            "CI lane execution toolchain differs from the canonical binding"
        )
    source = (
        repository / DEFAULT_LIBBOX_SOURCE_TEMPLATE.format(version=pins["SING_BOX_VERSION"])
        if libbox_source is None
        else libbox_source
    )
    artifact = repository / DEFAULT_LIBBOX_OUTPUT if libbox_output is None else libbox_output

    if output.exists() or output.is_symlink():
        raise PublicationError(f"refusing to replace an unsigned CI lane record: {output}")
    journal.mkdir(parents=True, exist_ok=True)
    if journal.is_symlink() or not journal.is_dir():
        raise PublicationError(f"CI lane journal is not a real directory: {journal}")

    report(
        "unsigned CI lanes: "
        f"commit={commit} release_source_sha256={release_source_sha256} "
        f"toolchain_sha256={digest}"
    )
    records: dict[str, dict[str, Any]] = {}
    pending_lanes: list[Lane] = []
    reproduction_digest: str | None = None
    with tempfile.TemporaryDirectory(prefix=".ci-lane-attempt.", dir=journal) as attempt:
        attempt_journal = Path(attempt)
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
                attempt_journal / "runner-temp" / lane.identifier,
                execution_toolchain_root,
                release_environment=execution_environment,
            )
            report(
                f"  {lane.identifier}: running (bound to {lane.timeout}s) $ {lane.command}"
            )
            started_at = int(time.time())
            output_bytes, exit_code, timed_out, duration = runner(
                repository, lane, environment
            )
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
            write_journal_record(attempt_journal, lane, record, output_bytes)
            pending_lanes.append(lane)
            records[lane.identifier] = record
            report(
                f"  {lane.identifier}: {record['status']} (exit {record['exit_code']}, "
                f"{record['duration_seconds']}s, log {record['log_sha256'][:12]})"
            )

        try:
            ending_execution_environment = release_tool_environment(
                repository, pins, execution_environment
            )
        except PublicationError as error:
            raise PublicationError(
                "release tool environment changed while CI lanes were executing"
            ) from error
        if ending_execution_environment != execution_environment:
            raise PublicationError(
                "release tool environment changed while CI lanes were executing"
            )

        try:
            ending_source_identity = current_identity(
                repository,
                require_clean=True,
                environment=ending_execution_environment,
            )
        except (OSError, SourceIdentityError) as error:
            raise PublicationError(
                "release source changed or became unreadable while CI lanes were executing"
            ) from error
        if ending_source_identity != starting_source_identity:
            raise PublicationError(
                "release source changed while CI lanes were executing"
            )

        ending_digest, ending_identity = derive_toolchain_binding(
            repository, release_environment=ending_execution_environment
        )
        ending_toolchain_root, ending_tree_digests = verified_release_toolchain_trees(
            repository, pins, environment=ending_execution_environment
        )
        if (
            ending_digest != digest
            or ending_identity != identity
            or ending_toolchain_root != execution_toolchain_root
            or ending_tree_digests != execution_tree_digests
            or ending_identity.get("release_tree_sha256") != ending_tree_digests
        ):
            raise PublicationError(
                "release toolchain changed while CI lanes were executing"
            )

        if set(records) == set(REQUIRED_CI_LANES) and all(
            record["status"] == PASSED for record in records.values()
        ):
            reproduction_digest = require_sha256(
                reproduction_verifier(
                    repository,
                    artifact,
                    pins,
                    ending_tree_digests,
                ),
                "verified Libbox reproduction tree digest",
            )

        _publish_toolchain_binding(journal, identity)
        for lane in pending_lanes:
            staged_record = read_journal_record(
                attempt_journal, lane, commit, release_source_sha256, digest
            )
            if staged_record is None or staged_record != records[lane.identifier]:
                raise PublicationError(
                    f"lane {lane.identifier!r} staged journal record changed before publication"
                )
            staged_output = _read_journal_output(
                attempt_journal, lane, staged_record
            )
            write_journal_record(journal, lane, staged_record, staged_output)

    if reproduction_digest is not None:
        repeated_reproduction_digest = require_sha256(
            reproduction_verifier(
                repository,
                artifact,
                pins,
                ending_tree_digests,
            ),
            "repeated Libbox reproduction tree digest",
        )
        if repeated_reproduction_digest != reproduction_digest:
            raise PublicationError(
                "Libbox reproduction changed while CI evidence was being published"
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
