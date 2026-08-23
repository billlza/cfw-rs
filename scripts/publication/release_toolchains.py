"""Publication adapter for the shared release-toolchain tree contract."""

from __future__ import annotations

from pathlib import Path

from .bounded_process import BoundedProcessError, run_bounded_process
from .common import PublicationError, require_sha256
from .graph_model import load_pins

if __package__ and __package__.startswith("scripts."):
    from scripts.release_cargo_inputs import (
        ReleaseCargoInputsError,
        verify_workspace_cargo_inputs,
    )
else:
    from release_cargo_inputs import (
        ReleaseCargoInputsError,
        verify_workspace_cargo_inputs,
    )


TOOLCHAIN_VERIFICATION_TIMEOUT_SECONDS = 900
MAX_TOOLCHAIN_VERIFICATION_OUTPUT_BYTES = 8 * 1024 * 1024


def verified_release_toolchain_trees(
    repository: Path,
    pins: dict[str, str],
    environment: dict[str, str],
) -> tuple[Path, dict[str, str]]:
    """Verify every release-managed tree before returning its bound digest."""

    canonical_pins = load_pins(repository / "scripts/dependency_pins.env")
    if pins != canonical_pins:
        raise PublicationError(
            "release toolchain pins do not match scripts/dependency_pins.env"
        )

    process_environment = dict(environment)
    configured_root = Path(
        process_environment.get(
            "CFW_TOOLCHAIN_ROOT", repository / "target/toolchains"
        )
    )
    selected_root = (
        configured_root if configured_root.is_absolute() else repository / configured_root
    )
    try:
        if not selected_root.is_dir() or selected_root.is_symlink():
            raise PublicationError(
                "release toolchain root is missing, not a directory, or a symlink"
            )
        toolchain_root = selected_root.resolve(strict=True)
        cargo_inputs_before = verify_workspace_cargo_inputs(
            repository,
            Path(process_environment["CFW_RELEASE_CARGO_INPUT_ROOT"]),
        )
    except OSError as error:
        raise PublicationError(f"cannot resolve the release toolchain root: {error}") from error
    except (KeyError, ReleaseCargoInputsError) as error:
        raise PublicationError("verified Cargo workspace inputs are unavailable") from error
    command = r'''
set -euo pipefail
repository="$1"
toolchain_root="$2"
source "$repository/scripts/dependency_pins.env"
source "$repository/scripts/release_toolchain_contract.sh"
source "$repository/scripts/ui_dependency_contract.sh"
go_digest="$(cfw_verify_go_toolchain_tree "$repository" "$toolchain_root")"
node_digest="$(cfw_verify_node_toolchain_tree "$repository" "$toolchain_root")"
xcodegen_digest="$(cfw_verify_xcodegen_toolchain_tree "$repository" "$toolchain_root")"
tauri_digest="$(cfw_verify_tauri_toolchain_tree "$repository" "$toolchain_root")"
go_tools_digest="$(cfw_verify_go_release_tools_tree "$repository" "$toolchain_root")"
go_module_digest="$(cfw_verify_go_module_cache_tree "$repository" "$toolchain_root")"
ui_dependencies_digest="$(cfw_verify_ui_dependencies_tree "$repository" "$toolchain_root")"
printf 'go=%s\n' "$go_digest"
printf 'node=%s\n' "$node_digest"
printf 'xcodegen=%s\n' "$xcodegen_digest"
printf 'tauri-cli=%s\n' "$tauri_digest"
printf 'go-release-tools=%s\n' "$go_tools_digest"
printf 'go-module-cache=%s\n' "$go_module_digest"
printf 'ui-dependencies=%s\n' "$ui_dependencies_digest"
'''
    try:
        completed = run_bounded_process(
            [
                "/bin/bash",
                "-p",
                "-c",
                command,
                "release-toolchain-contract",
                str(repository),
                str(toolchain_root),
            ],
            cwd=repository,
            environment=process_environment,
            timeout=TOOLCHAIN_VERIFICATION_TIMEOUT_SECONDS,
            output_limit=MAX_TOOLCHAIN_VERIFICATION_OUTPUT_BYTES,
        )
    except BoundedProcessError as error:
        detail = (error.stderr or error.stdout)[-8192:].decode(
            "utf-8", errors="replace"
        ).strip()
        raise PublicationError(
            "release toolchain tree verification was not bounded"
            + (f": {detail}" if detail else f": {error}")
        ) from error
    if completed.returncode != 0:
        output = (completed.stderr + completed.stdout)[-8192:].decode(
            "utf-8", errors="replace"
        ).strip()
        raise PublicationError(f"release toolchain tree verification failed: {output}")
    if completed.stderr:
        raise PublicationError(
            "release toolchain tree verification emitted diagnostics"
        )
    expected = {
        "cargo-workspace-sources",
        "go",
        "node",
        "xcodegen",
        "tauri-cli",
        "go-release-tools",
        "go-module-cache",
        "ui-dependencies",
    }
    digests: dict[str, str] = {}
    digests["cargo-workspace-sources"] = cargo_inputs_before.vendor_tree_sha256
    try:
        lines = completed.stdout.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise PublicationError("release toolchain verification output is not UTF-8") from error
    for line in lines:
        name, separator, digest = line.partition("=")
        if not separator or name not in expected or name in digests:
            raise PublicationError("release toolchain verification output is malformed")
        digests[name] = require_sha256(digest, f"verified {name} tree digest")
    if set(digests) != expected:
        raise PublicationError("release toolchain verification omitted a managed tree")
    try:
        cargo_inputs_after = verify_workspace_cargo_inputs(
            repository,
            Path(process_environment["CFW_RELEASE_CARGO_INPUT_ROOT"]),
        )
    except (KeyError, OSError, ReleaseCargoInputsError) as error:
        raise PublicationError(
            "verified Cargo workspace inputs changed during toolchain verification"
        ) from error
    if cargo_inputs_after != cargo_inputs_before:
        raise PublicationError(
            "verified Cargo workspace inputs changed during toolchain verification"
        )
    return toolchain_root, digests
