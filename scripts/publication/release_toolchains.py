"""Publication adapter for the shared release-toolchain tree contract."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .common import PublicationError, require_sha256
from .graph_model import load_pins


def verified_release_toolchain_trees(
    repository: Path,
    pins: dict[str, str],
) -> tuple[Path, dict[str, str]]:
    """Verify every release-managed tree before returning its bound digest."""

    canonical_pins = load_pins(repository / "scripts/dependency_pins.env")
    if pins != canonical_pins:
        raise PublicationError(
            "release toolchain pins do not match scripts/dependency_pins.env"
        )

    configured_root = Path(
        os.environ.get("CFW_TOOLCHAIN_ROOT", repository / "target/toolchains")
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
    except OSError as error:
        raise PublicationError(f"cannot resolve the release toolchain root: {error}") from error
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
    completed = subprocess.run(
        ["/bin/bash", "-c", command, "release-toolchain-contract", str(repository), str(toolchain_root)],
        cwd=repository,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    if completed.returncode != 0:
        output = completed.stdout.decode("utf-8", errors="replace").strip()
        raise PublicationError(f"release toolchain tree verification failed: {output}")
    expected = {
        "go",
        "node",
        "xcodegen",
        "tauri-cli",
        "go-release-tools",
        "go-module-cache",
        "ui-dependencies",
    }
    digests: dict[str, str] = {}
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
    return toolchain_root, digests
