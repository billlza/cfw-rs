from __future__ import annotations

from dataclasses import dataclass
import os
from pathlib import Path
from pathlib import PurePosixPath
from typing import Any
from urllib.parse import quote

from .cargo_collector import CollectorResult
from .common import PublicationError
from .graph_model import ComponentSeed, RELEASE_VERSION, run, run_json, seed
from .release_environment import swift_toolchain_identity
from .release_toolchains import verified_release_toolchain_trees
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


@dataclass(frozen=True)
class _CheckedToolchainObservation:
    versions: tuple[tuple[str, str], ...]
    toolchain_root: Path
    swift_identity: str


def _normalize_native_graph(value: Any, native_root: Path, path: str = "$") -> Any:
    """Remove machine-local roots while preserving checked relative target paths."""
    if isinstance(value, dict):
        normalized: dict[str, Any] = {}
        for key, child in value.items():
            child_path = f"{path}.{key}"
            if key == "path" and isinstance(child, str):
                candidate = Path(child)
                if candidate.is_absolute():
                    try:
                        relative = candidate.resolve(strict=True).relative_to(native_root)
                    except (OSError, ValueError) as error:
                        raise PublicationError(
                            f"native build graph path escaped its project root at {child_path}"
                        ) from error
                    normalized[key] = relative.as_posix() if relative.parts else "."
                    continue
                relative = PurePosixPath(child)
                if relative.is_absolute() or ".." in relative.parts:
                    raise PublicationError(
                        f"native build graph contains an unsafe relative path at {child_path}"
                    )
            normalized[key] = _normalize_native_graph(child, native_root, child_path)
        return normalized
    if isinstance(value, list):
        return [
            _normalize_native_graph(child, native_root, f"{path}[{index}]")
            for index, child in enumerate(value)
        ]
    if isinstance(value, str) and value.startswith("/"):
        raise PublicationError(f"native build graph contains an absolute path at {path}")
    return value


def _apple_tool_identity(
    repository: Path,
    pins: dict[str, str],
    release_environment: dict[str, str],
) -> tuple[str, str, str, str]:
    xcode = run(
        ["/usr/bin/xcodebuild", "-version"], repository, release_environment
    ).decode("utf-8").strip()
    expected_xcode = (
        f"Xcode {pins['XCODE_VERSION']}\n"
        f"Build version {pins['XCODE_BUILD_VERSION']}"
    )
    if xcode != expected_xcode:
        raise PublicationError("Xcode toolchain does not match the release pin")
    swift = swift_toolchain_identity(
        repository,
        release_environment,
        pins["MACOS_DEPLOYMENT_TARGET"],
    ).canonical
    try:
        developer_dir = Path(release_environment["DEVELOPER_DIR"]).resolve(strict=True)
        swift_path = Path(
            run(
                ["/usr/bin/xcrun", "--find", "swift"],
                repository,
                release_environment,
            )
            .decode("utf-8")
            .strip()
        ).resolve(strict=True)
        xcodebuild_path = Path(
            run(
                ["/usr/bin/xcrun", "--find", "xcodebuild"],
                repository,
                release_environment,
            )
            .decode("utf-8")
            .strip()
        ).resolve(strict=True)
    except (KeyError, OSError, UnicodeDecodeError) as error:
        raise PublicationError("cannot resolve the selected Apple toolchain") from error
    if not swift_path.is_relative_to(developer_dir) or not xcodebuild_path.is_relative_to(
        developer_dir
    ):
        raise PublicationError("selected Apple build tool escaped DEVELOPER_DIR")
    return xcode, swift, str(swift_path), str(xcodebuild_path)


def collect_native(
    repository: Path,
    pins: dict[str, str],
    release_environment: dict[str, str],
) -> CollectorResult:
    native_root = repository / "native/macos"
    apple_identity_start = _apple_tool_identity(
        repository, pins, release_environment
    )
    swift_graph = _normalize_native_graph(
        run_json(
            ["/usr/bin/swift", "package", "describe", "--type", "json"],
            native_root,
            release_environment,
        ),
        native_root.resolve(strict=True),
    )
    xcode_graph = _normalize_native_graph(
        run_json(
            [
                "/usr/bin/xcodebuild",
                "-project",
                "CFWNative.xcodeproj",
                "-disableAutomaticPackageResolution",
                "-list",
                "-json",
            ],
            native_root,
            release_environment,
        ),
        native_root.resolve(strict=True),
    )
    apple_identity_end = _apple_tool_identity(repository, pins, release_environment)
    if apple_identity_end != apple_identity_start:
        raise PublicationError("Apple toolchain changed while collecting native graphs")
    swift_seed = seed(
        "CFWNative",
        RELEASE_VERSION,
        "swift",
        "runtime",
        f"pkg:swift/cfwnative@{RELEASE_VERSION}",
        native_root,
        True,
        license_root=repository,
        metadata_path=repository / "Cargo.toml",
        declared_license="GPL-3.0-or-later",
    )
    native_seed = seed(
        "CFWNativeProducts",
        RELEASE_VERSION,
        "native",
        "runtime",
        f"pkg:generic/cfw-native-products@{RELEASE_VERSION}",
        native_root,
        True,
        license_root=repository,
        metadata_path=repository / "Cargo.toml",
        declared_license="GPL-3.0-or-later",
    )
    components = {swift_seed.identifier: swift_seed, native_seed.identifier: native_seed}
    component_ids = set(components)
    return (
        components,
        {(native_seed.identifier, swift_seed.identifier, "DEPENDS_ON")},
        {"swift-package": swift_graph, "xcode-modules": xcode_graph},
        {"swift-package": {swift_seed.identifier}, "xcode-modules": component_ids},
    )


def _checked_versions(
    repository: Path,
    pins: dict[str, str],
    release_environment: dict[str, str],
) -> _CheckedToolchainObservation:
    toolchain_root, _tree_digests = verified_release_toolchain_trees(
        repository, pins, release_environment
    )
    node_bin = toolchain_root / f"node-{pins['NODE_VERSION']}" / "bin/node"
    go_bin = toolchain_root / f"go-{pins['GO_VERSION']}" / "bin/go"
    xcodegen_bin = toolchain_root / f"xcodegen-{pins['XCODEGEN_VERSION']}" / "bin/xcodegen"
    gomobile_bin = toolchain_root / "go-workspace/bin/gomobile"
    tauri_bin = toolchain_root / f"tauri-cli-{pins['TAURI_CLI_VERSION']}" / "bin/cargo-tauri"
    for path, label in (
        (node_bin, "Node.js"),
        (go_bin, "Go"),
        (xcodegen_bin, "XcodeGen"),
        (gomobile_bin, "gomobile"),
        (tauri_bin, "tauri-cli"),
    ):
        if not path.is_file() or path.is_symlink() or not os.access(path, os.X_OK):
            raise PublicationError(f"pinned {label} tool is unavailable: {path}")
    try:
        rustc_bin = Path(release_environment["CFW_RELEASE_RUSTC_EXECUTABLE"])
    except KeyError as error:
        raise PublicationError("release environment omitted its Rust compiler") from error
    try:
        rust_toolchain_start = verify_pinned_toolchain(
            repository, rustc_bin.parent.parent.resolve(strict=True)
        )
    except (OSError, ReleaseRustToolchainError) as error:
        raise PublicationError("Rust release toolchain surface is invalid") from error
    if not rustc_bin.exists() or not os.access(rustc_bin, os.X_OK):
        raise PublicationError("trusted Rust compiler is unavailable")
    swift_identity = swift_toolchain_identity(
        repository,
        release_environment,
        pins["MACOS_DEPLOYMENT_TARGET"],
    )
    actual = {
        "rust": run([str(rustc_bin), "--version"], repository, release_environment)
        .decode()
        .strip(),
        "swift": swift_identity.canonical,
        "xcode": run(
            ["/usr/bin/xcodebuild", "-version"], repository, release_environment
        )
        .decode()
        .strip(),
        "node": run([str(node_bin), "--version"], repository, release_environment)
        .decode()
        .strip(),
        "go": run([str(go_bin), "version"], repository, release_environment)
        .decode()
        .strip(),
        "xcodegen": run(
            [str(xcodegen_bin), "--version"], repository, release_environment
        )
        .decode()
        .strip(),
        "tauri-cli": run(
            [str(tauri_bin), "--version"], repository, release_environment
        )
        .decode()
        .strip(),
    }
    expected = {
        "rust": f"rustc {pins['RUST_VERSION']} ",
        "xcode": f"Xcode {pins['XCODE_VERSION']}\nBuild version {pins['XCODE_BUILD_VERSION']}",
        "node": f"v{pins['NODE_VERSION']}",
        "go": f"go version go{pins['GO_VERSION']} darwin/arm64",
        "xcodegen": f"Version: {pins['XCODEGEN_VERSION']}",
        "tauri-cli": f"tauri-cli {pins['TAURI_CLI_VERSION']}",
    }
    if not actual["rust"].startswith(expected["rust"]):
        raise PublicationError("Rust toolchain does not match the release pin")
    for name in ("xcode", "node", "go", "xcodegen", "tauri-cli"):
        if actual[name] != expected[name]:
            raise PublicationError(f"{name} toolchain does not match the release pin")
    gomobile_identity = run(
        [str(go_bin), "version", "-m", str(gomobile_bin)],
        repository,
        release_environment,
    ).decode()
    expected_module = (
        f"mod\tgithub.com/sagernet/gomobile\t{pins['GOMOBILE_VERSION']}\t"
        f"{pins['GOMOBILE_MODULE_SUM']}"
    )
    if expected_module not in gomobile_identity:
        raise PublicationError("gomobile binary does not match its release module identity")
    versions = {
        "rust": pins["RUST_VERSION"],
        "node": pins["NODE_VERSION"],
        "go": pins["GO_VERSION"],
        "gomobile": pins["GOMOBILE_VERSION"],
        "swift": swift_identity.version,
        "xcode": pins["XCODE_VERSION"],
        "xcodegen": pins["XCODEGEN_VERSION"],
        "tauri-cli": pins["TAURI_CLI_VERSION"],
    }
    verified_release_toolchain_trees(repository, pins, release_environment)
    try:
        rust_toolchain_end = verify_pinned_toolchain(
            repository, rustc_bin.parent.parent.resolve(strict=True)
        )
    except (OSError, ReleaseRustToolchainError) as error:
        raise PublicationError("Rust release toolchain surface cannot be rechecked") from error
    if rust_toolchain_end.surface != rust_toolchain_start.surface:
        raise PublicationError("Rust release toolchain changed during collection")
    return _CheckedToolchainObservation(
        versions=tuple(sorted(versions.items())),
        toolchain_root=toolchain_root,
        swift_identity=swift_identity.canonical,
    )


def _require_unchanged_toolchains(
    initial: _CheckedToolchainObservation,
    ending: _CheckedToolchainObservation,
) -> None:
    if ending != initial:
        raise PublicationError(
            "release toolchain changed while collecting publication metadata"
        )


def collect_toolchains(
    repository: Path,
    pins: dict[str, str],
    release_environment: dict[str, str],
) -> tuple[dict[str, ComponentSeed], set[tuple[str, str, str]]]:
    toolchain_start = _checked_versions(
        repository, pins, release_environment
    )
    versions = dict(toolchain_start.versions)
    toolchain_root = toolchain_start.toolchain_root
    try:
        rustc_bin = Path(release_environment["CFW_RELEASE_RUSTC_EXECUTABLE"])
    except KeyError as error:
        raise PublicationError("release environment omitted its Rust compiler") from error
    rust_sysroot = Path(
        run(
            [str(rustc_bin), "--print", "sysroot"],
            repository,
            release_environment,
        )
        .decode()
        .strip()
    ).resolve(strict=True)
    node_root = toolchain_root / f"node-{pins['NODE_VERSION']}"
    go_root = toolchain_root / f"go-{pins['GO_VERSION']}"
    tauri_root = toolchain_root / f"tauri-cli-{pins['TAURI_CLI_VERSION']}"
    node_bin = (node_root / "bin/node").resolve(strict=True)
    go_bin = (go_root / "bin/go").resolve(strict=True)
    gomobile_bin = (toolchain_root / "go-workspace/bin/gomobile").resolve(strict=True)
    xcodegen_bin = (
        toolchain_root / f"xcodegen-{pins['XCODEGEN_VERSION']}" / "bin/xcodegen"
    ).resolve(strict=True)
    gomobile_source = (
        toolchain_root
        / "go-workspace/pkg/mod/github.com/sagernet"
        / f"gomobile@{pins['GOMOBILE_VERSION']}"
    ).resolve(strict=True)
    xcodegen_source = (
        toolchain_root / f"xcodegen-{pins['XCODEGEN_VERSION']}" / "source"
    ).resolve(strict=True)
    swift_binary = Path(
        run(
            ["/usr/bin/xcrun", "--find", "swiftc"],
            repository,
            release_environment,
        )
        .decode()
        .strip()
    ).resolve(strict=True)
    xcode_binary = Path(
        run(
            ["/usr/bin/xcrun", "--find", "xcodebuild"],
            repository,
            release_environment,
        )
        .decode()
        .strip()
    ).resolve(strict=True)
    developer_resources = (
        Path(release_environment["DEVELOPER_DIR"]).resolve(strict=True).parent
        / "Resources"
    )
    tauri_binary = (tauri_root / "bin/cargo-tauri").resolve(strict=True)
    tauri_source = (tauri_root / "source").resolve(strict=True)
    details: dict[str, tuple[Path | None, Path | None, str | None]] = {
        "rust": (
            None,
            rust_sysroot / "share/doc/rust",
            "Apache-2.0 OR MIT",
        ),
        "node": (
            None,
            node_root,
            f"LicenseRef-Nodejs-Distribution-{pins['NODE_VERSION']}",
        ),
        "go": (go_root, go_root, "BSD-3-Clause"),
        "gomobile": (gomobile_source, gomobile_source, "BSD-3-Clause"),
        "swift": (
            None,
            developer_resources,
            f"LicenseRef-Apple-Xcode-EULA-{pins['XCODE_VERSION']}",
        ),
        "xcode": (
            None,
            developer_resources,
            f"LicenseRef-Apple-Xcode-EULA-{pins['XCODE_VERSION']}",
        ),
        # Upstream contains a source symlink; publication requires a separately
        # prepared, dereferenced source tree.
        "xcodegen": (None, xcodegen_source, "MIT"),
        "tauri-cli": (
            None,
            tauri_source,
            "Apache-2.0 OR MIT",
        ),
    }
    provenance_paths = {
        "rust": (rust_sysroot / "bin/rustc",),
        "node": (node_bin,),
        "go": (go_bin,),
        "gomobile": (gomobile_bin,),
        "swift": (swift_binary,),
        "xcode": (xcode_binary,),
        "xcodegen": (xcodegen_bin,),
        "tauri-cli": (tauri_binary,),
    }
    components: dict[str, ComponentSeed] = {}
    for name, version in versions.items():
        purl = f"pkg:generic/{quote(name, safe='')}@{quote(version, safe='.+-')}"
        source_root, license_root, declared_license = details[name]
        candidate = seed(
            name,
            version,
            "toolchain",
            "toolchain",
            purl,
            source_root,
            license_root=license_root,
            metadata_path=(
                tauri_source / "Cargo.toml"
                if name == "tauri-cli"
                else repository / "scripts/dependency_pins.env"
            ),
            declared_license=declared_license,
            external_build_tool=True,
            provenance_paths=provenance_paths[name],
        )
        components[candidate.identifier] = candidate
    toolchain_end = _checked_versions(
        repository, pins, release_environment
    )
    _require_unchanged_toolchains(toolchain_start, toolchain_end)
    return components, set()
