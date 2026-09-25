#!/usr/bin/env python3
"""Build and verify the portable SwiftUI library used by the real preview Host.

This produces code/resources only. It does not sign, install, launch, register
services, or change networking. Candidate identity and signing remain separate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import plistlib
import re
import shutil
import stat
import subprocess

if __package__:
    from .hash_artifact import build_manifest
    from .repository_source_identity import current_identity
else:
    from hash_artifact import build_manifest
    from repository_source_identity import current_identity

LIBRARY = "libCFMNativeDashboard.dylib"
RESOURCES = "CFMNativeDashboard_CFMNativeDashboard.bundle"
INSTALL_NAME = "@rpath/" + LIBRARY
TRIPLE = "arm64-apple-macosx15.0"
SOURCE_PATHS = (
    "native/dashboard/Package.swift", "native/dashboard/Sources",
    "native/dashboard/include", "scripts/native_ui_artifact.py",
    "scripts/build_native_ui.sh", "scripts/dependency_pins.env",
)
LOCALES = frozenset({"en", "ja", "zh-Hans", "zh-Hant"})
COMPONENT_EXPORTS = frozenset({
    "cfm_profile_menu_present_v1", "cfm_profile_menu_update_v1",
    "cfm_profile_menu_dismiss_v1", "cfm_profile_menu_anchor_v1",
    "cfm_runtime_settings_present_v1", "cfm_runtime_settings_update_v1",
    "cfm_runtime_settings_dismiss_v1",
    "cfm_general_switches_sync_v1", "cfm_general_switches_focus_v1",
    "cfm_general_switches_dismiss_v1",
})
METADATA_KEYS = frozenset({
    "productVersion", "buildNumber", "configuration", "target", "signingMode", "buildSystem",
    "uiSourceSha256", "repositoryCommit", "releaseSourceSha256",
    "xcodeVersion", "xcodeBuildVersion", "swiftVersion",
})


class NativeUiArtifactError(ValueError):
    pass


def command(arguments: list[str], *, timeout: int = 30) -> str:
    result = subprocess.run(arguments, check=False, capture_output=True, text=True, timeout=timeout)
    if result.returncode or result.stderr:
        raise NativeUiArtifactError(
            f"{Path(arguments[0]).name} failed ({result.returncode}): {result.stderr.strip()}"
        )
    return result.stdout


def regular(path: Path, *, mode: int | None = None) -> None:
    value = path.lstat()
    if not stat.S_ISREG(value.st_mode) or value.st_nlink != 1:
        raise NativeUiArtifactError(f"not a single-link regular file: {path}")
    if mode is not None and stat.S_IMODE(value.st_mode) != mode:
        raise NativeUiArtifactError(f"unexpected file mode: {path}")


def source_digest(repository: Path) -> str:
    records = []
    for relative in SOURCE_PATHS:
        root = repository / relative
        if root.is_symlink():
            raise NativeUiArtifactError(f"UI source cannot be a link: {relative}")
        if root.is_dir():
            paths = []
            for directory, names, files in os.walk(root, followlinks=False):
                for name in names:
                    child = Path(directory) / name
                    if child.is_symlink() or not child.is_dir():
                        raise NativeUiArtifactError(f"UI source directory is unsafe: {child}")
                paths.extend(Path(directory) / name for name in files)
        else:
            paths = [root]
        for path in paths:
            regular(path)
            data = path.read_bytes()
            records.append({"path": path.relative_to(repository).as_posix(),
                            "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    digest = hashlib.sha256()
    for record in sorted(records, key=lambda item: item["path"]):
        digest.update((json.dumps(record, sort_keys=True, separators=(",", ":")) + "\n").encode())
    return digest.hexdigest()


def swift_compiler_version() -> str:
    result = subprocess.run(
        ["/usr/bin/xcrun", "swift", "--version"], check=False,
        capture_output=True, text=True, timeout=30,
    )
    # Apple's driver writes its version banner on stderr even when --version
    # succeeds. Admit that exact banner, while retaining rejection of warnings,
    # failed commands and unexpected compiler/target output.
    driver = result.stderr.strip()
    if (
        result.returncode != 0
        or (driver and re.fullmatch(r"swift-driver version: [0-9]+(?:\.[0-9]+)+", driver) is None)
        or re.fullmatch(r"Apple Swift version [^\r\n]+\nTarget: arm64-apple-macosx[0-9.]+\n", result.stdout) is None
    ):
        raise NativeUiArtifactError(f"Swift compiler identity failed ({result.returncode}): {result.stderr.strip()}")
    return result.stdout.strip() + ("\n" + driver if driver else "")


def expected_metadata(repository: Path, build: str, *, signing: str, clean: bool) -> dict[str, str]:
    if __package__:
        from .release_build_identity import SIGNED_PREVIEW_IDENTITY
    else:
        from release_build_identity import SIGNED_PREVIEW_IDENTITY
    if build != SIGNED_PREVIEW_IDENTITY.build_number or signing not in {"pre-sign", "developer-id"}:
        raise NativeUiArtifactError("UI products require the exact signed-preview identity")
    pins = dict(re.findall(r"^(XCODE_VERSION|XCODE_BUILD_VERSION)=([^\n]+)$",
                           (repository / "scripts/dependency_pins.env").read_text(), re.M))
    expected_xcode = f"Xcode {pins['XCODE_VERSION']}\nBuild version {pins['XCODE_BUILD_VERSION']}\n"
    if command(["/usr/bin/xcodebuild", "-version"]) != expected_xcode:
        raise NativeUiArtifactError("native UI products require the pinned production Xcode")
    return {
        "productVersion": SIGNED_PREVIEW_IDENTITY.product_version, "buildNumber": build,
        "configuration": "release", "target": TRIPLE, "signingMode": signing, "buildSystem": "swiftbuild",
        "uiSourceSha256": source_digest(repository),
        **current_identity(repository, require_clean=clean),
        "xcodeVersion": pins["XCODE_VERSION"], "xcodeBuildVersion": pins["XCODE_BUILD_VERSION"],
        "swiftVersion": swift_compiler_version(),
    }


def macho_load_paths(load_commands: str) -> tuple[str, list[str]]:
    names = re.findall(r"cmd LC_ID_DYLIB\s+cmdsize \d+\s+name (.+?) \(offset \d+\)", load_commands)
    paths = re.findall(r"cmd LC_RPATH\s+cmdsize \d+\s+path (.+?) \(offset \d+\)", load_commands)
    if len(names) != 1 or len(paths) != len(set(paths)):
        raise NativeUiArtifactError("UI library has an invalid install name or repeated rpath")
    return names[0], paths


def verify_load_paths(load_commands: str, linked_libraries: str) -> None:
    name, paths = macho_load_paths(load_commands)
    if name != INSTALL_NAME:
        raise NativeUiArtifactError("UI library install name is not package-relative")
    if any(path not in {"/usr/lib/swift", "@loader_path"} for path in paths):
        raise NativeUiArtifactError("UI library retains a build-directory or unexpected rpath")
    dependencies = [line.strip().split(" (", 1)[0] for line in linked_libraries.splitlines()[1:]]
    if not dependencies or dependencies[0] != INSTALL_NAME:
        raise NativeUiArtifactError("UI library identity differs between Mach-O load commands")
    for dependency in dependencies[1:]:
        if not dependency.startswith(("/System/Library/", "/usr/lib/")) or "/../" in dependency:
            raise NativeUiArtifactError(f"UI library has a non-system runtime dependency: {dependency}")


def verify_component_exports(symbols: str) -> None:
    exports = {line.split()[-1][1:] for line in symbols.splitlines()
               if line.split() and line.split()[-1].startswith("_cfm_")}
    if exports != COMPONENT_EXPORTS:
        raise NativeUiArtifactError(
            "Release UI C exports differ from the component ABI: "
            f"missing={sorted(COMPONENT_EXPORTS - exports)}, extra={sorted(exports - COMPONENT_EXPORTS)}"
        )


def verify_library(library: Path) -> None:
    regular(library, mode=0o755)
    if command(["/usr/bin/lipo", "-archs", str(library)]).strip() != "arm64":
        raise NativeUiArtifactError("UI library must be thin arm64")
    build = command(["/usr/bin/xcrun", "vtool", "-show-build", str(library)])
    if not re.search(r"\bplatform\s+MACOS\b", build) or not re.search(r"\bminos\s+15\.0(?:\s|$)", build):
        raise NativeUiArtifactError("UI library must support macOS 15.0")
    verify_load_paths(command(["/usr/bin/otool", "-l", str(library)]),
                      command(["/usr/bin/otool", "-L", str(library)]))
    verify_component_exports(command(["/usr/bin/nm", "-gU", str(library)]))


def remove_build_rpaths(library: Path) -> None:
    """Normalize only the selected Swift compiler's known compatibility rpath,
    before hashing or signing; never silently accept other injected search paths.
    """
    regular(library, mode=0o755)
    _, paths = macho_load_paths(command(["/usr/bin/otool", "-l", str(library)]))
    compiler = Path(command(["/usr/bin/xcrun", "--find", "swift"]).strip())
    toolchain = compiler.parent.parent
    allowed_compiler_path = re.compile(re.escape(str(toolchain / "lib")) + r"/swift(?:-[0-9]+\.[0-9]+)?/macosx\Z")
    compiler_paths = [path for path in paths if path not in {"/usr/lib/swift", "@loader_path"}]
    for path in compiler_paths:
        if not allowed_compiler_path.fullmatch(path):
            raise NativeUiArtifactError(f"unexpected Swift compiler search path: {path}")
    if compiler_paths:
        # install_name_tool may report the now-invalid compiler ad-hoc signature;
        # remove it first. Developer ID signing happens only in the signing lane.
        command(["/usr/bin/codesign", "--remove-signature", str(library)])
    for path in compiler_paths:
        command(["/usr/bin/install_name_tool", "-delete_rpath", path, str(library)])
    verify_library(library)


def verify_resources(resources: Path) -> None:
    if resources.is_symlink() or not resources.is_dir() or stat.S_IMODE(resources.stat().st_mode) != 0o755:
        raise NativeUiArtifactError("UI resource bundle must be a real distribution directory")
    for directory, names, files in os.walk(resources, followlinks=False):
        for name in names:
            path = Path(directory) / name
            if path.is_symlink() or not path.is_dir() or stat.S_IMODE(path.stat().st_mode) != 0o755:
                raise NativeUiArtifactError(f"unsafe UI resource directory: {path}")
        for name in files:
            regular(Path(directory) / name, mode=0o644)
    info = plistlib.loads((resources / "Contents/Info.plist").read_bytes())
    for key, value in {"CFBundleDevelopmentRegion": "en", "CFBundlePackageType": "BNDL",
                       "CFBundleName": "CFMNativeDashboard_CFMNativeDashboard",
                       "CFBundleSupportedPlatforms": ["MacOSX"], "LSMinimumSystemVersion": "15.0"}.items():
        if info.get(key) != value:
            raise NativeUiArtifactError(f"UI resource bundle has unexpected {key}")
    resource_root = resources / "Contents/Resources"
    actual = {path.name[:-6] for path in resource_root.glob("*.lproj")}
    if actual != LOCALES:
        raise NativeUiArtifactError("UI resource bundle must contain the four supported languages")
    for locale in LOCALES:
        path = resource_root / (locale + ".lproj") / "Localizable.strings"
        regular(path, mode=0o644)
        if not path.read_bytes():
            raise NativeUiArtifactError(f"UI localization is empty: {locale}")


def verify_products(repository: Path, products: Path, *, build: str, signing: str = "pre-sign") -> None:
    expected = expected_metadata(repository, build, signing=signing, clean=False)
    pre_sign_products = None
    if signing == "developer-id":
        if __package__:
            from .release_build_identity import preview_native_products_root
            from .promote_signed_native_manifest import verify_promoted_manifest
        else:
            from release_build_identity import preview_native_products_root
            from promote_signed_native_manifest import verify_promoted_manifest
        pre_sign_products = preview_native_products_root(repository)
        verify_products(repository, pre_sign_products, build=build, signing="pre-sign")
    verify_library(products / LIBRARY)
    verify_resources(products / RESOURCES)
    for name in (LIBRARY, RESOURCES):
        path = products / (name + ".manifest.json")
        regular(path, mode=0o644)
        value = json.loads(path.read_text())
        artifact_metadata = expected
        if pre_sign_products is not None:
            promoted = verify_promoted_manifest(
                pre_sign_products / name,
                pre_sign_products / (name + ".manifest.json"),
                products / name, path,
            )
            artifact_metadata = promoted["metadata"]
            public_metadata = {key: item for key, item in artifact_metadata.items()
                               if key not in {"preSignArtifactSha256", "preSignManifestSha256"}}
            if public_metadata != expected:
                raise NativeUiArtifactError(f"signed UI artifact changed its Release inputs: {name}")
            if name == RESOURCES and build_manifest(products / name) != build_manifest(pre_sign_products / name):
                raise NativeUiArtifactError("signing must not modify SwiftUI localization resources")
        if not isinstance(value, dict) or value.get("metadata") != artifact_metadata:
            raise NativeUiArtifactError(f"UI artifact is not bound to these Release inputs: {name}")
        if value != build_manifest(products / name, metadata=artifact_metadata):
            raise NativeUiArtifactError(f"UI artifact bytes differ from the recorded manifest: {name}")


def build_products(repository: Path, products: Path, *, build: str) -> None:
    if __package__:
        from .release_build_identity import preview_native_products_root, preview_preflight_root
    else:
        from release_build_identity import preview_native_products_root, preview_preflight_root
    expected_root = preview_native_products_root(repository)
    if products != expected_root or not products.is_dir() or products.resolve(strict=True) != products:
        raise NativeUiArtifactError("UI products must be built inside the exact preview preflight")
    metadata = expected_metadata(repository, build, signing="pre-sign", clean=True)
    for name in (LIBRARY, RESOURCES, LIBRARY + ".manifest.json", RESOURCES + ".manifest.json"):
        path = products / name
        if path.exists() or path.is_symlink():
            raise NativeUiArtifactError(f"refusing to replace an existing UI product: {path}")
    scratch = preview_preflight_root(repository) / "swift-ui-build"
    scratch.mkdir(mode=0o700)
    arguments = ["/usr/bin/xcrun", "swift", "build", "--package-path", str(repository / "native/dashboard"),
                 "--scratch-path", str(scratch), "--configuration", "release", "--triple", TRIPLE,
                 "--build-system", "swiftbuild", "--disable-automatic-resolution", "--product", "CFMNativeDashboard", "-Xswiftc", "-warnings-as-errors"]
    # Keep the compiler's full output in the candidate journal even on failure.
    with (scratch / "build.log").open("x") as log:
        result = subprocess.run(arguments, check=False, stdout=log, stderr=subprocess.STDOUT, timeout=600)
    if result.returncode:
        raise NativeUiArtifactError(f"SwiftUI Release build failed; retained {scratch / 'build.log'}")
    output = Path(command(arguments[:arguments.index("--product")] + ["--show-bin-path"]).strip())
    shutil.copyfile(output / LIBRARY, products / LIBRARY)
    os.chmod(products / LIBRARY, 0o755)
    shutil.copytree(output / RESOURCES, products / RESOURCES)
    remove_build_rpaths(products / LIBRARY)
    verify_resources(products / RESOURCES)
    if expected_metadata(repository, build, signing="pre-sign", clean=True) != metadata:
        raise NativeUiArtifactError("SwiftUI source or compiler changed during the build")
    for name in (LIBRARY, RESOURCES):
        with (products / (name + ".manifest.json")).open("x") as handle:
            json.dump(build_manifest(products / name, metadata=metadata), handle, sort_keys=True, indent=2)
            handle.write("\n")
        os.chmod(products / (name + ".manifest.json"), 0o644)
    verify_products(repository, products, build=build)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("build", "verify"))
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--products", type=Path, required=True)
    parser.add_argument("--build-number", required=True)
    arguments = parser.parse_args()
    try:
        repository = arguments.repository.resolve(strict=True)
        if arguments.operation == "build":
            build_products(repository, arguments.products, build=arguments.build_number)
        else:
            verify_products(repository, arguments.products, build=arguments.build_number)
    except (OSError, ValueError, subprocess.SubprocessError) as error:
        parser.exit(1, f"error: native UI artifact: {error}\n")
    print("native UI Release code/resources verified against source, compiler and candidate identity")


if __name__ == "__main__":
    main()
