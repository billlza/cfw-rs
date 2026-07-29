#!/usr/bin/env python3
"""Offline, fail-closed verifier for the design-pinned libbox and toolchain inputs.

This static verifier binds the pinned-input manifest (scripts/pinned_build_inputs.json)
to the tracked release configuration without invoking any toolchain or the network:

* every pinned tool version and the sing-box/gomobile upstream commits in
  scripts/dependency_pins.env match the manifest exactly;
* cargo-deny's CI install consumes the release pin with ``--locked`` and the
  release gate checks the exact Apple Silicon target graph;
* the XcodeGen installed-resource patch and patched source digest are bound to
    the isolated bootstrap and its installed-resource probe;
* the official Tauri CLI crate, its published lock, the narrow yanked-spin lock
  update, and the resulting lock are checksum-bound to one installer entrypoint;
* the three design-pinned patch files exist as regular files and their computed
  SHA-256 digests match both the manifest and dependency_pins.env;
* the combined diff SHA-256 is pinned and is distinct from any single patch digest;
* known legacy/partial patch digests are rejected;
* the verified Go module inputs (module sums and go.mod/go.sum digests) are present
  and well formed;
* the pinned libbox Go build tag list is exactly the pinned value, is well formed,
  and contains every tag the engine start path requires — including the tags whose
  omission would make ``box.New`` fail on every start;
* the native dependency lock agrees with the pins (source-tree binding);
* the offline libbox build script references the pins with no floating versions and
  no network or recursive build actions;
* the build scripts bind the pinned commit, patch, and combined-diff hashes into the
  produced artifact manifests (artifact-hash bindings).

Any unavailable, missing, malformed, wrong, or partial input fails closed.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from pathlib import Path

MANIFEST_RELATIVE_PATH = "scripts/pinned_build_inputs.json"
_SHA256_RE = re.compile(r"\A[0-9a-f]{64}\Z")
_ENV_LINE_RE = re.compile(r"\A([A-Za-z_][A-Za-z0-9_]*)=(.*)\Z")
_NETWORK_RECURSION_RE = re.compile(
    r"git\s+clone|https?://|(?<![A-Za-z])curl(?![A-Za-z])|"
    r"(?<![A-Za-z])wget(?![A-Za-z])|go\s+get|go\s+install|GOPROXY\s*=\s*https?",
    re.IGNORECASE,
)


class PinnedInputError(RuntimeError):
    """Raised when any pinned build input cannot be proven correct."""


def _read_text(path: Path, description: str) -> str:
    if path.is_symlink() or not path.is_file():
        raise PinnedInputError(f"{description} is missing or is not a regular file: {path}")
    try:
        return path.read_text(encoding="utf-8")
    except OSError as error:
        raise PinnedInputError(f"{description} cannot be read: {error}") from error


def _load_manifest(repository: Path) -> dict:
    manifest_path = repository / MANIFEST_RELATIVE_PATH
    text = _read_text(manifest_path, "pinned-input manifest")
    try:
        manifest = json.loads(text)
    except json.JSONDecodeError as error:
        raise PinnedInputError(f"pinned-input manifest is malformed: {error}") from error
    if not isinstance(manifest, dict) or manifest.get("schema") != "cfw-pinned-build-inputs-v1":
        raise PinnedInputError("pinned-input manifest has an unsupported schema")
    return manifest


def _parse_env(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        match = _ENV_LINE_RE.match(line)
        if not match:
            raise PinnedInputError(f"dependency_pins.env line {number} is malformed: {raw!r}")
        key, value = match.group(1), match.group(2)
        if key in values:
            raise PinnedInputError(f"dependency_pins.env defines {key} more than once")
        values[key] = value
    return values


def _require_env(env: dict[str, str], key: str) -> str:
    if key not in env:
        raise PinnedInputError(f"dependency_pins.env is missing required pin {key}")
    value = env[key]
    if value == "":
        raise PinnedInputError(f"dependency_pins.env pin {key} is empty")
    return value


def _require_sha256(value: str, description: str) -> str:
    if not _SHA256_RE.match(value):
        raise PinnedInputError(f"{description} is not a lowercase 64-hex SHA-256: {value!r}")
    return value


def _safe_repository_path(repository: Path, relative: str, description: str) -> Path:
    candidate = Path(relative)
    if candidate.is_absolute() or not candidate.parts:
        raise PinnedInputError(f"{description} path is not repository-relative: {relative!r}")
    if any(part in ("", ".", "..") for part in candidate.parts):
        raise PinnedInputError(f"{description} path has an unsafe component: {relative!r}")
    return repository.joinpath(*candidate.parts)


def _verify_tools(manifest: dict, env: dict[str, str]) -> None:
    tools = manifest.get("tools")
    if not isinstance(tools, dict) or not tools:
        raise PinnedInputError("pinned-input manifest has no tools table")
    for key, expected in tools.items():
        actual = _require_env(env, key)
        if actual != expected:
            raise PinnedInputError(
                f"pinned tool {key} must be {expected!r} but dependency_pins.env has {actual!r}"
            )


def _verify_cargo_deny(manifest: dict, repository: Path) -> None:
    spec = manifest.get("cargoDeny")
    if not isinstance(spec, dict):
        raise PinnedInputError("pinned-input manifest has no cargo-deny CI binding")
    workflow_relative = spec.get("ciWorkflowPath")
    fragments = spec.get("requiredCiFragments")
    if (
        not isinstance(workflow_relative, str)
        or not isinstance(fragments, list)
        or not fragments
    ):
        raise PinnedInputError("cargo-deny CI binding is incomplete")
    workflow = _read_text(
        _safe_repository_path(repository, workflow_relative, "cargo-deny CI workflow"),
        "cargo-deny CI workflow",
    )
    for fragment in fragments:
        if not isinstance(fragment, str) or not fragment or fragment not in workflow:
            raise PinnedInputError(
                f"cargo-deny CI workflow lacks required pinned fragment {fragment!r}"
            )
    if re.search(
        r"cargo\s+install\s+cargo-deny\s+--version\s+['\"]?[0-9]", workflow
    ):
        raise PinnedInputError(
            "cargo-deny CI install hard-codes a version outside release pins"
        )


def _verify_xcodegen(manifest: dict, env: dict[str, str], repository: Path) -> None:
    spec = manifest.get("xcodegen")
    if not isinstance(spec, dict):
        raise PinnedInputError("pinned-input manifest has no XcodeGen patch binding")

    patch_path_key = spec.get("patchPathKey")
    patch_sha_key = spec.get("patchSha256Key")
    patched_source_sha_key = spec.get("patchedSettingsBuilderSha256Key")
    if not all(
        isinstance(value, str)
        for value in (patch_path_key, patch_sha_key, patched_source_sha_key)
    ):
        raise PinnedInputError("XcodeGen patch binding has incomplete pin keys")
    expected_patch_sha = spec.get("patchSha256")
    expected_patched_source_sha = spec.get("patchedSettingsBuilderSha256")
    if not isinstance(expected_patch_sha, str) or not isinstance(
        expected_patched_source_sha, str
    ):
        raise PinnedInputError("XcodeGen patch binding has incomplete digests")
    _require_sha256(expected_patch_sha, "manifest XcodeGen patch digest")
    _require_sha256(
        expected_patched_source_sha, "manifest patched SettingsBuilder digest"
    )
    if _require_env(env, patch_sha_key) != expected_patch_sha:
        raise PinnedInputError("XcodeGen patch digest differs from the manifest")
    if _require_env(env, patched_source_sha_key) != expected_patched_source_sha:
        raise PinnedInputError(
            "XcodeGen patched SettingsBuilder digest differs from the manifest"
        )

    patch_relative = _require_env(env, patch_path_key)
    patch_path = _safe_repository_path(repository, patch_relative, "XcodeGen patch")
    if patch_path.is_symlink() or not patch_path.is_file():
        raise PinnedInputError(
            f"XcodeGen patch is missing or not a regular file: {patch_relative}"
        )
    try:
        actual_patch_sha = hashlib.sha256(patch_path.read_bytes()).hexdigest()
    except OSError as error:
        raise PinnedInputError(f"XcodeGen patch cannot be read: {error}") from error
    if actual_patch_sha != expected_patch_sha:
        raise PinnedInputError(
            f"XcodeGen patch file digest {actual_patch_sha} differs from the pinned "
            f"{expected_patch_sha}"
        )

    bootstrap_relative = spec.get("bootstrapPath")
    fragments = spec.get("requiredBootstrapFragments")
    if (
        not isinstance(bootstrap_relative, str)
        or not isinstance(fragments, list)
        or not fragments
    ):
        raise PinnedInputError("XcodeGen bootstrap binding is incomplete")
    bootstrap = _read_text(
        _safe_repository_path(repository, bootstrap_relative, "XcodeGen bootstrap"),
        "XcodeGen bootstrap",
    )
    for fragment in fragments:
        if not isinstance(fragment, str) or not fragment or fragment not in bootstrap:
            raise PinnedInputError(
                f"XcodeGen bootstrap lacks required pinned fragment {fragment!r}"
            )


def _verify_tauri_cli(manifest: dict, env: dict[str, str], repository: Path) -> None:
    spec = manifest.get("tauriCli")
    if not isinstance(spec, dict):
        raise PinnedInputError("pinned-input manifest has no Tauri CLI source binding")

    digest_pairs = (
        ("crateSha256Key", "crateSha256", "Tauri CLI crate"),
        (
            "upstreamCargoLockSha256Key",
            "upstreamCargoLockSha256",
            "Tauri CLI upstream Cargo.lock",
        ),
        ("lockPatchSha256Key", "lockPatchSha256", "Tauri CLI lock patch"),
        (
            "patchedCargoLockSha256Key",
            "patchedCargoLockSha256",
            "Tauri CLI patched Cargo.lock",
        ),
        ("spinCrateSha256Key", "spinCrateSha256", "Tauri CLI spin crate"),
    )
    for key_field, value_field, description in digest_pairs:
        key = spec.get(key_field)
        expected = spec.get(value_field)
        if not isinstance(key, str) or not isinstance(expected, str):
            raise PinnedInputError(f"{description} has no complete digest binding")
        _require_sha256(expected, f"manifest digest for {description}")
        actual = _require_env(env, key)
        _require_sha256(actual, f"dependency_pins.env value {key}")
        if actual != expected:
            raise PinnedInputError(
                f"{description} digest {key} is {actual} but must be {expected}"
            )

    spin_version_key = spec.get("spinVersionKey")
    spin_version = spec.get("spinVersion")
    if not isinstance(spin_version_key, str) or not isinstance(spin_version, str):
        raise PinnedInputError("Tauri CLI spin replacement has no version binding")
    if not re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", spin_version):
        raise PinnedInputError("Tauri CLI spin replacement version is malformed")
    if _require_env(env, spin_version_key) != spin_version:
        raise PinnedInputError("Tauri CLI spin replacement version differs from the manifest")

    patch_path_key = spec.get("lockPatchPathKey")
    if not isinstance(patch_path_key, str):
        raise PinnedInputError("Tauri CLI lock patch has no path binding")
    patch_relative = _require_env(env, patch_path_key)
    patch_path = _safe_repository_path(repository, patch_relative, "Tauri CLI lock patch")
    if patch_path.is_symlink() or not patch_path.is_file():
        raise PinnedInputError(
            f"Tauri CLI lock patch is missing or not a regular file: {patch_relative}"
        )
    try:
        computed_patch_sha = hashlib.sha256(patch_path.read_bytes()).hexdigest()
    except OSError as error:
        raise PinnedInputError(f"Tauri CLI lock patch cannot be read: {error}") from error
    if computed_patch_sha != spec["lockPatchSha256"]:
        raise PinnedInputError(
            f"Tauri CLI lock patch digest {computed_patch_sha} differs from the pinned "
            f"{spec['lockPatchSha256']}"
        )

    installer_relative = spec.get("installerPath")
    fragments = spec.get("requiredInstallerFragments")
    if not isinstance(installer_relative, str) or not isinstance(fragments, list) or not fragments:
        raise PinnedInputError("Tauri CLI installer binding is incomplete")
    installer = _read_text(
        _safe_repository_path(repository, installer_relative, "Tauri CLI installer"),
        "Tauri CLI installer",
    )
    for fragment in fragments:
        if not isinstance(fragment, str) or not fragment or fragment not in installer:
            raise PinnedInputError(
                f"Tauri CLI installer does not contain required pinned fragment {fragment!r}"
            )
    if re.search(r"cargo\s+install\s+tauri-cli", installer):
        raise PinnedInputError(
            "Tauri CLI installer bypasses the checksum-bound local --path source"
        )

    workflow_relative = spec.get("ciWorkflowPath")
    required_ci_fragment = spec.get("requiredCiFragment")
    if not isinstance(workflow_relative, str) or not isinstance(required_ci_fragment, str):
        raise PinnedInputError("Tauri CLI CI binding is incomplete")
    workflow = _read_text(
        _safe_repository_path(repository, workflow_relative, "CI workflow"),
        "CI workflow",
    )
    if required_ci_fragment not in workflow:
        raise PinnedInputError("CI does not use the checksum-bound Tauri CLI installer")
    if re.search(r"cargo\s+install\s+tauri-cli", workflow):
        raise PinnedInputError("CI still contains a floating direct Tauri CLI installation")


def _verify_commits(manifest: dict, env: dict[str, str]) -> None:
    for prefix, description in (
        ("singBox", "sing-box"),
        ("gomobile", "gomobile"),
    ):
        key = manifest.get(f"{prefix}CommitKey")
        expected = manifest.get(f"{prefix}Commit")
        if not isinstance(key, str) or not isinstance(expected, str):
            raise PinnedInputError(
                f"pinned-input manifest has no {description} commit binding"
            )
        if not re.fullmatch(r"[0-9a-f]{40}", expected):
            raise PinnedInputError(
                f"pinned {description} commit is not a 40-hex commit hash"
            )
        actual = _require_env(env, key)
        if actual != expected:
            raise PinnedInputError(
                f"pinned {description} commit must be {expected} but "
                f"dependency_pins.env has {actual}"
            )


def _verify_patches(manifest: dict, env: dict[str, str], repository: Path) -> list[str]:
    patches = manifest.get("patches")
    if not isinstance(patches, list) or len(patches) != 3:
        raise PinnedInputError("pinned-input manifest must pin exactly three patches")
    rejected = set(manifest.get("rejectedPatchDigests") or [])
    seen: set[str] = set()
    digests: list[str] = []
    for patch in patches:
        if not isinstance(patch, dict):
            raise PinnedInputError("pinned-input manifest has a malformed patch entry")
        name = patch.get("name", "<unnamed>")
        path_key = patch.get("pathKey")
        sha_key = patch.get("sha256Key")
        expected = patch.get("sha256")
        if not all(isinstance(item, str) for item in (path_key, sha_key, expected)):
            raise PinnedInputError(f"patch entry {name} is missing pin keys")
        _require_sha256(expected, f"manifest digest for {name}")
        if expected in rejected:
            raise PinnedInputError(f"patch {name} pins a rejected/legacy digest: {expected}")
        if expected in seen:
            raise PinnedInputError(f"patch {name} reuses another patch digest: {expected}")
        seen.add(expected)

        env_sha = _require_env(env, sha_key)
        _require_sha256(env_sha, f"dependency_pins.env value {sha_key}")
        if env_sha != expected:
            raise PinnedInputError(
                f"patch {name} digest {sha_key} is {env_sha} but must be {expected}"
            )
        if env_sha in rejected:
            raise PinnedInputError(f"patch {name} pins a rejected/legacy digest: {env_sha}")

        relative = _require_env(env, path_key)
        patch_path = _safe_repository_path(repository, relative, name)
        if patch_path.is_symlink() or not patch_path.is_file():
            raise PinnedInputError(f"patch {name} file is missing or not regular: {relative}")
        try:
            computed = hashlib.sha256(patch_path.read_bytes()).hexdigest()
        except OSError as error:
            raise PinnedInputError(f"patch {name} file cannot be read: {error}") from error
        if computed != expected:
            raise PinnedInputError(
                f"patch {name} file digest {computed} differs from the pinned {expected}"
            )
        digests.append(expected)
    return digests


def _verify_combined_diff(
    manifest: dict, env: dict[str, str], patch_digests: list[str]
) -> None:
    key = manifest.get("combinedDiffSha256Key")
    expected = manifest.get("combinedDiffSha256")
    if not isinstance(key, str) or not isinstance(expected, str):
        raise PinnedInputError("pinned-input manifest has no combined diff binding")
    _require_sha256(expected, "manifest combined diff digest")
    actual = _require_env(env, key)
    _require_sha256(actual, f"dependency_pins.env value {key}")
    if actual != expected:
        raise PinnedInputError(
            f"combined diff digest must be {expected} but dependency_pins.env has {actual}"
        )
    if actual in patch_digests:
        raise PinnedInputError(
            "combined diff digest equals a single patch digest; partial digest rejected"
        )
    partial = env.get("SING_BOX_PATCHED_DIFF_SHA256")
    if partial is not None and actual == partial:
        raise PinnedInputError(
            "combined diff digest equals the partial go.mod/go.sum diff digest"
        )


def _verify_source_contract(manifest: dict, env: dict[str, str]) -> None:
    contract = manifest.get("sourceContract")
    if not isinstance(contract, dict):
        raise PinnedInputError("pinned-input manifest has no source contract binding")
    for name in ("patchedDiffSha256", "patchedGoModSha256", "patchedGoSumSha256"):
        key = contract.get(f"{name}Key")
        expected = contract.get(name)
        if not isinstance(key, str) or not isinstance(expected, str):
            raise PinnedInputError(f"source contract is missing {name} binding")
        _require_sha256(expected, f"manifest source contract {name}")
        actual = _require_env(env, key)
        _require_sha256(actual, f"dependency_pins.env value {key}")
        if actual != expected:
            raise PinnedInputError(
                f"source contract {name} must be {expected} but dependency_pins.env has {actual}"
            )


def _verify_go_module_inputs(manifest: dict, env: dict[str, str]) -> None:
    keys = manifest.get("verifiedGoModuleInputKeys")
    if not isinstance(keys, list) or not keys:
        raise PinnedInputError("pinned-input manifest has no verified Go module input keys")
    for key in keys:
        value = _require_env(env, key)
        if key.endswith("_SHA256"):
            _require_sha256(value, f"dependency_pins.env value {key}")
        elif not value.startswith("h1:"):
            raise PinnedInputError(f"Go module sum {key} is not an h1: checksum: {value!r}")


def _verify_libbox_build_tags(manifest: dict, env: dict[str, str], repository: Path) -> None:
    """Bind the pinned libbox Go build tag list to the tags the engine requires.

    The tag list is a build input exactly like a version or a digest: omitting a
    tag silently removes compiled-in behaviour the runtime depends on. The
    ``with_clash_api`` omission made ``box.New`` fail on every engine start
    because the patched tree enables the clash API whenever a platform log writer
    is installed and the daemon always installs one, so the stub constructor
    returned an error instead of a server. This check therefore pins the exact
    tag list, requires each tag the start path needs, and additionally binds
    tracked source triggers (such as the application-owned
    ``experimental.clash_api`` projection block) to the tag that makes them
    reachable, so the same class of defect fails closed statically.
    """
    spec = manifest.get("libboxBuildTags")
    if not isinstance(spec, dict):
        raise PinnedInputError("pinned-input manifest has no libbox build tag binding")
    pin_key = spec.get("pinKey")
    expected_value = spec.get("value")
    if not isinstance(pin_key, str) or not isinstance(expected_value, str):
        raise PinnedInputError("libbox build tag binding has no pin key or pinned value")
    actual_value = _require_env(env, pin_key)
    if actual_value != expected_value:
        raise PinnedInputError(
            f"pinned libbox build tags {pin_key} must be {expected_value!r} but "
            f"dependency_pins.env has {actual_value!r}"
        )

    tags: list[str] = actual_value.split(",")
    seen: set[str] = set()
    for tag in tags:
        if not re.fullmatch(r"[a-z0-9_]+", tag):
            raise PinnedInputError(f"pinned libbox build tag is malformed: {tag!r}")
        if tag in seen:
            raise PinnedInputError(f"pinned libbox build tags repeat {tag!r}")
        seen.add(tag)

    required = spec.get("required")
    if not isinstance(required, list) or not required:
        raise PinnedInputError("libbox build tag binding pins no required tags")
    for entry in required:
        if not isinstance(entry, dict):
            raise PinnedInputError("libbox required-tag entry is malformed")
        tag = entry.get("tag")
        reason = entry.get("reason")
        if not isinstance(tag, str) or not tag:
            raise PinnedInputError("libbox required-tag entry has no tag")
        if not isinstance(reason, str) or not reason:
            raise PinnedInputError(f"libbox required tag {tag} has no recorded reason")
        if tag not in seen:
            raise PinnedInputError(
                f"pinned libbox build tags are missing the required tag {tag!r}: {reason}"
            )

    for binding in spec.get("engineStartPathBindings") or []:
        if not isinstance(binding, dict):
            raise PinnedInputError("libbox tag source binding is malformed")
        tag = binding.get("tag")
        relative = binding.get("path")
        trigger = binding.get("requiredWhenContains")
        reason = binding.get("reason")
        if not all(isinstance(item, str) and item for item in (tag, relative, trigger, reason)):
            raise PinnedInputError("libbox tag source binding is incomplete")
        text = _read_text(
            _safe_repository_path(repository, relative, "libbox tag source binding"),
            f"libbox tag source binding {relative}",
        )
        present = trigger in text
        if binding.get("triggerRequired") and not present:
            raise PinnedInputError(
                f"{relative} no longer contains the pinned tag trigger {trigger!r}; "
                f"re-pin the libbox build tags deliberately ({reason})"
            )
        if present and tag not in seen:
            raise PinnedInputError(
                f"{relative} requires libbox build tag {tag!r} but the pinned tag list "
                f"omits it: {reason}"
            )


def _verify_native_lock(manifest: dict, env: dict[str, str], repository: Path) -> None:
    relative = manifest.get("nativeLockPath")
    if not isinstance(relative, str):
        raise PinnedInputError("pinned-input manifest has no native lock path")
    lock_path = _safe_repository_path(repository, relative, "native dependency lock")
    text = _read_text(lock_path, "native dependency lock")
    try:
        lock = json.loads(text)
    except json.JSONDecodeError as error:
        raise PinnedInputError(f"native dependency lock is malformed: {error}") from error

    def _expect(actual: object, expected: str, label: str) -> None:
        if actual != expected:
            raise PinnedInputError(
                f"native dependency lock {label} is {actual!r} but must be {expected!r}"
            )

    sing_box = lock.get("singBox")
    if not isinstance(lock, dict) or not isinstance(sing_box, dict):
        raise PinnedInputError("native dependency lock has no singBox table")
    _expect(lock.get("go"), _require_env(env, "GO_VERSION"), "go")
    _expect(lock.get("gomobile"), _require_env(env, "GOMOBILE_VERSION"), "gomobile")
    _expect(sing_box.get("tag"), _require_env(env, "SING_BOX_VERSION"), "singBox.tag")
    _expect(sing_box.get("commit"), _require_env(env, "SING_BOX_COMMIT"), "singBox.commit")
    _expect(
        sing_box.get("combinedDiffSha256"),
        _require_env(env, "SING_BOX_COMBINED_DIFF_SHA256"),
        "singBox.combinedDiffSha256",
    )
    lock_patches = {
        "securityPatch": ("SING_BOX_SECURITY_PATCH_PATH", "SING_BOX_SECURITY_PATCH_SHA256"),
        "rawPacketPatch": ("SING_BOX_RAW_PACKET_PATCH_PATH", "SING_BOX_RAW_PACKET_PATCH_SHA256"),
        "dnsFailoverPatch": ("SING_BOX_DNS_FAILOVER_PATCH_PATH", "SING_BOX_DNS_FAILOVER_PATCH_SHA256"),
    }
    for lock_key, (path_key, sha_key) in lock_patches.items():
        entry = sing_box.get(lock_key)
        if not isinstance(entry, dict):
            raise PinnedInputError(f"native dependency lock has no {lock_key} entry")
        _expect(entry.get("path"), _require_env(env, path_key), f"singBox.{lock_key}.path")
        _expect(entry.get("sha256"), _require_env(env, sha_key), f"singBox.{lock_key}.sha256")
    security_patch = sing_box.get("securityPatch")
    assert isinstance(security_patch, dict)
    for lock_key, env_key in (
        ("patchedDiffSha256", "SING_BOX_PATCHED_DIFF_SHA256"),
        ("patchedGoModSha256", "SING_BOX_PATCHED_GO_MOD_SHA256"),
        ("patchedGoSumSha256", "SING_BOX_PATCHED_GO_SUM_SHA256"),
    ):
        _expect(
            security_patch.get(lock_key),
            _require_env(env, env_key),
            f"singBox.securityPatch.{lock_key}",
        )


def _verify_build_scripts(manifest: dict, repository: Path) -> None:
    build_scripts = manifest.get("buildScripts") or {}
    for relative, rules in build_scripts.items():
        text = _read_text(
            _safe_repository_path(repository, relative, "build script"),
            f"build script {relative}",
        )
        for reference in rules.get("requirePinReferences", []):
            if reference not in text:
                raise PinnedInputError(
                    f"build script {relative} does not reference pin {reference} (floating version risk)"
                )
        if rules.get("forbidNetworkRecursion"):
            match = _NETWORK_RECURSION_RE.search(text)
            if match:
                raise PinnedInputError(
                    f"build script {relative} contains a network or recursive action: {match.group(0)!r}"
                )

    artifact_bindings = manifest.get("artifactBindings") or {}
    for relative, bindings in artifact_bindings.items():
        text = _read_text(
            _safe_repository_path(repository, relative, "build script"),
            f"build script {relative}",
        )
        for binding in bindings:
            if binding not in text:
                raise PinnedInputError(
                    f"build script {relative} is missing artifact-hash binding {binding!r}"
                )


def verify(repository: Path) -> None:
    """Verify all pinned build inputs for the repository. Raises PinnedInputError."""
    manifest = _load_manifest(repository)
    env = _parse_env(
        _read_text(
            _safe_repository_path(
                repository,
                manifest.get("dependencyPinsPath", "scripts/dependency_pins.env"),
                "dependency pins",
            ),
            "dependency_pins.env",
        )
    )
    _verify_tools(manifest, env)
    _verify_cargo_deny(manifest, repository)
    _verify_xcodegen(manifest, env, repository)
    _verify_tauri_cli(manifest, env, repository)
    _verify_commits(manifest, env)
    patch_digests = _verify_patches(manifest, env, repository)
    _verify_combined_diff(manifest, env, patch_digests)
    _verify_source_contract(manifest, env)
    _verify_go_module_inputs(manifest, env)
    _verify_libbox_build_tags(manifest, env, repository)
    _verify_native_lock(manifest, env, repository)
    _verify_build_scripts(manifest, repository)


def main() -> int:
    repository = Path(__file__).resolve().parent.parent
    try:
        verify(repository)
    except PinnedInputError as error:
        print(f"error: pinned build inputs failed: {error}", file=sys.stderr)
        return 1
    print(
        "pinned build inputs verified: Rust/cargo-deny/Node/Go/gomobile/govulncheck/"
        "Tauri CLI/sing-box versions, checksum-bound Tauri CLI local-source installation, "
        "XcodeGen patch/source binding, sing-box and gomobile commits, three libbox patch "
        "digests, combined diff, Go module inputs, "
        "libbox build tags required by the engine start path, native lock binding, "
        "and offline artifact-hash build-script references"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
