#!/usr/bin/env python3
"""Offline, fail-closed verifier for the design-pinned libbox and toolchain inputs.

This static verifier binds the pinned-input manifest (scripts/pinned_build_inputs.json)
to the tracked release configuration without invoking any toolchain or the network:

* every pinned tool version and the sing-box upstream commit in
  scripts/dependency_pins.env match the manifest exactly;
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


def _verify_commit(manifest: dict, env: dict[str, str]) -> None:
    key = manifest.get("singBoxCommitKey")
    expected = manifest.get("singBoxCommit")
    if not isinstance(key, str) or not isinstance(expected, str):
        raise PinnedInputError("pinned-input manifest has no sing-box commit binding")
    if not re.fullmatch(r"[0-9a-f]{40}", expected):
        raise PinnedInputError("pinned sing-box commit is not a 40-hex commit hash")
    actual = _require_env(env, key)
    if actual != expected:
        raise PinnedInputError(
            f"pinned sing-box commit must be {expected} but dependency_pins.env has {actual}"
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
    _verify_commit(manifest, env)
    patch_digests = _verify_patches(manifest, env, repository)
    _verify_combined_diff(manifest, env, patch_digests)
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
        "pinned build inputs verified: Rust/Node/Go/gomobile/govulncheck/sing-box "
        "versions, commit, three patch digests, combined diff, Go module inputs, "
        "libbox build tags required by the engine start path, native lock binding, "
        "and offline artifact-hash build-script references"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
