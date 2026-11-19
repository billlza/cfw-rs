#!/usr/bin/env python3
"""Audit the exact shipped Rust target graph with RustSec.

Cargo.lock deliberately contains dependencies for every supported platform of
upstream crates.  cargo-audit's target flags filter advisory applicability but
do not remove packages that Cargo cannot resolve for the selected target.  This
script derives the reachable package inventory from `cargo metadata
--filter-platform`, emits a temporary audit-only lockfile, and runs cargo-audit
with warning advisories denied. It never ignores an advisory. Current yanked
status is owned by the mandatory cargo-deny gate, which uses the same target
and all-features graph and fails closed on registry or policy diagnostics.

Cargo also records an optional dependency that only a weak dependency feature
(`name?/feature`) names, in Cargo.lock and in the resolve graph, although only
`dep:name` or `name/feature` in an enabled feature builds it.  The walk
therefore follows a resolved dependency only when one of its declarations is
required or is enabled by a resolved feature of the dependent.  A resolved
edge, feature or declaration that the walk cannot account for fails closed.

The audited graph belongs to exactly one shipped program: ``--target`` names it
from the closed set in ``publication.rust_targets`` and defaults to the macOS
program, which the hosted macOS CI and the sealed lane transcription audit
without arguments.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Any, Mapping, Sequence

if __package__:
    from .publication.bounded_process import BoundedProcessError, run_bounded_process
    from .publication.rust_targets import MACOS_TARGET, SHIPPED_TARGETS
else:
    from publication.bounded_process import BoundedProcessError, run_bounded_process
    from publication.rust_targets import MACOS_TARGET, SHIPPED_TARGETS


METADATA_TIMEOUT_SECONDS = 300
AUDIT_TIMEOUT_SECONDS = 900
OUTPUT_LIMIT_BYTES = 64 * 1024 * 1024


class AuditContractError(RuntimeError):
    """The Cargo metadata or lockfile does not satisfy the audit contract."""


def _diagnostic_tail(stdout: bytes, stderr: bytes) -> str:
    encoded = (stderr or stdout)[-8192:]
    return encoded.decode("utf-8", errors="replace").strip()


def _bounded(
    command: Sequence[str],
    *,
    repository: Path,
    environment: Mapping[str, str],
    timeout: int,
    label: str,
) -> subprocess.CompletedProcess[bytes]:
    try:
        return run_bounded_process(
            command,
            cwd=repository,
            environment=environment,
            timeout=timeout,
            output_limit=OUTPUT_LIMIT_BYTES,
        )
    except BoundedProcessError as error:
        detail = _diagnostic_tail(error.stdout, error.stderr)
        raise AuditContractError(
            f"{label} failed its {error.reason} boundary"
            + (f": {detail}" if detail else "")
        ) from error


def _require_success_without_stderr(
    result: subprocess.CompletedProcess[bytes], label: str
) -> None:
    if result.returncode != 0:
        detail = _diagnostic_tail(result.stdout, result.stderr)
        raise AuditContractError(
            f"{label} failed with status {result.returncode}"
            + (f": {detail}" if detail else "")
        )
    if result.stderr:
        detail = _diagnostic_tail(b"", result.stderr)
        raise AuditContractError(
            f"{label} emitted diagnostics" + (f": {detail}" if detail else "")
        )


def _decode_utf8(encoded: bytes, label: str) -> str:
    try:
        return encoded.decode("utf-8")
    except UnicodeDecodeError as error:
        raise AuditContractError(f"{label} is not UTF-8") from error


def _packages_by_identifier(metadata: dict[str, Any]) -> dict[str, dict[str, Any]]:
    raw_packages = metadata.get("packages")
    if not isinstance(raw_packages, list):
        raise AuditContractError("cargo metadata has no package inventory")
    packages: dict[str, dict[str, Any]] = {}
    for package in raw_packages:
        if not isinstance(package, dict):
            raise AuditContractError("cargo metadata contains an invalid package")
        identifier = package.get("id")
        if not isinstance(identifier, str):
            raise AuditContractError("cargo metadata package identity is incomplete")
        if identifier in packages:
            raise AuditContractError(f"duplicate cargo package identifier: {identifier}")
        packages[identifier] = package
    return packages


def _enabled_dependency_keys(
    package: dict[str, Any], node: dict[str, Any], identifier: str
) -> set[str]:
    """Return the declaration keys that the resolved features of a package enable."""
    features = node.get("features")
    table = package.get("features")
    if not isinstance(features, list) or not isinstance(table, dict):
        raise AuditContractError(f"cargo metadata has no resolved features for {identifier}")
    enabled: set[str] = set()
    for feature in features:
        entries = table.get(feature) if isinstance(feature, str) else None
        if not isinstance(entries, list) or not all(isinstance(entry, str) for entry in entries):
            raise AuditContractError(f"{identifier} does not declare resolved feature {feature!r}")
        for entry in entries:
            if entry.startswith("dep:"):
                enabled.add(entry.removeprefix("dep:"))
            elif "/" in entry and "?/" not in entry:
                # `name/feature` enables `name`; the weak `name?/feature` does not.
                enabled.add(entry.split("/", 1)[0])
    return enabled


def _dependency_is_built(
    package: dict[str, Any],
    enabled: set[str],
    dependency: dict[str, Any],
    dependency_name: object,
    identifier: str,
) -> bool:
    """Whether a declaration behind a resolved edge is required or enabled.

    A kept edge lists the dependency's declarations for every platform, so a
    declaration for another platform can only add packages to the audit.
    """
    declarations = package.get("dependencies")
    extern_name = dependency.get("name")
    kinds = dependency.get("dep_kinds")
    if (
        not isinstance(declarations, list)
        or not all(isinstance(declaration, dict) for declaration in declarations)
        or not isinstance(dependency_name, str)
        or not isinstance(extern_name, str)
        or not isinstance(kinds, list)
        or not kinds
        or not all(isinstance(kind, dict) for kind in kinds)
    ):
        raise AuditContractError(f"resolve node contains an invalid dependency: {identifier}")
    named = [item for item in declarations if item.get("name") == dependency_name]
    renamed = [
        item
        for item in named
        if isinstance(item.get("rename"), str)
        and item["rename"].replace("-", "_") == extern_name
    ]
    candidates = renamed or [item for item in named if item.get("rename") is None]
    for kind in kinds:
        matching = [
            item
            for item in candidates
            if item.get("kind") == kind.get("kind") and item.get("target") == kind.get("target")
        ]
        if not matching or not all(isinstance(item.get("optional"), bool) for item in matching):
            raise AuditContractError(
                f"{identifier} has no declaration for resolved dependency {extern_name}"
            )
        if any(
            not item["optional"] or (item.get("rename") or item["name"]) in enabled
            for item in matching
        ):
            return True
    return False


def reachable_package_ids(metadata: dict[str, Any]) -> set[str]:
    resolve = metadata.get("resolve")
    workspace_members = metadata.get("workspace_members")
    if not isinstance(resolve, dict) or not isinstance(workspace_members, list):
        raise AuditContractError("cargo metadata has no complete resolve graph")

    raw_nodes = resolve.get("nodes")
    if not isinstance(raw_nodes, list):
        raise AuditContractError("cargo metadata resolve graph has no nodes")
    nodes: dict[str, dict[str, Any]] = {}
    for node in raw_nodes:
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            raise AuditContractError("cargo metadata contains an invalid resolve node")
        identifier = node["id"]
        if identifier in nodes:
            raise AuditContractError(f"duplicate cargo resolve node: {identifier}")
        nodes[identifier] = node

    packages = _packages_by_identifier(metadata)
    pending = list(workspace_members)
    reachable: set[str] = set()
    while pending:
        identifier = pending.pop()
        if not isinstance(identifier, str):
            raise AuditContractError("workspace package identifier is not a string")
        if identifier in reachable:
            continue
        node = nodes.get(identifier)
        if node is None:
            raise AuditContractError(
                f"workspace dependency is absent from target resolve graph: {identifier}"
            )
        package = packages.get(identifier)
        if package is None:
            raise AuditContractError(
                f"target resolve graph references a package missing from metadata: {identifier}"
            )
        reachable.add(identifier)
        dependencies = node.get("deps")
        if not isinstance(dependencies, list):
            raise AuditContractError(f"resolve node has no dependency list: {identifier}")
        enabled = _enabled_dependency_keys(package, node, identifier)
        for dependency in dependencies:
            child = dependency.get("pkg") if isinstance(dependency, dict) else None
            if not isinstance(child, str):
                raise AuditContractError(
                    f"resolve node contains an invalid dependency: {identifier}"
                )
            child_package = packages.get(child)
            if child_package is None:
                raise AuditContractError(
                    f"target resolve graph references a package missing from metadata: {child}"
                )
            if _dependency_is_built(
                package, enabled, dependency, child_package.get("name"), identifier
            ):
                pending.append(child)
    return reachable


def target_package_keys(metadata: dict[str, Any]) -> set[tuple[str, str, str | None]]:
    reachable = reachable_package_ids(metadata)
    by_identifier: dict[str, tuple[str, str, str | None]] = {}
    for identifier, package in _packages_by_identifier(metadata).items():
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or (source is not None and not isinstance(source, str))
        ):
            raise AuditContractError("cargo metadata package identity is incomplete")
        by_identifier[identifier] = (name, version, source)

    keys = {by_identifier[identifier] for identifier in reachable}
    if len(keys) != len(reachable):
        raise AuditContractError("target graph contains ambiguous package identities")
    return keys


def select_locked_packages(
    lock_data: dict[str, Any], keys: set[tuple[str, str, str | None]]
) -> list[dict[str, Any]]:
    if lock_data.get("version") != 4:
        raise AuditContractError("Cargo.lock must use lockfile format version 4")
    raw_packages = lock_data.get("package")
    if not isinstance(raw_packages, list):
        raise AuditContractError("Cargo.lock has no package inventory")

    selected: list[dict[str, Any]] = []
    matched: set[tuple[str, str, str | None]] = set()
    for package in raw_packages:
        if not isinstance(package, dict):
            raise AuditContractError("Cargo.lock contains an invalid package")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        if (
            not isinstance(name, str)
            or not isinstance(version, str)
            or (source is not None and not isinstance(source, str))
        ):
            raise AuditContractError("Cargo.lock package identity is incomplete")
        key = (name, version, source)
        if key not in keys:
            continue
        if key in matched:
            raise AuditContractError(f"duplicate Cargo.lock package identity: {key}")
        matched.add(key)
        selected.append(package)

    missing = keys.difference(matched)
    if missing:
        formatted = ", ".join(
            f"{name}@{version} ({source or 'workspace'})"
            for name, version, source in sorted(missing, key=lambda item: str(item))
        )
        raise AuditContractError(f"target packages are absent from Cargo.lock: {formatted}")
    return sorted(
        selected,
        key=lambda package: (
            package["name"],
            package["version"],
            package.get("source") or "",
        ),
    )


def toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=True)


def render_audit_lock(packages: list[dict[str, Any]], target: str) -> str:
    lines = [
        "# Generated from Cargo's exact target resolve graph; do not publish as Cargo.lock.",
        f"# target = {target}",
        "version = 4",
        "",
    ]
    for package in packages:
        lines.extend(
            [
                "[[package]]",
                f"name = {toml_string(package['name'])}",
                f"version = {toml_string(package['version'])}",
            ]
        )
        for key in ("source", "checksum"):
            value = package.get(key)
            if value is not None:
                if not isinstance(value, str):
                    raise AuditContractError(f"Cargo.lock package {key} is not a string")
                lines.append(f"{key} = {toml_string(value)}")
        lines.append("")
    return "\n".join(lines)


def parse_audit_result(encoded: str, expected_package_count: int) -> None:
    try:
        result = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise AuditContractError(f"cargo audit returned invalid JSON: {error}") from error
    lockfile = result.get("lockfile")
    if not isinstance(lockfile, dict) or lockfile.get("dependency-count") != expected_package_count:
        raise AuditContractError("cargo audit did not inspect the complete target inventory")
    vulnerabilities = result.get("vulnerabilities")
    if not isinstance(vulnerabilities, dict) or vulnerabilities.get("count") != 0:
        raise AuditContractError("cargo audit reported a vulnerability")
    warnings = result.get("warnings")
    if not isinstance(warnings, dict):
        raise AuditContractError("cargo audit returned no warning inventory")
    warning_count = sum(
        len(items) if isinstance(items, list) else 1 for items in warnings.values()
    )
    if warning_count != 0:
        raise AuditContractError(f"cargo audit reported {warning_count} warning advisories")


def run(repository: Path, no_fetch: bool, target: str) -> int:
    cargo_value = os.environ.get("CFW_RELEASE_CARGO_EXECUTABLE")
    cargo_audit_value = os.environ.get("CFW_RELEASE_CARGO_AUDIT_EXECUTABLE")
    if not cargo_value or not cargo_audit_value:
        raise AuditContractError("closed Cargo and cargo-audit executables are required")
    cargo = Path(cargo_value)
    cargo_audit = Path(cargo_audit_value)
    for executable, label in ((cargo, "Cargo"), (cargo_audit, "cargo-audit")):
        if (
            not executable.is_absolute()
            or not executable.is_file()
            or executable.is_symlink()
            or not os.access(executable, os.X_OK)
        ):
            raise AuditContractError(f"closed {label} executable is unavailable")
    metadata_command = [
        str(cargo),
        "metadata",
        "--locked",
        "--all-features",
        "--filter-platform",
        target,
        "--format-version",
        "1",
    ]
    closed_environment = dict(os.environ)
    metadata_result = _bounded(
        metadata_command,
        repository=repository,
        environment=closed_environment,
        timeout=METADATA_TIMEOUT_SECONDS,
        label="closed Cargo metadata",
    )
    _require_success_without_stderr(metadata_result, "closed Cargo metadata")
    metadata = json.loads(_decode_utf8(metadata_result.stdout, "closed Cargo metadata"))
    keys = target_package_keys(metadata)
    with (repository / "Cargo.lock").open("rb") as handle:
        lock_data = tomllib.load(handle)
    packages = select_locked_packages(lock_data, keys)
    encoded_lock = render_audit_lock(packages, target)

    descriptor, temporary_path = tempfile.mkstemp(prefix="cfw-rustsec-", suffix=".lock")
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(encoded_lock)
            handle.flush()
            os.fsync(handle.fileno())
        command = [
            str(cargo_audit),
            "audit",
            "--file",
            temporary_path,
            "--deny",
            "warnings",
            "--json",
            "--quiet",
            # cargo-deny owns the live yanked-status query for this same graph.
            # Avoid cargo-audit's duplicate per-package sparse-index path.
            "--no-yanked",
        ]
        if no_fetch:
            command.append("--no-fetch")
        audit_result = _bounded(
            command,
            repository=repository,
            environment=closed_environment,
            timeout=AUDIT_TIMEOUT_SECONDS,
            label="target cargo-audit",
        )
        _require_success_without_stderr(audit_result, "target cargo-audit")
        parse_audit_result(
            _decode_utf8(audit_result.stdout, "target cargo-audit output"),
            len(packages),
        )
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass

    print(
        "RustSec target audit passed: "
        f"{target}, {len(packages)} reachable packages, "
        "0 vulnerabilities, 0 advisory warnings; "
        "current yanked status is owned by the mandatory cargo-deny gate"
    )
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--no-fetch",
        action="store_true",
        help="reuse the local RustSec database instead of updating it",
    )
    parser.add_argument(
        "--target",
        choices=SHIPPED_TARGETS,
        default=MACOS_TARGET,
        help="the shipped program's Rust target to audit (default: the macOS program)",
    )
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    try:
        raise SystemExit(run(repository, arguments.no_fetch, arguments.target))
    except (AuditContractError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f"error: target RustSec audit failed: {error}") from error


if __name__ == "__main__":
    main()
