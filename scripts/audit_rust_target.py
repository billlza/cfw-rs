#!/usr/bin/env python3
"""Audit the exact shipped Rust target graph with RustSec.

Cargo.lock deliberately contains dependencies for every supported platform of
upstream crates.  cargo-audit's target flags filter advisory applicability but
do not remove packages that Cargo cannot resolve for the selected target.  This
script derives the reachable package inventory from `cargo metadata
--filter-platform`, emits a temporary audit-only lockfile, and runs cargo-audit
with warnings denied.  It never ignores an advisory.
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import tempfile
import tomllib
from pathlib import Path
from typing import Any


SUPPORTED_TARGET = "aarch64-apple-darwin"


class AuditContractError(RuntimeError):
    """The Cargo metadata or lockfile does not satisfy the audit contract."""


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
        reachable.add(identifier)
        dependencies = node.get("deps")
        if not isinstance(dependencies, list):
            raise AuditContractError(f"resolve node has no dependency list: {identifier}")
        for dependency in dependencies:
            package = dependency.get("pkg") if isinstance(dependency, dict) else None
            if not isinstance(package, str):
                raise AuditContractError(
                    f"resolve node contains an invalid dependency: {identifier}"
                )
            pending.append(package)
    return reachable


def target_package_keys(metadata: dict[str, Any]) -> set[tuple[str, str, str | None]]:
    reachable = reachable_package_ids(metadata)
    raw_packages = metadata.get("packages")
    if not isinstance(raw_packages, list):
        raise AuditContractError("cargo metadata has no package inventory")
    by_identifier: dict[str, tuple[str, str, str | None]] = {}
    for package in raw_packages:
        if not isinstance(package, dict):
            raise AuditContractError("cargo metadata contains an invalid package")
        identifier = package.get("id")
        name = package.get("name")
        version = package.get("version")
        source = package.get("source")
        if (
            not isinstance(identifier, str)
            or not isinstance(name, str)
            or not isinstance(version, str)
            or (source is not None and not isinstance(source, str))
        ):
            raise AuditContractError("cargo metadata package identity is incomplete")
        if identifier in by_identifier:
            raise AuditContractError(f"duplicate cargo package identifier: {identifier}")
        by_identifier[identifier] = (name, version, source)

    missing = reachable.difference(by_identifier)
    if missing:
        raise AuditContractError(
            "target resolve graph references packages missing from metadata: "
            + ", ".join(sorted(missing))
        )
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


def run(repository: Path, no_fetch: bool) -> int:
    metadata_command = [
        "cargo",
        "metadata",
        "--locked",
        "--filter-platform",
        SUPPORTED_TARGET,
        "--format-version",
        "1",
    ]
    metadata_result = subprocess.run(
        metadata_command,
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
    )
    metadata = json.loads(metadata_result.stdout)
    keys = target_package_keys(metadata)
    with (repository / "Cargo.lock").open("rb") as handle:
        lock_data = tomllib.load(handle)
    packages = select_locked_packages(lock_data, keys)
    encoded_lock = render_audit_lock(packages, SUPPORTED_TARGET)

    descriptor, temporary_path = tempfile.mkstemp(prefix="cfw-rustsec-", suffix=".lock")
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            descriptor = -1
            handle.write(encoded_lock)
            handle.flush()
            os.fsync(handle.fileno())
        command = [
            "cargo",
            "audit",
            "--file",
            temporary_path,
            "--deny",
            "warnings",
            "--json",
        ]
        if no_fetch:
            command.append("--no-fetch")
        audit_result = subprocess.run(
            command,
            cwd=repository,
            check=False,
            capture_output=True,
            text=True,
        )
        if audit_result.returncode != 0:
            if audit_result.stdout:
                print(audit_result.stdout, end="", file=os.sys.stderr)
            if audit_result.stderr:
                print(audit_result.stderr, end="", file=os.sys.stderr)
            return audit_result.returncode
        parse_audit_result(audit_result.stdout, len(packages))
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        try:
            os.unlink(temporary_path)
        except FileNotFoundError:
            pass

    print(
        "RustSec target audit passed: "
        f"{SUPPORTED_TARGET}, {len(packages)} reachable packages, "
        "0 vulnerabilities, 0 warnings"
    )
    return 0


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--no-fetch",
        action="store_true",
        help="reuse the local RustSec database instead of updating it",
    )
    arguments = parser.parse_args()
    repository = Path(__file__).resolve().parent.parent
    try:
        raise SystemExit(run(repository, arguments.no_fetch))
    except (AuditContractError, json.JSONDecodeError, OSError, subprocess.SubprocessError) as error:
        raise SystemExit(f"error: target RustSec audit failed: {error}") from error


if __name__ == "__main__":
    main()
