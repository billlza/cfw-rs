#!/usr/bin/env python3
"""Fail-closed audit that the CI workflow cannot mask failures or drift toolchains.

Task 8.4 requires the deterministic unsigned CI lanes to be bound to exactly one
commit and one toolchain and to fail on unavailable tools, missing artifacts,
timeouts, malformed output, nonzero exits, unconditional skips, swallowed exit
status, warning suppression, or ``|| true`` (Requirements 4.1, 5.1, 6.5).

This checker enforces the *structural* half of that guarantee against
``.github/workflows/ci.yml``:

* no masking construct appears anywhere in the workflow (``|| true``, ``|| :``,
  ``set +e``, ``continue-on-error: true``, or an unconditional ``if: false``);
* every job pins a runner and an explicit ``timeout-minutes`` so a hung lane
  fails instead of blocking forever;
* the Rust, Node, and Xcode toolchains referenced by the workflow each resolve
  to exactly one version, and that version equals the pinned value in
  ``scripts/dependency_pins.env`` (single-toolchain binding); the Node lane must
  use the repository's checksum-bound bootstrap rather than ``setup-node``;
* UI installation, test, build, and audit steps must use the sealed dependency
  preparation and pinned-Node wrappers; a raw workflow ``npm`` command is
  rejected because it can replace or bypass the sealed tree; and
* the warning-as-error gates stay armed - ``cargo clippy`` keeps ``-D warnings``,
  ``cargo fmt`` keeps ``--check``, ``swift format lint`` keeps ``--strict``, and
  the Swift package test keeps ``-Xswiftc -warnings-as-errors``.

The audit is fail-closed: any violation, an unreadable workflow, or a missing
pinned input aborts with a nonzero exit and a specific message. It never edits
``scripts/evidence_manifest.py`` or any other lane; it only reads the workflow
and the pins file.
"""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
DEFAULT_PINS = REPO_ROOT / "scripts" / "dependency_pins.env"

# Constructs that swallow a failure, suppress warnings, or unconditionally skip a
# step. Each maps to a human-readable reason used in the failure report.
MASKING_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\|\|\s*true\b"), "'|| true' swallows a failing command"),
    (re.compile(r"\|\|\s*:(?:\s|$)"), "'|| :' swallows a failing command"),
    (re.compile(r"\bset\s+\+e\b"), "'set +e' disables fail-fast shell behavior"),
    (re.compile(r"continue-on-error\s*:\s*true"), "'continue-on-error: true' masks a failing step"),
    (re.compile(r"if\s*:\s*false\b"), "'if: false' unconditionally skips a step"),
    (
        re.compile(r"if\s*:\s*\$\{\{\s*false\s*\}\}"),
        "'if: ${{ false }}' unconditionally skips a step",
    ),
    (re.compile(r"2>\s*/dev/null"), "redirecting stderr to /dev/null can hide malformed output"),
)

# Warning-as-error gates that must remain present exactly once so a lane cannot
# silently downgrade a lint failure into a warning.
REQUIRED_GATES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"cargo clippy[^\n]*-D warnings"), "cargo clippy must keep '-D warnings'"),
    (re.compile(r"cargo fmt[^\n]*--check"), "cargo fmt must keep '--check'"),
    (re.compile(r"swift format lint[^\n]*--strict"), "swift format lint must keep '--strict'"),
    (
        re.compile(r"swift test[^\n]*-Xswiftc -warnings-as-errors"),
        "swift test must keep '-Xswiftc -warnings-as-errors'",
    ),
)


class CiPolicyError(ValueError):
    """The CI workflow violates the deterministic, fail-closed lane policy."""


def _read_pins(pins_path: Path) -> dict[str, str]:
    if pins_path.is_symlink() or not pins_path.is_file():
        raise CiPolicyError(f"pinned inputs file is missing: {pins_path}")
    pins: dict[str, str] = {}
    for line in pins_path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, _, value = stripped.partition("=")
        pins[key.strip()] = value.strip()
    for required in ("RUST_VERSION", "NODE_VERSION", "XCODE_VERSION", "XCODE_BUILD_VERSION"):
        if required not in pins:
            raise CiPolicyError(f"pinned inputs file does not define {required}")
    return pins


def _split_jobs(text: str) -> dict[str, str]:
    """Return each top-level job body keyed by job name.

    A structural, dependency-free scan: job names are the two-space-indented
    keys directly under the top-level ``jobs:`` mapping.
    """
    lines = text.splitlines()
    in_jobs = False
    jobs: dict[str, list[str]] = {}
    current: str | None = None
    job_key = re.compile(r"^  (?P<name>[A-Za-z0-9_-]+):\s*$")
    for line in lines:
        if not in_jobs:
            if re.match(r"^jobs:\s*$", line):
                in_jobs = True
            continue
        # A non-indented, non-blank line ends the jobs mapping.
        if line and not line.startswith(" ") and not line.startswith("#"):
            break
        match = job_key.match(line)
        if match:
            current = match.group("name")
            jobs[current] = []
            continue
        if current is not None:
            jobs[current].append(line)
    if not jobs:
        raise CiPolicyError("workflow declares no jobs")
    return {name: "\n".join(body) for name, body in jobs.items()}


def _check_masking(text: str) -> list[str]:
    findings: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for pattern, reason in MASKING_PATTERNS:
            if pattern.search(line):
                findings.append(f"line {number}: {reason}: {line.strip()!r}")
    return findings


def _check_gates(text: str) -> list[str]:
    findings: list[str] = []
    for pattern, reason in REQUIRED_GATES:
        if not pattern.search(text):
            findings.append(reason)
    return findings


def _check_ui_boundary(text: str) -> list[str]:
    findings: list[str] = []
    required = (
        "./scripts/bootstrap_release_toolchain.sh --node-only",
        "./scripts/prepare_ui_dependencies.sh",
        "./scripts/build_ui_with_pinned_node.sh --test",
        "./scripts/build_ui_with_pinned_node.sh --audit",
    )
    for command in required:
        if command not in text:
            findings.append(f"workflow lacks required pinned UI command {command!r}")
    if not re.search(
        r"^\s*run:\s*\./scripts/build_ui_with_pinned_node\.sh\s*$",
        text,
        re.MULTILINE,
    ):
        findings.append("workflow lacks the pinned offline UI build command")
    for number, line in enumerate(text.splitlines(), start=1):
        if re.match(r"^\s*run:\s*npm(?:\s|$)", line):
            findings.append(
                f"line {number}: raw npm command bypasses the sealed UI boundary: {line.strip()!r}"
            )
    return findings


def _check_job_bounds(jobs: dict[str, str]) -> list[str]:
    findings: list[str] = []
    for name, body in jobs.items():
        if not re.search(r"^\s*runs-on:\s*\S+", body, re.MULTILINE):
            findings.append(f"job {name!r} does not pin a runner with 'runs-on'")
        timeouts = re.findall(r"^\s*timeout-minutes:\s*(\d+)\s*$", body, re.MULTILINE)
        if not timeouts:
            findings.append(f"job {name!r} does not declare an explicit 'timeout-minutes'")
    return findings


def _single(values: set[str], label: str, expected: str, findings: list[str]) -> None:
    if not values:
        findings.append(f"workflow never references the {label} toolchain")
        return
    if len(values) != 1:
        findings.append(f"workflow binds multiple {label} toolchains: {sorted(values)}")
        return
    (found,) = tuple(values)
    if found != expected:
        findings.append(
            f"{label} toolchain {found!r} does not match the pinned {expected!r}"
        )


def _check_single_toolchain(text: str, pins: dict[str, str]) -> list[str]:
    findings: list[str] = []

    rust = set(re.findall(r'toolchain:\s*"([0-9][0-9A-Za-z.\-]*)"', text))
    _single(rust, "Rust", pins["RUST_VERSION"], findings)

    node = set(re.findall(r'node-version:\s*"([0-9][0-9A-Za-z.\-]*)"', text))
    node |= set(re.findall(r"node-(\d+\.\d+\.\d+)/bin", text))
    if "./scripts/bootstrap_release_toolchain.sh --node-only" in text:
        node.add(pins["NODE_VERSION"])
    _single(node, "Node.js", pins["NODE_VERSION"], findings)

    xcode = set(re.findall(r"Xcode_([0-9][0-9A-Za-z.]*)\.app", text))
    xcode |= set(re.findall(r"Xcode\s+([0-9][0-9A-Za-z.]*)", text))
    _single(xcode, "Xcode", pins["XCODE_VERSION"], findings)

    build_versions = set(re.findall(r"Build version\s+([0-9A-Za-z]+)", text))
    if build_versions and build_versions != {pins["XCODE_BUILD_VERSION"]}:
        findings.append(
            f"Xcode build version binding {sorted(build_versions)} does not match "
            f"the pinned {pins['XCODE_BUILD_VERSION']!r}"
        )
    return findings


def audit_workflow(workflow_path: Path, pins_path: Path) -> None:
    if workflow_path.is_symlink() or not workflow_path.is_file():
        raise CiPolicyError(f"CI workflow is missing: {workflow_path}")
    text = workflow_path.read_text(encoding="utf-8")
    pins = _read_pins(pins_path)

    findings: list[str] = []
    findings += _check_masking(text)
    findings += _check_gates(text)
    findings += _check_ui_boundary(text)
    findings += _check_job_bounds(_split_jobs(text))
    findings += _check_single_toolchain(text, pins)

    if findings:
        raise CiPolicyError(
            "CI workflow is not deterministic or fails open:\n  - " + "\n  - ".join(findings)
        )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Fail-closed audit of the deterministic unsigned CI workflow."
    )
    parser.add_argument("--workflow", type=Path, default=DEFAULT_WORKFLOW)
    parser.add_argument("--pins", type=Path, default=DEFAULT_PINS)
    arguments = parser.parse_args()
    try:
        audit_workflow(arguments.workflow, arguments.pins)
    except (CiPolicyError, OSError) as error:
        print(f"error: CI lane audit failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print(f"CI lane audit verified: {arguments.workflow}")


if __name__ == "__main__":
    main()
