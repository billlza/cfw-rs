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
* Apple build steps must invoke ``/usr/bin/swift`` and
  ``/usr/bin/xcodebuild`` so an ambient PATH cannot replace the tools selected
  by the fixed ``DEVELOPER_DIR``; and
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
import shlex
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
DEFAULT_PINS = REPO_ROOT / "scripts" / "dependency_pins.env"
RELEASE_CI_GATE = REPO_ROOT / "scripts" / "run_release_ci_gate.sh"

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
REQUIRED_GATES: tuple[tuple[str, str], ...] = (
    (
        "rust-clippy",
        "cargo clippy must keep '-D warnings' behind the closed CI gate",
    ),
    (
        "rust-fmt",
        "cargo fmt must keep '--check' behind the closed CI gate",
    ),
    (
        "swift-format-lint",
        "swift format lint must keep '--strict' behind the closed CI gate",
    ),
    (
        "swift-package-test",
        "swift test must keep '-Xswiftc -warnings-as-errors' behind the closed CI gate",
    ),
)


class CiPolicyError(ValueError):
    """The CI workflow violates the deterministic, fail-closed lane policy."""


def _without_full_line_comments(text: str) -> str:
    """Preserve line numbers while excluding non-executable YAML comments."""
    return "\n".join(
        "" if line.lstrip().startswith("#") else line
        for line in text.splitlines()
    )


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
    for required in (
        "RUST_VERSION",
        "NODE_VERSION",
        "PYTHON_VERSION",
        "XCODE_VERSION",
        "XCODE_BUILD_VERSION",
    ):
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
    for gate, reason in REQUIRED_GATES:
        if not _uses_release_gate(text, gate):
            findings.append(reason)
    return findings


_RELEASE_GATE_WRAPPER = "./scripts/run_release_ci_gate.sh"
_SHELL_CONTROL_WORDS = frozenset(
    {
        "case",
        "do",
        "done",
        "elif",
        "else",
        "esac",
        "fi",
        "for",
        "function",
        "if",
        "select",
        "then",
        "until",
        "while",
    }
)


def _logical_shell_commands(script: str) -> tuple[str, ...]:
    commands: list[str] = []
    continuation: list[str] = []
    for raw_line in script.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.endswith("\\"):
            continuation.append(line[:-1].rstrip())
            continue
        continuation.append(line)
        commands.append(" ".join(continuation))
        continuation = []
    if continuation:
        commands.append(" ".join((*continuation, "\\")))
    return tuple(commands)


def _shell_tokens(command: str) -> tuple[str, ...] | None:
    lexer = shlex.shlex(
        command,
        posix=True,
        punctuation_chars=";&|<>()",
    )
    lexer.whitespace_split = True
    lexer.commenters = "#"
    try:
        return tuple(lexer)
    except ValueError:
        return None


def _source_contains_token_sequence(source: str, expected: tuple[str, ...]) -> bool:
    for command in _logical_shell_commands(source):
        tokens = _shell_tokens(command)
        if tokens is None or len(tokens) < len(expected):
            continue
        if any(
            tokens[index : index + len(expected)] == expected
            for index in range(len(tokens) - len(expected) + 1)
        ):
            return True
    return False


def _has_shell_control(tokens: tuple[str, ...]) -> bool:
    return any(
        token in _SHELL_CONTROL_WORDS
        or (token and all(character in ";&|<>()" for character in token))
        or "`" in token
        or "$(" in token
        for token in tokens
    )


def _is_simple_assignment(tokens: tuple[str, ...]) -> bool:
    return bool(tokens) and not _has_shell_control(tokens) and all(
        re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", token) is not None
        for token in tokens
    )


def _canonical_release_gate(tokens: tuple[str, ...]) -> str | None:
    if not tokens or tokens[0] != _RELEASE_GATE_WRAPPER or _has_shell_control(tokens):
        return None
    gate_index = 1
    if len(tokens) > 1 and tokens[1] == "--validation-python-executable":
        if len(tokens) <= 2 or not tokens[2]:
            return None
        gate_index = 3
    elif len(tokens) > 1 and tokens[1].startswith("-"):
        return None
    if len(tokens) <= gate_index:
        return None
    gate = tokens[gate_index]
    return gate if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", gate) else None


def _release_gate_commands(text: str) -> tuple[str, ...]:
    lines = text.splitlines()
    scripts: list[str] = []
    index = 0
    run_key = re.compile(r"^(?P<indent>\s*)(?:-\s+)?run:\s*(?P<value>.*)$")
    while index < len(lines):
        line = lines[index]
        match = run_key.match(line)
        if match is None:
            index += 1
            continue
        value = match.group("value").strip()
        if not value or value.startswith("#"):
            index += 1
            continue
        if value in {"|", "|-", "|+", ">", ">-", ">+"}:
            base_indent = len(match.group("indent"))
            block: list[str] = []
            index += 1
            while index < len(lines):
                child = lines[index]
                child_indent = len(child) - len(child.lstrip())
                if child.strip() and child_indent <= base_indent:
                    break
                if child.strip() and not child.lstrip().startswith("#"):
                    block.append(child.strip())
                index += 1
            script = (
                " ".join(block)
                if value.startswith(">")
                else "\n".join(block)
            )
        else:
            script = value
            index += 1
        scripts.append(script)

    gates: list[str] = []
    for script in scripts:
        reachable = True
        for command in _logical_shell_commands(script):
            tokens = _shell_tokens(command)
            if tokens is None:
                reachable = False
                continue
            if _is_simple_assignment(tokens):
                continue
            gate = _canonical_release_gate(tokens)
            if reachable and gate is not None:
                gates.append(gate)
                continue
            reachable = False
    return tuple(gates)


def _uses_release_gate(text: str, gate: str) -> bool:
    return gate in _release_gate_commands(text)


def _check_ui_boundary(text: str) -> list[str]:
    findings: list[str] = []
    required = (
        "bootstrap-node-toolchain",
        "prepare-ui-dependencies",
        "ui-test",
        "ui-build",
        "ui-audit",
    )
    for gate in required:
        if not _uses_release_gate(text, gate):
            findings.append(f"workflow lacks required closed UI gate {gate!r}")
    for number, line in enumerate(text.splitlines(), start=1):
        if re.match(r"^\s*run:\s*npm(?:\s|$)", line):
            findings.append(
                f"line {number}: raw npm command bypasses the sealed UI boundary: {line.strip()!r}"
            )
    return findings


def _check_apple_driver_boundary(text: str) -> list[str]:
    findings: list[str] = []
    required = (
        "swift-format-lint",
        "swift-package-test",
        "xcode-unsigned-test",
        "xcode-analyze",
    )
    for gate in required:
        if not _uses_release_gate(text, gate):
            findings.append(f"workflow lacks closed Apple driver gate {gate!r}")
    direct_driver = re.compile(r"(?:/usr/bin/)?(swift|xcodebuild)\s")
    for number, line in enumerate(text.splitlines(), start=1):
        match = direct_driver.search(line)
        if (
            match
            and "run_release_ci_gate.sh" not in line
            and "-version" not in line
            and "--version" not in line
        ):
            findings.append(
                f"line {number}: direct {match.group(1)} command bypasses the closed Apple driver gate"
            )
    return findings


def _check_python_isolation(text: str) -> list[str]:
    findings: list[str] = []
    unisolated = re.compile(r"\bpython3\s+(?!(?:-I\s+)?-S\s+-B\b)")
    for number, line in enumerate(text.splitlines(), start=1):
        if unisolated.search(line):
            findings.append(
                f"line {number}: Python release command does not disable site initialization"
            )
    return findings


def _check_release_ci_boundary(text: str, pins: dict[str, str]) -> list[str]:
    findings: list[str] = []
    required_workflow_gates = (
        "prepare-cargo-workspace-inputs",
        "bootstrap-policy-tools",
        "build-script-boundary",
        "ci-no-masking",
        "evidence-manifest-lane",
        "version-contract",
        "rust-fmt",
        "rust-metadata",
        "rust-clippy",
        "rust-test",
        "rust-target-audit",
        "cargo-deny",
        "bootstrap-node-toolchain",
        "prepare-ui-dependencies",
        "ui-test",
        "ui-build",
        "ui-audit",
        "release-tool-tests",
        "bootstrap-release-toolchain",
        "verify-xcode-project",
        "fetch-libbox-upstream",
        "swift-format-lint",
        "swift-package-test",
        "xcode-unsigned-test",
        "xcode-analyze",
        "materialize-libbox-source",
        "libbox-source-tests",
        "libbox-vulnerability-scan",
        "build-libbox",
        "install-tauri-cli",
        "updater-signer-integration",
    )
    for gate in required_workflow_gates:
        command = f"./scripts/run_release_ci_gate.sh ... {gate}"
        if not _uses_release_gate(text, gate):
            findings.append(f"workflow lacks closed release CI gate {command!r}")
    raw_cargo = re.compile(r"(?<![A-Za-z0-9_./-])cargo(?:\s|$)")
    for number, line in enumerate(text.splitlines(), start=1):
        if raw_cargo.search(line):
            findings.append(
                f"line {number}: raw Cargo command bypasses the closed release CI gate"
            )

    for name, body in _split_jobs(text).items():
        job_gates = _release_gate_commands(body)
        if not job_gates:
            continue
        for fragment in (
            "actions/setup-python@a309ff8b426b58ec0e2a45f0f869d46889d02405",
            "id: validation-python",
            f'python-version: "{pins["PYTHON_VERSION"]}"',
            "architecture: arm64",
            "update-environment: false",
            "--validation-python-executable",
            "steps.validation-python.outputs.python-path",
        ):
            if fragment not in body:
                findings.append(
                    f"job {name!r} does not bind closed CI Python through {fragment!r}"
                )
        if "bootstrap-policy-tools" in job_gates:
            if "prepare-cargo-workspace-inputs" not in job_gates:
                findings.append(
                    f"job {name!r} bootstraps policy tools without verified Cargo inputs"
                )
            elif job_gates.index("prepare-cargo-workspace-inputs") > job_gates.index(
                "bootstrap-policy-tools"
            ):
                findings.append(
                    f"job {name!r} prepares verified Cargo inputs after policy bootstrap"
                )

    if RELEASE_CI_GATE.is_symlink() or not RELEASE_CI_GATE.is_file():
        findings.append("closed release CI gate script is missing or is a symlink")
        return findings
    raw_gate_source = RELEASE_CI_GATE.read_text(encoding="utf-8")
    gate_source = _without_full_line_comments(raw_gate_source)
    if not raw_gate_source.startswith("#!/bin/bash -p\n"):
        findings.append("closed release CI gate lacks the privileged-mode Bash shebang")
    required_implementation = (
        "cfw_seal_release_tool_environment tool-bootstrap",
        'cfw_seal_release_tool_environment "$ci_release_role"',
        "cfw_select_release_apple_toolchain",
        'source "$repo_root/scripts/release_policy_tool_directory.sh"',
        "cfw_run_warning_free_policy_install",
        "cfw_run_with_release_cargo_runtime",
        "cfw_run_with_fresh_release_cargo_target",
        "prepare-cargo-workspace-inputs",
        "cfw_run_release_python_script",
        '"$repo_root/scripts/run_release_python_tests.py"',
        '"$repo_root/scripts/audit_cargo_policy.py"',
        '/bin/bash -p "$test_script"',
        "/usr/bin/swift format lint --recursive --strict",
        "/usr/bin/swift test --package-path native/macos",
        "-Xswiftc -warnings-as-errors",
        "/usr/bin/xcodebuild test",
        "/usr/bin/xcodebuild analyze",
        "/usr/bin/env -i",
        '"HOME=/var/empty"',
        '"GIT_ATTR_NOSYSTEM=1"',
        '"GIT_TERMINAL_PROMPT=0"',
        "/usr/bin/git",
        "core.attributesFile=/dev/null",
        "core.hooksPath=/dev/null",
        "empty_git_template",
        "init -q",
    )
    for fragment in required_implementation:
        if fragment not in gate_source:
            findings.append(
                f"closed release CI gate omits required implementation {fragment!r}"
            )
    required_cargo_commands = (
        ("$CFW_RELEASE_CARGO_EXECUTABLE", "install"),
        (
            "cfw_run_with_release_cargo_runtime",
            "$repo_root",
            "$CFW_RELEASE_CARGO_EXECUTABLE",
            "fmt",
            "--all",
            "--",
            "--check",
        ),
        (
            "cfw_run_with_release_cargo_runtime",
            "$repo_root",
            "$CFW_RELEASE_CARGO_EXECUTABLE",
            "metadata",
            "--locked",
        ),
        (
            "cfw_run_with_fresh_release_cargo_target",
            "$repo_root",
            "$CFW_RELEASE_CARGO_EXECUTABLE",
            "clippy",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ),
        (
            "cfw_run_with_fresh_release_cargo_target",
            "$repo_root",
            "$CFW_RELEASE_CARGO_EXECUTABLE",
            "test",
            "--locked",
            "--workspace",
            "--all-targets",
            "--all-features",
        ),
        (
            "cfw_run_with_release_cargo_runtime",
            "$repo_root",
            "cfw_run_release_python_script",
            "$repo_root",
            "$repo_root/scripts/audit_cargo_policy.py",
        ),
    )
    for expected in required_cargo_commands:
        if not _source_contains_token_sequence(gate_source, expected):
            findings.append(
                "closed release CI gate omits required Cargo command "
                + repr(" ".join(expected))
            )
    return findings


def audit_shell_test_python_isolation(shell_tests_root: Path) -> None:
    if not shell_tests_root.is_dir() or shell_tests_root.is_symlink():
        raise CiPolicyError("release shell-test directory is missing or a symlink")
    findings: list[str] = []
    invocation = re.compile(
        r"(?<![A-Za-z0-9_./-])(?:/[A-Za-z0-9_@+.,/-]+/)?python3\s+"
    )
    for path in sorted(shell_tests_root.glob("*_test.sh")):
        if not path.is_file() or path.is_symlink():
            raise CiPolicyError(f"release shell test is unsafe: {path}")
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if not invocation.search(line):
                continue
            findings.append(
                f"{path.name}:{number}: shell-test Python bypasses the closed release executable"
            )
    if findings:
        raise CiPolicyError(
            "release shell tests bypass closed Python:\n  - "
            + "\n  - ".join(findings)
        )


def _check_job_bounds(jobs: dict[str, str]) -> list[str]:
    findings: list[str] = []
    for name, body in jobs.items():
        if not re.search(r"^\s*runs-on:\s*\S+", body, re.MULTILINE):
            findings.append(f"job {name!r} does not pin a runner with 'runs-on'")
        timeouts = re.findall(r"^\s*timeout-minutes:\s*(\d+)\s*$", body, re.MULTILINE)
        if not timeouts:
            findings.append(f"job {name!r} does not declare an explicit 'timeout-minutes'")
    return findings


def _check_release_tool_test_dependencies(jobs: dict[str, str]) -> list[str]:
    findings: list[str] = []
    for name, body in jobs.items():
        if (
            "unittest discover" not in body
            and not _uses_release_gate(body, "release-tool-tests")
        ):
            continue
        if not _uses_release_gate(body, "bootstrap-policy-tools"):
            findings.append(
                f"job {name!r} runs release-tool tests without pinned identity tool bootstrap"
            )
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
    if _uses_release_gate(text, "bootstrap-node-toolchain"):
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
    active_text = _without_full_line_comments(text)
    pins = _read_pins(pins_path)

    findings: list[str] = []
    findings += _check_masking(active_text)
    findings += _check_gates(active_text)
    findings += _check_ui_boundary(active_text)
    findings += _check_apple_driver_boundary(active_text)
    findings += _check_python_isolation(active_text)
    findings += _check_release_ci_boundary(active_text, pins)
    jobs = _split_jobs(active_text)
    findings += _check_job_bounds(jobs)
    findings += _check_release_tool_test_dependencies(jobs)
    findings += _check_single_toolchain(active_text, pins)

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
        audit_shell_test_python_isolation(REPO_ROOT / "scripts/tests")
    except (CiPolicyError, OSError) as error:
        print(f"error: CI lane audit failed: {error}", file=sys.stderr)
        raise SystemExit(1) from error
    print(f"CI lane audit verified: {arguments.workflow}")


if __name__ == "__main__":
    main()
