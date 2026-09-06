#!/usr/bin/env python3
"""Fail-closed audit that the CI workflow cannot mask failures or drift toolchains.

Task 8.4 requires the deterministic unsigned CI lanes to be bound to exactly one
commit and one toolchain and to fail on unavailable tools, missing artifacts,
timeouts, malformed output, nonzero exits, conditional skips, swallowed exit
status, warning suppression, or ``|| true`` (Requirements 4.1, 5.1, 6.5).

This checker enforces the *structural* half of that guarantee against
``.github/workflows/ci.yml``:

* no masking construct appears anywhere in the workflow (``|| true``, ``|| :``,
  ``set +e``, any ``continue-on-error:``, or any conditional ``if:``); release
  evidence jobs and steps must always execute when the workflow executes;
* every ``run`` step inherits one exact privileged-mode Bash boundary, so
  ``BASH_ENV`` and exported functions cannot execute before a required gate;
* every job pins a runner and an explicit ``timeout-minutes`` so a hung lane
  fails instead of blocking forever;
* every job starts from the same explicit pull-request-head-or-event SHA,
  disables persisted checkout credentials, and immediately verifies the
  materialized ``HEAD`` through the absolute system Git executable while its
  step identity carries the GitHub workflow-file SHA for receipt validation;
* the hosted release-tooling job then normalizes only the exact pinned Xcode
  application through a physical, no-follow ownership pass before executing
  any setup action or repository command, and revalidates its identity;
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
import hashlib
from pathlib import Path
import re
import shlex
import sys

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_WORKFLOW = REPO_ROOT / ".github" / "workflows" / "ci.yml"
DEFAULT_PINS = REPO_ROOT / "scripts" / "dependency_pins.env"
RELEASE_CI_GATE = REPO_ROOT / "scripts" / "run_release_ci_gate.sh"
REQUIRED_RUN_SHELL = "/bin/bash --noprofile --norc -p -e -o pipefail {0}"
REQUIRED_CHECKOUT_ACTION = (
    "actions/checkout@d23441a48e516b6c34aea4fa41551a30e30af803"
)
REQUIRED_SOURCE_REF = (
    "${{ github.event_name == 'pull_request' && "
    "github.event.pull_request.head.sha || github.sha }}"
)
REQUIRED_WORKFLOW_SOURCE_SHA = "${{ github.workflow_sha }}"
REQUIRED_HEAD_ASSERTION = (
    f'/bin/test "$(/usr/bin/git rev-parse HEAD)" = "{REQUIRED_SOURCE_REF}"'
)
REQUIRED_SOURCE_ASSERTION_STEP = (
    "      - name: Assert exact CI source and workflow identity "
    f"{REQUIRED_WORKFLOW_SOURCE_SHA}\n"
    f"        run: {REQUIRED_HEAD_ASSERTION}"
)
REQUIRED_XCODE_OWNERSHIP_STEP = """      - name: Normalize pinned Xcode ownership
        run: |
          readonly xcode_application=/Applications/Xcode_26.6.app
          /bin/test "$DEVELOPER_DIR" = "$xcode_application/Contents/Developer"
          /bin/test -d "$xcode_application"
          /bin/test ! -L "$xcode_application"
          /bin/test -d "$xcode_application/Contents"
          /bin/test ! -L "$xcode_application/Contents"
          /bin/test -d "$xcode_application/Contents/Developer"
          /bin/test ! -L "$xcode_application/Contents/Developer"
          /usr/sbin/spctl --assess --type execute "$xcode_application"
          /bin/test "$(DEVELOPER_DIR="$DEVELOPER_DIR" /usr/bin/xcodebuild -version)" = $'Xcode 26.6\\nBuild version 17F113'

          runner_uid="$(/usr/bin/id -u)"
          readonly runner_uid
          /bin/test "$runner_uid" -ne 0
          runner_groups=" $(/usr/bin/id -G) "
          readonly runner_groups
          [[ "$runner_groups" != *" 0 "* ]]
          xcode_device_inode="$(/usr/bin/stat -f '%d:%i' "$xcode_application")"
          readonly xcode_device_inode
          unexpected_entry="$(
            /usr/bin/find -P -x "$xcode_application" \\
              \\( \\( ! -uid 0 -a ! -uid "$runner_uid" \\) -o -perm -0002 \\) \\
              -print -quit
          )"
          readonly unexpected_entry
          /bin/test -z "$unexpected_entry"

          /usr/bin/sudo -n /usr/bin/find -P -x "$xcode_application" \\
            -exec /usr/sbin/chown -h 0:0 {} +

          /bin/test "$(/usr/bin/stat -f '%d:%i' "$xcode_application")" = "$xcode_device_inode"
          remaining_unsafe_entry="$(
            /usr/bin/find -P -x "$xcode_application" \\
              \\( ! -uid 0 -o ! -gid 0 -o -perm -0002 \\) -print -quit
          )"
          readonly remaining_unsafe_entry
          /bin/test -z "$remaining_unsafe_entry"
          /usr/sbin/spctl --assess --type execute "$xcode_application"
          /bin/test "$(DEVELOPER_DIR="$DEVELOPER_DIR" /usr/bin/xcodebuild -version)" = $'Xcode 26.6\\nBuild version 17F113'"""
REQUIRED_TAURI_TMPDIR = "${{ runner.temp }}"
REQUIRED_SWIFT_TARGET_INFO_PROBE = (
    'swift_identity_stderr="$(/usr/bin/mktemp '
    '"$RUNNER_TEMP/swift-target-info.XXXXXX")"\n'
    "          cleanup_swift_identity_stderr() {\n"
    '            /bin/rm -f -- "$swift_identity_stderr"\n'
    "          }\n"
    "          trap cleanup_swift_identity_stderr EXIT\n"
    '          if ! swift_target_info="$(\n'
    '              /usr/bin/swift -print-target-info \\\n'
    '                -target "arm64-apple-macosx$MACOS_DEPLOYMENT_TARGET" \\\n'
    '                2>"$swift_identity_stderr"\n'
    '            )"; then\n'
    '            /bin/cat "$swift_identity_stderr" >&2\n'
    "            exit 1\n"
    "          fi\n"
    '          if [[ -s "$swift_identity_stderr" ]]; then\n'
    '            /bin/cat "$swift_identity_stderr" >&2\n'
    "            exit 1\n"
    "          fi\n"
    '          if [[ -z "$swift_target_info" ]]; then\n'
    '            echo "error: Swift target identity is empty" >&2\n'
    "            exit 1\n"
    "          fi\n"
    "          cleanup_swift_identity_stderr\n"
    "          trap - EXIT"
)
# Level 1 integrity identity for the complete dispatch program. This detects
# unreviewed control-flow drift; it is not an authentication mechanism.
REQUIRED_RELEASE_CI_GATE_SHA256 = (
    "e10113e967081dcc4bbd4b6eeff5d6d1e5a739b1eabfd773584f9b9e95bacc41"
)
REQUIRED_WORKFLOW_SHA256 = (
    "b0881faa331b4072b1d0e9d957fe5db99920aef0e7ee8d6284accb6531d3a724"
)

# Constructs that swallow a failure, suppress warnings, or conditionally skip a
# step. Each maps to a human-readable reason used in the failure report.
MASKING_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"\|\|\s*true\b"), "'|| true' swallows a failing command"),
    (re.compile(r"\|\|\s*:(?:\s|$)"), "'|| :' swallows a failing command"),
    (re.compile(r"\bset\s+\+e\b"), "'set +e' disables fail-fast shell behavior"),
    (re.compile(r"2>\s*/dev/null"), "redirecting stderr to /dev/null can hide malformed output"),
    (re.compile(r"\bBASH_ENV\b"), "BASH_ENV can execute before a required release gate"),
    (re.compile(r"\bBASH_FUNC_"), "an exported Bash function can replace a release command"),
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
        "MACOS_DEPLOYMENT_TARGET",
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


def _split_job_steps(body: str) -> tuple[str, ...]:
    """Return direct step blocks from one job in the restricted CI dialect."""

    lines = body.splitlines()
    steps_headers = [
        index for index, line in enumerate(lines) if line == "    steps:"
    ]
    if len(steps_headers) != 1:
        return ()

    first_child = steps_headers[0] + 1
    end = len(lines)
    for index in range(first_child, len(lines)):
        line = lines[index]
        if not line.strip():
            continue
        indent = len(line) - len(line.lstrip(" "))
        if indent <= 4:
            end = index
            break

    starts = [
        index
        for index in range(first_child, end)
        if re.match(r"^      -\s+\S", lines[index])
    ]
    if not starts:
        return ()
    return tuple(
        "\n".join(lines[start:stop]).rstrip()
        for start, stop in zip(starts, (*starts[1:], end), strict=True)
    )


def _check_source_checkout(jobs: dict[str, str]) -> list[str]:
    """Bind every release job to the exact event source before tool setup."""

    findings: list[str] = []
    checkout_use = re.compile(
        r"^\s*(?:-\s+)?uses:\s*actions/checkout@(?P<revision>\S+)",
        re.MULTILINE,
    )
    required_checkout = re.compile(
        rf"^      - uses: {re.escape(REQUIRED_CHECKOUT_ACTION)}(?:\s+#.*)?\n"
        r"        with:\n"
        rf"          ref: {re.escape(REQUIRED_SOURCE_REF)}\n"
        r"          persist-credentials: false$"
    )
    for name, body in jobs.items():
        checkout_matches = tuple(checkout_use.finditer(body))
        if len(checkout_matches) != 1:
            findings.append(
                f"job {name!r} must contain exactly one actions/checkout step"
            )

        steps = _split_job_steps(body)
        checkout_steps = tuple(
            index for index, step in enumerate(steps) if checkout_use.search(step)
        )
        if len(checkout_steps) != 1:
            findings.append(
                f"job {name!r} must expose exactly one direct actions/checkout step"
            )
            continue

        checkout_index = checkout_steps[0]
        checkout_step = steps[checkout_index]
        if checkout_index != 0 or required_checkout.fullmatch(checkout_step) is None:
            findings.append(
                f"job {name!r} must start with pinned {REQUIRED_CHECKOUT_ACTION!r}, "
                "the exact pull-request-head-or-event SHA ref, and only "
                "'persist-credentials: false'"
            )

        assertion_steps = tuple(
            index
            for index, step in enumerate(steps)
            if step == REQUIRED_SOURCE_ASSERTION_STEP
        )
        if len(assertion_steps) != 1:
            findings.append(
                f"job {name!r} must contain exactly one exact source assertion "
                "carrying the workflow-file identity"
            )
        if (
            checkout_index + 1 >= len(steps)
            or steps[checkout_index + 1] != REQUIRED_SOURCE_ASSERTION_STEP
        ):
            findings.append(
                f"job {name!r} must immediately assert the exact event SHA and carry "
                "the workflow-file SHA with absolute /bin/test and /usr/bin/git "
                "after checkout"
            )
    return findings


def _check_hosted_xcode_ownership(
    jobs: dict[str, str],
    pins: dict[str, str],
) -> list[str]:
    """Require the one privileged hosted-Xcode adapter before repository code."""

    findings: list[str] = []
    release_tooling_jobs = tuple(
        (name, body)
        for name, body in jobs.items()
        if "release-tool-tests" in _release_gate_commands(body)
    )
    if len(release_tooling_jobs) != 1:
        return [
            "workflow must contain exactly one release-tooling job for pinned "
            "Xcode ownership normalization"
        ]

    job_name, job_body = release_tooling_jobs[0]
    steps = _split_job_steps(job_body)
    normalization_steps = tuple(
        index
        for index, step in enumerate(steps)
        if step == REQUIRED_XCODE_OWNERSHIP_STEP
    )
    if normalization_steps != (2,):
        findings.append(
            f"job {job_name!r} must normalize the exact pinned Xcode ownership "
            "once, immediately after checkout and exact-HEAD verification"
        )

    expected_application = f"/Applications/Xcode_{pins['XCODE_VERSION']}.app"
    expected_identity = (
        f"Xcode {pins['XCODE_VERSION']}\\n"
        f"Build version {pins['XCODE_BUILD_VERSION']}"
    )
    if (
        f"readonly xcode_application={expected_application}"
        not in REQUIRED_XCODE_OWNERSHIP_STEP
        or REQUIRED_XCODE_OWNERSHIP_STEP.count(expected_identity) != 2
    ):
        findings.append(
            "pinned Xcode ownership policy differs from the Xcode version pins"
        )

    privileged_commands = (
        "/usr/bin/sudo",
        "/usr/sbin/chown",
        "/usr/sbin/spctl",
    )
    for name, body in jobs.items():
        for index, step in enumerate(_split_job_steps(body)):
            if (
                name == job_name
                and index == 2
                and step == REQUIRED_XCODE_OWNERSHIP_STEP
            ):
                continue
            if any(command in step for command in privileged_commands):
                findings.append(
                    f"job {name!r} step {index + 1} contains an unreviewed "
                    "privileged Xcode ownership command"
                )
    return findings


def _check_masking(text: str) -> list[str]:
    findings: list[str] = []
    for number, line in enumerate(text.splitlines(), start=1):
        for pattern, reason in MASKING_PATTERNS:
            if pattern.search(line):
                findings.append(f"line {number}: {reason}: {line.strip()!r}")
    return findings


def _unquoted_yaml_syntax(line: str) -> str:
    """Return structural YAML characters while removing scalar/comment content."""

    output: list[str] = []
    index = 0
    quote: str | None = None
    while index < len(line):
        character = line[index]
        if quote == "'":
            if character == "'" and index + 1 < len(line) and line[index + 1] == "'":
                index += 2
                continue
            if character == "'":
                quote = None
            output.append(" ")
            index += 1
            continue
        if quote == '"':
            if character == "\\" and index + 1 < len(line):
                output.extend((" ", " "))
                index += 2
                continue
            if character == '"':
                quote = None
            output.append(" ")
            index += 1
            continue
        if line.startswith("${{", index):
            end = line.find("}}", index + 3)
            if end < 0:
                output.extend(" " for _ in line[index:])
                break
            output.extend(" " for _ in line[index : end + 2])
            index = end + 2
            continue
        if character in {"'", '"'}:
            quote = character
            output.append(" ")
            index += 1
            continue
        if character == "#" and (index == 0 or line[index - 1].isspace()):
            output.extend(" " for _ in line[index:])
            break
        output.append(character)
        index += 1
    return "".join(output)


def _yaml_structural_lines(text: str) -> list[tuple[int, str, str]]:
    """Exclude block-scalar bodies and return original plus unquoted syntax."""

    result: list[tuple[int, str, str]] = []
    block_parent_indent: int | None = None
    block_header = re.compile(r":\s*[|>](?:[1-9][+-]?|[+-][1-9]?)?\s*$")
    for number, line in enumerate(text.splitlines(), start=1):
        if "\t" in line[: len(line) - len(line.lstrip("\t "))]:
            result.append((number, line, "\t"))
            continue
        stripped = line.strip()
        indent = len(line) - len(line.lstrip(" "))
        if block_parent_indent is not None:
            if not stripped or indent > block_parent_indent:
                continue
            block_parent_indent = None
        syntax = _unquoted_yaml_syntax(line)
        result.append((number, line, syntax))
        if block_header.search(syntax):
            # A compact sequence mapping starts its first key after ``- ``.
            # Sibling keys align with that key, not with the sequence marker.
            # Track every leading sequence indicator so a sibling ``if`` or
            # ``continue-on-error`` cannot be mistaken for scalar content.
            structural_content = syntax[indent:]
            sequence_prefix = re.match(r"(?:-[ ]+)+", structural_content)
            block_parent_indent = indent + (
                len(sequence_prefix.group(0)) if sequence_prefix is not None else 0
            )
    return result


def _check_yaml_mapping_policy(text: str) -> list[str]:
    """Enforce one non-conditional YAML dialect without a third-party parser."""

    findings: list[str] = []
    forbidden_keys = {"if", "continue-on-error", "working-directory", "BASH_ENV"}
    quoted_key = re.compile(r"^(?:\"(?:[^\"\\]|\\.)*\"|'(?:[^']|'')*')\s*:")
    anchor_or_alias = re.compile(r"(?<![A-Za-z0-9_])[&*][A-Za-z_][A-Za-z0-9_-]*")
    defaults_lines: list[int] = []
    shell_lines: list[int] = []
    required_shell_line = f'    shell: "{REQUIRED_RUN_SHELL}"'
    for number, original, syntax in _yaml_structural_lines(text):
        if syntax == "\t":
            findings.append(f"line {number}: tab-indented YAML is outside the release dialect")
            continue
        candidate = original.lstrip(" ")
        syntax_candidate = syntax.lstrip(" ")
        while candidate.startswith("-") and candidate[1:2].isspace():
            candidate = candidate[1:].lstrip(" ")
            syntax_candidate = syntax_candidate[1:].lstrip(" ")
        structural_candidate = syntax_candidate.rstrip(" ")
        if structural_candidate == "?" or (
            structural_candidate.startswith("?")
            and structural_candidate[1:2].isspace()
        ):
            findings.append(
                f"line {number}: explicit YAML mapping keys are outside the release dialect"
            )
        if structural_candidate == ":" or (
            structural_candidate.startswith(":")
            and structural_candidate[1:2].isspace()
        ):
            findings.append(
                f"line {number}: explicit YAML mapping values are outside the release dialect"
            )
        if quoted_key.match(candidate):
            findings.append(
                f"line {number}: quoted YAML mapping keys are outside the release dialect"
            )
        plain_key = re.match(r"^([A-Za-z0-9_-]+)\s*:", syntax_candidate)
        if plain_key is not None and plain_key.group(1) in forbidden_keys:
            key = plain_key.group(1)
            findings.append(
                f"line {number}: {key!r} can conditionally skip or mask a required release job or step"
            )
        if plain_key is not None and plain_key.group(1) == "defaults":
            defaults_lines.append(number)
            if original != "defaults:":
                findings.append(
                    f"line {number}: job or step defaults are outside the release dialect"
                )
        if plain_key is not None and plain_key.group(1) == "shell":
            shell_lines.append(number)
            if original != required_shell_line:
                findings.append(
                    f"line {number}: shell override differs from the fixed release boundary"
                )
        if "{" in syntax or "}" in syntax:
            findings.append(
                f"line {number}: flow-style YAML mappings are outside the release dialect"
            )
        if "<<" in syntax or anchor_or_alias.search(syntax):
            findings.append(
                f"line {number}: YAML anchors, aliases, and merges are outside the release dialect"
            )
        if re.match(r"^[!&*]", syntax_candidate):
            findings.append(
                f"line {number}: tagged or anchored YAML keys are outside the release dialect"
            )
    required_shell_block = (
        "defaults:\n"
        "  run:\n"
        f"{required_shell_line}\n"
    )
    if (
        len(defaults_lines) != 1
        or len(shell_lines) != 1
        or text.count(required_shell_block) != 1
    ):
        findings.append(
            "workflow must declare exactly one top-level fixed privileged Bash boundary"
        )
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
    probe_count = text.count("/usr/bin/swift -print-target-info")
    if probe_count > 1:
        findings.append("workflow contains multiple Swift target identity probes")
    if probe_count and text.count(REQUIRED_SWIFT_TARGET_INFO_PROBE) != 1:
        findings.append(
            "Swift host identity probe must use the pinned target and reject stderr"
        )
    if re.search(r"(?:/usr/bin/)?swift\s+--?version\b", text):
        findings.append(
            "Swift host identity must use structured target info instead of --version"
        )
    direct_driver = re.compile(r"(?:/usr/bin/)?(swift|xcodebuild)\s")
    for number, line in enumerate(text.splitlines(), start=1):
        match = direct_driver.search(line)
        if not match or "run_release_ci_gate.sh" in line:
            continue
        is_reviewed_swift_probe = (
            match.group(1) == "swift"
            and "/usr/bin/swift -print-target-info" in line
            and probe_count == 1
            and text.count(REQUIRED_SWIFT_TARGET_INFO_PROBE) == 1
        )
        is_xcode_version_probe = (
            match.group(1) == "xcodebuild" and "-version" in line
        )
        if not is_reviewed_swift_probe and not is_xcode_version_probe:
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
        "packet-lan-peer",
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

    tauri_steps = tuple(
        (job_name, step)
        for job_name, body in _split_jobs(text).items()
        for step in _split_job_steps(body)
        if "install-tauri-cli" in _release_gate_commands(step)
    )
    if len(tauri_steps) != 1:
        findings.append(
            "workflow must contain exactly one direct pinned Tauri CLI install step"
        )
    else:
        job_name, tauri_step = tauri_steps[0]
        required_temporary_binding = (
            "        env:\n"
            f"          TMPDIR: {REQUIRED_TAURI_TMPDIR}"
        )
        if (
            required_temporary_binding not in tauri_step
            or tauri_step.count("        env:") != 1
            or tauri_step.count("          TMPDIR:") != 1
        ):
            findings.append(
                f"job {job_name!r} must bind the pinned Tauri CLI install step "
                "to exactly one runner-owned temporary directory"
            )
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
        if "packet-lan-peer" in job_gates:
            if "bootstrap-release-toolchain" not in job_gates:
                findings.append(
                    f"job {name!r} verifies the packet LAN peer without the pinned release toolchain"
                )
            elif job_gates.index("bootstrap-release-toolchain") > job_gates.index(
                "packet-lan-peer"
            ):
                findings.append(
                    f"job {name!r} verifies the packet LAN peer before release-toolchain bootstrap"
                )

    if RELEASE_CI_GATE.is_symlink() or not RELEASE_CI_GATE.is_file():
        findings.append("closed release CI gate script is missing or is a symlink")
        return findings
    raw_gate_bytes = RELEASE_CI_GATE.read_bytes()
    if hashlib.sha256(raw_gate_bytes).hexdigest() != REQUIRED_RELEASE_CI_GATE_SHA256:
        findings.append(
            "closed release CI gate differs from the exact reviewed dispatch policy"
        )
    try:
        raw_gate_source = raw_gate_bytes.decode("utf-8")
    except UnicodeDecodeError:
        findings.append("closed release CI gate is not UTF-8 source")
        return findings
    gate_source = _without_full_line_comments(raw_gate_source)
    if not raw_gate_source.startswith("#!/bin/bash -p\n"):
        findings.append("closed release CI gate lacks the privileged-mode Bash shebang")
    entry_commands = tuple(
        line.strip() for line in gate_source.splitlines() if line.strip()
    )
    if entry_commands[:2] != ("set -euo pipefail", "umask 022"):
        findings.append(
            "closed release CI gate must set umask 022 before loading helpers or dispatching"
        )
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
        '"$repo_root/scripts/verify_packet_lan_peer.sh"',
        '"$repo_root/scripts/verify_pinned_build_inputs.py"',
        '/bin/bash -p "$test_script"',
        "/usr/bin/swift format lint --recursive --strict",
        "/usr/bin/swift test --package-path native/macos",
        "--no-parallel",
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
        'tauri_temporary_parent_input="${TMPDIR:-}"',
        "export -n TMPDIR",
        "/bin/pwd -P",
        "tauri_temporary_mode=",
        "must not be group- or other-writable",
        "must not contain ':'",
        'TMPDIR="$tauri_temporary_parent"',
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
    expected_packet_command = (
        "/bin/bash",
        "-p",
        "$repo_root/scripts/verify_packet_lan_peer.sh",
    )
    if not _source_contains_token_sequence(gate_source, expected_packet_command):
        findings.append(
            "closed release CI gate omits required packet LAN peer command "
            + repr(" ".join(expected_packet_command))
        )
    expected_complete_pin_command = (
        "cfw_run_release_python_script",
        "$repo_root",
        "$repo_root/scripts/verify_pinned_build_inputs.py",
    )
    if not _source_contains_token_sequence(gate_source, expected_complete_pin_command):
        findings.append(
            "closed release CI gate omits the complete packet artifact pin verifier"
        )
    expected_swift_test_command = (
        "/usr/bin/swift",
        "test",
        "--package-path",
        "native/macos",
        "--no-parallel",
        "-Xswiftc",
        "-warnings-as-errors",
    )
    if not _source_contains_token_sequence(gate_source, expected_swift_test_command):
        findings.append(
            "closed release CI gate omits deterministic Swift package test command "
            + repr(" ".join(expected_swift_test_command))
        )
    expected_tauri_install_command = (
        "TMPDIR=$tauri_temporary_parent",
        "/bin/bash",
        "-p",
        "$repo_root/scripts/install_pinned_tauri_cli.sh",
    )
    if not _source_contains_token_sequence(gate_source, expected_tauri_install_command):
        findings.append(
            "closed release CI gate omits explicit Tauri temporary-directory forwarding"
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
        gates = _release_gate_commands(body)
        if (
            "unittest discover" not in body
            and "release-tool-tests" not in gates
        ):
            continue
        if gates.count("bootstrap-policy-tools") != 1:
            findings.append(
                f"job {name!r} runs release-tool tests without pinned identity tool bootstrap"
            )
        if gates.count("release-tool-tests") != 1:
            findings.append(
                f"job {name!r} must run exactly one closed release-tool test gate"
            )
        if gates.count("apple-toolchain") != 1:
            findings.append(
                f"job {name!r} must run exactly one strict Apple toolchain preflight"
            )
        if (
            gates.count("bootstrap-policy-tools") == 1
            and gates.count("apple-toolchain") == 1
            and gates.count("release-tool-tests") == 1
            and not (
                gates.index("bootstrap-policy-tools")
                < gates.index("apple-toolchain")
                < gates.index("release-tool-tests")
            )
        ):
            findings.append(
                f"job {name!r} must run the strict Apple toolchain preflight after "
                "identity-tool bootstrap and before release-tool tests"
            )
    return findings


def _check_tauri_frontend_dependencies(jobs: dict[str, str]) -> list[str]:
    """Require the real frontend build before Rust expands Tauri context macros."""

    findings: list[str] = []
    rust_consumers = ("rust-clippy", "rust-test")
    ui_producers = ("bootstrap-node-toolchain", "prepare-ui-dependencies", "ui-build")
    for name, body in jobs.items():
        gates = _release_gate_commands(body)
        active_consumers = tuple(gate for gate in rust_consumers if gate in gates)
        if not active_consumers:
            continue
        for producer in ui_producers:
            if gates.count(producer) != 1:
                findings.append(
                    f"job {name!r} must run exactly one {producer!r} before Tauri Rust gates"
                )
        if any(gates.count(producer) != 1 for producer in ui_producers):
            continue
        producer_indexes = {producer: gates.index(producer) for producer in ui_producers}
        if not (
            producer_indexes["bootstrap-node-toolchain"]
            < producer_indexes["prepare-ui-dependencies"]
            < producer_indexes["ui-build"]
        ):
            findings.append(
                f"job {name!r} must bootstrap Node and prepare UI dependencies "
                "before ui-build"
            )
        for consumer in active_consumers:
            if producer_indexes["ui-build"] > gates.index(consumer):
                findings.append(
                    f"job {name!r} must run ui-build before {consumer}"
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
    raw_workflow = workflow_path.read_bytes()
    workflow_identity_drifted = (
        workflow_path.absolute() == DEFAULT_WORKFLOW.absolute()
        and hashlib.sha256(raw_workflow).hexdigest() != REQUIRED_WORKFLOW_SHA256
    )
    try:
        text = raw_workflow.decode("utf-8")
    except UnicodeDecodeError as error:
        raise CiPolicyError("CI workflow is not UTF-8 source") from error
    active_text = _without_full_line_comments(text)
    pins = _read_pins(pins_path)

    findings: list[str] = []
    if workflow_identity_drifted:
        findings.append("CI workflow differs from the exact reviewed execution policy")
    findings += _check_yaml_mapping_policy(active_text)
    findings += _check_masking(active_text)
    findings += _check_gates(active_text)
    findings += _check_ui_boundary(active_text)
    findings += _check_apple_driver_boundary(active_text)
    findings += _check_python_isolation(active_text)
    findings += _check_release_ci_boundary(active_text, pins)
    jobs = _split_jobs(active_text)
    findings += _check_source_checkout(jobs)
    findings += _check_hosted_xcode_ownership(jobs, pins)
    findings += _check_job_bounds(jobs)
    findings += _check_release_tool_test_dependencies(jobs)
    findings += _check_tauri_frontend_dependencies(jobs)
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
