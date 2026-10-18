#!/usr/bin/env python3
"""Run cargo-deny without mixing live policy data into build inputs.

Cargo metadata is produced from the verified, offline release Cargo home. The
license/source/bans checks reuse that closed environment. Advisories and yanked
status use the same metadata but a fresh private Cargo home so current registry
policy data can be fetched without becoming a compiler input. Both cargo-deny
results must be a single warning-free JSON summary.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import stat
import subprocess
import tempfile
import tomllib
from typing import Any, Mapping, Sequence

if __package__:
    from .publication.bounded_process import BoundedProcessError, run_bounded_process
else:
    from publication.bounded_process import BoundedProcessError, run_bounded_process


SUPPORTED_TARGET = "aarch64-apple-darwin"
POLICY_NAMES = ("advisories", "bans", "licenses", "sources")
SUMMARY_STAT_NAMES = ("errors", "helps", "notes", "warnings")
METADATA_TIMEOUT_SECONDS = 300
OFFLINE_POLICY_TIMEOUT_SECONDS = 300
ONLINE_POLICY_TIMEOUT_SECONDS = 900
OUTPUT_LIMIT_BYTES = 64 * 1024 * 1024


class CargoPolicyError(RuntimeError):
    """The cargo-deny execution or its closed result contract failed."""


class _DuplicateFieldError(ValueError):
    pass


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise _DuplicateFieldError(f"duplicate JSON field: {key}")
        result[key] = value
    return result


def _decode_json(encoded: bytes, label: str) -> Any:
    try:
        return json.loads(
            encoded.decode("utf-8"),
            object_pairs_hook=_strict_object,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, _DuplicateFieldError) as error:
        raise CargoPolicyError(f"{label} is not strict UTF-8 JSON") from error


def parse_policy_result(encoded: bytes, expected_checks: Sequence[str]) -> dict[str, dict[str, int]]:
    """Accept exactly one clean cargo-deny JSON summary and no diagnostics."""

    if not expected_checks or any(name not in POLICY_NAMES for name in expected_checks):
        raise CargoPolicyError("cargo-deny expected check set is invalid")
    records = []
    for line in encoded.splitlines():
        if line.strip():
            records.append(_decode_json(line, "cargo-deny output line"))
    if len(records) != 1:
        kinds = [
            record.get("type", "unknown") if isinstance(record, dict) else "non-object"
            for record in records[:4]
        ]
        rendered = ", ".join(kinds) if kinds else "empty output"
        raise CargoPolicyError(
            "cargo-deny emitted diagnostics instead of one summary: " + rendered
        )
    record = records[0]
    if not isinstance(record, dict) or set(record) != {"fields", "type"}:
        raise CargoPolicyError("cargo-deny summary has an unexpected shape")
    if record.get("type") != "summary" or not isinstance(record.get("fields"), dict):
        raise CargoPolicyError("cargo-deny did not return a summary record")
    fields = record["fields"]
    if set(fields) != set(expected_checks):
        raise CargoPolicyError("cargo-deny summary has an unexpected policy set")
    parsed: dict[str, dict[str, int]] = {}
    for policy_name in expected_checks:
        values = fields.get(policy_name)
        if not isinstance(values, dict) or set(values) != set(SUMMARY_STAT_NAMES):
            raise CargoPolicyError(
                f"cargo-deny {policy_name} summary has an unexpected shape"
            )
        policy_values: dict[str, int] = {}
        for stat_name in SUMMARY_STAT_NAMES:
            value = values.get(stat_name)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise CargoPolicyError(
                    f"cargo-deny {policy_name} {stat_name} is not a non-negative integer"
                )
            policy_values[stat_name] = value
        parsed[policy_name] = policy_values
    for policy_name in expected_checks:
        values = parsed[policy_name]
        if values["errors"] or values["warnings"] or values["notes"]:
            raise CargoPolicyError(
                f"cargo-deny {policy_name} reported "
                f"{values['errors']} errors, {values['warnings']} warnings, "
                f"and {values['notes']} notes"
            )
    return parsed


def _require_executable(value: str | None, label: str) -> Path:
    if not value:
        raise CargoPolicyError(f"closed {label} executable is required")
    path = Path(value)
    if (
        not path.is_absolute()
        or not path.is_file()
        or path.is_symlink()
        or not os.access(path, os.X_OK)
    ):
        raise CargoPolicyError(f"closed {label} executable is unavailable")
    return path


def _require_private_directory(path: Path, label: str) -> Path:
    try:
        metadata = path.lstat()
        canonical = path.resolve(strict=True)
    except OSError as error:
        raise CargoPolicyError(f"{label} is unavailable") from error
    if (
        not path.is_absolute()
        or canonical != path
        or not stat.S_ISDIR(metadata.st_mode)
        or path.is_symlink()
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) != 0o700
    ):
        raise CargoPolicyError(f"{label} is not an owner-only real directory")
    return path


def _require_policy_config(path: Path) -> None:
    try:
        with path.open("rb") as handle:
            config = tomllib.load(handle)
    except (OSError, tomllib.TOMLDecodeError) as error:
        raise CargoPolicyError("deny.toml is not valid TOML") from error
    if not isinstance(config, dict):
        raise CargoPolicyError("deny.toml root is not a table")
    graph = config.get("graph")
    if not isinstance(graph, dict):
        raise CargoPolicyError("deny.toml has no graph policy")
    if (
        graph.get("targets") != [SUPPORTED_TARGET]
        or graph.get("all-features") is not True
    ):
        raise CargoPolicyError(
            "deny.toml must select the exact macOS Arm64 all-features graph"
        )
    advisories = config.get("advisories")
    if not isinstance(advisories, dict):
        raise CargoPolicyError("deny.toml has no advisory policy")
    if advisories.get("yanked") != "deny":
        raise CargoPolicyError("deny.toml must deny yanked packages")
    if advisories.get("disable-yank-checking") is not False:
        raise CargoPolicyError("deny.toml must keep yanked-package checking enabled")


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
        raise CargoPolicyError(f"{label} failed its {error.reason} boundary") from error


def _require_success(
    result: subprocess.CompletedProcess[bytes],
    label: str,
) -> None:
    if result.returncode != 0:
        encoded = (result.stderr or result.stdout)[-8192:]
        detail = encoded.decode("utf-8", errors="replace").strip()
        raise CargoPolicyError(
            f"{label} failed with status {result.returncode}"
            + (f": {detail}" if detail else "")
        )


def _write_private(path: Path, encoded: bytes) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags, 0o600)
    try:
        written = 0
        while written < len(encoded):
            written += os.write(descriptor, encoded[written:])
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _cargo_deny_command(
    cargo_deny: Path,
    metadata_path: Path,
    config_path: Path,
    checks: Sequence[str],
) -> list[str]:
    return [
        str(cargo_deny),
        "--format",
        "json",
        "--metadata-path",
        str(metadata_path),
        "--config",
        str(config_path),
        "--locked",
        "--target",
        SUPPORTED_TARGET,
        "check",
        *checks,
    ]


def run(repository: Path) -> int:
    repository = repository.resolve(strict=True)
    cargo = _require_executable(
        os.environ.get("CFW_RELEASE_CARGO_EXECUTABLE"), "Cargo"
    )
    cargo_deny = _require_executable(
        os.environ.get("CFW_RELEASE_CARGO_DENY_EXECUTABLE"), "cargo-deny"
    )
    closed_cargo_home_value = os.environ.get("CARGO_HOME")
    if not closed_cargo_home_value:
        raise CargoPolicyError("closed Cargo home is required")
    closed_cargo_home = _require_private_directory(
        Path(closed_cargo_home_value), "closed Cargo home"
    )
    if os.environ.get("CARGO_NET_OFFLINE") != "true":
        raise CargoPolicyError("closed Cargo metadata must run offline")
    config_path = repository / "deny.toml"
    if not config_path.is_file() or config_path.is_symlink():
        raise CargoPolicyError("deny.toml is unavailable")
    _require_policy_config(config_path)

    release_home_value = os.environ.get("HOME")
    if not release_home_value:
        raise CargoPolicyError("closed release home is required")
    release_home = Path(release_home_value).resolve(strict=True)
    policy_parent = release_home / ".cfm-release-tooling" / "cargo-policy-checks"
    policy_parent.mkdir(mode=0o700, parents=False, exist_ok=True)
    _require_private_directory(policy_parent, "Cargo policy check parent")

    closed_environment = dict(os.environ)
    metadata_result = _bounded(
        [
            str(cargo),
            "metadata",
            "--locked",
            "--all-features",
            "--filter-platform",
            SUPPORTED_TARGET,
            "--format-version",
            "1",
        ],
        repository=repository,
        environment=closed_environment,
        timeout=METADATA_TIMEOUT_SECONDS,
        label="closed Cargo metadata",
    )
    _require_success(metadata_result, "closed Cargo metadata")
    if metadata_result.stderr:
        raise CargoPolicyError("closed Cargo metadata emitted stderr")
    metadata = _decode_json(metadata_result.stdout, "closed Cargo metadata")
    if (
        not isinstance(metadata, dict)
        or not isinstance(metadata.get("packages"), list)
        or not isinstance(metadata.get("resolve"), dict)
        or not isinstance(metadata.get("workspace_members"), list)
    ):
        raise CargoPolicyError("closed Cargo metadata has an incomplete graph")

    with tempfile.TemporaryDirectory(prefix="cargo-deny.", dir=policy_parent) as temporary:
        temporary_root = Path(temporary)
        temporary_root.chmod(0o700)
        _require_private_directory(temporary_root, "Cargo policy temporary root")
        metadata_path = temporary_root / "metadata.json"
        _write_private(metadata_path, metadata_result.stdout)

        offline_result = _bounded(
            _cargo_deny_command(
                cargo_deny,
                metadata_path,
                config_path,
                ("bans", "licenses", "sources"),
            ),
            repository=repository,
            environment=closed_environment,
            timeout=OFFLINE_POLICY_TIMEOUT_SECONDS,
            label="offline cargo-deny policy",
        )
        _require_success(offline_result, "offline cargo-deny policy")
        parse_policy_result(
            offline_result.stdout + offline_result.stderr,
            ("bans", "licenses", "sources"),
        )

        policy_home = temporary_root / "home"
        policy_cargo_home = temporary_root / "cargo-home"
        policy_tmp = temporary_root / "tmp"
        for directory in (policy_home, policy_cargo_home, policy_tmp):
            directory.mkdir(mode=0o700)
            _require_private_directory(directory, "Cargo policy private directory")
        online_environment = {
            "CARGO": str(cargo),
            "CARGO_HOME": str(policy_cargo_home),
            "CARGO_NET_OFFLINE": "false",
            "CARGO_TERM_COLOR": "never",
            "GIT_ASKPASS": "/usr/bin/false",
            "GIT_ATTR_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_SYSTEM": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
            "HOME": str(policy_home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": os.environ.get("PATH", ""),
            "TMPDIR": str(policy_tmp),
        }
        online_result = _bounded(
            _cargo_deny_command(
                cargo_deny,
                metadata_path,
                config_path,
                ("advisories",),
            ),
            repository=repository,
            environment=online_environment,
            timeout=ONLINE_POLICY_TIMEOUT_SECONDS,
            label="online cargo-deny advisory policy",
        )
        _require_success(online_result, "online cargo-deny advisory policy")
        parse_policy_result(
            online_result.stdout + online_result.stderr,
            ("advisories",),
        )

    # The outer shell wrapper verifies and removes closed_cargo_home after this
    # script returns. Keep the reference live here to make that ownership clear.
    if not closed_cargo_home.exists():
        raise CargoPolicyError("closed Cargo home disappeared during policy checks")
    print(
        "cargo-deny policy passed: "
        f"{SUPPORTED_TARGET}, advisories/yanked/bans/licenses/sources, "
        "0 errors, 0 warnings, 0 notes"
    )
    return 0


def main() -> None:
    try:
        raise SystemExit(run(Path(__file__).resolve().parent.parent))
    except (CargoPolicyError, OSError, ValueError) as error:
        raise SystemExit(f"error: cargo-deny policy failed: {error}") from error


if __name__ == "__main__":
    main()


__all__ = ["CargoPolicyError", "parse_policy_result", "run"]
