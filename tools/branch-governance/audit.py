#!/usr/bin/env python3
"""Read-only audit of control-plane branch ancestry; never merges or deletes.

Run against a local clone with the named remote refs fetched. Results are
observations of Git history, not code equivalence or release qualification.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


class AuditError(Exception):
    pass


BRANCH = re.compile(r"[A-Za-z0-9][A-Za-z0-9/_.-]{0,159}\Z")
MANIFEST_KEYS = {
    "schema_version", "observed_at", "repository", "windows_integration_branch",
    "windows_snapshots", "windows_experiments", "independent_review_branches",
    "historical_release_branches", "main_branch",
}
GROUP_KEYS = (
    "windows_snapshots", "windows_experiments",
    "independent_review_branches", "historical_release_branches",
)


def validate_branch(name: object) -> str:
    if not isinstance(name, str) or not BRANCH.fullmatch(name):
        raise AuditError("branch name violates the audit schema")
    if any(part in {"", ".", ".."} or part.endswith(".lock") for part in name.split("/")):
        raise AuditError("branch name contains an unsafe component")
    if ".." in name or "@{" in name or name.endswith("."):
        raise AuditError("invalid Git branch name")
    return name


def unique_json_pairs(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for key, value in pairs:
        if key in result:
            raise AuditError("duplicate manifest field")
        result[key] = value
    return result


def load_manifest(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=unique_json_pairs)
    except (ValueError, UnicodeError) as exc:
        raise AuditError("manifest is invalid JSON") from exc
    if not isinstance(data, dict) or set(data) != MANIFEST_KEYS:
        raise AuditError("unexpected manifest fields")
    if type(data["schema_version"]) is not int or data["schema_version"] != 1:
        raise AuditError("unsupported manifest version")
    if not isinstance(data["observed_at"], str) or not re.fullmatch(r"\d{4}-\d{2}-\d{2}", data["observed_at"]):
        raise AuditError("manifest observation date is invalid")
    if data["repository"] != "billlza/cfw-rs":
        raise AuditError("manifest repository identity is invalid")
    names = [validate_branch(data["windows_integration_branch"]), validate_branch(data["main_branch"])]
    for group in GROUP_KEYS:
        entries = data[group]
        if not isinstance(entries, list) or len(entries) > 128 or (group == "windows_snapshots" and not entries):
            raise AuditError("invalid manifest branch group")
        names.extend(validate_branch(entry) for entry in entries)
    if len(names) != len(set(names)):
        raise AuditError("a branch belongs to multiple authority groups")
    return data


def git(repository: Path, *args: str) -> str:
    try:
        p = subprocess.run(
            ["git", "-C", str(repository), *args], check=False,
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise AuditError("Git observation failed or timed out") from exc
    if p.returncode:
        # Git error output can contain untrusted URL or credential context.
        raise AuditError(f"Git observation unavailable (exit {p.returncode})")
    return p.stdout.strip()


def ref_for(remote: str, branch: str) -> str:
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,49}", remote):
        raise AuditError("invalid Git remote name")
    return "refs/remotes/" + remote + "/" + validate_branch(branch)


def ref_sha(repository: Path, remote: str, branch: str) -> str:
    ref = ref_for(remote, branch)
    sha = git(repository, "rev-parse", "--verify", ref + "^{commit}")
    if not re.fullmatch("[a-f0-9]{40,64}", sha):
        raise AuditError("Git commit identity is not canonical")
    return sha


def divergence(repository: Path, source_sha: str, target_sha: str) -> tuple[str, int, int]:
    output = git(repository, "rev-list", "--left-right", "--count",
                 source_sha + "..." + target_sha)
    tokens = output.split()
    if len(tokens) != 2 or any(not token.isascii() or not token.isdecimal() for token in tokens):
        raise AuditError("invalid ancestry comparison")
    source_only, target_only = map(int, tokens)
    if source_only == 0 and target_only == 0:
        category = "identical"
    elif source_only == 0:
        category = "contained_in_target"
    elif target_only == 0:
        category = "target_behind_source"
    else:
        category = "diverged"
    return category, source_only, target_only


def audit(repository: Path, manifest: dict, remote: str) -> tuple[dict, bool]:
    main = manifest["main_branch"]
    windows = manifest["windows_integration_branch"]
    named = [main, windows]
    for group in GROUP_KEYS:
        named.extend(manifest[group])
    shas = {name: ref_sha(repository, remote, name) for name in named}
    records = []
    safe = True
    for group in ("windows_snapshots", "windows_experiments",
                  "independent_review_branches", "historical_release_branches"):
        target = windows if group.startswith("windows_") else main
        for branch in manifest[group]:
            status, source_only, target_only = divergence(repository, shas[branch], shas[target])
            if group in {"windows_snapshots", "historical_release_branches"}:
                decision = "already_in_canonical_history" if source_only == 0 else "review_unexpected_divergence"
                safe = safe and source_only == 0
            else:
                decision = "independent_review_no_automatic_merge"
            records.append({
                "group": group, "branch": branch, "branch_sha": shas[branch],
                "target": target, "target_sha": shas[target],
                "status": status, "source_only_commits": source_only,
                "target_only_commits": target_only, "decision": decision,
            })
    return {
        "schema_version": 1,
        "observed_at": manifest["observed_at"],
        "main_sha": shas[main], "windows_integration_sha": shas[windows],
        "records": records,
        "audit_conclusion": "expected_history" if safe else "unexpected_divergence",
        "note": "Git ancestry only; no merge, deletion, source equivalence or CI qualification",
    }, safe


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--remote", default="origin")
    parser.add_argument("--strict", action="store_true",
                        help="fail if archived/snapshot branch contains changes absent from its canonical history")
    opts = parser.parse_args(argv)
    try:
        manifest = load_manifest(opts.manifest)
        result, safe = audit(opts.repository, manifest, opts.remote)
        print(json.dumps(result, sort_keys=True, indent=2))
        return 0 if safe or not opts.strict else 2
    except (AuditError, OSError) as exc:
        print(f"branch governance: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
