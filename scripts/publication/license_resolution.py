from __future__ import annotations

import json
import os
import re
import stat
import tomllib
from pathlib import Path
from typing import Any

from .common import PublicationError, read_regular, require_sha256, sha256_file
from .graph_model import ComponentSeed


MAX_LICENSE_BYTES = 4 * 1024 * 1024
LICENSE_NAME_RE = re.compile(
    r"^(license|licence|copying|copyright|notice|unlicense)([._-].*)?$", re.I
)
SPDX_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9.+-]*")
SPDX_LEXER_RE = re.compile(r"\(|\)|AND\b|OR\b|WITH\b|[A-Za-z0-9][A-Za-z0-9.+-]*")
OPERATORS = {"AND", "OR", "WITH"}
MAX_SPDX_BRANCHES = 128
_CARGO_LICENSE_DONORS = {
    "BSD-3-Clause": (
        "alloc-no-stdlib-2.0.4/LICENSE",
        "c0c56f26d9c051cac4d200c34c84e7ae9aaa853e01a982a1df08b09931e518ae",
    ),
    "MIT": (
        "ident_case-1.0.1/LICENSE",
        "508a77d2e7b51d98adeed32648ad124b7b30241a8e70b2e72c99f92d8e5874d1",
    ),
    "MPL-2.0": (
        "cssparser-0.36.0/LICENSE",
        "fab3dd6bdab226f1c08630b1dd917e11fcb4ec5e1e020e2c16f83a0a13863e85",
    ),
}


def canonical_spdx_expression(value: str) -> str:
    expression = value.strip()
    expression = re.sub(r"\s*/\s*", " OR ", expression)
    expression = re.sub(r"\s+", " ", expression)
    matches = list(SPDX_LEXER_RE.finditer(expression))
    tokens = [match.group(0) for match in matches]
    if not tokens or any(token.upper() in {"NONE", "NOASSERTION", "UNKNOWN"} for token in tokens):
        raise PublicationError("declared license expression is not reviewable SPDX")
    cursor = 0
    for match in matches:
        if expression[cursor : match.start()].strip():
            raise PublicationError("declared license expression contains unsupported syntax")
        cursor = match.end()
    if expression[cursor:].strip():
        raise PublicationError("declared license expression contains unsupported syntax")
    position = 0

    def primary() -> None:
        nonlocal position
        if position >= len(tokens):
            raise PublicationError("declared license expression is incomplete")
        if tokens[position] == "(":
            position += 1
            disjunction()
            if position >= len(tokens) or tokens[position] != ")":
                raise PublicationError("declared license expression has unbalanced parentheses")
            position += 1
            return
        if tokens[position] in {"AND", "OR", "WITH", ")"}:
            raise PublicationError("declared license expression has an invalid operand")
        position += 1

    def with_exception() -> None:
        nonlocal position
        primary()
        if position < len(tokens) and tokens[position] == "WITH":
            position += 1
            if position >= len(tokens) or tokens[position] in {"AND", "OR", "WITH", "(", ")"}:
                raise PublicationError("declared license exception is invalid")
            position += 1

    def conjunction() -> None:
        nonlocal position
        with_exception()
        while position < len(tokens) and tokens[position] == "AND":
            position += 1
            with_exception()

    def disjunction() -> None:
        nonlocal position
        conjunction()
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            conjunction()

    disjunction()
    if position != len(tokens):
        raise PublicationError("declared license expression has trailing tokens")
    return expression


def _license_ids(expression: str) -> set[str]:
    return {token for token in SPDX_TOKEN_RE.findall(expression) if token.upper() not in OPERATORS}


def _license_branches(expression: str) -> list[frozenset[str]]:
    """Return bounded DNF branches so one declared OR choice can be concluded."""
    tokens = [match.group(0) for match in SPDX_LEXER_RE.finditer(expression)]
    position = 0

    def primary() -> list[frozenset[str]]:
        nonlocal position
        if tokens[position] == "(":
            position += 1
            branches = disjunction()
            position += 1
            return branches
        identifier = tokens[position]
        position += 1
        return [frozenset({identifier})]

    def with_exception() -> list[frozenset[str]]:
        nonlocal position
        branches = primary()
        if position < len(tokens) and tokens[position] == "WITH":
            position += 1
            exception = tokens[position]
            position += 1
            branches = [branch | {exception} for branch in branches]
        return branches

    def conjunction() -> list[frozenset[str]]:
        nonlocal position
        branches = with_exception()
        while position < len(tokens) and tokens[position] == "AND":
            position += 1
            right = with_exception()
            branches = [left | candidate for left in branches for candidate in right]
            if len(branches) > MAX_SPDX_BRANCHES:
                raise PublicationError("declared license expression has too many branches")
        return branches

    def disjunction() -> list[frozenset[str]]:
        nonlocal position
        branches = conjunction()
        while position < len(tokens) and tokens[position] == "OR":
            position += 1
            branches.extend(conjunction())
            if len(branches) > MAX_SPDX_BRANCHES:
                raise PublicationError("declared license expression has too many branches")
        return branches

    branches = disjunction()
    if position != len(tokens):
        raise PublicationError("declared license expression could not be normalized")
    return branches


def _cargo_license_donors(seed: ComponentSeed) -> dict[str, Path]:
    if seed.ecosystem != "cargo" or seed.source_root is None:
        return {}
    registry_root = seed.source_root.parent
    donors: dict[str, Path] = {}
    for identifier, (relative, expected_digest) in _CARGO_LICENSE_DONORS.items():
        path = registry_root / relative
        if (
            path.is_file()
            and not path.is_symlink()
            and sha256_file(path) == expected_digest
        ):
            donors[identifier] = path.resolve(strict=True)
    return donors


def _required_notice(path: Path) -> bool:
    return path.name.casefold().startswith(("copyright", "notice"))


def _automatic_files(
    selected: dict[Path, set[str]], candidates: list[Path]
) -> list[dict[str, Any]]:
    for notice in candidates:
        if _required_notice(notice):
            selected.setdefault(notice, set())
    return [
        {
            "path": str(path),
            "sha256": sha256_file(path),
            "supports": sorted(license_ids),
        }
        for path, license_ids in sorted(selected.items(), key=lambda item: str(item[0]))
    ]


def _candidate_files(root: Path | None, maximum_depth: int = 3) -> list[Path]:
    if root is None or not root.is_dir() or root.is_symlink():
        return []
    candidates: list[Path] = []
    excluded = {".build", ".git", ".hg", ".svn", "node_modules", "reverse", "target"}
    for current, directories, files in os.walk(root, topdown=True, followlinks=False):
        current_path = Path(current)
        depth = len(current_path.relative_to(root).parts)
        directories[:] = sorted(
            name
            for name in directories
            if name not in excluded and not (current_path / name).is_symlink() and depth < maximum_depth
        )
        for name in sorted(files):
            path = current_path / name
            metadata = path.lstat()
            in_license_directory = "licenses" in {
                part.casefold() for part in path.relative_to(root).parent.parts
            }
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or not (
                    LICENSE_NAME_RE.fullmatch(name)
                    or (in_license_directory and path.suffix.casefold() in {".md", ".txt"})
                )
            ):
                continue
            if metadata.st_size <= 0 or metadata.st_size > MAX_LICENSE_BYTES:
                continue
            candidates.append(path.resolve(strict=True))
    return sorted(set(candidates), key=lambda value: str(value))


def _supports(identifier: str, text: str, filename: str) -> bool:
    uncommented = re.sub(r"(?m)^\s*(?://+|#+|\*+)\s?", "", text)
    lowered = " ".join(uncommented.casefold().split())
    name = filename.casefold()
    if identifier == "MIT":
        return (
            "permission is hereby granted, free of charge, to any person obtaining a copy"
            in lowered
            and "mit no attribution" not in lowered
            and "unicode" not in name
        )
    if identifier == "MIT-0":
        return "mit no attribution" in lowered or "mit-0" in name
    if identifier == "Apache-2.0":
        return "apache license" in lowered and (
            "version 2.0, january 2004" in lowered
            or "apache license, version 2.0" in lowered
        )
    if identifier == "LLVM-exception":
        return "llvm exceptions to the apache 2.0 license" in lowered or "llvm-exception" in name
    if identifier == "MPL-2.0":
        return (
            "mozilla public license version 2.0" in lowered
            or "mozilla public license, version 2.0" in lowered
        )
    if identifier == "Unicode-3.0":
        return (
            "unicode license v3" in lowered
            or "unicode license agreement - data files and software" in lowered
            or "unicode-3.0" in name
        )
    if identifier == "Zlib":
        return "this software is provided 'as-is', without any express or implied warranty" in lowered
    if identifier == "ISC":
        return (
            "permission to use, copy, modify, and/or distribute this software for any purpose"
            in lowered
            and (
                "isc" in name
                or "provided that the above copyright notice" in lowered
                or "this permission notice appear in all copies" in lowered
            )
        )
    if identifier == "BSD-3-Clause":
        return (
            "redistribution and use in source and binary forms" in lowered
            and "neither the name" in lowered
        )
    if identifier == "BSD-2-Clause":
        return (
            "redistribution and use in source and binary forms" in lowered
            and "neither the name" not in lowered
        )
    if identifier == "0BSD":
        return "zero-clause bsd" in lowered or "0bsd" in name
    if identifier == "Unlicense":
        return "this is free and unencumbered software released into the public domain" in lowered
    if identifier == "CC0-1.0":
        return "cc0 1.0 universal" in lowered or "creative commons legal code" in lowered
    if identifier == "GPL-3.0-or-later":
        return "gnu general public license" in lowered and (
            "version 3, 29 june 2007" in lowered
            or (
                "either version 3" in lowered
                and "at your option) any later version" in lowered
            )
        )
    if identifier == "GPL-2.0-only":
        return "gnu general public license" in lowered and "version 2, june 1991" in lowered
    if identifier == "BSL-1.0":
        return "boost software license - version 1.0" in lowered
    if identifier == "NCSA":
        return "university of illinois/ncsa open source license" in lowered
    return False


def _metadata_identity(seed: ComponentSeed) -> dict[str, str] | None:
    path = seed.metadata_path
    if path is None or not path.is_file() or path.is_symlink():
        return None
    if seed.ecosystem == "npm":
        try:
            package = json.loads(read_regular(path))
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise PublicationError(f"npm package metadata is invalid: {path}") from error
        if not isinstance(package, dict) or package.get("name") != seed.name:
            raise PublicationError(f"npm package metadata identity mismatch: {seed.identifier}")
        declared = package.get("license")
        if seed.declared_license is not None and declared != seed.declared_license:
            raise PublicationError(f"npm package license metadata mismatch: {seed.identifier}")
    elif seed.ecosystem in {"application", "native", "swift"}:
        try:
            manifest = tomllib.loads(read_regular(path).decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise PublicationError(f"project license metadata is invalid: {path}") from error
        declared = manifest.get("workspace", {}).get("package", {}).get("license")
        if not isinstance(declared, str) or declared != seed.declared_license:
            raise PublicationError(f"project license metadata mismatch: {seed.identifier}")
    elif seed.ecosystem == "cargo":
        try:
            manifest = tomllib.loads(read_regular(path).decode("utf-8"))
        except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
            raise PublicationError(f"Cargo package metadata is invalid: {path}") from error
        declared = manifest.get("package", {}).get("license")
        if isinstance(declared, str) and declared != seed.declared_license:
            raise PublicationError(f"Cargo package license metadata mismatch: {seed.identifier}")
    elif seed.ecosystem == "go":
        text = read_regular(path).decode("utf-8")
        module_lines = [line.split(None, 1)[1] for line in text.splitlines() if line.startswith("module ")]
        if module_lines != [seed.name]:
            raise PublicationError(f"Go module metadata identity mismatch: {seed.identifier}")
    return {"path": str(path.resolve(strict=True)), "sha256": sha256_file(path)}


def resolve_license(seed: ComponentSeed) -> dict[str, Any]:
    metadata = _metadata_identity(seed)
    candidates = _candidate_files(seed.license_root, 1 if seed.ecosystem == "go" else 3)
    decoded: dict[Path, str] = {}
    for path in candidates:
        try:
            decoded[path] = read_regular(path, MAX_LICENSE_BYTES).decode("utf-8")
        except UnicodeDecodeError:
            continue
    declared = seed.declared_license
    if declared:
        expression = canonical_spdx_expression(declared)
        donors = _cargo_license_donors(seed)
        supporting_by_id: dict[str, list[Path]] = {}
        for identifier in sorted(_license_ids(expression)):
            supporting = [
                path for path, text in decoded.items() if _supports(identifier, text, path.name)
            ]
            supporting.sort(key=lambda path: (_required_notice(path), str(path)))
            donor = donors.get(identifier)
            if donor is not None and donor not in supporting:
                supporting.append(donor)
            supporting_by_id[identifier] = supporting
        branches = _license_branches(expression)
        satisfied = [
            branch
            for branch in branches
            if all(supporting_by_id.get(identifier) for identifier in branch)
        ]
        if satisfied and metadata is not None:
            selected_branch = satisfied[0]
            selected: dict[Path, set[str]] = {}
            for identifier in sorted(selected_branch):
                selected.setdefault(supporting_by_id[identifier][0], set()).add(identifier)
            return {
                "status": "automatic",
                "expression": expression,
                "method": "declared-spdx-selected-branch-plus-license-text-v2",
                "reason": "",
                "metadata": metadata,
                "files": _automatic_files(selected, candidates),
            }
        available = sorted(
            identifier for identifier, supporting in supporting_by_id.items() if supporting
        )
        required_branches = [sorted(branch) for branch in branches]
        reason = (
            "no declared SPDX licensing branch has complete source text; "
            f"available={available}, required_branches={required_branches}"
            if not satisfied
            else "component lacks hashed machine-readable identity metadata"
        )
        return _manual_result(expression, reason, metadata, candidates)

    recognized: dict[str, list[Path]] = {}
    for identifier in (
        "0BSD",
        "Apache-2.0",
        "BSD-2-Clause",
        "BSD-3-Clause",
        "BSL-1.0",
        "CC0-1.0",
        "GPL-2.0-only",
        "GPL-3.0-or-later",
        "ISC",
        "MIT",
        "MIT-0",
        "MPL-2.0",
        "NCSA",
        "Unicode-3.0",
        "Unlicense",
        "Zlib",
    ):
        matches = [path for path, text in decoded.items() if _supports(identifier, text, path.name)]
        if matches:
            recognized[identifier] = matches
    if len(recognized) == 1 and metadata is not None:
        identifier, matches = next(iter(recognized.items()))
        path = matches[0]
        return {
            "status": "automatic",
            "expression": identifier,
            "method": "source-license-text-plus-package-identity-v1",
            "reason": "",
            "metadata": metadata,
            "files": _automatic_files({path: {identifier}}, candidates),
        }
    if not recognized:
        reason = "no supported canonical license text was found"
    else:
        reason = f"license texts imply an ambiguous expression: {sorted(recognized)}"
    if metadata is None:
        reason += "; hashed machine-readable identity metadata is absent"
    return _manual_result("", reason, metadata, candidates)


def _manual_result(
    expression: str,
    reason: str,
    metadata: dict[str, str] | None,
    candidates: list[Path],
) -> dict[str, Any]:
    return {
        "status": "manual-required",
        "expression": expression,
        "method": "",
        "reason": reason,
        "metadata": metadata,
        "files": [
            {"path": str(path), "sha256": sha256_file(path), "supports": []}
            for path in candidates
        ],
    }


def validate_automatic_resolution(seed: ComponentSeed, value: object) -> dict[str, Any]:
    expected = resolve_license(seed)
    if not isinstance(value, dict):
        raise PublicationError(f"component license resolution is not an object: {seed.identifier}")
    if value.get("status") == "automatic":
        if value != expected or expected["status"] != "automatic":
            raise PublicationError(f"automatic license evidence no longer recomputes: {seed.identifier}")
        return expected
    if value.get("status") == "manual-required":
        raise PublicationError(f"component still requires legal license review: {seed.identifier}")
    if value.get("status") != "manual-reviewed":
        raise PublicationError(f"component has an unsupported license review state: {seed.identifier}")
    required = {"status", "expression", "method", "reason", "metadata", "files"}
    if set(value) != required or value.get("method") != "human-legal-review":
        raise PublicationError(f"manual license review is not explicit: {seed.identifier}")
    expression = canonical_spdx_expression(value.get("expression", ""))
    expression_ids = _license_ids(expression)
    if not isinstance(value.get("reason"), str) or not value["reason"].strip():
        raise PublicationError(f"manual license review has no rationale: {seed.identifier}")
    files = value.get("files")
    if not isinstance(files, list) or not files:
        raise PublicationError(f"manual license review has no source text: {seed.identifier}")
    for item in files:
        if not isinstance(item, dict) or set(item) != {"path", "sha256", "supports"}:
            raise PublicationError(f"manual license evidence is malformed: {seed.identifier}")
        path_value = item["path"]
        supports = item["supports"]
        if (
            not isinstance(path_value, str)
            or not path_value.startswith("/")
            or not isinstance(supports, list)
            or not supports
            or supports != sorted(set(supports))
            or not set(supports).issubset(expression_ids)
        ):
            raise PublicationError(f"manual license evidence binding is invalid: {seed.identifier}")
        path = Path(path_value)
        digest = require_sha256(item["sha256"], f"manual license digest for {seed.identifier}")
        if path.is_symlink() or sha256_file(path) != digest:
            raise PublicationError(f"manual license evidence changed: {seed.identifier}")
    metadata = value.get("metadata")
    expected_metadata = _metadata_identity(seed)
    if expected_metadata is not None and metadata != expected_metadata:
        raise PublicationError(f"manual license metadata no longer recomputes: {seed.identifier}")
    if metadata is not None:
        if not isinstance(metadata, dict) or set(metadata) != {"path", "sha256"}:
            raise PublicationError(f"manual license metadata is malformed: {seed.identifier}")
        metadata_path = metadata["path"]
        if not isinstance(metadata_path, str) or not metadata_path.startswith("/"):
            raise PublicationError(f"manual license metadata path is invalid: {seed.identifier}")
        metadata_digest = require_sha256(
            metadata["sha256"], f"manual license metadata digest for {seed.identifier}"
        )
        if sha256_file(Path(metadata_path)) != metadata_digest:
            raise PublicationError(f"manual license metadata changed: {seed.identifier}")
    normalized = dict(value)
    normalized["expression"] = expression
    return normalized
