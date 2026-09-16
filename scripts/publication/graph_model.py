from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .common import MAX_JSON_BYTES, PublicationError, canonical_json
from .bounded_process import BoundedProcessError, run_bounded_process


RELEASE_VERSION = "0.4.0"
MAX_COMMAND_BYTES = 256 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 600


@dataclass(frozen=True)
class ComponentSeed:
    identifier: str
    name: str
    version: str
    ecosystem: str
    scope: str
    purl: str
    source_root: Path | None
    repository_source: bool = False
    license_root: Path | None = None
    metadata_path: Path | None = None
    declared_license: str | None = None
    external_build_tool: bool = False
    provenance_paths: tuple[Path, ...] = ()


@dataclass
class CollectedGraphs:
    components: dict[str, ComponentSeed]
    relationships: set[tuple[str, str, str]]
    graphs: dict[str, dict[str, Any]]
    graph_components: dict[str, set[str]]


def load_pins(path: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise PublicationError(f"dependency pin line {line_number} is not KEY=VALUE")
        key, value = line.split("=", 1)
        if not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or not value:
            raise PublicationError(f"dependency pin line {line_number} is invalid")
        if key in pins:
            raise PublicationError(f"dependency pin is duplicated: {key}")
        pins[key] = value
    return pins


def run(command: list[str], cwd: Path, environment: dict[str, str]) -> bytes:
    try:
        completed = run_bounded_process(
            command,
            cwd=cwd,
            environment=environment,
            timeout=COMMAND_TIMEOUT_SECONDS,
            output_limit=MAX_COMMAND_BYTES,
        )
    except BoundedProcessError as error:
        if error.reason == "output-limit":
            message = f"build graph output exceeded its fixed bound: {command[0]}"
        elif error.reason == "timeout":
            message = f"build graph command timed out: {command[0]}"
        else:
            message = f"cannot collect build graph with {command[0]}: {error}"
        raise PublicationError(message) from error
    if completed.returncode != 0:
        detail = completed.stderr[-8192:].decode("utf-8", errors="replace").strip()
        raise PublicationError(
            f"build graph command failed ({command[0]}, exit {completed.returncode}): {detail}"
        )
    if completed.stderr:
        detail = completed.stderr[-8192:].decode("utf-8", errors="replace").strip()
        raise PublicationError(
            f"build graph command emitted diagnostics ({command[0]}): {detail}"
        )
    return completed.stdout


def run_json(command: list[str], cwd: Path, environment: dict[str, str]) -> Any:
    payload = run(command, cwd, environment)
    try:
        return json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise PublicationError(f"build graph command returned invalid JSON: {command[0]}") from error


def component_id(ecosystem: str, name: str, purl: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9._-]+", "-", name).strip("-")[:64] or "component"
    digest = hashlib.sha256(purl.encode("utf-8")).hexdigest()[:16]
    return f"{ecosystem}:{slug}:{digest}"


def seed(
    name: str,
    version: str,
    ecosystem: str,
    scope: str,
    purl: str,
    source_root: Path | None,
    repository_source: bool = False,
    license_root: Path | None = None,
    metadata_path: Path | None = None,
    declared_license: str | None = None,
    external_build_tool: bool = False,
    provenance_paths: tuple[Path, ...] = (),
) -> ComponentSeed:
    return ComponentSeed(
        identifier=component_id(ecosystem, name, purl),
        name=name,
        version=version,
        ecosystem=ecosystem,
        scope=scope,
        purl=purl,
        source_root=source_root,
        repository_source=repository_source,
        license_root=license_root or source_root,
        metadata_path=metadata_path,
        declared_license=declared_license,
        external_build_tool=external_build_tool,
        provenance_paths=provenance_paths,
    )


def merge_seed(components: dict[str, ComponentSeed], candidate: ComponentSeed) -> None:
    current = components.get(candidate.identifier)
    if current is None:
        components[candidate.identifier] = candidate
        return
    identity = lambda value: (
        value.name,
        value.version,
        value.ecosystem,
        value.purl,
        value.source_root,
        value.license_root,
        value.metadata_path,
        value.declared_license,
        value.external_build_tool,
        value.provenance_paths,
    )
    if identity(current) != identity(candidate):
        raise PublicationError(f"component identity collision: {candidate.identifier}")
    if current.scope == "build" and candidate.scope == "runtime":
        components[candidate.identifier] = ComponentSeed(
            **{**current.__dict__, "scope": "runtime"}
        )


def canonical_graph_bytes(value: object) -> bytes:
    payload = canonical_json(value)
    if len(payload) > MAX_JSON_BYTES:
        raise PublicationError("normalized graph exceeds the fixed JSON bound")
    return payload
