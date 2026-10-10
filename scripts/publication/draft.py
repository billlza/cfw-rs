from __future__ import annotations

from pathlib import Path

from .closure import build_machine_closure
from .common import PublicationError, canonical_json, sha256_bytes, write_new
from .release_contract import draft_path, require_fixed_path


def draft(
    prepared: Path,
    app: Path,
    output: Path,
    fixture: bool,
    *,
    repository: Path | None = None,
) -> str:
    if not fixture:
        if repository is None:
            raise PublicationError("production draft requires an explicit artifact repository")
        require_fixed_path(output, draft_path(repository), "draft closure", repository=repository)
    machine = build_machine_closure(prepared, app, fixture, repository=repository)
    payload = canonical_json(machine)
    write_new(output, payload)
    return sha256_bytes(payload)
