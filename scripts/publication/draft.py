from __future__ import annotations

from pathlib import Path

from .closure import build_machine_closure
from .common import canonical_json, sha256_bytes, write_new
from .release_contract import draft_path, require_fixed_path


def draft(prepared: Path, app: Path, output: Path, fixture: bool) -> str:
    prepared = prepared.resolve(strict=True)
    app = app.resolve(strict=True)
    if not fixture:
        repository = Path(__file__).resolve().parent.parent.parent
        require_fixed_path(output, draft_path(repository), "draft closure")
    machine = build_machine_closure(prepared, app, fixture)
    payload = canonical_json(machine)
    write_new(output, payload)
    return sha256_bytes(payload)
