from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Any

from .common import PublicationError, load_json, require_exact_keys


REVIEW_DATE_RE = re.compile(
    r"^20[0-9]{2}-[01][0-9]-[0-3][0-9]T[0-2][0-9]:[0-5][0-9]:[0-5][0-9]Z$"
)


def legal_review(
    path: Path, closure_digest: str, component_ids: list[str], fixture: bool
) -> dict[str, Any]:
    review = require_exact_keys(
        load_json(path),
        {
            "schema_version",
            "decision",
            "reviewer",
            "reviewed_at",
            "closure_sha256",
            "component_ids",
            "license_texts_reviewed",
            "source_scope_reviewed",
            "notes",
        },
        "legal review",
    )
    if review["schema_version"] != 1 or review["decision"] != "approved":
        raise PublicationError("legal review is not an explicit approval")
    reviewer = review["reviewer"]
    if not isinstance(reviewer, str) or not reviewer.strip() or len(reviewer) > 200:
        raise PublicationError("legal review has no bounded reviewer identity")
    if not fixture and any(marker in reviewer.casefold() for marker in ("fixture", "test")):
        raise PublicationError("fixture reviewer identity is forbidden in production evidence")
    reviewed_at = review["reviewed_at"]
    if not isinstance(reviewed_at, str) or not REVIEW_DATE_RE.fullmatch(reviewed_at):
        raise PublicationError("legal review timestamp is not canonical UTC")
    try:
        datetime.strptime(reviewed_at, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as error:
        raise PublicationError("legal review timestamp is not a real UTC date") from error
    if review["closure_sha256"] != closure_digest:
        raise PublicationError("legal review does not bind the machine closure")
    if review["component_ids"] != component_ids:
        raise PublicationError("legal review does not bind the exact component set")
    if review["license_texts_reviewed"] is not True or review["source_scope_reviewed"] is not True:
        raise PublicationError("legal review omitted license or corresponding-source scope")
    if not isinstance(review["notes"], str) or not review["notes"].strip() or len(review["notes"]) > 4096:
        raise PublicationError("legal review notes are missing or unbounded")
    return review
