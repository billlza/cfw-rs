from __future__ import annotations

import hashlib
import shutil
import tempfile
from pathlib import Path
from typing import Any

from .artifact_preparation import component_specs, write_artifacts, write_graphs
from .build_tool_preparation import build_tool_specs
from .common import (
    PublicationError,
    canonical_json,
    load_json,
    require_exact_keys,
    safe_identifier,
    write_new,
)
from .graph_collectors import collect_all
from .graph_model import CollectedGraphs, ComponentSeed, RELEASE_VERSION, run
from .license_resolution import resolve_license
from .release_contract import (
    PRODUCT_NAME,
    blocker_report,
    evidence_root,
    native_products_root as release_native_products_root,
    prepared_root,
    require_fixed_path,
    review_template,
    signed_app,
)
from .source_preparation import source_input_evidence
if __package__.startswith("scripts."):
    from scripts.release_build_identity import bundle_build_identity
else:
    from release_build_identity import bundle_build_identity


def expected_signed_app(repository: Path) -> Path:
    return signed_app(repository)


def expected_prepared_root(repository: Path) -> Path:
    return prepared_root(repository)


def expected_evidence_root(repository: Path) -> Path:
    return evidence_root(repository)


def expected_review_template(repository: Path) -> Path:
    return review_template(repository)


def expected_blocker_report(repository: Path) -> Path:
    return blocker_report(repository)


def require_fixed_signed_app(repository: Path, app: Path) -> Path:
    expected = signed_app(repository)
    if app.is_symlink() or not app.is_dir():
        raise PublicationError("0.4.0 signed app is absent or is a symlink")
    require_fixed_path(app, expected, "signed app")
    return app.resolve(strict=True)


def _require_clean_repository(repository: Path) -> None:
    status = run(
        ["git", "status", "--porcelain=v1", "-z", "--untracked-files=all"], repository
    )
    if status:
        raise PublicationError(
            "release source tree is not clean; corresponding source must bind a committed state"
        )


def _application_seed(repository: Path) -> ComponentSeed:
    purl = f"pkg:generic/clash-for-mac@{RELEASE_VERSION}"
    identifier = "application:clash-for-mac:" + hashlib.sha256(
        purl.encode("utf-8")
    ).hexdigest()[:16]
    return ComponentSeed(
        identifier=identifier,
        name=PRODUCT_NAME,
        version=RELEASE_VERSION,
        ecosystem="application",
        scope="runtime",
        purl=purl,
        source_root=repository,
        repository_source=True,
        license_root=repository,
        metadata_path=repository / "Cargo.toml",
        declared_license="GPL-3.0-or-later",
    )


def _complete_collected_graphs(repository: Path, libbox_source: Path) -> CollectedGraphs:
    run(
        [
            "/bin/bash",
            "-c",
            'source "$1/scripts/dependency_pins.env"; '
            'source "$1/scripts/libbox_source_contract.sh"; '
            'libbox_validate_patched_source "$1" "$2"',
            "publication-source-contract",
            str(repository),
            str(libbox_source),
        ],
        repository,
    )
    collected = collect_all(repository, libbox_source)
    application = _application_seed(repository)
    collected.components[application.identifier] = application
    by_name = {seed.name: seed.identifier for seed in collected.components.values()}
    required_names = {
        "cfw-tauri-shell",
        "cfw-tauri-shell-ui",
        "CFWNativeProducts",
        "github.com/sagernet/sing-box",
        "rust",
        "node",
        "go",
        "gomobile",
        "swift",
        "xcode",
        "xcodegen",
        "tauri-cli",
    }
    missing = sorted(required_names - set(by_name))
    if missing:
        raise PublicationError(f"release closure is missing required roots: {missing}")
    for target in ("cfw-tauri-shell", "cfw-tauri-shell-ui", "CFWNativeProducts"):
        collected.relationships.add((application.identifier, by_name[target], "DEPENDS_ON"))
    build_targets = {
        "rust": "cfw-tauri-shell",
        "tauri-cli": "cfw-tauri-shell",
        "node": "cfw-tauri-shell-ui",
        "go": "github.com/sagernet/sing-box",
        "gomobile": "github.com/sagernet/sing-box",
        "swift": "CFWNativeProducts",
        "xcode": "CFWNativeProducts",
        "xcodegen": "CFWNativeProducts",
    }
    for tool, target in build_targets.items():
        collected.relationships.add((by_name[tool], by_name[target], "BUILD_DEPENDENCY_OF"))
    graph_tools = {
        "cargo-build-graph": {"rust", "tauri-cli"},
        "npm-esbuild-meta": {"node"},
        "npm-lock": {"node"},
        "go-linked-packages": {"go", "gomobile"},
        "swift-package": {"swift"},
        "xcode-modules": {"swift", "xcode", "xcodegen"},
    }
    for graph_kind, names in graph_tools.items():
        collected.graph_components[graph_kind].update(by_name[name] for name in names)
    return collected


def _review_records(path: Path, seeds: dict[str, ComponentSeed]) -> dict[str, dict[str, Any]]:
    document = require_exact_keys(
        load_json(path), {"schema_version", "product", "components"}, "reviewed component input"
    )
    if (
        type(document["schema_version"]) is not int
        or document["schema_version"] != 1
        or document["product"]
        != {
            "name": PRODUCT_NAME,
            "version": RELEASE_VERSION,
        }
    ):
        raise PublicationError("reviewed component input is not for the fixed 0.4.0 product")
    raw_records = document["components"]
    if not isinstance(raw_records, list):
        raise PublicationError("reviewed component input is not an array")
    records: dict[str, dict[str, Any]] = {}
    expected_fields = {
        "id",
        "name",
        "version",
        "purl",
        "copyright_text",
        "license_resolution",
        "source_override",
        "source_evidence",
    }
    for index, raw in enumerate(raw_records):
        record = require_exact_keys(raw, expected_fields, f"reviewed component[{index}]")
        identifier = safe_identifier(record["id"], f"reviewed component[{index}].id")
        if identifier in records:
            raise PublicationError(f"reviewed component is duplicated: {identifier}")
        seed = seeds.get(identifier)
        if seed is not None and (record["name"], record["version"], record["purl"]) != (
            seed.name,
            seed.version,
            seed.purl,
        ):
            raise PublicationError(f"reviewed component identity drifted: {identifier}")
        records[identifier] = record
    expected = set(seeds)
    actual = set(records)
    if expected != actual:
        missing = [
            f"{identifier} ({seeds[identifier].name} {seeds[identifier].version})"
            for identifier in sorted(expected - actual)
        ]
        raise PublicationError(
            "reviewed component set differs from exact build closure; "
            f"missing={missing}, extra={sorted(actual - expected)}"
        )
    return records


def prepare(
    repository: Path,
    app: Path,
    libbox_source: Path,
    reviewed_components: Path,
    output: Path,
) -> Path:
    repository = repository.resolve(strict=True)
    app = require_fixed_signed_app(repository, app)
    fixed_output = prepared_root(repository)
    require_fixed_path(output, fixed_output, "prepared evidence")
    if output.exists() or output.is_symlink():
        raise PublicationError(f"refusing to replace prepared publication evidence: {output}")
    build_identity = bundle_build_identity(app)
    native_products = release_native_products_root(repository, build_identity.build_version)
    run(
        [
            str(repository / "scripts/verify_release_app.sh"),
            str(app),
            str(native_products),
        ],
        repository,
    )
    _require_clean_repository(repository)
    collected = _complete_collected_graphs(repository, libbox_source.resolve(strict=True))
    reviews = _review_records(reviewed_components.resolve(strict=True), collected.components)
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.parent.is_symlink():
        raise PublicationError("publication release output parent is a symlink")
    staging = Path(tempfile.mkdtemp(prefix=".publication-prepared.", dir=output.parent))
    try:
        closure = {
            "schema_version": 1,
            "fixture": False,
            "product": {
                "name": PRODUCT_NAME,
                "version": RELEASE_VERSION,
                "build_number": build_identity.build_version,
            },
            "components": component_specs(repository, staging, collected.components, reviews),
            "build_tools": build_tool_specs(repository, collected.components, reviews),
            "relationships": [
                {"source": source, "target": target, "type": relation_type}
                for source, target, relation_type in sorted(collected.relationships)
            ],
            "artifacts": write_artifacts(
                repository,
                staging,
                collected.components,
                native_products,
                app,
                build_identity.build_version,
            ),
            "graphs": write_graphs(staging, collected),
        }
        write_new(staging / "closure-components.json", canonical_json(closure))
        staging.rename(output)
    except BaseException:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return output


def _license_closure(record: dict[str, Any]) -> dict[str, Any]:
    name = record["name"]
    if name in {"swift", "xcode"}:
        return {
            "category": "apple-proprietary-toolchain-terms",
            "evidence_gap": (
                "Apple Swift is part of the pinned Xcode distribution and has no "
                "standalone SPDX license payload in the installed toolchain"
                if name == "swift"
                else "the installed Xcode license is a non-SPDX Apple EULA"
            ),
            "closure_action": (
                "review the exact hashed Xcode 26.6 License.rtf/PDF once for build and "
                "application-distribution rights; record LicenseRef-Apple-Xcode-26.6 "
                "with a human-legal-review rationale bound to those files"
            ),
            "legal_question": (
                "confirm use of the pinned Apple toolchain to build and distribute the app; "
                "the toolchain itself is not redistributed"
            ),
        }
    return {
        "category": "component-license-evidence",
        "evidence_gap": record["license_resolution"]["reason"],
        "closure_action": (
            "supply a component-specific SPDX conclusion, hashed identity metadata, and "
            "the exact supporting license text"
        ),
        "legal_question": "confirm the concluded terms are compatible with the release",
    }


_SOURCE_CLOSURE_PLANS = {
    "@esbuild/darwin-arm64": {
        "classification": "shared-official-tag-source",
        "upstream": "https://github.com/evanw/esbuild",
        "reference": "v0.28.1",
        "closure_action": (
            "bind npm lock integrity, executable SHA-256, upstream v0.28.1 commit, and esbuild "
            "metafile proof that the compiler binary is absent from the app"
        ),
        "acceptance": (
            "bind the tag commit and archive SHA-256, verify package version 0.28.1, and "
            "record the darwin-arm64 binary build provenance"
        ),
    },
    "esbuild": {
        "classification": "shared-official-tag-source",
        "upstream": "https://github.com/evanw/esbuild",
        "reference": "v0.28.1",
        "closure_action": (
            "bind npm lock integrity, executable SHA-256, upstream v0.28.1 commit, and esbuild "
            "metafile proof that the compiler package is absent from the app"
        ),
        "acceptance": (
            "bind the tag commit and archive SHA-256, verify package version 0.28.1, and "
            "record the darwin-arm64 binary build provenance"
        ),
    },
    "node": {
        "classification": "official-release-source-archive",
        "upstream": "https://nodejs.org/dist/v24.18.0/",
        "reference": "node-v24.18.0.tar.gz",
        "closure_action": (
            "bind the signed SHASUMS256.txt entry, executable SHA-256, and version output as "
            "external build-tool provenance"
        ),
        "acceptance": "record signer identity, archive SHA-256, extracted tree digest, and version",
    },
    "go": {
        "classification": "external-build-tool-pinned-binary",
        "upstream": "https://go.dev/dl/",
        "reference": "go1.26.5.darwin-arm64",
        "closure_action": (
            "retain version, executable SHA-256, module verification, and the official release "
            "archive checksum as build provenance; do not add the compiler to corresponding source"
        ),
        "acceptance": "bind go version output, executable hash, and official archive digest",
    },
    "gomobile": {
        "classification": "external-build-tool-pinned-module",
        "upstream": "https://github.com/sagernet/gomobile",
        "reference": "v0.1.13",
        "closure_action": (
            "retain the pinned Go module sum, executable SHA-256, and version -m identity as build "
            "provenance; do not add the tool binary to corresponding source"
        ),
        "acceptance": "bind module version, module sum, build info, and executable hash",
    },
    "rust": {
        "classification": "official-release-source-archive",
        "upstream": "https://static.rust-lang.org/dist/",
        "reference": "rustc-1.97.1-src.tar.xz",
        "closure_action": (
            "bind signed Rust 1.97.1 channel metadata, rustc executable SHA-256, verbose version, "
            "and source commit as external build-tool provenance"
        ),
        "acceptance": (
            "bind archive SHA-256 and source commit 8bab26f4f68e0e26f0bb7960be334d5b520ea452"
        ),
    },
    "swift": {
        "classification": "official-multi-repository-source",
        "upstream": "https://github.com/swiftlang/swift",
        "reference": "swiftlang-6.3.3.1.3",
        "closure_action": (
            "bind the installed compiler SHA-256 and exact swiftlang/clang build identifiers as an "
            "external Apple toolchain prerequisite; do not package Apple toolchain payloads"
        ),
        "acceptance": (
            "record the exact swiftlang and clang build identifiers plus every repository commit; "
            "a marketing-version-only tag is insufficient"
        ),
    },
    "tauri-cli": {
        "classification": "official-registry-source-archive",
        "upstream": "https://crates.io/crates/tauri-cli/2.11.4",
        "reference": "tauri-cli-2.11.4.crate",
        "closure_action": (
            "bind the crates.io checksum, published Cargo.lock checksum, digest-pinned spin lock "
            "update, patched Cargo.lock checksum, cargo-install record, executable SHA-256, and "
            "version as external build-tool provenance"
        ),
        "acceptance": (
            "bind crate checksum, extracted tree digest, both lock checksums, lock-patch checksum, "
            "cargo-install identity, and binary version"
        ),
    },
    "xcode": {
        "classification": "apple-proprietary-source-not-redistributable",
        "upstream": "Apple Developer distribution",
        "reference": "Xcode 26.6 exact build from dependency_pins.env",
        "closure_action": (
            "record an explicit nonredistributable external prerequisite bound to Xcode "
            "version/build, executable SHA-256, code signature, and hashed License.rtf/PDF"
        ),
        "acceptance": (
            "human legal review confirms the GPL general-purpose tool/System Library boundary and "
            "that no Xcode payload is redistributed"
        ),
    },
    "xcodegen": {
        "classification": "prepared-official-tag-needs-safe-dereference",
        "upstream": "https://github.com/yonaskolb/XcodeGen",
        "reference": "2.46.0",
        "closure_action": (
            "bind v2.46.0 tag/commit, executable SHA-256, and version output as external "
            "build-tool provenance; its upstream source symlink is not copied into app source"
        ),
        "acceptance": "bind upstream commit, tag, original tree digest, and dereferenced tree digest",
    },
}


def _source_closure(seed: ComponentSeed) -> dict[str, Any]:
    plan = _SOURCE_CLOSURE_PLANS.get(seed.name)
    if plan is None:
        raise PublicationError(f"missing source-closure plan for {seed.identifier}")
    return {
        **plan,
        "release_impact": "non-blocking-external-build-tool-provenance",
    }


def _blocker_document(
    records: list[dict[str, Any]], seeds: dict[str, ComponentSeed]
) -> dict[str, Any]:
    shipped_records = [record for record in records if not seeds[record["id"]].external_build_tool]
    license_blockers = [
        {
            "id": record["id"],
            "name": record["name"],
            "version": record["version"],
            "ecosystem": record["id"].split(":", 1)[0],
            "reason": record["license_resolution"]["reason"],
            **_license_closure(record),
        }
        for record in shipped_records
        if record["license_resolution"]["status"] != "automatic"
    ]
    source_blockers = [
        {
            "id": record["id"],
            "name": record["name"],
            "version": record["version"],
            "ecosystem": record["id"].split(":", 1)[0],
            "reason": "complete corresponding-source root is absent",
            **_source_closure(seeds[record["id"]]),
        }
        for record in shipped_records
        if record["source_evidence"]["method"] == "missing-source"
    ]
    copyright_blockers = [
        {
            "id": record["id"],
            "name": record["name"],
            "version": record["version"],
            "ecosystem": record["id"].split(":", 1)[0],
            "reason": (
                "component copyright attribution requires human legal confirmation; "
                "license boilerplate is not treated as package copyright"
            ),
        }
        for record in shipped_records
        if not record["copyright_text"].strip()
    ]
    build_tools = [
        {
            "id": record["id"],
            "name": record["name"],
            "version": record["version"],
            "ecosystem": record["id"].split(":", 1)[0],
            "distribution": "external-build-tool-not-distributed",
            "license_metadata_status": record["license_resolution"]["status"],
            "license_metadata_reason": record["license_resolution"]["reason"],
            **_source_closure(seeds[record["id"]]),
        }
        for record in records
        if seeds[record["id"]].external_build_tool
    ]
    return {
        "schema_version": 1,
        "product": {"name": PRODUCT_NAME, "version": RELEASE_VERSION},
        "component_count": len(records),
        "shipped_component_count": len(shipped_records),
        "external_build_tool_count": len(build_tools),
        "automatic_license_count": len(shipped_records) - len(license_blockers),
        "license_review_required_count": len(license_blockers),
        "copyright_review_required_count": len(copyright_blockers),
        "corresponding_source_missing_count": len(source_blockers),
        "external_nonredistributable_prerequisite_count": sum(
            item["name"] in {"swift", "xcode"} for item in build_tools
        ),
        "license_review_required": license_blockers,
        "copyright_review_required": copyright_blockers,
        "corresponding_source_missing": source_blockers,
        "external_build_tools": build_tools,
    }


def write_review_template(repository: Path, libbox_source: Path, output: Path) -> Path:
    repository = repository.resolve(strict=True)
    fixed_output = review_template(repository)
    require_fixed_path(output, fixed_output, "review template")
    blocker_path = blocker_report(repository)
    if output.exists() or output.is_symlink() or blocker_path.exists() or blocker_path.is_symlink():
        raise PublicationError("refusing to replace an existing component review or blocker report")
    collected = _complete_collected_graphs(repository, libbox_source.resolve(strict=True))
    records = []
    for identifier in sorted(collected.components):
        seed = collected.components[identifier]
        records.append(
            {
                "id": identifier,
                "name": seed.name,
                "version": seed.version,
                "purl": seed.purl,
                "copyright_text": "",
                "license_resolution": resolve_license(seed),
                "source_override": None,
                "source_evidence": source_input_evidence(repository, seed, seed.source_root),
            }
        )
    document = {
        "schema_version": 1,
        "product": {"name": PRODUCT_NAME, "version": RELEASE_VERSION},
        "components": records,
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.parent.is_symlink():
        raise PublicationError("component review parent is a symlink")
    try:
        write_new(output, canonical_json(document))
        write_new(blocker_path, canonical_json(_blocker_document(records, collected.components)))
    except BaseException:
        output.unlink(missing_ok=True)
        blocker_path.unlink(missing_ok=True)
        raise
    return output
