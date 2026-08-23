from __future__ import annotations

import re
from pathlib import Path, PurePosixPath
from typing import Any

from .common import (
    PublicationError,
    bounded_text,
    copy_regular_new,
    load_json,
    sha256_file,
    tree_digest,
    write_new,
)
from .graph_model import CollectedGraphs, ComponentSeed, canonical_graph_bytes
from .license_resolution import validate_automatic_resolution
from .release_contract import PRODUCT_NAME
from .sbom import validate_components
from .source_preparation import (
    MAX_COPY_FILE_BYTES,
    select_source,
    source_input_evidence,
    stage_licenses,
    stage_source,
)
if __package__.startswith("scripts."):
    from scripts.candidate_artifact_binding import (
        CandidateBindingError,
        validate_candidate_app_manifest,
        validate_ci_toolchain_evidence,
    )
    from scripts.repository_source_identity import SourceIdentityError, current_identity
    from scripts.validated_candidate_evidence import validate_candidate_review
else:
    from candidate_artifact_binding import (
        CandidateBindingError,
        validate_candidate_app_manifest,
        validate_ci_toolchain_evidence,
    )
    from repository_source_identity import SourceIdentityError, current_identity
    from validated_candidate_evidence import validate_candidate_review


REPOSITORY_ARTIFACT_INPUTS = {
    "libbox-manifest": "target/native-dependencies/Libbox.xcframework.manifest.json",
}
NATIVE_ARTIFACT_INPUTS = {
    "native-host-bridge-manifest": "CFWNativeBridge.framework.manifest.json",
    "native-proxy-agent-manifest": "CFWProxyAgent.app.manifest.json",
    "native-packet-tunnel-manifest": "com.bill.clashformac.packet-tunnel.systemextension.manifest.json",
    "legacy-tombstone-manifest": "CFWLegacyTombstone.manifest.json",
}


def _reject_absolute_graph_paths(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            _reject_absolute_graph_paths(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _reject_absolute_graph_paths(child, f"{path}[{index}]")
    elif isinstance(value, str) and (
        value.startswith("/") or re.match(r"^[A-Za-z]:[\\/]", value)
    ):
        raise PublicationError(f"normalized graph contains an absolute path at {path}")


def component_specs(
    repository: Path,
    staging: Path,
    seeds: dict[str, ComponentSeed],
    reviews: dict[str, dict[str, Any]],
    release_environment: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    specs: list[dict[str, Any]] = []
    for identifier in sorted(seeds):
        seed = seeds[identifier]
        if seed.external_build_tool:
            continue
        review = reviews[identifier]
        source_root = select_source(seed, review)
        evidence = source_input_evidence(
            repository, seed, source_root, release_environment
        )
        if review["source_evidence"] != evidence:
            raise PublicationError(f"component source evidence no longer recomputes: {identifier}")
        resolution = validate_automatic_resolution(seed, review["license_resolution"])
        source_relative, source_entries = stage_source(
            repository, staging, seed, source_root, release_environment
        )
        license_files = stage_licenses(
            staging,
            seed,
            source_root,
            [item["path"] for item in resolution["files"]],
        )
        spec = {
            "id": identifier,
            "name": seed.name,
            "version": seed.version,
            "ecosystem": seed.ecosystem,
            "scope": seed.scope,
            "purl": seed.purl,
            "license_expression": bounded_text(
                resolution["expression"], f"license expression for {identifier}", 1024
            ),
            "copyright_text": bounded_text(
                review["copyright_text"], f"copyright text for {identifier}", 4096
            ),
            "license_files": license_files,
            "source_path": source_relative,
        }
        validate_components(
            [
                {
                    **spec,
                    "license_files": [
                        {
                            "path": path,
                            "sha256": sha256_file(staging.joinpath(*PurePosixPath(path).parts)),
                        }
                        for path in license_files
                    ],
                    "source_sha256": tree_digest(source_entries),
                }
            ]
        )
        specs.append(spec)
    return specs


def write_graphs(staging: Path, collected: CollectedGraphs) -> list[dict[str, Any]]:
    output = []
    (staging / "graphs").mkdir()
    for kind in sorted(collected.graphs):
        _reject_absolute_graph_paths(collected.graphs[kind])
        path = f"graphs/{kind}.json"
        write_new(staging / path, canonical_graph_bytes(collected.graphs[kind]))
        output.append(
            {
                "id": f"graph:{kind}",
                "kind": kind,
                "path": path,
                "component_ids": sorted(collected.graph_components[kind]),
            }
        )
    return output


def _require_manifest_metadata(
    path: Path, expected: dict[str, str], label: str
) -> None:
    document = load_json(path)
    metadata = document.get("metadata") if isinstance(document, dict) else None
    if not isinstance(metadata, dict) or any(
        metadata.get(key) != value for key, value in expected.items()
    ):
        raise PublicationError(f"{label} metadata does not bind the final build")


def _artifact_sources(
    repository: Path,
    native_products: Path,
    app: Path,
    build_number: str,
    release_environment: dict[str, str] | None,
) -> dict[str, Path]:
    sources = {
        kind: repository / relative
        for kind, relative in REPOSITORY_ARTIFACT_INPUTS.items()
    }
    sources.update(
        {
            kind: native_products / relative
            for kind, relative in NATIVE_ARTIFACT_INPUTS.items()
        }
    )
    signed_root = app.parent
    app_manifest = signed_root / "Clash for Mac.app.manifest.json"
    notary_result = signed_root / "notarization.json"
    notary_submission = (
        signed_root / f"Clash.for.Mac_0.4.0_{build_number}_notary.zip.manifest.json"
    )
    review_path = repository / "target/candidates/0.4.0/review/validated-candidate.json"
    try:
        source_identity = current_identity(
            repository, environment=release_environment
        )
        review = validate_candidate_review(
            repository,
            review_path,
            build_number,
            expected_source_identity=source_identity,
        )
        candidate = review["candidate"]
        ci_evidence = repository / candidate["ci_evidence_path"]
        toolchain_binding = repository / candidate["toolchain_binding_path"]
        toolchain_metadata = validate_ci_toolchain_evidence(
            ci_evidence,
            toolchain_binding,
            source_identity["repositoryCommit"],
            source_identity["releaseSourceSha256"],
        )
        validate_candidate_app_manifest(
            app_manifest,
            app,
            artifact_kind="notarized-release-v1",
            build_number=build_number,
            source_identity=source_identity,
            toolchain_metadata=toolchain_metadata,
            team_id="YKUPL7Z869",
        )
    except (CandidateBindingError, SourceIdentityError, KeyError, OSError, ValueError) as error:
        raise PublicationError(f"release app source/toolchain binding failed: {error}") from error
    _require_manifest_metadata(
        notary_submission,
        {
            "artifactKind": "notarization-submission-v1",
            "buildNumber": build_number,
            **source_identity,
            **toolchain_metadata,
            "version": "0.4.0",
        },
        "notarization submission manifest",
    )
    notary = load_json(notary_result)
    if (
        not isinstance(notary, dict)
        or notary.get("status") != "Accepted"
        or not isinstance(notary.get("id"), str)
        or not notary["id"]
    ):
        raise PublicationError("final notarization result is not Accepted")
    sources.update(
        {
            "signed-app-manifest": app_manifest,
            "notarization-result": notary_result,
            "notarization-submission-manifest": notary_submission,
        }
    )
    sources.update(
        {
            "validated-candidate-review": review_path,
            "validated-candidate-app-manifest": repository
            / candidate["app_manifest_path"],
            "validated-candidate-notarization": repository
            / candidate["notarization_result_path"],
            "validated-candidate-runtime-recovery": repository
            / candidate["runtime_evidence_path"],
            "validated-candidate-unsigned-ci": ci_evidence,
            "validated-candidate-toolchain-binding": toolchain_binding,
        }
    )
    return sources


def write_artifacts(
    repository: Path,
    staging: Path,
    components: dict[str, ComponentSeed],
    native_products: Path,
    app: Path,
    build_number: str,
    release_environment: dict[str, str] | None = None,
) -> list[dict[str, Any]]:
    by_name = {seed.name: seed.identifier for seed in components.values()}
    artifact_root = staging / "artifacts"
    artifact_root.mkdir()
    output = []
    for kind, source in sorted(
        _artifact_sources(
            repository,
            native_products,
            app,
            build_number,
            release_environment,
        ).items()
    ):
        destination = artifact_root / f"{kind}.json"
        copy_regular_new(source, destination, MAX_COPY_FILE_BYTES)
        if kind == "libbox-manifest":
            bindings = [by_name["github.com/sagernet/sing-box"]]
        elif kind.startswith("native-") or kind == "legacy-tombstone-manifest":
            bindings = [by_name[PRODUCT_NAME], by_name["CFWNative"], by_name["CFWNativeProducts"]]
        else:
            bindings = [by_name[PRODUCT_NAME]]
        output.append(
            {
                "id": f"artifact:{kind}",
                "kind": kind,
                "path": f"artifacts/{destination.name}",
                "component_ids": sorted(bindings),
            }
        )
    return output
