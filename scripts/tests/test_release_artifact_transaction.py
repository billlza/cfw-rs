from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import gzip
import hashlib
import json
import os
from pathlib import Path
import sys
import tarfile
import tempfile
import threading
from typing import Callable
import unittest
from unittest.mock import patch

import scripts.dmg_notarization_transaction as dmg_transaction
from scripts.dmg_notarization_transaction import (
    DmgContext,
    execute_transaction,
    recover_transaction,
)
from scripts.candidate_artifact_binding import TOOLCHAIN_METADATA_ORDER
from scripts.gatekeeper_assessment import validate_evidence
from scripts.hash_artifact import build_manifest
from scripts.notarization_transaction import (
    CommandResult,
    CommandRole,
    NOTARY_PROFILE,
    TransactionError,
)
from scripts.publication.common import PublicationError
from scripts.publication.ga_release_contract import (
    verify_prepackage_authorization as verify_ga_prepackage_stage,
    verify_publication_authorization as verify_ga_publication_stages,
)
from scripts.release_artifact_set import (
    ArtifactSetError,
    DISTRIBUTION_SEAL_NAME,
    MAX_CORRESPONDING_SOURCE_ARCHIVE_BYTES,
    MAX_DMG_BYTES,
    MAX_GITHUB_RELEASE_ASSET_BYTES_EXCLUSIVE,
    MAX_PUBLICATION_BUNDLE_AUXILIARY_BYTES,
    MAX_PUBLICATION_BUNDLE_BYTES,
    MAX_PUBLICATION_DOCUMENT_BYTES,
    MAX_UPDATER_ARCHIVE_BYTES,
    ReleaseVerifierBuild,
    _release_toolchain_surface,
    seal_dmg_set,
    seal_distribution_set,
    seal_updater_set,
    verify_distribution_set,
    verify_dmg_set,
    verify_release_sets,
    verify_updater_set,
)
from scripts.release_apple_toolchain import (
    APPLE_TOOLCHAIN_DOCUMENT,
    APPLE_TOOLCHAIN_SCHEMA_VERSION,
    DEVELOPER_DIRECTORY_PLACEHOLDER,
    ReleaseAppleToolchain,
    ReleaseAppleToolchainError,
)
from scripts.release_cargo_inputs import (
    ReleaseCargoInputsError,
    WorkspaceCargoInputs,
    reject_ambient_cargo_configuration,
)
from scripts.tests.gatekeeper_fixture import fixture as base_gatekeeper_fixture
from scripts.tests.notary_fixture import (
    ARCHIVE_BYTES,
    SUBMISSION_ID,
    accepted_log,
    response,
    submit_response,
)


ATTEMPT_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
CLOCK = "2026-07-28T04:02:00Z"
SOURCE_IDENTITY = {
    "repositoryCommit": "a" * 40,
    "releaseSourceSha256": "b" * 64,
}
SEALED_SOURCE_IDENTITY = {
    "repository_commit": "a" * 40,
    "release_source_sha256": "b" * 64,
}


def prepackage_binding(
    repository: Path, manifest: Path
) -> dict[str, object]:
    data = manifest.read_bytes()
    return {
        "manifest": {
            "filename": manifest.name,
            "sha256": hashlib.sha256(data).hexdigest(),
            "size": len(data),
        },
        "manifest_path": str(manifest.relative_to(repository)),
    }


def create_prepackage_stage(repository: Path) -> tuple[Path, dict[str, object]]:
    manifest = (
        repository
        / "target/candidates/0.4.0/ga/40043/prepackage/manifest.json"
    )
    manifest.parent.mkdir(parents=True, mode=0o700)
    manifest.write_text(
        '{"fixture":"verified-prepackage-stage"}\n', encoding="utf-8"
    )
    return manifest, prepackage_binding(repository, manifest)


def create_signed_candidate(repository: Path, build_number: str = "40043") -> Path:
    app = (
        repository
        / "target/candidates/0.4.0/ga/40043/signed/Clash for Mac.app"
    )
    executable = app / "Contents/MacOS/clash-for-mac"
    executable.parent.mkdir(parents=True)
    (app / "Contents/Info.plist").write_bytes(b"fixture plist")
    executable.write_bytes(b"fixture executable")
    executable.chmod(0o755)
    metadata = {
        "architecture": "arm64",
        "artifactKind": "notarized-ga-candidate-v1",
        "buildNumber": build_number,
        "deploymentTarget": "15.0",
        "releaseSourceSha256": SEALED_SOURCE_IDENTITY["release_source_sha256"],
        "repositoryCommit": SEALED_SOURCE_IDENTITY["repository_commit"],
        "teamID": "YKUPL7Z869",
        "version": "0.4.0",
        **{name: "c" * 64 for name in TOOLCHAIN_METADATA_ORDER},
    }
    manifest = build_manifest(
        app,
        metadata=metadata,
        algorithm="sha256-tree-v2",
    )
    (app.parent / "Clash for Mac.app.manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return app


def create_release_verifier_build(repository: Path) -> ReleaseVerifierBuild:
    source_files = {
        "Cargo.lock": "# fixture lock\n",
        "Cargo.toml": "[workspace]\nmembers = [\"crates/cfw-release-verifier\"]\n",
        "crates/cfw-release-verifier/Cargo.toml": (
            "[package]\nname = \"cfw-release-verifier\"\nversion = \"0.1.0\"\n"
        ),
        "crates/cfw-release-verifier/src/main.rs": "fn main() {}\n",
        "rust-toolchain.toml": (
            "[toolchain]\n"
            "channel = \"1.97.1\"\n"
            "components = [\"rustfmt\", \"clippy\"]\n"
            "profile = \"minimal\"\n"
        ),
        "apps/cfw-tauri-shell/tauri.conf.json": (
            '{"plugins":{"updater":{"pubkey":"fixture-public-key"}}}\n'
        ),
    }
    for relative, contents in source_files.items():
        path = repository.joinpath(*Path(relative).parts)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(contents, encoding="utf-8")

    toolchain_root = repository / "fixture-rust-toolchain"
    (toolchain_root / "bin").mkdir(parents=True, mode=0o700)
    cargo = toolchain_root / "bin/cargo"
    rustc = toolchain_root / "bin/rustc"
    tool_directory = repository / "fixture-release-tools"
    tool_directory.mkdir(mode=0o700)
    executable = tool_directory / "cfw-release-verifier"
    cargo.write_bytes(b"fixture cargo executable\n")
    rustc.write_bytes(b"fixture rustc executable\n")
    for path in (cargo, rustc):
        path.chmod(0o700)

    components = [
        "cargo-aarch64-apple-darwin",
        "clippy-preview-aarch64-apple-darwin",
        "rust-std-aarch64-apple-darwin",
        "rustc-aarch64-apple-darwin",
        "rustfmt-preview-aarch64-apple-darwin",
    ]
    rustlib = toolchain_root / "lib/rustlib"
    rustlib.mkdir(parents=True, mode=0o700)
    (rustlib / "components").write_text("\n".join(components) + "\n", encoding="utf-8")
    (rustlib / "multirust-channel-manifest.toml").write_text(
        "manifest-version = \"2\"\n", encoding="utf-8"
    )
    (rustlib / "multirust-config.toml").write_text(
        "config_version = \"1\"\n", encoding="utf-8"
    )
    (rustlib / "rust-installer-version").write_text("3\n", encoding="utf-8")
    share = toolchain_root / "share"
    share.mkdir(mode=0o700)
    for component in components:
        if component.startswith("cargo-"):
            entries = ["file:bin/cargo"]
        elif component.startswith("rustc-"):
            entries = ["file:bin/rustc"]
        else:
            marker = share / f"{component}.txt"
            marker.write_text(component + "\n", encoding="utf-8")
            entries = [f"file:share/{marker.name}"]
        (rustlib / f"manifest-{component}").write_text(
            "\n".join(entries) + "\n", encoding="utf-8"
        )
    toolchain_surface = _release_toolchain_surface(toolchain_root)
    (repository / "scripts").mkdir(exist_ok=True)
    (repository / "scripts/dependency_pins.env").write_text(
        "MACOS_DEPLOYMENT_TARGET=15.0\n"
        "XCODE_VERSION=26.6\n"
        "XCODE_BUILD_VERSION=17F113\n"
        "RUST_VERSION=1.97.1\n"
        "RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256="
        + str(toolchain_surface["sha256"])
        + "\n",
        encoding="utf-8",
    )
    (repository / "scripts/pinned_build_inputs.json").write_text(
        json.dumps(
            {
                "schema": "cfw-pinned-build-inputs-v1",
                "tools": {
                    "RUST_VERSION": "1.97.1",
                    "RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256": (
                        toolchain_surface["sha256"]
                    )
                },
            },
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n",
        encoding="utf-8",
    )
    executable.write_text(
        """#!/usr/bin/python3
import hashlib
import json
from pathlib import Path
import sys

configuration, archive, signature, output = sys.argv[1:]
if output != "--json":
    raise SystemExit(2)

def identity(path):
    data = Path(path).read_bytes()
    return len(data), hashlib.sha256(data).hexdigest()

archive_size, archive_digest = identity(archive)
signature_size, signature_digest = identity(signature)
_configuration_size, configuration_digest = identity(configuration)
if Path(signature).read_bytes() != b"fixture-signature\\n":
    raise SystemExit("fixture signature rejected")
print(json.dumps({
    "archive_filename": Path(archive).name,
    "archive_sha256": archive_digest,
    "archive_size": archive_size,
    "document": "cfw-updater-embedded-pubkey-verification-v1",
    "embedded_public_key_sha256": "c" * 64,
    "result": "verified",
    "schema_version": 1,
    "signature_filename": Path(signature).name,
    "signature_sha256": signature_digest,
    "signature_size": signature_size,
    "tauri_config_sha256": configuration_digest,
}, sort_keys=True, separators=(",", ":")))
""",
        encoding="utf-8",
    )
    executable.chmod(0o700)
    dependency_crates = [
        {
            "crate_sha256": "1" * 64,
            "name": "fixture-dependency",
            "source": "registry+https://github.com/rust-lang/crates.io-index",
            "source_tree_sha256": "2" * 64,
            "version": "1.0.0",
        }
    ]
    dependency_digest = hashlib.sha256(
        (
            json.dumps(
                dependency_crates,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n"
        ).encode("utf-8")
    ).hexdigest()
    cargo_input_root = repository / "fixture-cargo-workspace"
    cargo_archives = cargo_input_root / "archives"
    cargo_vendor = cargo_input_root / "verified-vendor"
    cargo_archives.mkdir(parents=True, mode=0o700)
    cargo_vendor.mkdir(mode=0o700)
    developer_directory = repository / "fixture-xcode/Contents/Developer"
    clang = developer_directory / "Toolchains/XcodeDefault.xctoolchain/usr/bin/clang"
    linker = developer_directory / "Toolchains/XcodeDefault.xctoolchain/usr/bin/ld"
    sdk_root = (
        developer_directory
        / "Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.5.sdk"
    )
    apple_toolchain = {
        "clang": {
            "path": "Toolchains/XcodeDefault.xctoolchain/usr/bin/clang",
            "sha256": "5" * 64,
            "size": 101,
        },
        "deployment_target": "15.0",
        "developer_directory": DEVELOPER_DIRECTORY_PLACEHOLDER,
        "document": APPLE_TOOLCHAIN_DOCUMENT,
        "ld": {
            "path": "Toolchains/XcodeDefault.xctoolchain/usr/bin/ld",
            "sha256": "6" * 64,
            "size": 102,
        },
        "schema_version": APPLE_TOOLCHAIN_SCHEMA_VERSION,
        "sdk": {
            "resolved_path": (
                "Platforms/MacOSX.platform/Developer/SDKs/MacOSX.sdk"
            ),
            "selected_path": (
                "Platforms/MacOSX.platform/Developer/SDKs/MacOSX26.5.sdk"
            ),
            "settings": {
                "path": (
                    "Platforms/MacOSX.platform/Developer/SDKs/"
                    "MacOSX.sdk/SDKSettings.json"
                ),
                "sha256": "7" * 64,
                "size": 103,
            },
            "version": "26.5",
        },
        "xcode_build_version": "17F113",
        "xcode_version": "26.6",
    }
    return ReleaseVerifierBuild(
        executable=executable,
        apple_toolchain=apple_toolchain,
        cargo=cargo,
        cargo_version="cargo 1.97.1 (fixture)",
        cargo_input_root=cargo_input_root,
        cargo_lock_sha256=hashlib.sha256(
            (repository / "Cargo.lock").read_bytes()
        ).hexdigest(),
        cargo_vendor_sha256="4" * 64,
        dependency_sources={
            "algorithm": "crates-io-lock-archive-tree-v1",
            "crates": dependency_crates,
            "sha256": dependency_digest,
        },
        isolated_lock_sha256="3" * 64,
        developer_directory=developer_directory,
        deployment_target="15.0",
        rustc=rustc,
        rustc_version="rustc 1.97.1 (fixture)",
        toolchain="1.97.1-aarch64-apple-darwin",
        toolchain_surface=toolchain_surface,
        sdk_root=sdk_root,
    )


def cargo_inputs_for_build(build: ReleaseVerifierBuild) -> WorkspaceCargoInputs:
    return WorkspaceCargoInputs(
        root=build.cargo_input_root,
        archives=build.cargo_input_root / "archives",
        vendor=build.cargo_input_root / "verified-vendor",
        cargo_lock_sha256=build.cargo_lock_sha256,
        crates_sha256=str(build.dependency_sources["sha256"]),
        vendor_tree_sha256=build.cargo_vendor_sha256,
        crate_records=tuple(build.dependency_sources["crates"]),
    )


def require_fixture_cargo_boundary(repository: Path) -> None:
    try:
        reject_ambient_cargo_configuration(repository)
    except ReleaseCargoInputsError as error:
        raise ArtifactSetError("ambient Cargo configuration is forbidden") from error


@contextmanager
def verified_cargo_fixture(build: ReleaseVerifierBuild):
    inputs = cargo_inputs_for_build(build)
    apple_toolchain = ReleaseAppleToolchain(
        developer_directory=build.developer_directory,
        clang=(
            build.developer_directory
            / str(build.apple_toolchain["clang"]["path"])
        ),
        linker=(
            build.developer_directory
            / str(build.apple_toolchain["ld"]["path"])
        ),
        sdk_root=build.sdk_root,
        deployment_target=build.deployment_target,
        binding=build.apple_toolchain,
    )

    def verify_inputs(repository: Path, root: Path) -> WorkspaceCargoInputs:
        if repository != build.cargo_input_root.parent or root != inputs.root:
            raise AssertionError("release verifier used the wrong Cargo input fixture")
        return inputs

    def validate_apple_toolchain(
        value: object, repository: Path
    ) -> dict[str, object]:
        if (
            repository != build.cargo_input_root.parent
            or value != apple_toolchain.binding
        ):
            raise ReleaseAppleToolchainError(
                "recorded Apple linker inputs differ from the fixture"
            )
        return apple_toolchain.binding

    with patch.dict(
        os.environ,
        {"CFW_RELEASE_CARGO_INPUT_ROOT": str(inputs.root)},
    ), patch(
        "scripts.release_artifact_set.verify_workspace_cargo_inputs",
        side_effect=verify_inputs,
    ), patch(
        "scripts.release_artifact_set.release_verifier_dependency_records",
        return_value=build.dependency_sources,
    ), patch(
        "scripts.release_artifact_set.capture_release_apple_toolchain",
        return_value=apple_toolchain,
    ), patch(
        "scripts.release_artifact_set.validate_recorded_release_apple_toolchain",
        side_effect=validate_apple_toolchain,
    ):
        yield


class SimulatedCrash(BaseException):
    pass


def publisher(source: Path, destination: Path) -> None:
    if os.path.lexists(destination):
        raise AssertionError("publisher must not replace a destination")
    os.rename(source, destination)


class ReleaseVerifierBuildPolicyTests(unittest.TestCase):
    def test_bounded_verifier_process_preserves_only_operational_noncompletion(
        self,
    ) -> None:
        from scripts import release_artifact_set as artifact_sets

        operational = {
            "command_descendant_survived": "descendant",
            "command_output_oversized": "output_limit",
            "command_pipe_failed": "pipe",
            "command_start_failed": "start",
            "command_timeout": "timeout",
        }
        for code, reason in operational.items():
            with (
                self.subTest(code=code),
                patch.object(
                    artifact_sets,
                    "_run_transaction_process",
                    side_effect=TransactionError(code, "fixture failure"),
                ),
                self.assertRaises(
                    artifact_sets.ReleaseVerifierOperationalError
                ) as raised,
            ):
                artifact_sets._run_bounded_process(
                    ["fixture-command"],
                    cwd=Path("/fixture"),
                    environment={"PATH": "/usr/bin:/bin"},
                    timeout=1,
                    label="fixture verifier command",
                )
            self.assertEqual(
                raised.exception.code, "release_verifier_unavailable"
            )
            self.assertEqual(raised.exception.reason, reason)

        with (
            patch.object(
                artifact_sets,
                "_run_transaction_process",
                side_effect=TransactionError(
                    "command_output_invalid_utf8", "fixture semantic failure"
                ),
            ),
            self.assertRaises(ArtifactSetError) as semantic,
        ):
            artifact_sets._run_bounded_process(
                ["fixture-command"],
                cwd=Path("/fixture"),
                environment={"PATH": "/usr/bin:/bin"},
                timeout=1,
                label="fixture verifier command",
            )
        self.assertNotIsInstance(
            semantic.exception, artifact_sets.ReleaseVerifierOperationalError
        )

        with (
            patch.object(
                artifact_sets,
                "_run_transaction_process",
                return_value=CommandResult(9, "", ""),
            ),
            self.assertRaises(ArtifactSetError) as nonzero,
        ):
            artifact_sets._run_bounded_process(
                ["fixture-command"],
                cwd=Path("/fixture"),
                environment={"PATH": "/usr/bin:/bin"},
                timeout=1,
                label="fixture verifier command",
            )
        self.assertNotIsInstance(
            nonzero.exception, artifact_sets.ReleaseVerifierOperationalError
        )

    def test_canonical_build_invocation_uses_the_single_argv_constructor(
        self,
    ) -> None:
        from scripts import release_artifact_set as artifact_sets

        expected = artifact_sets._release_verifier_build_argv(
            cargo="cargo",
            workspace="<private-isolated-workspace>",
            target="<private-ephemeral-target>",
            private_root="<private-root>",
            verified_vendor="<verified-vendor>",
            clang="<selected-xcode-clang>",
            linker="<selected-xcode-ld>",
        )
        invocation = artifact_sets.RELEASE_VERIFIER_BUILD_INVOCATION

        self.assertEqual(invocation["argv"], expected)
        rustflags = json.loads(
            expected[-1].removeprefix("build.rustflags=")
        )
        self.assertEqual(
            rustflags,
            [
                "--remap-path-prefix=<private-root>="
                "/cfw-release-verifier-build",
                "--remap-path-prefix=<verified-vendor>="
                "/cfw-release-verifier-vendor",
                "-C",
                "linker=<selected-xcode-clang>",
                "-C",
                "link-arg=-fuse-ld=<selected-xcode-ld>",
                "-C",
                "link-arg=-Wl,-S",
                "-C",
                "link-arg=-Wl,-x",
            ],
        )
        self.assertNotIn("-no_uuid", expected[-1])

    def test_build_and_execution_environments_are_separate_allowlists(
        self,
    ) -> None:
        from scripts import release_artifact_set as artifact_sets

        environment = artifact_sets._release_verifier_build_environment(
            tool_directory="/release/rust/bin",
            developer_directory=(
                "/Applications/Xcode.app/Contents/Developer"
            ),
            deployment_target="15.0",
            sdk_root="/Applications/Xcode.app/SDKs/MacOSX.sdk",
            cargo_home="/private/cargo-home",
            home="/private/home",
            rustc="/release/rust/bin/rustc",
            temporary_directory="/private/tmp",
        )

        self.assertEqual(
            set(environment),
            {
                "CARGO_HOME",
                "CARGO_NET_OFFLINE",
                "DEVELOPER_DIR",
                "HOME",
                "LANG",
                "LC_ALL",
                "MACOSX_DEPLOYMENT_TARGET",
                "PATH",
                "RUSTC",
                "SDKROOT",
                "TMPDIR",
            },
        )
        self.assertEqual(
            artifact_sets.RELEASE_VERIFIER_BUILD_INVOCATION["environment"],
            artifact_sets._release_verifier_build_environment(
                tool_directory="<pinned-rust-bin>",
                developer_directory=(
                    artifact_sets.DEVELOPER_DIRECTORY_PLACEHOLDER
                ),
                deployment_target="<pinned-macos-deployment-target>",
                sdk_root="<selected-macos-sdk>",
                cargo_home="<private-runtime-cargo-home>",
                home="<private-home>",
                rustc="<pinned-rustc>",
                temporary_directory="<private-temp>",
            ),
        )
        self.assertEqual(
            artifact_sets.RELEASE_VERIFIER_VERIFY_INVOCATION["environment"],
            {
                "LANG": "C",
                "LC_ALL": "C",
                "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
            },
        )
        self.assertEqual(
            artifact_sets.RELEASE_VERIFIER_VERIFY_INVOCATION["argv"],
            artifact_sets._release_verifier_verify_argv(
                executable="cfw-release-verifier",
                configuration=(
                    "<repository>/apps/cfw-tauri-shell/tauri.conf.json"
                ),
                archive="<staging>/updater-archive",
                signature="<staging>/updater-signature",
            ),
        )
        for injectable in (
            "CC",
            "CFLAGS",
            "LDFLAGS",
            "RUSTFLAGS",
            "RUSTC_WRAPPER",
        ):
            self.assertNotIn(injectable, environment)


def dmg_gatekeeper_fixture(target: Path, digest: str) -> dict:
    evidence = base_gatekeeper_fixture(digest, CLOCK, target)
    evidence["assessment_type"] = "open"
    evidence["primary_signature_context"] = True
    evidence["target_identity_algorithm"] = "sha256-file"
    evidence["assessment_command"] = [
        "/usr/sbin/spctl",
        "--assess",
        "--type",
        "open",
        "--context",
        "context:primary-signature",
        "--verbose=4",
        str(target),
    ]
    return validate_evidence(
        evidence,
        expected_assessment_type="open",
        expected_primary_signature_context=True,
        expected_target=target,
    )


class FakeRunner:
    def __init__(self, dmg_name: str) -> None:
        self.dmg_name = dmg_name
        self.calls: list[object] = []
        self.commands: list[tuple[object, tuple[str, ...]]] = []
        self.crash_role: object | None = None
        self.crash_after_effect = False
        self.fail_role: object | None = None
        self.wait_status = "Accepted"
        self.info_status = "Accepted"
        self.info_created_at = "2026-07-28T04:02:00Z"
        self.submission_id = SUBMISSION_ID
        self.log = accepted_log(dmg_name)

    def __call__(
        self, role: object, command: list[str], _timeout: float
    ) -> CommandResult:
        self.calls.append(role)
        self.commands.append((role, tuple(command)))
        if role == self.fail_role:
            return CommandResult(9, "", "fixture failure")
        if role == CommandRole.STAPLE:
            with Path(command[-1]).open("ab") as handle:
                handle.write(b"-stapled-ticket")
        if role == self.crash_role and (
            role != CommandRole.STAPLE or self.crash_after_effect
        ):
            raise SimulatedCrash(str(role))
        if role == CommandRole.SUBMIT:
            stdout = submit_response(command[3]).replace(SUBMISSION_ID, self.submission_id)
        elif role == CommandRole.WAIT:
            stdout = response(self.wait_status).replace(SUBMISSION_ID, self.submission_id)
        elif role == CommandRole.INFO:
            stdout = json.dumps(
                {
                    "createdDate": self.info_created_at,
                    "id": self.submission_id,
                    "message": "Successfully received submission info",
                    "name": self.dmg_name,
                    "status": self.info_status,
                },
                sort_keys=True,
            )
        elif role == CommandRole.HISTORY:
            stdout = json.dumps(
                {
                    "history": [
                        {
                            "createdDate": self.info_created_at,
                            "id": self.submission_id,
                            "name": self.dmg_name,
                            "status": self.info_status,
                        }
                    ],
                    "message": "Successfully received submission history.",
                },
                sort_keys=True,
            )
        elif role == CommandRole.FETCH_LOG:
            stdout = json.dumps(self.log, sort_keys=True)
        else:
            stdout = "ok\n"
        if role == self.crash_role:
            raise SimulatedCrash(str(role))
        return CommandResult(0, stdout, "")


class DmgFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name).resolve()
        self.app = create_signed_candidate(self.repository)
        self.ga_root = self.repository / "target/candidates/0.4.0/ga/40043"
        self.prepackage_manifest, self.prepackage = create_prepackage_stage(
            self.repository
        )
        self.package_root = self.ga_root / "packages"
        (self.package_root / "dmg").mkdir(parents=True)
        staging = self.package_root / "dmg/dmg-stage.fixture"
        staging.mkdir()
        self.dmg = staging / "Clash.for.Mac_0.4.0_arm64.dmg"
        self.dmg.write_bytes(ARCHIVE_BYTES)
        self.context = DmgContext(
            repository=self.repository,
            version="0.4.0",
            build_number="40043",
            notary_profile=NOTARY_PROFILE,
            source_identity=SOURCE_IDENTITY,
            staged_dmg=self.dmg,
        )
        self.runner = FakeRunner(self.context.dmg_name)

    def close(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def source_identity(_repository: Path) -> dict[str, str]:
        return SOURCE_IDENTITY

    @staticmethod
    def gatekeeper(target: Path, digest: str) -> dict:
        return dmg_gatekeeper_fixture(target, digest)

    def package_manifest(self, _dmg: Path) -> dict[str, object]:
        return build_manifest(self.app, algorithm="sha256-tree-v2")

    def prepackage_stage(self, repository: Path) -> dict[str, object]:
        if repository != self.repository:
            raise AssertionError("prepackage verifier used the wrong repository")
        return prepackage_binding(repository, self.prepackage_manifest)

    def verify(self, destination: Path) -> dict:
        return verify_dmg_set(
            destination,
            repository=self.repository,
            version="0.4.0",
            packaged_app_manifest_reader=self.package_manifest,
            prepackage_stage_verifier=self.prepackage_stage,
        )

    def arguments(self) -> dict[str, object]:
        return {
            "runner": self.runner,
            "gatekeeper_capture": self.gatekeeper,
            "source_identity_reader": self.source_identity,
            "publisher": publisher,
            "packaged_app_manifest_reader": self.package_manifest,
            "clock": lambda: CLOCK,
            "attempt_id_factory": lambda: ATTEMPT_ID,
            "prepackage_stage_verifier": self.prepackage_stage,
        }

    def execute(self, **overrides: object) -> Path:
        arguments = self.arguments()
        arguments.update(overrides)
        return execute_transaction(self.context, **arguments)

    def recover(self, submission_id: str = SUBMISSION_ID, **overrides: object) -> Path:
        arguments = self.arguments()
        arguments.pop("attempt_id_factory")
        arguments.update(overrides)
        return recover_transaction(
            replace(self.context, staged_dmg=None),
            submission_id,
            **arguments,
        )


class DmgNotarizationTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = DmgFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_success_uses_no_wait_and_publishes_one_sealed_set(self) -> None:
        destination = self.fixture.execute()
        self.assertEqual(destination, self.fixture.context.final_root)
        submit = next(
            command
            for role, command in self.fixture.runner.commands
            if role == CommandRole.SUBMIT
        )
        self.assertIn("--no-wait", submit)
        self.assertNotIn("--wait", submit)
        self.assertEqual(
            self.fixture.verify(destination)["submission_id"],
            SUBMISSION_ID,
        )
        self.assertTrue((destination / "dmg-set.seal.json").is_file())
        self.assertFalse((self.fixture.package_root / self.fixture.context.dmg_name).exists())
        intent = json.loads(
            (self.fixture.context.attempt_root / "intent.json").read_text(
                encoding="utf-8"
            )
        )
        receipt = json.loads(
            (
                self.fixture.context.attempt_root / "submission-receipt.json"
            ).read_text(encoding="utf-8")
        )
        self.assertEqual(intent["schema_version"], 3)
        self.assertEqual(intent["notary_profile"], NOTARY_PROFILE)
        self.assertEqual(receipt["schema_version"], 2)
        self.assertEqual(receipt["notary_profile"], NOTARY_PROFILE)

    def test_nonfixed_notary_profile_is_rejected_before_dmg_custody_or_remote_io(
        self,
    ) -> None:
        with self.assertRaises(TransactionError) as raised:
            execute_transaction(
                replace(
                    self.fixture.context,
                    notary_profile="different-profile",
                ),
                **self.fixture.arguments(),
            )
        self.assertEqual(raised.exception.code, "invalid_notary_profile")
        self.assertTrue(self.fixture.dmg.is_file())
        self.assertFalse(self.fixture.context.attempt_root.exists())
        self.assertEqual(self.fixture.runner.calls, [])

    def test_initial_prepare_holds_recovery_lock_before_attempt_creation(self) -> None:
        entered_prepare = threading.Event()
        release_prepare = threading.Event()
        real_prepare = dmg_transaction._prepare_attempt

        def blocking_prepare(*args: object, **kwargs: object):
            self.assertFalse(self.fixture.context.attempt_root.exists())
            entered_prepare.set()
            if not release_prepare.wait(5):
                raise AssertionError("test did not release DMG preparation")
            return real_prepare(*args, **kwargs)

        with patch.object(
            dmg_transaction,
            "_prepare_attempt",
            side_effect=blocking_prepare,
        ), ThreadPoolExecutor(max_workers=2) as executor:
            executing = executor.submit(self.fixture.execute)
            try:
                self.assertTrue(entered_prepare.wait(2))
                self.assertTrue(self.fixture.context.transaction_root.is_dir())
                self.assertFalse(self.fixture.context.attempt_root.exists())
                with self.assertRaises(TransactionError) as raised:
                    self.fixture.recover()
                self.assertEqual(
                    raised.exception.code,
                    "recovery_in_progress",
                )
                self.assertEqual(self.fixture.runner.calls, [])
            finally:
                release_prepare.set()
            self.assertTrue(executing.result(timeout=5).is_dir())

    def test_context_derives_only_the_fixed_ga_package_and_transaction_roots(self) -> None:
        self.assertEqual(
            self.fixture.context.final_root,
            self.fixture.repository
            / "target/candidates/0.4.0/ga/40043/packages/dmg/v0.4.0",
        )
        self.assertEqual(
            self.fixture.context.attempt_root,
            self.fixture.repository
            / "target/candidates/0.4.0/ga/40043/transactions/dmg-notary/v0.4.0",
        )

    def test_non_ga_build_is_rejected_before_any_remote_command(self) -> None:
        for build_number in (
            "40030",
            "40031",
            "40032",
            "40033",
            "40034",
            "40035",
            "40036",
            "40037",
            "40038",
        ):
            runner = FakeRunner(self.fixture.context.dmg_name)
            with self.subTest(build_number=build_number):
                with self.assertRaisesRegex(TransactionError, "active GA build"):
                    execute_transaction(
                        replace(self.fixture.context, build_number=build_number),
                        runner=runner,
                        gatekeeper_capture=self.fixture.gatekeeper,
                        source_identity_reader=self.fixture.source_identity,
                        publisher=publisher,
                        clock=lambda: CLOCK,
                        attempt_id_factory=lambda: ATTEMPT_ID,
                        packaged_app_manifest_reader=self.fixture.package_manifest,
                    )
                self.assertEqual(runner.calls, [])

    def test_missing_prepackage_is_rejected_before_dmg_custody_or_submit(self) -> None:
        self.fixture.prepackage_manifest.unlink()
        with self.assertRaisesRegex(TransactionError, "prepackage stage authorization"):
            self.fixture.execute()
        self.assertTrue(self.fixture.dmg.is_file())
        self.assertEqual(self.fixture.runner.calls, [])

    def test_recovery_reopens_the_intent_bound_prepackage_stage(self) -> None:
        self.fixture.runner.crash_role = CommandRole.WAIT
        with self.assertRaises(SimulatedCrash):
            self.fixture.execute()
        self.fixture.prepackage_manifest.write_text(
            '{"fixture":"drifted-prepackage-stage"}\n', encoding="utf-8"
        )
        recovery_runner = FakeRunner(self.fixture.context.dmg_name)
        with self.assertRaisesRegex(TransactionError, "differs from the DMG transaction intent"):
            self.fixture.recover(runner=recovery_runner)
        self.assertEqual(recovery_runner.calls, [])

    def test_recovery_rejects_notary_profile_drift_in_intent_before_apple_io(
        self,
    ) -> None:
        self.fixture.runner.crash_role = CommandRole.WAIT
        with self.assertRaises(SimulatedCrash):
            self.fixture.execute()
        intent_path = self.fixture.context.attempt_root / "intent.json"
        intent = json.loads(intent_path.read_text(encoding="utf-8"))
        intent["notary_profile"] = "different-profile"
        intent_path.write_bytes(
            dmg_transaction._canonical_json(intent).encode("utf-8")
        )
        recovery_runner = FakeRunner(self.fixture.context.dmg_name)

        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover(runner=recovery_runner)
        self.assertEqual(raised.exception.code, "intent_identity_drift")
        self.assertEqual(recovery_runner.calls, [])

    def test_recovery_rejects_notary_profile_drift_in_receipt_before_apple_io(
        self,
    ) -> None:
        self.fixture.runner.crash_role = CommandRole.WAIT
        with self.assertRaises(SimulatedCrash):
            self.fixture.execute()
        receipt_path = self.fixture.context.attempt_root / "submission-receipt.json"
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["notary_profile"] = "different-profile"
        receipt_path.write_bytes(
            dmg_transaction._canonical_json(receipt).encode("utf-8")
        )
        recovery_runner = FakeRunner(self.fixture.context.dmg_name)

        with self.assertRaises(TransactionError) as raised:
            self.fixture.recover(runner=recovery_runner)
        self.assertEqual(
            raised.exception.code,
            "submission_receipt_identity_drift",
        )
        self.assertEqual(recovery_runner.calls, [])

    def test_direct_preflight_cli_cannot_bypass_the_prepackage_stage(self) -> None:
        from scripts import dmg_notarization_transaction as transaction

        self.fixture.prepackage_manifest.unlink()
        arguments = [
            str(Path(transaction.__file__).resolve()),
            "preflight",
            "--repository",
            str(self.fixture.repository),
            "--version",
            "0.4.0",
            "--build-number",
            "40043",
            "--notary-profile",
            NOTARY_PROFILE,
        ]
        with patch.object(sys, "argv", arguments), patch.object(
            transaction, "current_identity", return_value=SOURCE_IDENTITY
        ):
            with self.assertRaisesRegex(SystemExit, "prepackage"):
                transaction.main()

    def test_dmg_sealer_rejects_a_caller_selected_staging_root(self) -> None:
        with self.assertRaisesRegex(ArtifactSetError, "transaction final-set"):
            seal_dmg_set(
                self.fixture.dmg.parent,
                repository=self.fixture.repository,
                version="0.4.0",
                build_number="40043",
                pre_staple_sha256="a" * 64,
                prepackage=self.fixture.prepackage,
                source_identity=SEALED_SOURCE_IDENTITY,
                sealed_at=CLOCK,
                packaged_app_manifest_reader=self.fixture.package_manifest,
                prepackage_stage_verifier=self.fixture.prepackage_stage,
            )
        with self.assertRaisesRegex(ArtifactSetError, "transaction final-set"):
            verify_dmg_set(
                self.fixture.dmg.parent,
                repository=self.fixture.repository,
                version="0.4.0",
                require_version_directory=False,
                prepackage_stage_verifier=self.fixture.prepackage_stage,
            )

    def test_submit_reply_loss_recovers_by_unique_history_without_resubmit(self) -> None:
        self.fixture.runner.crash_role = CommandRole.SUBMIT
        with self.assertRaises(SimulatedCrash):
            self.fixture.execute()
        self.assertTrue((self.fixture.context.attempt_root / self.fixture.context.dmg_name).is_file())
        recovery_runner = FakeRunner(self.fixture.context.dmg_name)
        destination = self.fixture.recover(runner=recovery_runner)
        self.assertTrue(destination.is_dir())
        self.assertNotIn(CommandRole.SUBMIT, recovery_runner.calls)
        self.assertIn(CommandRole.INFO, recovery_runner.calls)
        self.assertIn(CommandRole.HISTORY, recovery_runner.calls)

    def test_wait_crash_recovers_observed_id_without_history_or_resubmit(self) -> None:
        self.fixture.runner.crash_role = CommandRole.WAIT
        with self.assertRaises(SimulatedCrash):
            self.fixture.execute()
        recovery_runner = FakeRunner(self.fixture.context.dmg_name)
        self.fixture.recover(runner=recovery_runner)
        self.assertNotIn(CommandRole.SUBMIT, recovery_runner.calls)
        self.assertNotIn(CommandRole.HISTORY, recovery_runner.calls)
        self.assertIn(CommandRole.INFO, recovery_runner.calls)

    def test_crash_after_staple_discards_copy_and_restaples_submitted_bytes(self) -> None:
        self.fixture.runner.crash_role = CommandRole.STAPLE
        self.fixture.runner.crash_after_effect = True
        with self.assertRaises(SimulatedCrash):
            self.fixture.execute()
        submitted = self.fixture.context.attempt_root / self.fixture.context.dmg_name
        self.assertEqual(submitted.read_bytes(), ARCHIVE_BYTES)
        self.assertEqual(submitted.stat().st_mode & 0o777, 0o400)
        pending = (
            self.fixture.context.attempt_root
            / "staple-pending"
            / self.fixture.context.dmg_name
        )
        pending.write_bytes(b"different-valid-stapled-dmg-fixture")
        recovery_runner = FakeRunner(self.fixture.context.dmg_name)
        destination = self.fixture.recover(runner=recovery_runner)
        self.assertIn(CommandRole.STAPLE, recovery_runner.calls)
        self.assertIn(CommandRole.STAPLE_VALIDATE, recovery_runner.calls)
        self.assertEqual(
            (destination / self.fixture.context.dmg_name).read_bytes(),
            ARCHIVE_BYTES + b"-stapled-ticket",
        )

    def test_recovery_rejects_a_different_submission_id_before_tool_calls(self) -> None:
        self.fixture.runner.crash_role = CommandRole.WAIT
        with self.assertRaises(SimulatedCrash):
            self.fixture.execute()
        recovery_runner = FakeRunner(self.fixture.context.dmg_name)
        with self.assertRaisesRegex(TransactionError, "differs from durable"):
            self.fixture.recover(
                "99999999-2222-3333-4444-555555555555",
                runner=recovery_runner,
            )
        self.assertEqual(recovery_runner.calls, [])

    def test_digest_drift_before_stapling_fails_before_recovery_tools(self) -> None:
        self.fixture.runner.crash_role = CommandRole.SUBMIT
        with self.assertRaises(SimulatedCrash):
            self.fixture.execute()
        attempt_dmg = self.fixture.context.attempt_root / self.fixture.context.dmg_name
        attempt_dmg.unlink()
        attempt_dmg.write_bytes(b"tampered")
        attempt_dmg.chmod(0o400)
        recovery_runner = FakeRunner(self.fixture.context.dmg_name)
        with self.assertRaisesRegex(TransactionError, "submitted DMG bytes changed"):
            self.fixture.recover(runner=recovery_runner)
        self.assertEqual(recovery_runner.calls, [])

    def test_duplicate_start_refuses_before_second_submit(self) -> None:
        self.fixture.runner.crash_role = CommandRole.SUBMIT
        with self.assertRaises(SimulatedCrash):
            self.fixture.execute()
        second_stage = self.fixture.package_root / "dmg/dmg-stage.second"
        second_stage.mkdir()
        second_dmg = second_stage / self.fixture.context.dmg_name
        second_dmg.write_bytes(ARCHIVE_BYTES)
        second_runner = FakeRunner(self.fixture.context.dmg_name)
        with self.assertRaisesRegex(TransactionError, "must not be resubmitted"):
            execute_transaction(
                replace(self.fixture.context, staged_dmg=second_dmg),
                runner=second_runner,
                gatekeeper_capture=self.fixture.gatekeeper,
                source_identity_reader=self.fixture.source_identity,
                publisher=publisher,
                clock=lambda: CLOCK,
                attempt_id_factory=lambda: "bbbbbbbb-cccc-dddd-eeee-ffffffffffff",
                prepackage_stage_verifier=self.fixture.prepackage_stage,
            )
        self.assertEqual(second_runner.calls, [])

    def test_unknown_event_field_is_rejected(self) -> None:
        self.fixture.runner.crash_role = CommandRole.SUBMIT
        with self.assertRaises(SimulatedCrash):
            self.fixture.execute()
        event_path = self.fixture.context.attempt_root / "events/00000002.json"
        event = json.loads(event_path.read_text(encoding="utf-8"))
        event["unexpected"] = True
        event_path.write_text(
            json.dumps(event, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(TransactionError, "unexpected schema or field set"):
            self.fixture.recover()

    def test_publication_reply_loss_is_recognized_from_the_complete_seal(self) -> None:
        from scripts import dmg_notarization_transaction as dmg_transaction

        calls = 0
        durability_calls = 0
        real_confirm = dmg_transaction.confirm_published_tree_durable

        def reply_lost_publisher(source: Path, destination: Path) -> None:
            nonlocal calls
            calls += 1
            publisher(source, destination)
            if calls == 2:
                raise RuntimeError("lost rename reply")

        def confirm_after_reply_loss(source: Path, destination: Path) -> None:
            nonlocal durability_calls
            durability_calls += 1
            real_confirm(source, destination)

        with patch.object(
            dmg_transaction,
            "confirm_published_tree_durable",
            side_effect=confirm_after_reply_loss,
        ):
            destination = self.fixture.execute(publisher=reply_lost_publisher)
        self.assertEqual(destination, self.fixture.context.final_root)
        self.assertEqual(calls, 2)
        self.assertEqual(durability_calls, 1)
        self.fixture.verify(destination)

    def test_publish_durability_failure_remains_deferred_until_recovery_fsync(
        self,
    ) -> None:
        calls = 0

        def reply_lost_publisher(source: Path, destination: Path) -> None:
            nonlocal calls
            calls += 1
            publisher(source, destination)
            if calls == 2:
                raise RuntimeError("lost rename reply")

        with patch(
            "scripts.dmg_notarization_transaction.confirm_published_tree_durable",
            side_effect=TransactionError(
                "publish_durability_unknown",
                "fixture fsync failure",
                terminal_state="outcome_unknown",
            ),
        ):
            with self.assertRaisesRegex(TransactionError, "fixture fsync failure"):
                self.fixture.execute(publisher=reply_lost_publisher)
        event_path = sorted(
            (self.fixture.context.attempt_root / "events").glob("*.json")
        )[-1]
        self.assertEqual(
            json.loads(event_path.read_text(encoding="utf-8"))["state"],
            "publication_deferred",
        )
        recovery_runner = FakeRunner(self.fixture.context.dmg_name)
        destination = self.fixture.recover(runner=recovery_runner)
        self.assertEqual(destination, self.fixture.context.final_root)
        self.assertEqual(recovery_runner.calls, [])

    def test_unpublished_sealed_set_is_discarded_and_rebuilt_after_crash(self) -> None:
        calls = 0

        def crash_before_final_publish(source: Path, destination: Path) -> None:
            nonlocal calls
            calls += 1
            if calls == 2:
                raise SimulatedCrash("before final rename")
            publisher(source, destination)

        with self.assertRaises(SimulatedCrash):
            self.fixture.execute(publisher=crash_before_final_publish)
        unpublished = self.fixture.context.attempt_root / "final-set"
        self.assertTrue(unpublished.is_dir())
        (unpublished / self.fixture.context.dmg_name).write_bytes(
            b"substituted-unpublished-final-set"
        )
        recovery_runner = FakeRunner(self.fixture.context.dmg_name)
        destination = self.fixture.recover(runner=recovery_runner)
        self.assertIn(CommandRole.STAPLE, recovery_runner.calls)
        self.assertEqual(
            (destination / self.fixture.context.dmg_name).read_bytes(),
            ARCHIVE_BYTES + b"-stapled-ticket",
        )

    def test_dmg_size_bound_fails_before_any_runner_call(self) -> None:
        with self.fixture.dmg.open("r+b") as handle:
            handle.truncate(MAX_DMG_BYTES + 1)
        with self.assertRaisesRegex(TransactionError, "size must be within"):
            self.fixture.execute()
        self.assertEqual(self.fixture.runner.calls, [])

    def test_partial_or_hardlinked_public_dmg_set_is_not_uploadable(self) -> None:
        destination = self.fixture.execute()
        evidence = destination / "Clash.for.Mac_0.4.0_arm64.gatekeeper.json"
        evidence.unlink()
        with self.assertRaisesRegex(ArtifactSetError, "partial"):
            self.fixture.verify(destination)

        # Rebuild a fresh complete fixture for the independent hard-link case.
        other = DmgFixture()
        try:
            complete = other.execute()
            external = other.repository / "linked-dmg"
            os.link(complete / other.context.dmg_name, external)
            with self.assertRaisesRegex(ArtifactSetError, "single-link"):
                other.verify(complete)
        finally:
            other.close()

    def test_duplicate_or_unknown_dmg_seal_fields_are_rejected(self) -> None:
        destination = self.fixture.execute()
        seal_path = destination / "dmg-set.seal.json"
        original = seal_path.read_text(encoding="utf-8")
        seal_path.write_text(
            original.replace(
                '"architecture":"arm64"',
                '"architecture":"arm64","architecture":"arm64"',
                1,
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ArtifactSetError, "strict JSON"):
            self.fixture.verify(destination)

    def test_same_source_and_build_cannot_substitute_another_signed_app(self) -> None:
        destination = self.fixture.execute()
        executable = self.fixture.app / "Contents/MacOS/clash-for-mac"
        executable.write_bytes(b"different signed application")
        with self.assertRaisesRegex(
            ArtifactSetError, "manifest differs from the application tree"
        ):
            self.fixture.verify(destination)


class UpdaterArtifactSetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name).resolve()
        self.app = create_signed_candidate(self.root)
        self.prepackage_manifest, self.prepackage = create_prepackage_stage(
            self.root
        )
        self.package_root = (
            self.root / "target/candidates/0.4.0/ga/40043/packages"
        )
        updater_root = self.package_root / "updater"
        updater_root.mkdir(parents=True, mode=0o700)
        self.staging = updater_root / "updater-stage.fixture"
        self.staging.mkdir(mode=0o700)
        self.destination = updater_root / "v0.4.0"
        self.archive_name = "Clash.for.Mac_0.4.0_aarch64.app.tar.gz"
        self.archive = self.staging / self.archive_name
        self.signature = self.staging / f"{self.archive_name}.sig"
        self.latest = self.staging / "latest.json"
        self.verification = self.staging / "embedded-pubkey-verification.json"
        self.verifier_build = create_release_verifier_build(self.root)

        def canonical_tar_metadata(info: tarfile.TarInfo) -> tarfile.TarInfo:
            info.pax_headers = {}
            info.mtime = int(info.mtime)
            return info

        with tarfile.open(self.archive, "w:gz") as archive:
            archive.add(
                self.app,
                arcname=self.app.name,
                recursive=True,
                filter=canonical_tar_metadata,
            )
        self.signature.write_text("fixture-signature\n", encoding="utf-8")
        signature = self.signature.read_text(encoding="utf-8").strip()
        url = (
            "https://github.com/billlza/cfw-rs/releases/download/v0.4.0/"
            + self.archive_name
        )
        self.latest.write_text(
            json.dumps(
                {
                    "notes": "Clash for Mac 0.4.0",
                    "platforms": {
                        target: {"signature": signature, "url": url}
                        for target in ("darwin-aarch64", "darwin-arm64")
                    },
                    "pub_date": CLOCK,
                    "version": "0.4.0",
                },
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @contextmanager
    def _compiled_verifier(self, repository: Path):
        self.assertEqual(repository, self.root)
        require_fixture_cargo_boundary(repository)
        yield self.verifier_build

    def prepackage_stage(self, repository: Path) -> dict[str, object]:
        if repository != self.root:
            raise AssertionError("prepackage verifier used the wrong repository")
        return prepackage_binding(repository, self.prepackage_manifest)

    def seal(self, publish: Callable[[Path, Path], None] = publisher) -> Path:
        with patch(
            "scripts.release_artifact_set._compiled_release_verifier",
            new=self._compiled_verifier,
        ), verified_cargo_fixture(self.verifier_build):
            return seal_updater_set(
                self.staging,
                self.destination,
                version="0.4.0",
                source_identity=SEALED_SOURCE_IDENTITY,
                sealed_at=CLOCK,
                repository=self.root,
                publisher=publish,
                prepackage_stage_verifier=self.prepackage_stage,
            )

    def verify(self, directory: Path | None = None) -> dict:
        with patch(
            "scripts.release_artifact_set._compiled_release_verifier",
            new=self._compiled_verifier,
        ), verified_cargo_fixture(self.verifier_build):
            return verify_updater_set(
                directory or self.destination,
                repository=self.root,
                version="0.4.0",
                prepackage_stage_verifier=self.prepackage_stage,
            )

    def test_complete_updater_group_is_published_as_one_directory(self) -> None:
        destination = self.seal()
        self.assertFalse(self.staging.exists())
        seal = self.verify(destination)
        self.assertEqual(seal["schema_version"], 2)
        self.assertEqual(seal["document"], "cfw-updater-release-set-seal-v2")
        self.assertEqual(seal["prepackage"], self.prepackage)
        self.assertEqual(
            seal["official_url"],
            (
                "https://github.com/billlza/cfw-rs/releases/download/v0.4.0/"
                + self.archive_name
            ),
        )

    def test_missing_prepackage_fails_before_updater_verifier_or_publication(self) -> None:
        self.prepackage_manifest.unlink()
        with self.assertRaisesRegex(ArtifactSetError, "prepackage stage authorization"):
            self.seal()
        self.assertFalse(self.destination.exists())
        self.assertFalse(self.verification.exists())

    def test_wrong_prepackage_digest_cannot_be_written_into_the_updater_seal(self) -> None:
        wrong = {
            "manifest": {**self.prepackage["manifest"], "sha256": "0" * 64},
            "manifest_path": self.prepackage["manifest_path"],
        }
        with self.assertRaisesRegex(ArtifactSetError, "differs from the sealed release asset"):
            seal_updater_set(
                self.staging,
                self.destination,
                version="0.4.0",
                source_identity=SEALED_SOURCE_IDENTITY,
                sealed_at=CLOCK,
                repository=self.root,
                prepackage_stage_verifier=lambda _repository: wrong,
            )
        self.assertFalse(self.destination.exists())

    def test_prepackage_drift_after_sealing_invalidates_updater_verification(self) -> None:
        destination = self.seal()
        self.prepackage_manifest.write_text(
            '{"fixture":"drifted-after-updater-seal"}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(ArtifactSetError, "prepackage"):
            self.verify(destination)

    def test_prepackage_manifest_mutation_during_authorization_is_rejected(self) -> None:
        def mutate(_repository: Path, _stage: str) -> dict[str, object]:
            self.prepackage_manifest.write_text(
                '{"fixture":"mutated-during-stage-check"}\n', encoding="utf-8"
            )
            return {"document": "fixture"}

        with patch(
            "scripts.publication.ga_release_contract.verify_stage", side_effect=mutate
        ):
            with self.assertRaisesRegex(PublicationError, "changed during authorization"):
                verify_ga_prepackage_stage(self.root)

    def test_direct_seal_updater_cli_cannot_bypass_prepackage(self) -> None:
        from scripts import release_artifact_set as artifact_sets
        from scripts import release_artifact_set_cli as artifact_cli

        self.prepackage_manifest.unlink()
        arguments = [
            str(Path(artifact_cli.__file__).resolve()),
            "seal-updater",
            "--staging",
            str(self.staging),
            "--destination",
            str(self.destination),
            "--version",
            "0.4.0",
            "--repository",
            str(self.root),
        ]
        with patch.object(sys, "argv", arguments), patch(
            "scripts.release_python_runtime.require_closed_release_runtime"
        ), patch.object(
            artifact_sets, "current_identity", return_value=SOURCE_IDENTITY
        ):
            with self.assertRaisesRegex(SystemExit, "prepackage"):
                artifact_cli.main()

    def test_caller_selected_destination_is_rejected_before_verifier_build(self) -> None:
        with self.assertRaisesRegex(ArtifactSetError, "fixed GA package path"):
            seal_updater_set(
                self.staging,
                self.root / "caller-selected/v0.4.0",
                version="0.4.0",
                source_identity=SEALED_SOURCE_IDENTITY,
                sealed_at=CLOCK,
                repository=self.root,
            )

    def test_unsealed_updater_verifier_rejects_a_caller_selected_stage(self) -> None:
        caller_stage = self.root / "updater-stage.caller"
        caller_stage.mkdir()
        with self.assertRaisesRegex(ArtifactSetError, "fixed GA package path"):
            verify_updater_set(
                caller_stage,
                repository=self.root,
                version="0.4.0",
                require_version_directory=False,
            )

    def test_caller_supplied_verified_receipt_is_discarded_and_reproduced(self) -> None:
        self.verification.write_text(
            '{"result":"verified","embedded_public_key_sha256":"'
            + "f" * 64
            + '"}\n',
            encoding="utf-8",
        )
        destination = self.seal()
        receipt = json.loads(
            (destination / self.verification.name).read_text(encoding="utf-8")
        )
        self.assertEqual(receipt["result"], "verified")
        self.assertEqual(receipt["embedded_public_key_sha256"], "c" * 64)
        seal = json.loads(
            (destination / "updater-set.seal.json").read_text(encoding="utf-8")
        )
        self.assertEqual(
            seal["release_verifier"]["executable"]["filename"],
            "cfw-release-verifier",
        )
        self.assertEqual(seal["release_verifier"]["schema_version"], 4)
        self.assertEqual(
            seal["release_verifier"]["cargo_workspace_lock_sha256"],
            self.verifier_build.cargo_lock_sha256,
        )
        self.assertEqual(
            seal["release_verifier"]["cargo_workspace_vendor_sha256"],
            self.verifier_build.cargo_vendor_sha256,
        )
        self.assertEqual(seal["release_verifier"]["network"], "offline")

    def test_legacy_or_non_integer_verifier_binding_schema_is_rejected(self) -> None:
        destination = self.seal()
        seal_path = destination / "updater-set.seal.json"
        original = json.loads(seal_path.read_text(encoding="utf-8"))

        for schema_version in (3, True, "4"):
            with self.subTest(schema_version=schema_version):
                changed = deepcopy(original)
                changed["release_verifier"]["schema_version"] = schema_version
                seal_path.write_text(
                    json.dumps(
                        changed,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    ArtifactSetError, "build policy is inconsistent"
                ):
                    self.verify(destination)

    def test_verifier_binding_rejects_field_or_build_invocation_drift(self) -> None:
        destination = self.seal()
        seal_path = destination / "updater-set.seal.json"
        original = json.loads(seal_path.read_text(encoding="utf-8"))
        mutations = {
            "extra-field": lambda binding: binding.update({"legacy": False}),
            "missing-field": lambda binding: binding.pop("lock_invocation"),
            "reordered-rustflags": lambda binding: binding[
                "build_invocation"
            ]["argv"][-1].replace(
                '"-C","link-arg=-Wl,-S","-C","link-arg=-Wl,-x"',
                '"-C","link-arg=-Wl,-x","-C","link-arg=-Wl,-S"',
            ),
        }

        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = deepcopy(original)
                binding = changed["release_verifier"]
                if name == "reordered-rustflags":
                    binding["build_invocation"]["argv"][-1] = mutate(binding)
                else:
                    mutate(binding)
                seal_path.write_text(
                    json.dumps(
                        changed,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    ArtifactSetError,
                    "unexpected field set|build policy is inconsistent",
                ):
                    self.verify(destination)

    def test_apple_linker_binding_drift_is_rejected(self) -> None:
        destination = self.seal()
        seal_path = destination / "updater-set.seal.json"
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        seal["release_verifier"]["apple_toolchain"]["ld"]["sha256"] = (
            "0" * 64
        )
        seal_path.write_text(
            json.dumps(
                seal,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            ArtifactSetError, "Apple linker inputs are inconsistent"
        ):
            self.verify(destination)

    def test_source_input_size_requires_one_strict_json_integer(self) -> None:
        destination = self.seal()
        seal_path = destination / "updater-set.seal.json"
        original = json.loads(seal_path.read_text(encoding="utf-8"))
        original_size = original["release_verifier"]["source_inputs"][
            "crate_source"
        ]["size"]

        for changed_size in (float(original_size), True):
            with self.subTest(changed_size=changed_size):
                changed = deepcopy(original)
                changed["release_verifier"]["source_inputs"]["crate_source"][
                    "size"
                ] = changed_size
                seal_path.write_text(
                    json.dumps(
                        changed,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    ArtifactSetError, "source input crate_source is malformed"
                ):
                    self.verify(destination)

    def test_source_input_record_shape_path_and_digest_are_strict(self) -> None:
        destination = self.seal()
        seal_path = destination / "updater-set.seal.json"
        original = json.loads(seal_path.read_text(encoding="utf-8"))

        for source_key in original["release_verifier"]["source_inputs"]:
            for mutation in ("missing-field", "extra-field"):
                with self.subTest(source_key=source_key, mutation=mutation):
                    changed = deepcopy(original)
                    record = changed["release_verifier"]["source_inputs"][
                        source_key
                    ]
                    if mutation == "missing-field":
                        record.pop("path")
                    else:
                        record["legacy"] = False
                    seal_path.write_text(
                        json.dumps(
                            changed,
                            ensure_ascii=False,
                            sort_keys=True,
                            separators=(",", ":"),
                        )
                        + "\n",
                        encoding="utf-8",
                    )
                    with self.assertRaises(ArtifactSetError):
                        self.verify(destination)

        mutations = {
            "path-type": lambda record: record.update({"path": True}),
            "path-value": lambda record: record.update(
                {"path": "scripts/not-the-release-verifier.rs"}
            ),
            "digest-type": lambda record: record.update({"sha256": False}),
            "digest-format": lambda record: record.update({"sha256": "A" * 64}),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                changed = deepcopy(original)
                record = changed["release_verifier"]["source_inputs"][
                    "crate_source"
                ]
                mutate(record)
                seal_path.write_text(
                    json.dumps(
                        changed,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaises(ArtifactSetError):
                    self.verify(destination)

    def test_updater_verification_numeric_fields_require_strict_integers(
        self,
    ) -> None:
        destination = self.seal()
        receipt_path = destination / self.verification.name
        seal_path = destination / "updater-set.seal.json"
        original_receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        original_seal = json.loads(seal_path.read_text(encoding="utf-8"))

        for field, changed_value in (
            ("schema_version", True),
            ("archive_size", float(original_receipt["archive_size"])),
            ("signature_size", float(original_receipt["signature_size"])),
        ):
            with self.subTest(field=field):
                receipt = deepcopy(original_receipt)
                receipt[field] = changed_value
                receipt_path.write_text(
                    json.dumps(
                        receipt,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                    encoding="utf-8",
                )
                receipt_data = receipt_path.read_bytes()
                seal = deepcopy(original_seal)
                seal["artifacts"]["embedded_public_key_verification"] = {
                    "filename": receipt_path.name,
                    "sha256": hashlib.sha256(receipt_data).hexdigest(),
                    "size": len(receipt_data),
                }
                seal_path.write_text(
                    json.dumps(
                        seal,
                        ensure_ascii=False,
                        sort_keys=True,
                        separators=(",", ":"),
                    )
                    + "\n",
                    encoding="utf-8",
                )
                with self.assertRaisesRegex(
                    ArtifactSetError, "malformed numeric fields"
                ):
                    self.verify(destination)

    def test_sealed_artifact_size_requires_one_strict_json_integer(self) -> None:
        destination = self.seal()
        seal_path = destination / "updater-set.seal.json"
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        record_value = seal["artifacts"]["embedded_public_key_verification"]
        record_value["size"] = float(record_value["size"])
        seal_path.write_text(
            json.dumps(
                seal,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            )
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ArtifactSetError,
            "embedded public-key verification evidence is malformed",
        ):
            self.verify(destination)

    def test_hand_forged_complete_set_cannot_bypass_fresh_signature_verification(
        self,
    ) -> None:
        destination = self.seal()
        signature_path = destination / self.signature.name
        signature_path.write_text("forged-signature\n", encoding="utf-8")
        signature_bytes = signature_path.read_bytes()

        latest_path = destination / self.latest.name
        latest = json.loads(latest_path.read_text(encoding="utf-8"))
        for target in ("darwin-aarch64", "darwin-arm64"):
            latest["platforms"][target]["signature"] = "forged-signature"
        latest_path.write_text(
            json.dumps(latest, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )

        receipt_path = destination / self.verification.name
        receipt = json.loads(receipt_path.read_text(encoding="utf-8"))
        receipt["signature_sha256"] = hashlib.sha256(signature_bytes).hexdigest()
        receipt["signature_size"] = len(signature_bytes)
        receipt_path.write_text(
            json.dumps(receipt, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )

        def record(path: Path) -> dict[str, object]:
            data = path.read_bytes()
            return {
                "filename": path.name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "size": len(data),
            }

        seal_path = destination / "updater-set.seal.json"
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        seal["artifacts"]["signature"] = record(signature_path)
        seal["artifacts"]["manifest"] = record(latest_path)
        seal["artifacts"]["embedded_public_key_verification"] = record(
            receipt_path
        )
        seal_path.write_text(
            json.dumps(seal, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )

        with self.assertRaisesRegex(
            ArtifactSetError, "release verifier execution failed"
        ):
            self.verify(destination)

    def test_repository_cargo_wrapper_configuration_is_rejected(self) -> None:
        cargo_configuration = self.root / ".cargo"
        cargo_configuration.mkdir()
        (cargo_configuration / "config.toml").write_text(
            '[build]\nrustc-wrapper = "/tmp/forged-rustc-wrapper"\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ArtifactSetError, "ambient Cargo configuration"):
            self.seal()
        self.assertFalse(self.destination.exists())

    def test_forged_dependency_closure_binding_is_rejected_by_fresh_build(self) -> None:
        destination = self.seal()
        seal_path = destination / "updater-set.seal.json"
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        dependencies = seal["release_verifier"]["dependency_sources"]
        dependencies["crates"][0]["source_tree_sha256"] = "9" * 64
        dependencies["sha256"] = hashlib.sha256(
            (
                json.dumps(
                    dependencies["crates"],
                    ensure_ascii=False,
                    sort_keys=True,
                    separators=(",", ":"),
                )
                + "\n"
            ).encode("utf-8")
        ).hexdigest()
        seal_path.write_text(
            json.dumps(seal, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ArtifactSetError,
            "Cargo dependency binding|fresh release verifier build differs",
        ):
            self.verify(destination)

    def test_workspace_vendor_digest_tamper_is_rejected(self) -> None:
        destination = self.seal()
        seal_path = destination / "updater-set.seal.json"
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        seal["release_verifier"]["cargo_workspace_vendor_sha256"] = "9" * 64
        seal_path.write_text(
            json.dumps(seal, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ArtifactSetError, "Cargo dependency binding"):
            self.verify(destination)

    def test_workspace_lock_digest_tamper_is_rejected(self) -> None:
        destination = self.seal()
        seal_path = destination / "updater-set.seal.json"
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        seal["release_verifier"]["cargo_workspace_lock_sha256"] = "9" * 64
        seal_path.write_text(
            json.dumps(seal, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ArtifactSetError,
            "workspace Cargo.lock differs|Cargo dependency binding",
        ):
            self.verify(destination)

    def test_pinned_toolchain_drift_during_replay_is_rejected(self) -> None:
        destination = self.seal()
        with self.verifier_build.cargo.open("ab") as handle:
            handle.write(b"toolchain drift")
        with self.assertRaisesRegex(ArtifactSetError, "toolchain changed"):
            self.verify(destination)

    def test_verifier_replacement_during_execution_is_rejected(self) -> None:
        from scripts import release_artifact_set as artifact_sets

        real_invoke = artifact_sets._invoke_release_verifier

        def invoke_then_replace(*args, **kwargs):
            receipt = real_invoke(*args, **kwargs)
            with self.verifier_build.executable.open("ab") as handle:
                handle.write(b"# replaced after execution\n")
            return receipt

        with patch.object(
            artifact_sets,
            "_invoke_release_verifier",
            side_effect=invoke_then_replace,
        ):
            with self.assertRaisesRegex(
                ArtifactSetError, "executable changed during verification"
            ):
                self.seal()
        self.assertFalse(self.destination.exists())

    def test_archive_drift_during_verifier_execution_is_rejected(self) -> None:
        from scripts import release_artifact_set as artifact_sets

        real_invoke = artifact_sets._invoke_release_verifier

        def invoke_then_drift(build, repository, archive, signature):
            receipt = real_invoke(build, repository, archive, signature)
            with archive.open("ab") as handle:
                handle.write(b"drift-after-verification")
            return receipt

        with patch.object(
            artifact_sets,
            "_invoke_release_verifier",
            side_effect=invoke_then_drift,
        ):
            with self.assertRaisesRegex(
                ArtifactSetError, "changed during embedded-key verification"
            ):
                self.seal()
        self.assertFalse(self.destination.exists())

    def test_crash_after_receipt_write_replays_from_original_inputs(self) -> None:
        from scripts import release_artifact_set as artifact_sets

        real_write = artifact_sets._write_canonical_new
        crashed = False

        def write_then_crash(path: Path, value: object) -> None:
            nonlocal crashed
            real_write(path, value)
            if path.name == self.verification.name and not crashed:
                crashed = True
                raise SimulatedCrash("after internally produced receipt")

        with patch.object(
            artifact_sets, "_write_canonical_new", side_effect=write_then_crash
        ):
            with self.assertRaises(SimulatedCrash):
                self.seal()
        self.assertTrue(self.verification.is_file())
        self.assertFalse(self.destination.exists())

        destination = self.seal()
        self.verify(destination)

    def test_process_crash_after_rename_is_idempotently_recovered(self) -> None:
        def rename_then_crash(source: Path, destination: Path) -> None:
            publisher(source, destination)
            raise SimulatedCrash("after updater set rename")

        with self.assertRaises(SimulatedCrash):
            self.seal(rename_then_crash)
        self.assertFalse(self.staging.exists())
        self.assertTrue(self.destination.is_dir())
        self.assertEqual(self.seal(), self.destination)

    def test_verifier_source_drift_after_sealing_is_rejected(self) -> None:
        destination = self.seal()
        source = self.root / "crates/cfw-release-verifier/src/main.rs"
        source.write_text("fn main() { panic!(\"drift\"); }\n", encoding="utf-8")
        with self.assertRaisesRegex(ArtifactSetError, "source inputs differ"):
            self.verify(destination)

    def test_partial_group_never_reaches_the_destination(self) -> None:
        self.latest.unlink()
        with self.assertRaisesRegex(ArtifactSetError, "partial"):
            self.seal()
        self.assertFalse(self.destination.exists())

    def test_digest_drift_after_sealing_is_rejected(self) -> None:
        destination = self.seal()
        (destination / self.archive_name).write_bytes(b"drift")
        with self.assertRaisesRegex(ArtifactSetError, "differs"):
            self.verify(destination)

    def test_unknown_seal_field_is_rejected(self) -> None:
        destination = self.seal()
        seal_path = destination / "updater-set.seal.json"
        seal = json.loads(seal_path.read_text(encoding="utf-8"))
        seal["unexpected"] = True
        seal_path.write_text(
            json.dumps(seal, ensure_ascii=False, sort_keys=True, separators=(",", ":"))
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ArtifactSetError, "unexpected field"):
            self.verify(destination)

    def test_atomic_publication_reply_loss_accepts_only_the_complete_set(self) -> None:
        from scripts import release_artifact_set as artifact_sets

        events: list[str] = []
        real_fsync = artifact_sets._fsync_release_set
        real_confirm = artifact_sets.confirm_published_tree_durable

        def fsync_before_publish(path: Path, label: str) -> None:
            events.append("fsync-source")
            real_fsync(path, label)

        def confirm_after_reply_loss(source: Path, destination: Path) -> None:
            events.append("fsync-destination-and-parents")
            real_confirm(source, destination)

        def reply_lost(source: Path, destination: Path) -> None:
            events.append("rename")
            publisher(source, destination)
            raise RuntimeError("lost rename reply")

        with patch.object(
            artifact_sets,
            "_fsync_release_set",
            side_effect=fsync_before_publish,
        ), patch.object(
            artifact_sets,
            "confirm_published_tree_durable",
            side_effect=confirm_after_reply_loss,
        ):
            destination = self.seal(reply_lost)
        self.assertEqual(destination, self.destination)
        self.assertEqual(
            events,
            ["fsync-source", "rename", "fsync-destination-and-parents"],
        )
        self.verify(destination)

    def test_reply_loss_is_not_success_when_durability_cannot_be_closed(self) -> None:
        def reply_lost(source: Path, destination: Path) -> None:
            publisher(source, destination)
            raise RuntimeError("lost rename reply")

        with patch(
            "scripts.release_artifact_set.confirm_published_tree_durable",
            side_effect=TransactionError(
                "publish_durability_unknown",
                "fixture fsync failure",
                terminal_state="outcome_unknown",
            ),
        ):
            with self.assertRaisesRegex(ArtifactSetError, "durability is unconfirmed"):
                self.seal(reply_lost)

    def test_same_source_and_build_cannot_substitute_another_signed_app(self) -> None:
        destination = self.seal()
        (self.app / "Contents/MacOS/clash-for-mac").write_bytes(
            b"different signed application"
        )
        with self.assertRaisesRegex(
            ArtifactSetError, "manifest differs from the application tree"
        ):
            self.verify(destination)

    def test_symlink_and_hardlink_assets_are_rejected(self) -> None:
        self.latest.unlink()
        self.latest.symlink_to(self.archive.name)
        with self.assertRaisesRegex(ArtifactSetError, "single-link"):
            self.seal()
        self.latest.unlink()
        self.latest.write_text("{}\n", encoding="utf-8")
        hardlink = self.staging / "archive-copy"
        os.link(self.archive, hardlink)
        with self.assertRaisesRegex(ArtifactSetError, "single-link"):
            self.seal()

    def test_archive_size_bound_is_enforced_without_reading_the_payload(self) -> None:
        with self.archive.open("r+b") as handle:
            handle.truncate(MAX_UPDATER_ARCHIVE_BYTES + 1)
        with self.assertRaisesRegex(ArtifactSetError, "size is outside"):
            self.seal()


class DistributionFixture:
    def __init__(self) -> None:
        self.dmg = DmgFixture()
        self.dmg.execute()
        self.updater = UpdaterArtifactSetTests(methodName="runTest")
        self.updater.setUp()
        # Distribution verification runs in the DMG repository. Reproduce the
        # exact verifier/configuration source inputs that sealed the updater.
        self.verifier_build = create_release_verifier_build(self.dmg.repository)
        updater_set = self.updater.seal()
        destination_parent = self.dmg.package_root / "updater"
        destination_parent.mkdir()
        os.rename(updater_set, destination_parent / "v0.4.0")
        publication = self.dmg.ga_root / "stage-inputs/publication"
        publication.mkdir(parents=True)
        self.raw_publication = publication
        (self.dmg.repository / "LICENSE").write_text(
            "GPL-3.0-or-later fixture\n", encoding="utf-8"
        )
        (self.dmg.repository / "CHANGELOG.md").write_text(
            "# 0.4.0 fixture modifications\n", encoding="utf-8"
        )
        for name in (
            "corresponding-source.manifest.json",
            "evidence-manifest.json",
            "inventory.json",
            "legal-review.json",
            "machine-closure.json",
            "sbom.cyclonedx.json",
            "sbom.spdx.json",
        ):
            (publication / name).write_text(
                json.dumps({"fixture": name}, sort_keys=True) + "\n",
                encoding="utf-8",
            )
        (publication / "corresponding-source.tar.gz").write_bytes(
            b"fixture corresponding source"
        )
        license_directory = publication / "licenses/example-component"
        license_directory.mkdir(parents=True)
        (license_directory / "LICENSE.txt").write_text(
            "fixture third-party license and notice\n", encoding="utf-8"
        )
        prepackage = self.dmg.prepackage_manifest
        sealed_publication = self.dmg.ga_root / "publication/manifest.json"
        sealed_publication.parent.mkdir()
        sealed_publication.write_text(
            '{"fixture":"publication"}\n', encoding="utf-8"
        )
        self.prepackage_manifest = prepackage
        self.publication_manifest = sealed_publication
        self.publication_semantic_verifier = (
            lambda _repository, _publication, _app: None
        )

        def stage_verifier(repository: Path) -> dict[str, object]:
            self.assert_repository(repository)

            def record(path: Path) -> dict[str, object]:
                data = path.read_bytes()
                return {
                    "filename": path.name,
                    "sha256": hashlib.sha256(data).hexdigest(),
                    "size": len(data),
                }

            return {
                "legal_source": {"fixture": "same-prepackage-publication-source"},
                "prepackage_manifest": record(self.prepackage_manifest),
                "prepackage_manifest_path": str(
                    self.prepackage_manifest.relative_to(repository)
                ),
                "publication_manifest": record(self.publication_manifest),
                "publication_manifest_path": str(
                    self.publication_manifest.relative_to(repository)
                ),
            }

        self.publication_stage_verifier = stage_verifier

    def close(self) -> None:
        self.updater.tearDown()
        self.dmg.close()

    def assert_repository(self, repository: Path) -> None:
        if repository != self.dmg.repository:
            raise AssertionError("distribution verifier used the wrong repository")

    @contextmanager
    def _compiled_verifier(self, repository: Path):
        self.assert_repository(repository)
        require_fixture_cargo_boundary(repository)
        yield self.verifier_build

    def seal(self, publication_publisher: Callable[[Path, Path], None] = publisher) -> Path:
        with patch(
            "scripts.release_artifact_set._compiled_release_verifier",
            new=self._compiled_verifier,
        ), verified_cargo_fixture(self.verifier_build):
            return seal_distribution_set(
                self.dmg.repository,
                version="0.4.0",
                source_identity=SEALED_SOURCE_IDENTITY,
                sealed_at=CLOCK,
                publisher=publication_publisher,
                packaged_app_manifest_reader=self.dmg.package_manifest,
                publication_semantic_verifier=self.publication_semantic_verifier,
                publication_stage_verifier=self.publication_stage_verifier,
                prepackage_stage_verifier=self.dmg.prepackage_stage,
            )

    def verify_release(self) -> list[Path]:
        with patch(
            "scripts.release_artifact_set._compiled_release_verifier",
            new=self._compiled_verifier,
        ), verified_cargo_fixture(self.verifier_build):
            return verify_release_sets(
                self.dmg.repository,
                version="0.4.0",
                expected_source_identity=SEALED_SOURCE_IDENTITY,
                packaged_app_manifest_reader=self.dmg.package_manifest,
                publication_semantic_verifier=self.publication_semantic_verifier,
                publication_stage_verifier=self.publication_stage_verifier,
                prepackage_stage_verifier=self.dmg.prepackage_stage,
            )

    def verify(self, destination: Path) -> dict:
        with patch(
            "scripts.release_artifact_set._compiled_release_verifier",
            new=self._compiled_verifier,
        ), verified_cargo_fixture(self.verifier_build):
            return verify_distribution_set(
                destination,
                repository=self.dmg.repository,
                version="0.4.0",
                expected_source_identity=SEALED_SOURCE_IDENTITY,
                packaged_app_manifest_reader=self.dmg.package_manifest,
                publication_semantic_verifier=self.publication_semantic_verifier,
                publication_stage_verifier=self.publication_stage_verifier,
                prepackage_stage_verifier=self.dmg.prepackage_stage,
            )


class DistributionArtifactSetTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = DistributionFixture()

    def tearDown(self) -> None:
        self.fixture.close()

    def test_final_seal_joins_app_packages_and_publication_closure(self) -> None:
        destination = self.fixture.seal()
        seal = self.fixture.verify(destination)
        self.assertEqual(
            seal["candidate_app"]["signed_app_tree_sha256"],
            build_manifest(
                self.fixture.dmg.app, algorithm="sha256-tree-v2"
            )["sha256"],
        )
        uploadable = self.fixture.verify_release()
        self.assertEqual(len(uploadable), 15)
        self.assertIn(destination / DISTRIBUTION_SEAL_NAME, uploadable)
        private_gatekeeper = (
            self.fixture.dmg.package_root
            / "dmg/v0.4.0/Clash.for.Mac_0.4.0_arm64.gatekeeper.json"
        )
        public_gatekeeper = (
            destination
            / "Clash.for.Mac_0.4.0_arm64.gatekeeper.public.json"
        )
        self.assertNotIn(private_gatekeeper, uploadable)
        self.assertIn(public_gatekeeper, uploadable)
        private_bytes = private_gatekeeper.read_bytes()
        private_evidence = json.loads(private_bytes)
        public_bytes = public_gatekeeper.read_bytes()
        public_evidence = json.loads(public_bytes)
        assessed_target = private_evidence["assessed_target"].encode("utf-8")
        self.assertNotIn(assessed_target, public_bytes)
        self.assertEqual(
            public_evidence["private_evidence_sha256"],
            hashlib.sha256(private_bytes).hexdigest(),
        )
        self.assertEqual(public_evidence["assessment"], "accepted")
        self.assertEqual(public_evidence["assessment_type"], "open")
        self.assertIs(public_evidence["primary_signature_context"], True)
        final_dmg = (
            self.fixture.dmg.package_root
            / "dmg/v0.4.0/Clash.for.Mac_0.4.0_arm64.dmg"
        )
        self.assertEqual(
            public_evidence["target_sha256"],
            hashlib.sha256(final_dmg.read_bytes()).hexdigest(),
        )
        bundle = destination / "Clash.for.Mac_0.4.0_publication.tar.gz"
        self.assertIn(bundle, uploadable)
        with tarfile.open(bundle, "r:gz") as archive:
            names = {member.name for member in archive}
            public_bundle_evidence = archive.extractfile(
                "Clash.for.Mac_0.4.0_publication/verification/"
                "Clash.for.Mac_0.4.0_arm64.gatekeeper.public.json"
            )
            self.assertIsNotNone(public_bundle_evidence)
            assert public_bundle_evidence is not None
            bundled_projection = public_bundle_evidence.read()
        self.assertEqual(bundled_projection, public_bytes)
        self.assertNotIn(assessed_target, bundled_projection)
        self.assertNotIn(
            "Clash.for.Mac_0.4.0_publication/verification/"
            "Clash.for.Mac_0.4.0_arm64.gatekeeper.json",
            names,
        )
        self.assertIn(
            "Clash.for.Mac_0.4.0_publication/publication/"
            "corresponding-source.tar.gz",
            names,
        )
        self.assertIn(
            "Clash.for.Mac_0.4.0_publication/publication/sbom.spdx.json",
            names,
        )
        self.assertIn(
            "Clash.for.Mac_0.4.0_publication/publication/sbom.cyclonedx.json",
            names,
        )
        self.assertNotIn(
            "Clash.for.Mac_0.4.0_publication/publication/legal-review.json",
            names,
        )

    def test_public_bundle_budget_is_strictly_below_github_asset_limit(self) -> None:
        self.assertEqual(
            MAX_GITHUB_RELEASE_ASSET_BYTES_EXCLUSIVE,
            2 * 1024 * 1024 * 1024,
        )
        self.assertEqual(
            MAX_PUBLICATION_BUNDLE_BYTES,
            MAX_GITHUB_RELEASE_ASSET_BYTES_EXCLUSIVE - 1,
        )
        self.assertLess(
            MAX_CORRESPONDING_SOURCE_ARCHIVE_BYTES
            + MAX_PUBLICATION_BUNDLE_AUXILIARY_BYTES
            + MAX_PUBLICATION_DOCUMENT_BYTES,
            MAX_PUBLICATION_BUNDLE_BYTES,
        )

    def test_nested_corresponding_source_has_a_separate_smaller_bound(self) -> None:
        source = self.fixture.raw_publication / "corresponding-source.tar.gz"
        with source.open("r+b") as handle:
            handle.truncate(MAX_CORRESPONDING_SOURCE_ARCHIVE_BYTES + 1)
        with patch(
            "scripts.release_artifact_set.enumerate_tree",
            side_effect=AssertionError("oversized archive reached tree hashing"),
        ), patch(
            "scripts.release_artifact_set.tarfile.open",
            side_effect=AssertionError("oversized archive reached tar parsing"),
        ):
            with self.assertRaisesRegex(ArtifactSetError, "size is outside"):
                self.fixture.seal()

    def test_public_projection_requires_the_original_real_target_bytes(self) -> None:
        private_gatekeeper = (
            self.fixture.dmg.package_root
            / "dmg/v0.4.0/Clash.for.Mac_0.4.0_arm64.gatekeeper.json"
        )
        assessed_target = Path(
            json.loads(private_gatekeeper.read_bytes())["assessed_target"]
        )
        assessed_target.write_bytes(b"different DMG bytes")
        with self.assertRaisesRegex(
            ArtifactSetError, "real target evidence|exact target identity"
        ):
            self.fixture.seal()

    def test_public_projection_tamper_is_rejected(self) -> None:
        destination = self.fixture.seal()
        projection_path = (
            destination
            / "Clash.for.Mac_0.4.0_arm64.gatekeeper.public.json"
        )
        projection = json.loads(projection_path.read_bytes())
        projection["target_sha256"] = "0" * 64
        projection_path.write_text(
            json.dumps(projection, sort_keys=True, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ArtifactSetError, "public Gatekeeper projection"):
            self.fixture.verify(destination)

    def test_private_gatekeeper_copy_cannot_enter_public_sources(self) -> None:
        private_gatekeeper = (
            self.fixture.dmg.package_root
            / "dmg/v0.4.0/Clash.for.Mac_0.4.0_arm64.gatekeeper.json"
        )
        leaked = self.fixture.raw_publication / "renamed-gatekeeper-evidence.json"
        leaked.write_bytes(private_gatekeeper.read_bytes())
        with self.assertRaisesRegex(ArtifactSetError, "leaks a private Gatekeeper"):
            self.fixture.seal()

    def test_private_visibility_document_cannot_enter_public_sources(self) -> None:
        private_document = self.fixture.raw_publication / "final-candidate.private.json"
        private_document.write_text(
            '{"evidence":{"visibility":"private-release-operations"}}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            ArtifactSetError, "private release evidence"
        ):
            self.fixture.seal()

    def test_private_evidence_visibility_cannot_enter_public_sources(self) -> None:
        private_document = self.fixture.raw_publication / "physical-archive.private.json"
        private_document.write_text(
            '{"visibility":"private-release-evidence"}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ArtifactSetError, "private release evidence"):
            self.fixture.seal()

    def test_private_source_id_cannot_enter_public_sources(self) -> None:
        private_document = self.fixture.raw_publication / "renamed-private-source.json"
        private_document.write_text(
            '{"sources":[{"id":"physical-evidence-private-archive"}]}\n',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ArtifactSetError, "private release evidence"):
            self.fixture.seal()

    def test_private_evidence_filename_cannot_enter_public_sources(self) -> None:
        private_document = self.fixture.raw_publication / "physical-evidence.json"
        private_document.write_text('{"fixture":true}\n', encoding="utf-8")
        with self.assertRaisesRegex(ArtifactSetError, "private evidence filename"):
            self.fixture.seal()

    def test_publication_closure_drift_is_rejected(self) -> None:
        destination = self.fixture.seal()
        legal = self.fixture.raw_publication / "legal-review.json"
        legal.write_text('{"fixture":"changed"}\n', encoding="utf-8")
        with self.assertRaisesRegex(ArtifactSetError, "publication evidence"):
            self.fixture.verify(destination)

    def test_publication_stage_seal_drift_is_rejected(self) -> None:
        destination = self.fixture.seal()
        self.fixture.publication_manifest.write_text(
            '{"fixture":"changed publication seal"}\n', encoding="utf-8"
        )
        with self.assertRaisesRegex(ArtifactSetError, "publication evidence"):
            self.fixture.verify(destination)

    def test_direct_seal_release_rejects_missing_publication_stage(self) -> None:
        def reject_stage(_repository: Path) -> dict[str, object]:
            raise ArtifactSetError("fixture publication stage is unavailable")

        self.fixture.publication_stage_verifier = reject_stage
        with self.assertRaisesRegex(ArtifactSetError, "publication stage is unavailable"):
            self.fixture.seal()

    def test_direct_verify_release_reopens_publication_stage(self) -> None:
        destination = self.fixture.seal()

        def reject_stage(_repository: Path) -> dict[str, object]:
            raise ArtifactSetError("fixture publication stage was tampered")

        self.fixture.publication_stage_verifier = reject_stage
        with self.assertRaisesRegex(ArtifactSetError, "publication stage was tampered"):
            self.fixture.verify(destination)

    def test_prepackage_and_publication_must_bind_one_legal_source(self) -> None:
        prepackage = {"bindings": {"legal_source": {"tree": "a"}}}
        publication = {"bindings": {"legal_source": {"tree": "b"}}}
        with patch(
            "scripts.publication.ga_release_contract.verify_stage",
            side_effect=(prepackage, publication),
        ):
            with self.assertRaisesRegex(PublicationError, "legal sources differ"):
                verify_ga_publication_stages(self.fixture.dmg.repository)

    def test_source_archive_or_sbom_cannot_be_omitted_from_public_bundle(self) -> None:
        spdx = self.fixture.raw_publication / "sbom.spdx.json"
        spdx.unlink()
        with self.assertRaisesRegex(ArtifactSetError, "omits CCS"):
            self.fixture.seal()

    def test_public_bundle_rejects_a_concatenated_gzip_member(self) -> None:
        destination = self.fixture.seal()
        bundle = destination / "Clash.for.Mac_0.4.0_publication.tar.gz"
        with bundle.open("ab") as stream:
            stream.write(gzip.compress(b"hidden-second-member", mtime=0))
        with self.assertRaisesRegex(
            ArtifactSetError, "invalid gzip/tar termination boundary"
        ):
            self.fixture.verify(destination)

    def test_corresponding_source_cannot_be_omitted_from_public_bundle(self) -> None:
        source = self.fixture.raw_publication / "corresponding-source.tar.gz"
        source.unlink()
        with self.assertRaisesRegex(ArtifactSetError, "omits CCS"):
            self.fixture.seal()

    def test_distribution_atomic_publication_reply_loss_is_revalidated(self) -> None:
        from scripts import release_artifact_set as artifact_sets

        events: list[str] = []
        real_fsync = artifact_sets._fsync_release_set
        real_confirm = artifact_sets.confirm_published_tree_durable

        def fsync_before_publish(path: Path, label: str) -> None:
            events.append("fsync-source")
            real_fsync(path, label)

        def confirm_after_reply_loss(source: Path, destination: Path) -> None:
            events.append("fsync-destination-and-parents")
            real_confirm(source, destination)

        def reply_lost(source: Path, destination: Path) -> None:
            events.append("rename")
            publisher(source, destination)
            raise RuntimeError("lost distribution rename reply")

        with patch.object(
            artifact_sets,
            "_fsync_release_set",
            side_effect=fsync_before_publish,
        ), patch.object(
            artifact_sets,
            "confirm_published_tree_durable",
            side_effect=confirm_after_reply_loss,
        ):
            destination = self.fixture.seal(reply_lost)
        self.assertEqual(
            events,
            ["fsync-source", "rename", "fsync-destination-and-parents"],
        )
        self.fixture.verify(destination)

    def test_upload_gate_rejects_missing_final_distribution_seal(self) -> None:
        with self.assertRaisesRegex(ArtifactSetError, "distribution release root"):
            verify_release_sets(
                self.fixture.dmg.repository,
                version="0.4.0",
                expected_source_identity=SEALED_SOURCE_IDENTITY,
                packaged_app_manifest_reader=self.fixture.dmg.package_manifest,
                publication_semantic_verifier=(
                    self.fixture.publication_semantic_verifier
                ),
                publication_stage_verifier=(
                    self.fixture.publication_stage_verifier
                ),
                prepackage_stage_verifier=self.fixture.dmg.prepackage_stage,
            )

    def test_python_sealer_requires_semantic_publication_authorization(self) -> None:
        def reject_semantics(
            _repository: Path, _publication: Path, _app: Path
        ) -> None:
            raise ArtifactSetError("semantic authorization fixture rejected")

        with patch(
            "scripts.release_artifact_set._compiled_release_verifier",
            new=self.fixture._compiled_verifier,
        ), verified_cargo_fixture(self.fixture.verifier_build):
            with self.assertRaisesRegex(
                ArtifactSetError, "semantic authorization fixture rejected"
            ):
                seal_distribution_set(
                    self.fixture.dmg.repository,
                    version="0.4.0",
                    source_identity=SEALED_SOURCE_IDENTITY,
                    sealed_at=CLOCK,
                    publisher=publisher,
                    packaged_app_manifest_reader=self.fixture.dmg.package_manifest,
                    publication_semantic_verifier=reject_semantics,
                    publication_stage_verifier=(
                        self.fixture.publication_stage_verifier
                    ),
                    prepackage_stage_verifier=self.fixture.dmg.prepackage_stage,
                )


class ReleaseUploadGateTests(unittest.TestCase):
    def test_gate_rejects_a_partial_release_even_with_one_valid_set(self) -> None:
        fixture = UpdaterArtifactSetTests(methodName="runTest")
        fixture.setUp()
        try:
            fixture.seal()
            with self.assertRaisesRegex(ArtifactSetError, "unavailable"):
                verify_release_sets(fixture.root, version="0.4.0")
        finally:
            fixture.tearDown()

    def test_gate_rejects_legacy_unsealed_assets_at_the_package_root(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            package_root = (
                repository / "target/candidates/0.4.0/ga/40043/packages"
            )
            package_root.mkdir(parents=True)
            (package_root / "latest.json").write_text("{}\n", encoding="utf-8")
            with self.assertRaisesRegex(ArtifactSetError, "legacy unsealed"):
                verify_release_sets(repository, version="0.4.0")


class PackagingEntrypointContractTests(unittest.TestCase):
    def test_shell_packagers_require_prepackage_and_fixed_ga_paths(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        for relative in ("make_dmg.sh", "make_updater_manifest.sh"):
            source = (repository / "scripts" / relative).read_text(encoding="utf-8")
            with self.subTest(script=relative):
                self.assertIn("target/candidates/0.4.0/ga/40043", source)
                self.assertNotIn("target/candidates/0.4.0/ga/40037", source)
                self.assertNotIn("target/candidates/0.4.0/ga/40038", source)
                self.assertIn("verify_release_prepackage_evidence", source)
                self.assertNotIn("verify_release_" + "publication_evidence", source)
                self.assertNotIn("target/candidates/0.4.0/" + "release", source)
                self.assertNotIn("target/candidates/0.4.0/" + "signed", source)

    def test_dmg_cli_has_no_caller_selected_output_roots(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        source = (
            repository / "scripts/dmg_notarization_transaction.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("--release" + "-root", source)
        self.assertNotIn("--transaction" + "-root", source)
        self.assertIn('"transactions/dmg-notary"', source)
        self.assertIn('"packages"', source)

    def test_publication_gate_seals_and_verifies_the_distribution_allowlist(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        source = (repository / "scripts/release_publication_gate.sh").read_text(
            encoding="utf-8"
        )
        seal_case = source[source.index("    --seal-publication)") : source.index(
            "    --verify-prepackage)"
        )]
        self.assertLess(
            seal_case.index("run_production_ga_stage publication"),
            seal_case.index("run_production_ga_stage verify publication"),
        )
        self.assertLess(
            seal_case.index("run_production_ga_stage verify publication"),
            seal_case.index("seal-release"),
        )
        upload_start = source.index("verify_release_upload_artifacts()")
        upload_function = source[
            upload_start : source.index(
                'if [[ "${BASH_SOURCE[0]}" == "$0" ]]', upload_start
            )
        ]
        self.assertIn("verify_release_publication_evidence", upload_function)
        self.assertIn("verify-release", upload_function)


if __name__ == "__main__":
    unittest.main()
