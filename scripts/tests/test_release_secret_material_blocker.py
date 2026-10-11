from __future__ import annotations

import builtins
import contextlib
import dataclasses
import io
import json
import os
import subprocess
import tempfile
import unittest
from unittest import mock
from pathlib import Path

from scripts import release_secret_material_blocker as secret_blocker
from scripts.release_secret_material_blocker import (
    DetectedSecretMaterial,
    RequiredTrustAction,
    SecretMaterialKind,
    SecurityResponse,
    SecretMaterialReleaseBlock,
    assert_response_complete,
    build_security_response,
    classify_secret_material,
    evaluate_workspace,
    exposure_is_plausible,
    format_response,
    main,
    scan_workspace,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
SYSTEM_GIT = "/usr/bin/git"


def _run_git(repository: Path, *arguments: str) -> None:
    subprocess.run(
        [SYSTEM_GIT, "-C", str(repository), *arguments],
        check=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
        env={
            "PATH": "/usr/bin:/bin",
            "LC_ALL": "C",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_OPTIONAL_LOCKS": "0",
        },
    )


def _create_release_worktree(repository: Path, build: str = "40028") -> Path:
    """Add a detached Git worktree with an empty target at the fixed release path."""
    _run_git(repository, "init", "--quiet")
    (repository / "tracked.txt").write_text("fixture", encoding="utf-8")
    _run_git(repository, "add", "tracked.txt")
    _run_git(
        repository,
        "-c",
        "user.name=Release Test",
        "-c",
        "user.email=release-test@example.invalid",
        "commit",
        "--quiet",
        "-m",
        "test fixture",
    )
    worktree = repository / "target/release-worktrees" / build
    worktree.parent.mkdir(parents=True)
    _run_git(
        repository,
        "worktree",
        "add",
        "--quiet",
        "--detach",
        str(worktree),
        "HEAD",
    )
    (worktree / "target").mkdir()
    return worktree


def _worktree_admin_directory(worktree: Path) -> Path:
    marker = (worktree / ".git").read_bytes()
    prefix = b"gitdir: "
    if not marker.startswith(prefix) or not marker.endswith(b"\n"):
        raise AssertionError("test worktree marker is malformed")
    return Path(os.fsdecode(marker[len(prefix) : -1]))


def _write_retired_cache_scope_receipt(
    worktree: Path, *, device_offset: int
) -> dict[Path, bytes]:
    """Leave the files that retired cache-scope enrollment wrote in Git's registry.

    Operator clones still hold these files. The receipt records the device and
    inode of the administrative entry, worktree, marker and target as
    enrollment saw them; ``device_offset`` models a reboot that renumbered the
    volume afterwards.
    """
    admin = _worktree_admin_directory(worktree)

    def identity(path: Path) -> dict[str, int]:
        metadata = path.stat(follow_symlinks=False)
        return {"device": metadata.st_dev + device_offset, "inode": metadata.st_ino}

    receipt = {
        "adminIdentity": identity(admin),
        "build": worktree.name,
        "head": (admin / "HEAD").read_text(encoding="ascii").strip(),
        "markerIdentity": identity(worktree / ".git"),
        "schema": "cfm-release-worktree-cache-scope-v1",
        "targetIdentity": identity(worktree / "target"),
        "worktreeIdentity": identity(worktree),
        "worktreePath": str(worktree),
    }
    files = {
        admin / "cfm-release-worktree-cache-scope-v1.json": (
            json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n"
        ).encode("ascii"),
        admin / ".cfm-release-worktree-cache-scope-v1.lock": b"",
    }
    for path, data in files.items():
        path.write_bytes(data)
        path.chmod(0o600)
    return files


class _NoFileReads:
    """Context manager that makes any attempt to open a file fail the test.

    The blocker must detect updater keys by path and name only; opening a
    candidate would be a contract violation.
    """

    def __enter__(self) -> "_NoFileReads":
        def _forbidden(*args: object, **kwargs: object):
            raise AssertionError(
                f"secret-material blocker attempted to open a file: {args!r}"
            )

        self._patcher = mock.patch.object(builtins, "open", side_effect=_forbidden)
        self._patcher.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._patcher.stop()


class ScanByPathAndNameTests(unittest.TestCase):
    def test_detects_key_files_without_opening_them(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            tauri = Path(root) / ".tauri"
            tauri.mkdir()
            (tauri / "cfw-rs.key").write_text("PRIVATE", encoding="utf-8")
            (Path(root) / "cert.pem").write_text("PRIVATE", encoding="utf-8")
            (Path(root) / "AuthKey_TEST.p8").write_text(
                "PRIVATE", encoding="utf-8"
            )
            (Path(root) / "notes.txt").write_text("safe", encoding="utf-8")

            with _NoFileReads():
                detected = scan_workspace(root)

            names = sorted(item.name for item in detected)
            self.assertEqual(names, ["AuthKey_TEST.p8", "cert.pem", "cfw-rs.key"])
            for item in detected:
                self.assertTrue(item.path.endswith(item.name))

    def test_prunes_caches_but_scans_generated_release_roots(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            for pruned in (".git", "node_modules", ".build"):
                sub = Path(root) / pruned
                sub.mkdir()
                (sub / "buried.key").write_text("PRIVATE", encoding="utf-8")
            for pruned in ("toolchains", "debug", "sources"):
                sub = Path(root) / "target" / pruned
                sub.mkdir(parents=True)
                (sub / "cache.pem").write_text("UPSTREAM FIXTURE", encoding="utf-8")
            temporary = Path(root) / "target/tmp"
            temporary.mkdir()
            (temporary / "temporary.pem").write_text("PRIVATE", encoding="utf-8")
            candidates = Path(root) / "target/candidates/0.4.0"
            candidates.mkdir(parents=True)
            (candidates / "candidate.key").write_text("PRIVATE", encoding="utf-8")
            historical_release = Path(root) / "target/release"
            historical_release.mkdir()
            (historical_release / "historical.pem").write_text(
                "PRIVATE", encoding="utf-8"
            )
            unexpected = Path(root) / "target/unexpected"
            unexpected.mkdir()
            (unexpected / "unexpected.key").write_text("PRIVATE", encoding="utf-8")

            detected = scan_workspace(root)
            self.assertEqual(
                [item.name for item in detected],
                [
                    "candidate.key",
                    "historical.pem",
                    "temporary.pem",
                    "unexpected.key",
                ],
            )

    def test_release_worktree_prunes_only_its_direct_managed_target_roots(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root:
            worktree = _create_release_worktree(Path(root))
            managed = worktree / "target/toolchains/node-26.8.2"
            corepack = managed / "bin/corepack"
            corepack_target = managed / "lib/node_modules/corepack/dist/corepack.js"
            corepack_target.parent.mkdir(parents=True)
            corepack_target.write_text("managed toolchain", encoding="utf-8")
            corepack.parent.mkdir(parents=True)
            corepack.symlink_to("../lib/node_modules/corepack/dist/corepack.js")
            (managed / "cache.pem").write_text("UPSTREAM FIXTURE", encoding="utf-8")

            (worktree / "source.key").write_text("PRIVATE", encoding="utf-8")
            for relative, name in (
                ("target/candidates", "candidate.pem"),
                ("target/release", "historical.pem"),
                ("target/tmp", "temporary.key"),
                ("target/unexpected", "unexpected.p8"),
                ("vendor/component/target/toolchains", "deep-target.key"),
            ):
                directory = worktree / relative
                directory.mkdir(parents=True)
                (directory / name).write_text("PRIVATE", encoding="utf-8")

            self.assertEqual(
                [item.name for item in scan_workspace(root)],
                [
                    "source.key",
                    "candidate.pem",
                    "historical.pem",
                    "temporary.key",
                    "unexpected.p8",
                    "deep-target.key",
                ],
            )

    def test_release_worktree_managed_roots_are_pruned_by_name_alone(
        self,
    ) -> None:
        # Like the workspace's own target, no Git registration or receipt is
        # consulted: the fixed path and the managed name decide the exclusion.
        with tempfile.TemporaryDirectory() as root:
            worktree = Path(root) / "target/release-worktrees/40028"
            for managed in sorted(secret_blocker.MANAGED_TARGET_ROOTS):
                cache = worktree / "target" / managed
                cache.mkdir(parents=True)
                (cache / "upstream-fixture.pem").write_text(
                    "UPSTREAM FIXTURE", encoding="utf-8"
                )
            for relative, name in (
                ("", "source.key"),
                ("target", "loose.pem"),
                ("target/candidates", "candidate.p8"),
                ("target/toolchains-copy", "unexpected.key"),
            ):
                directory = worktree / relative
                directory.mkdir(parents=True, exist_ok=True)
                (directory / name).write_text("PRIVATE", encoding="utf-8")
            self.assertEqual(
                [item.name for item in scan_workspace(root)],
                ["source.key", "candidate.p8", "loose.pem", "unexpected.key"],
            )

    def test_only_the_fixed_five_digit_release_path_gains_managed_pruning(
        self,
    ) -> None:
        for relative in (
            "target/release-worktrees/not-a-build/target/toolchains",
            "target/release-worktrees/4002/target/toolchains",
            "target/release-worktrees/400280/target/toolchains",
            "target/release-worktrees/04002/target/toolchains",
            "target/release-worktrees/40028/toolchains",
            "target/release-worktrees/40028/other/toolchains",
            "target/release-worktrees/40028/Target/toolchains",
            "target/release-worktrees/40028/target/candidates/toolchains",
            "target/release-worktrees/40028/nested/target/toolchains",
            "target/release-worktrees/40028/target/release-worktrees/40029/target/toolchains",
            "target/other/40028/target/toolchains",
            "release-worktrees/40028/target/toolchains",
        ):
            with self.subTest(relative=relative), tempfile.TemporaryDirectory() as root:
                cache = Path(root) / relative
                cache.mkdir(parents=True)
                (cache / "must-remain-visible.key").write_text(
                    "PRIVATE", encoding="utf-8"
                )
                self.assertEqual(
                    [item.name for item in scan_workspace(root)],
                    ["must-remain-visible.key"],
                )

    def test_reboot_or_replaced_target_no_longer_blocks_the_scan(self) -> None:
        # Retired cache-scope receipts went stale on a reboot or a recreated
        # target and blocked every operator scan until an explicit recovery.
        for change in ("device-renumbered", "target-replaced"):
            with self.subTest(change=change), tempfile.TemporaryDirectory() as parent:
                root = Path(parent).resolve()
                worktree = _create_release_worktree(root)
                retired = _write_retired_cache_scope_receipt(
                    worktree,
                    device_offset=1_000 if change == "device-renumbered" else 0,
                )
                if change == "target-replaced":
                    original = (worktree / "target").stat().st_ino
                    replacement = worktree / "target-replacement"
                    replacement.mkdir()
                    (worktree / "target").rmdir()
                    replacement.rename(worktree / "target")
                    self.assertNotEqual((worktree / "target").stat().st_ino, original)
                managed = worktree / "target/toolchains/go/src/crypto/tls/testdata"
                managed.mkdir(parents=True)
                (managed / "upstream-fixture.pem").write_text(
                    "UPSTREAM FIXTURE", encoding="utf-8"
                )

                stdout = io.StringIO()
                with contextlib.redirect_stdout(stdout):
                    self.assertEqual(main([str(root)]), 0)
                self.assertIn("no release secret material found", stdout.getvalue())

                (worktree / "source.p8").write_text("PRIVATE", encoding="utf-8")
                candidate = worktree / "target/candidates/candidate.key"
                candidate.parent.mkdir()
                candidate.write_text("PRIVATE", encoding="utf-8")
                self.assertEqual(
                    [item.name for item in scan_workspace(root)],
                    ["source.p8", "candidate.key"],
                )
                for path, data in retired.items():
                    self.assertEqual(path.read_bytes(), data)

    def test_case_insensitive_suffix_match(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / "UPPER.KEY").write_text("PRIVATE", encoding="utf-8")
            (Path(root) / "APPSTORE.P8").write_text("PRIVATE", encoding="utf-8")
            detected = scan_workspace(root)
            self.assertEqual(
                [item.name for item in detected], ["APPSTORE.P8", "UPPER.KEY"]
            )


class ClassificationPolicyTests(unittest.TestCase):
    def test_exact_current_notary_key_requires_notary_reprovision_when_exposed(
        self,
    ) -> None:
        name = "AuthKey_DYHRNJ2Z4M.p8"
        path = Path("/ws/backups") / name
        kind = classify_secret_material(path, name)
        self.assertIs(kind, SecretMaterialKind.APPLE_ASC_NOTARY_KEY)
        response = build_security_response(
            DetectedSecretMaterial(str(path), name, kind),
            "/ws",
        )
        self.assertIs(
            response.required_trust_action,
            RequiredTrustAction.ROTATE_ASC_AND_REPROVISION_NOTARY,
        )
        self.assertTrue(response.notary_profile_reprovision_required)
        self.assertFalse(response.updater_trust_migration_required)
        self.assertIn("updater trust migration: not required", format_response(response))

    def test_other_canonical_apple_key_requires_domain_identification(self) -> None:
        name = "AuthKey_A1B2C3D4E5.p8"
        path = Path("/ws/archive") / name
        kind = classify_secret_material(path, name)
        self.assertIs(kind, SecretMaterialKind.APPLE_API_PRIVATE_KEY)
        response = build_security_response(
            DetectedSecretMaterial(str(path), name, kind),
            "/ws",
        )
        self.assertIs(
            response.required_trust_action,
            RequiredTrustAction.IDENTIFY_APPLE_DOMAIN_AND_ROTATE,
        )
        self.assertTrue(response.trust_domain_identification_required)
        self.assertFalse(response.notary_profile_reprovision_required)
        self.assertFalse(response.updater_trust_migration_required)

        isolated_path = Path("/ws") / name
        isolated = build_security_response(
            DetectedSecretMaterial(str(isolated_path), name, kind),
            "/ws",
        )
        self.assertIs(
            isolated.required_trust_action,
            RequiredTrustAction.IDENTIFY_APPLE_DOMAIN_AND_RELOCATE,
        )
        self.assertFalse(isolated.rotation_required)

    def test_generic_p8_is_unknown_and_never_defaults_to_updater(self) -> None:
        for name in ("AuthKey_SHORT.p8", "distribution.P8", "unknown.p8"):
            with self.subTest(name=name):
                kind = classify_secret_material(Path("/ws") / name, name)
                self.assertIs(kind, SecretMaterialKind.UNKNOWN_PRIVATE_KEY)

    def test_exact_updater_names_and_tauri_path_are_updater_domain(self) -> None:
        for path, name in (
            (Path("/ws/updater.key"), "updater.key"),
            (Path("/ws/cfw-rs-v2.key"), "cfw-rs-v2.key"),
            (Path("/ws/.tauri/custom.pem"), "custom.pem"),
        ):
            with self.subTest(path=path):
                self.assertIs(
                    classify_secret_material(path, name),
                    SecretMaterialKind.UPDATER_SIGNING_KEY,
                )

    def test_isolated_unknown_requires_identification_and_relocation(self) -> None:
        detected = DetectedSecretMaterial(
            path="/ws/private.pem",
            name="private.pem",
            kind=SecretMaterialKind.UNKNOWN_PRIVATE_KEY,
        )
        response = build_security_response(detected, "/ws")
        self.assertIs(
            response.required_trust_action,
            RequiredTrustAction.IDENTIFY_DOMAIN_AND_RELOCATE,
        )
        self.assertTrue(response.trust_domain_identification_required)
        self.assertFalse(response.rotation_required)
        self.assertFalse(response.updater_trust_migration_required)
        self.assertIn("updater trust migration: not required", format_response(response))


class ReportContentTests(unittest.TestCase):
    def test_response_reports_only_path_and_name(self) -> None:
        detected = DetectedSecretMaterial(
            path="/ws/.tauri/cfw-rs.key",
            name="cfw-rs.key",
            kind=SecretMaterialKind.UPDATER_SIGNING_KEY,
        )
        response = build_security_response(detected, "/ws")

        field_names = {f.name for f in dataclasses.fields(SecurityResponse)}
        # The only file-identity fields are the path and the name.
        self.assertEqual(
            field_names & {"detected_path", "detected_name"},
            {"detected_path", "detected_name"},
        )
        self.assertNotIn("contents", field_names)
        self.assertNotIn("bytes", field_names)

        rendered = format_response(response)
        self.assertIn("/ws/.tauri/cfw-rs.key", rendered)
        self.assertIn("cfw-rs.key", rendered)
        self.assertIn("contents never read", rendered)


class AtomicResponseTests(unittest.TestCase):
    def test_complete_response_passes_and_blocks(self) -> None:
        detected = DetectedSecretMaterial(
            path="/ws/backup/x.key",
            name="x.key",
            kind=SecretMaterialKind.UNKNOWN_PRIVATE_KEY,
        )
        response = build_security_response(detected, "/ws")
        # Should not raise.
        assert_response_complete(response)
        self.assertTrue(response.block_release)
        self.assertTrue(response.relocation_required)

    def test_omitting_the_block_step_fails_closed(self) -> None:
        response = dataclasses.replace(
            build_security_response(
                DetectedSecretMaterial(
                    path="/ws/backup/x.key",
                    name="x.key",
                    kind=SecretMaterialKind.UNKNOWN_PRIVATE_KEY,
                ),
                "/ws",
            ),
            block_release=False,
        )
        with self.assertRaises(SecretMaterialReleaseBlock):
            assert_response_complete(response)

    def test_omitting_the_relocation_step_fails_closed(self) -> None:
        response = dataclasses.replace(
            build_security_response(
                DetectedSecretMaterial(
                    path="/ws/backup/x.key",
                    name="x.key",
                    kind=SecretMaterialKind.UNKNOWN_PRIVATE_KEY,
                ),
                "/ws",
            ),
            relocation_required=False,
            relocation_target="",
        )
        with self.assertRaises(SecretMaterialReleaseBlock):
            assert_response_complete(response)

    def test_rotation_without_trust_migration_fails_closed(self) -> None:
        response = dataclasses.replace(
            build_security_response(
                DetectedSecretMaterial(
                    path="/ws/backups/updater.key",
                    name="updater.key",
                    kind=SecretMaterialKind.UPDATER_SIGNING_KEY,
                ),
                "/ws",
            ),
            updater_trust_migration_required=False,
        )
        with self.assertRaises(SecretMaterialReleaseBlock):
            assert_response_complete(response)

    def test_spoofed_updater_action_for_apple_key_fails_closed(self) -> None:
        valid = build_security_response(
            DetectedSecretMaterial(
                path="/ws/backups/AuthKey_DYHRNJ2Z4M.p8",
                name="AuthKey_DYHRNJ2Z4M.p8",
                kind=SecretMaterialKind.APPLE_ASC_NOTARY_KEY,
            ),
            "/ws",
        )
        spoofed = dataclasses.replace(
            valid,
            required_trust_action=(
                RequiredTrustAction.ROTATE_UPDATER_AND_MIGRATE_TRUST
            ),
            updater_trust_migration_required=True,
            notary_profile_reprovision_required=False,
        )
        with self.assertRaises(SecretMaterialReleaseBlock):
            assert_response_complete(spoofed)


class ExposurePlausibilityTests(unittest.TestCase):
    def test_public_counterpart_makes_exposure_plausible(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            key = Path(root) / "cfw-rs.key"
            key.write_text("PRIVATE", encoding="utf-8")
            (Path(root) / "cfw-rs.key.pub").write_text("PUBLIC", encoding="utf-8")

            detected = DetectedSecretMaterial(
                path=str(key),
                name="cfw-rs.key",
                kind=SecretMaterialKind.UPDATER_SIGNING_KEY,
            )
            self.assertTrue(exposure_is_plausible(detected, root))
            response = build_security_response(detected, root)
            self.assertTrue(response.rotation_required)
            self.assertTrue(response.updater_trust_migration_required)

    def test_backup_path_marker_makes_exposure_plausible(self) -> None:
        detected = DetectedSecretMaterial(
            path="/ws/backups/cfw-rs.key",
            name="cfw-rs.key",
            kind=SecretMaterialKind.UPDATER_SIGNING_KEY,
        )
        self.assertTrue(exposure_is_plausible(detected, "/ws"))

    def test_git_repository_makes_exposure_plausible(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / ".git").mkdir()
            key = Path(root) / "cfw-rs.key"
            key.write_text("PRIVATE", encoding="utf-8")
            detected = DetectedSecretMaterial(
                path=str(key),
                name="cfw-rs.key",
                kind=SecretMaterialKind.UPDATER_SIGNING_KEY,
            )
            self.assertTrue(exposure_is_plausible(detected, root))

    def test_isolated_key_has_no_plausible_exposure(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            key = Path(root) / "cfw-rs.key"
            key.write_text("PRIVATE", encoding="utf-8")
            detected = DetectedSecretMaterial(
                path=str(key),
                name="cfw-rs.key",
                kind=SecretMaterialKind.UPDATER_SIGNING_KEY,
            )
            self.assertFalse(exposure_is_plausible(detected, root))
            response = build_security_response(detected, root)
            # Rotation is conditional; relocation and blocking are not.
            self.assertFalse(response.rotation_required)
            self.assertFalse(response.updater_trust_migration_required)
            self.assertTrue(response.block_release)
            self.assertTrue(response.relocation_required)
            assert_response_complete(response)


class FailClosedInputTests(unittest.TestCase):
    def test_missing_workspace_root_fails_closed(self) -> None:
        with self.assertRaises(SecretMaterialReleaseBlock):
            scan_workspace("/nonexistent/workspace/root/for/blocker/test")

    def test_symlinked_workspace_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            real = Path(parent) / "real"
            real.mkdir()
            link = Path(parent) / "link"
            link.symlink_to(real, target_is_directory=True)
            with self.assertRaises(SecretMaterialReleaseBlock):
                scan_workspace(link)

    def test_file_as_workspace_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            not_a_dir = Path(parent) / "file.txt"
            not_a_dir.write_text("x", encoding="utf-8")
            with self.assertRaises(SecretMaterialReleaseBlock):
                scan_workspace(not_a_dir)

    def test_symlinked_generated_release_subtree_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            (root / "target").mkdir()
            elsewhere = Path(parent).parent / f"{root.name}-external"
            elsewhere.mkdir()
            try:
                (elsewhere / "hidden.key").write_text("PRIVATE", encoding="utf-8")
                (root / "target/candidates").symlink_to(
                    elsewhere, target_is_directory=True
                )
                with self.assertRaisesRegex(
                    SecretMaterialReleaseBlock, "directory symlink escapes"
                ):
                    scan_workspace(root)
            finally:
                (elsewhere / "hidden.key").unlink(missing_ok=True)
                elsewhere.rmdir()

    def test_symlinked_managed_target_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            (root / "target").mkdir()
            elsewhere = root / "elsewhere"
            elsewhere.mkdir()
            (root / "target/toolchains").symlink_to(
                elsewhere, target_is_directory=True
            )
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock, "managed target root is not a trustworthy"
            ):
                scan_workspace(root)

    def test_symlinked_release_worktree_managed_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_release_worktree(root)
            nested_target = worktree / "target"
            elsewhere = root / "elsewhere"
            elsewhere.mkdir()
            (nested_target / "toolchains").symlink_to(
                elsewhere, target_is_directory=True
            )
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock, "managed target root is not a trustworthy"
            ):
                scan_workspace(root)

    def test_regular_file_at_a_managed_target_root_fails_closed(self) -> None:
        for target in ("target", "target/release-worktrees/40028/target"):
            with self.subTest(target=target), tempfile.TemporaryDirectory() as root:
                directory = Path(root) / target
                directory.mkdir(parents=True)
                (directory / "toolchains").write_text(
                    "not a directory", encoding="utf-8"
                )
                with self.assertRaisesRegex(
                    SecretMaterialReleaseBlock,
                    "managed target root is not a trustworthy",
                ):
                    scan_workspace(root)

    def test_release_worktree_managed_root_with_wrong_owner_is_rejected(self) -> None:
        # Either the managed root changes owner while it is read, or it is
        # stably owned by someone other than the workspace owner.
        for foreign in ("managed-root", "workspace-root"):
            with self.subTest(foreign=foreign), tempfile.TemporaryDirectory() as parent:
                root = Path(parent)
                worktree = _create_release_worktree(root)
                managed = worktree / "target/toolchains"
                managed.mkdir()
                foreign_path = managed if foreign == "managed-root" else root
                real_path_stat = Path.stat

                def foreign_owned_stat(path: Path, *args, **kwargs):
                    metadata = real_path_stat(path, *args, **kwargs)
                    if path == foreign_path:
                        fields = list(metadata)
                        fields[4] = metadata.st_uid + 1
                        return os.stat_result(fields)
                    return metadata

                with mock.patch.object(
                    Path, "stat", autospec=True, side_effect=foreign_owned_stat
                ):
                    with self.assertRaisesRegex(
                        SecretMaterialReleaseBlock,
                        "managed target root changed or has an unsafe owner",
                    ):
                        scan_workspace(root)

    def test_alias_to_release_worktree_managed_cache_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_release_worktree(root)
            managed_file = (
                worktree / "target/toolchains/cache/safe.txt"
            )
            managed_file.parent.mkdir(parents=True)
            managed_file.write_text("managed toolchain", encoding="utf-8")
            (root / "cache-alias.txt").symlink_to(managed_file)
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock, "excluded tree only through an alias"
            ):
                scan_workspace(root)

    def test_case_variant_alias_into_a_managed_cache_is_still_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_release_worktree(root)
            managed_file = worktree / "target/toolchains/cache/safe.txt"
            managed_file.parent.mkdir(parents=True)
            managed_file.write_text("managed toolchain", encoding="utf-8")
            relative = managed_file.relative_to(root).as_posix()
            variant = relative.replace("/target/toolchains/", "/Target/Toolchains/")
            self.assertNotEqual(variant, relative)
            self.assertTrue((root / variant).exists(), "fixture needs a case-insensitive volume")
            (root / "cache-alias.txt").symlink_to(root / variant)
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock, "not reachable by a scanned real path"
            ):
                scan_workspace(root)

    def test_directory_alias_into_a_managed_cache_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_release_worktree(root)
            for managed in (root / "target/toolchains/cache", worktree / "target/toolchains/cache"):
                managed.mkdir(parents=True, exist_ok=True)
            for alias, managed in (
                ("primary-alias", root / "target/toolchains/cache"),
                ("nested-alias", worktree / "target/toolchains/cache"),
            ):
                with self.subTest(alias=alias):
                    link = root / alias
                    link.symlink_to(managed, target_is_directory=True)
                    try:
                        with self.assertRaisesRegex(
                            SecretMaterialReleaseBlock,
                            "directory symlink reaches an excluded tree only through an alias",
                        ):
                            scan_workspace(root)
                    finally:
                        link.unlink()

    def test_symlinked_release_path_components_never_hide_their_targets(self) -> None:
        cases = (
            ("target/release-worktrees", "../elsewhere", "elsewhere/40028/target/toolchains"),
            ("target/release-worktrees/40028/target", "../../../elsewhere", "elsewhere/toolchains"),
        )
        for link_relative, link_text, hidden_relative in cases:
            with self.subTest(link=link_relative), tempfile.TemporaryDirectory() as parent:
                root = Path(parent)
                hidden = root / hidden_relative
                hidden.mkdir(parents=True)
                (hidden / "hidden.key").write_text("PRIVATE", encoding="utf-8")
                link = root / link_relative
                link.parent.mkdir(parents=True, exist_ok=True)
                link.symlink_to(link_text, target_is_directory=True)
                self.assertEqual(
                    [item.name for item in scan_workspace(root)], ["hidden.key"]
                )

    def test_relative_workspace_root_prunes_the_same_managed_caches(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_release_worktree(root)
            for managed in (root / "target/toolchains", worktree / "target/toolchains"):
                managed.mkdir(parents=True, exist_ok=True)
                (managed / "cache.pem").write_text("UPSTREAM FIXTURE", encoding="utf-8")
            candidates = worktree / "target/candidates"
            candidates.mkdir(parents=True)
            (candidates / "candidate.key").write_text("PRIVATE", encoding="utf-8")
            with contextlib.chdir(root):
                detected = scan_workspace(".")
            self.assertEqual([item.name for item in detected], ["candidate.key"])

    def test_scan_of_a_release_worktree_never_opens_a_file(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_release_worktree(root)
            managed = worktree / "target/toolchains"
            managed.mkdir()
            (managed / "cache.pem").write_text("UPSTREAM FIXTURE", encoding="utf-8")
            candidate = root / "target/candidates/private.key"
            candidate.parent.mkdir(parents=True)
            candidate.write_text("PRIVATE", encoding="utf-8")
            # Unreadable fixtures make any read path fail, including ones the
            # open mocks below cannot intercept (pathlib reads use io.open).
            for fixture in (managed / "cache.pem", candidate):
                fixture.chmod(0)

            def reject_open(path, *args, **kwargs):
                raise AssertionError(
                    f"scanner attempted to open a file: {os.fsdecode(path)}"
                )

            with mock.patch.object(
                secret_blocker.os, "open", side_effect=reject_open
            ), _NoFileReads():
                detected = scan_workspace(root)
            self.assertEqual([item.name for item in detected], ["private.key"])

    def test_non_key_symlink_to_regular_file_does_not_hide_path_names(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            source = root / "safe.txt"
            source.write_text("not inspected", encoding="utf-8")
            (root / "alias.txt").symlink_to(source)
            self.assertEqual(scan_workspace(root), [])

            key = root / "real-updater.pem"
            key.write_text("PRIVATE", encoding="utf-8")
            (root / "innocent.dat").symlink_to(key)
            self.assertEqual(
                [item.name for item in scan_workspace(root)],
                ["real-updater.pem"],
            )

    def test_non_key_file_symlink_to_external_key_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent) / "workspace"
            root.mkdir()
            outside = Path(parent) / "outside.key"
            outside.write_text("PRIVATE", encoding="utf-8")
            (root / "innocent.dat").symlink_to(outside)
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock, "file symlink escapes"
            ):
                scan_workspace(root)

    def test_internal_framework_directory_symlink_is_safe_and_target_is_scanned(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            versions = (
                root
                / "target/candidates/0.4.0/signed/Fixture.framework/Versions"
            )
            real_version = versions / "A"
            real_version.mkdir(parents=True)
            (versions / "Current").symlink_to("A", target_is_directory=True)
            self.assertEqual(scan_workspace(root), [])
            (real_version / "embedded.pem").write_text("PRIVATE", encoding="utf-8")
            self.assertEqual(
                [item.name for item in scan_workspace(root)], ["embedded.pem"]
            )

    def test_directory_symlink_cycle_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            first = root / "first"
            second = root / "second"
            first.mkdir()
            second.mkdir()
            (first / "to-second").symlink_to(second, target_is_directory=True)
            (second / "to-first").symlink_to(first, target_is_directory=True)
            with self.assertRaisesRegex(SecretMaterialReleaseBlock, "traversal cycle"):
                scan_workspace(root)


class RealRepositoryTests(unittest.TestCase):
    def test_real_repo_updater_key_state_is_explicit_without_reading_it(self) -> None:
        tauri_key = REPO_ROOT / ".tauri" / "cfw-rs.key"
        with _NoFileReads():
            responses = evaluate_workspace(REPO_ROOT)

        paths = {response.detected_path for response in responses}
        if not tauri_key.exists():
            self.assertNotIn(str(tauri_key), paths)
            self.assertEqual(responses, [], "any other workspace updater key must block release")
            return

        self.assertIn(str(tauri_key), paths)

        blocker_response = next(
            r for r in responses if r.detected_path == str(tauri_key)
        )
        self.assertTrue(blocker_response.block_release)
        self.assertTrue(blocker_response.relocation_required)
        # The repository is a git tree with a distributed .pub counterpart, so
        # rotation and updater trust migration are both required.
        self.assertTrue(blocker_response.exposure_plausible)
        self.assertTrue(blocker_response.rotation_required)
        self.assertTrue(blocker_response.updater_trust_migration_required)
        # A populated response list means release is blocked.
        self.assertTrue(responses)


if __name__ == "__main__":
    unittest.main()
