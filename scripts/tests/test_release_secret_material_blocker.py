from __future__ import annotations

import builtins
import dataclasses
import os
import shutil
import subprocess
import sys
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


def _create_registered_release_worktree(
    repository: Path,
    build: str = "40026",
    *,
    authorize_cache_scope: bool = True,
) -> Path:
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
    if authorize_cache_scope:
        secret_blocker.authorize_release_worktree_cache_scope(repository, build)
    return worktree


def _worktree_admin_directory(worktree: Path) -> Path:
    marker = (worktree / ".git").read_bytes()
    prefix = b"gitdir: "
    if not marker.startswith(prefix) or not marker.endswith(b"\n"):
        raise AssertionError("test worktree marker is malformed")
    return Path(os.fsdecode(marker[len(prefix) : -1]))


def _expected_scope_receipt_data(repository: Path, build: str) -> bytes:
    registered = secret_blocker._registered_release_worktree_targets(
        repository.resolve(), require_scope_receipt=False
    )[build]
    receipt = secret_blocker._scope_receipt(
        build=build,
        worktree_path=registered.path,
        head=registered.head,
        admin=registered.admin,
        worktree=registered.worktree,
        marker=registered.marker,
        target=registered.target,
    )
    return secret_blocker.canonical_scope_receipt_bytes(receipt)


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
            worktree = _create_registered_release_worktree(Path(root))
            managed = worktree / "target/toolchains/node-24.18.0"
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

    def test_unregistered_numeric_release_worktree_does_not_gain_pruning(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as root:
            worktree = Path(root) / "target/release-worktrees/40026"
            cache = worktree / "target/toolchains"
            cache.mkdir(parents=True)
            (worktree / ".git").write_text("self-authored marker", encoding="utf-8")
            (cache / "self-authored.manifest.json").write_text(
                "{}", encoding="utf-8"
            )
            (cache / "must-remain-visible.key").write_text(
                "PRIVATE", encoding="utf-8"
            )
            self.assertEqual(
                [item.name for item in scan_workspace(root)],
                ["must-remain-visible.key"],
            )

    def test_non_numeric_release_worktree_does_not_gain_managed_pruning(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            cache = (
                Path(root)
                / "target/release-worktrees/not-a-build/target/toolchains"
            )
            cache.mkdir(parents=True)
            (cache / "must-remain-visible.key").write_text(
                "PRIVATE", encoding="utf-8"
            )
            self.assertEqual(
                [item.name for item in scan_workspace(root)],
                ["must-remain-visible.key"],
            )

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
    def test_fifo_control_file_is_rejected_without_blocking(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            os.mkfifo(root / "gitdir")
            program = """
import os
import sys
from scripts.release_secret_material_blocker import (
    SecretMaterialReleaseBlock,
    _read_git_control_file,
)

directory_fd = os.open(
    sys.argv[1],
    os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
)
try:
    try:
        _read_git_control_file(directory_fd, "gitdir", expected_owner=os.getuid())
    except SecretMaterialReleaseBlock:
        raise SystemExit(0)
    raise SystemExit(2)
finally:
    os.close(directory_fd)
"""
            completed = subprocess.run(
                [sys.executable, "-B", "-c", program, str(root)],
                cwd=REPO_ROOT,
                check=False,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=2,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr.decode())

    def test_directory_descriptor_is_closed_when_fstat_fails(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            descriptor = os.open(
                parent,
                os.O_RDONLY | os.O_CLOEXEC | os.O_DIRECTORY | os.O_NOFOLLOW,
            )
            with mock.patch.object(
                secret_blocker.os, "open", return_value=descriptor
            ), mock.patch.object(
                secret_blocker.os,
                "fstat",
                side_effect=OSError("injected fstat failure"),
            ):
                with self.assertRaisesRegex(
                    SecretMaterialReleaseBlock,
                    "identity could not be inspected",
                ):
                    secret_blocker._open_verified_directory(
                        parent,
                        expected_owner=os.getuid(),
                        label="fixture directory",
                    )
            with self.assertRaises(OSError):
                os.fstat(descriptor)

    def test_control_descriptor_is_closed_and_error_is_typed_on_io_fault(
        self,
    ) -> None:
        for operation in ("fstat", "read"):
            with self.subTest(operation=operation), tempfile.TemporaryDirectory() as parent:
                root = Path(parent)
                (root / "gitdir").write_text("fixture\n", encoding="utf-8")
                directory_fd = os.open(
                    root,
                    os.O_RDONLY
                    | os.O_CLOEXEC
                    | os.O_DIRECTORY
                    | os.O_NOFOLLOW,
                )
                opened: list[int] = []
                system_open = os.open

                def capture_open(path, flags, *args, **kwargs):
                    descriptor = system_open(path, flags, *args, **kwargs)
                    opened.append(descriptor)
                    return descriptor

                try:
                    with mock.patch.object(
                        secret_blocker.os, "open", side_effect=capture_open
                    ), mock.patch.object(
                        secret_blocker.os,
                        operation,
                        side_effect=OSError(f"injected {operation} failure"),
                    ):
                        with self.assertRaisesRegex(
                            SecretMaterialReleaseBlock,
                            "control file could not be read safely",
                        ):
                            secret_blocker._read_git_control_file(
                                directory_fd,
                                "gitdir",
                                expected_owner=os.getuid(),
                            )
                    self.assertEqual(len(opened), 1)
                    with self.assertRaises(OSError):
                        os.fstat(opened[0])
                finally:
                    os.close(directory_fd)

    def test_scope_lock_fstat_fault_closes_the_lock_once(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            _create_registered_release_worktree(
                root, authorize_cache_scope=False
            )
            registered = secret_blocker._registered_release_worktree_targets(
                root.resolve(), require_scope_receipt=False
            )["40026"]
            system_open = os.open
            system_fstat = os.fstat
            system_close = os.close
            lock_descriptors: list[int] = []
            lock_close_count = 0

            def capture_lock_open(path, flags, *args, **kwargs):
                descriptor = system_open(path, flags, *args, **kwargs)
                if path == secret_blocker.RELEASE_WORKTREE_CACHE_SCOPE_LOCK:
                    lock_descriptors.append(descriptor)
                return descriptor

            def fail_lock_fstat(descriptor):
                if descriptor in lock_descriptors:
                    raise OSError("injected lock fstat failure")
                return system_fstat(descriptor)

            def count_lock_close(descriptor):
                nonlocal lock_close_count
                if descriptor in lock_descriptors:
                    lock_close_count += 1
                return system_close(descriptor)

            with mock.patch.object(
                secret_blocker.os, "open", side_effect=capture_lock_open
            ), mock.patch.object(
                secret_blocker.os, "fstat", side_effect=fail_lock_fstat
            ), mock.patch.object(
                secret_blocker.os, "close", side_effect=count_lock_close
            ):
                with self.assertRaisesRegex(
                    SecretMaterialReleaseBlock,
                    "cache-scope lock is unavailable",
                ):
                    secret_blocker._publish_scope_receipt(registered)
            self.assertEqual(len(lock_descriptors), 1)
            self.assertEqual(lock_close_count, 1)
            with self.assertRaises(OSError):
                os.fstat(lock_descriptors[0])

    def test_scope_unlock_fault_still_closes_lock_and_admin(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            _create_registered_release_worktree(
                root, authorize_cache_scope=False
            )
            registered = secret_blocker._registered_release_worktree_targets(
                root.resolve(), require_scope_receipt=False
            )["40026"]
            system_open = os.open
            system_flock = secret_blocker.fcntl.flock
            observed: dict[str, int] = {}

            def capture_open(path, flags, *args, **kwargs):
                descriptor = system_open(path, flags, *args, **kwargs)
                if path == registered.admin_path:
                    observed["admin"] = descriptor
                elif path == secret_blocker.RELEASE_WORKTREE_CACHE_SCOPE_LOCK:
                    observed["lock"] = descriptor
                return descriptor

            def fail_unlock(descriptor, operation):
                if operation == secret_blocker.fcntl.LOCK_UN:
                    raise OSError("injected unlock failure")
                return system_flock(descriptor, operation)

            with mock.patch.object(
                secret_blocker.os, "open", side_effect=capture_open
            ), mock.patch.object(
                secret_blocker.fcntl, "flock", side_effect=fail_unlock
            ):
                with self.assertRaisesRegex(
                    SecretMaterialReleaseBlock,
                    "enrollment cleanup failed",
                ):
                    secret_blocker._publish_scope_receipt(registered)
            self.assertEqual(set(observed), {"admin", "lock"})
            for descriptor in observed.values():
                with self.assertRaises(OSError):
                    os.fstat(descriptor)

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
            worktree = _create_registered_release_worktree(root)
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

    def test_release_worktree_managed_root_with_wrong_owner_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(root)
            managed = worktree / "target/toolchains"
            managed.mkdir()
            real_path_stat = Path.stat

            def foreign_owned_stat(path: Path, *args, **kwargs):
                metadata = real_path_stat(path, *args, **kwargs)
                if path == managed:
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
            worktree = _create_registered_release_worktree(root)
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

    def test_registered_worktree_git_marker_hardlink_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(root)
            marker = worktree / ".git"
            retained = worktree / ".git-retained"
            marker.rename(retained)
            os.link(retained, marker)
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock,
                "control file has unsafe metadata: .git",
            ):
                scan_workspace(root)

    def test_registered_marker_rebind_after_discovery_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(root)
            managed = worktree / "target/toolchains"
            managed.mkdir()
            original_discovery = (
                secret_blocker._registered_release_worktree_targets
            )

            def discover_then_rebind(canonical_root: Path):
                discovered = original_discovery(canonical_root)
                marker = worktree / ".git"
                marker.rename(worktree / ".git-before-rebind")
                marker.write_text("replacement marker", encoding="utf-8")
                return discovered

            with mock.patch.object(
                secret_blocker,
                "_registered_release_worktree_targets",
                side_effect=discover_then_rebind,
            ):
                with self.assertRaisesRegex(
                    SecretMaterialReleaseBlock,
                    "identity changed during the scan",
                ):
                    scan_workspace(root)

    def test_registered_marker_same_inode_overwrite_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(root)
            managed = worktree / "target/toolchains"
            managed.mkdir()
            original_discovery = (
                secret_blocker._registered_release_worktree_targets
            )

            def discover_then_overwrite(canonical_root: Path):
                discovered = original_discovery(canonical_root)
                marker = worktree / ".git"
                marker.write_bytes(b"x" * marker.stat().st_size)
                return discovered

            with mock.patch.object(
                secret_blocker,
                "_registered_release_worktree_targets",
                side_effect=discover_then_overwrite,
            ):
                with self.assertRaisesRegex(
                    SecretMaterialReleaseBlock,
                    "identity changed during the scan",
                ):
                    scan_workspace(root)

    def test_stale_admin_without_scope_receipt_cannot_be_replayed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(
                root, build="40007", authorize_cache_scope=False
            )
            marker_data = (worktree / ".git").read_bytes()
            shutil.rmtree(worktree)
            cache = worktree / "target/toolchains"
            cache.mkdir(parents=True)
            (worktree / ".git").write_bytes(marker_data)
            (cache / "stale-replay.key").write_text(
                "PRIVATE", encoding="utf-8"
            )
            self.assertEqual(
                [item.name for item in scan_workspace(root)],
                ["stale-replay.key"],
            )

    def test_stale_admin_with_old_scope_receipt_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(root, build="40007")
            marker_data = (worktree / ".git").read_bytes()
            shutil.rmtree(worktree)
            cache = worktree / "target/toolchains"
            cache.mkdir(parents=True)
            (worktree / ".git").write_bytes(marker_data)
            (cache / "stale-replay.key").write_text(
                "PRIVATE", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock,
                "cache-scope receipt identity is stale",
            ):
                scan_workspace(root)

    def test_scope_enrollment_requires_empty_new_target(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(
                root, authorize_cache_scope=False
            )
            (worktree / "target/cache.txt").write_text(
                "existing output", encoding="utf-8"
            )
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock,
                "target must be empty before cache-scope enrollment",
            ):
                secret_blocker.authorize_release_worktree_cache_scope(
                    root, "40026"
                )

    def test_scope_enrollment_recovers_complete_pending_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(
                root, authorize_cache_scope=False
            )
            admin = _worktree_admin_directory(worktree)
            pending = admin / secret_blocker.RELEASE_WORKTREE_CACHE_SCOPE_PENDING
            pending.write_bytes(_expected_scope_receipt_data(root, "40026"))
            pending.chmod(0o600)
            receipt = secret_blocker.authorize_release_worktree_cache_scope(
                root, "40026"
            )
            self.assertTrue(receipt.is_file())
            self.assertFalse(pending.exists())
            self.assertEqual(receipt.stat().st_nlink, 1)

    def test_scope_enrollment_reproves_pending_after_initial_fsync_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(
                root, authorize_cache_scope=False
            )
            admin = _worktree_admin_directory(worktree)
            pending = admin / secret_blocker.RELEASE_WORKTREE_CACHE_SCOPE_PENDING
            final = admin / secret_blocker.RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT
            system_fsync = os.fsync
            calls = 0

            def fail_first_fsync(descriptor):
                nonlocal calls
                calls += 1
                if calls == 1:
                    raise OSError("injected first fsync failure")
                return system_fsync(descriptor)

            with mock.patch.object(
                secret_blocker.os, "fsync", side_effect=fail_first_fsync
            ):
                with self.assertRaisesRegex(
                    SecretMaterialReleaseBlock,
                    "pending file could not be committed",
                ):
                    secret_blocker.authorize_release_worktree_cache_scope(
                        root, "40026"
                    )
            self.assertTrue(pending.is_file())
            self.assertFalse(final.exists())
            receipt = secret_blocker.authorize_release_worktree_cache_scope(
                root, "40026"
            )
            self.assertEqual(receipt, final)
            self.assertFalse(pending.exists())
            self.assertEqual(final.stat().st_nlink, 1)

    def test_scope_enrollment_recovers_linked_publish_receipt(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(
                root, authorize_cache_scope=False
            )
            admin = _worktree_admin_directory(worktree)
            pending = admin / secret_blocker.RELEASE_WORKTREE_CACHE_SCOPE_PENDING
            final = admin / secret_blocker.RELEASE_WORKTREE_CACHE_SCOPE_RECEIPT
            pending.write_bytes(_expected_scope_receipt_data(root, "40026"))
            pending.chmod(0o600)
            os.link(pending, final)
            self.assertEqual(final.stat().st_nlink, 2)
            receipt = secret_blocker.authorize_release_worktree_cache_scope(
                root, "40026"
            )
            self.assertEqual(receipt, final)
            self.assertFalse(pending.exists())
            self.assertEqual(final.stat().st_nlink, 1)

    def test_existing_receipt_is_idempotent_after_cache_materialization(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(root)
            (worktree / "target/manifest-bound-cache.txt").write_text(
                "fixture", encoding="utf-8"
            )
            receipt = secret_blocker.authorize_release_worktree_cache_scope(
                root, "40026"
            )
            self.assertTrue(receipt.is_file())
            self.assertEqual(scan_workspace(root), [])

    def test_malformed_or_duplicate_git_admin_controls_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(root)
            admin = _worktree_admin_directory(worktree)
            (admin / "commondir").write_bytes(b"../../..\n")
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock, "commondir control is malformed"
            ):
                scan_workspace(root)

        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(root)
            admin = _worktree_admin_directory(worktree)
            duplicate = admin.parent / "zz-duplicate"
            shutil.copytree(admin, duplicate)
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock,
                "registered release worktree build is duplicated",
            ):
                scan_workspace(root)

    def test_symlinked_and_oversize_git_controls_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(root)
            admin = _worktree_admin_directory(worktree)
            commondir = admin / "commondir"
            retained = admin / "commondir-retained"
            commondir.rename(retained)
            commondir.symlink_to(retained)
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock,
                "control file is unavailable: commondir",
            ):
                scan_workspace(root)

    def test_group_writable_git_control_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(root)
            admin = _worktree_admin_directory(worktree)
            (admin / "HEAD").chmod(0o664)
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock,
                "control file has unsafe metadata: HEAD",
            ):
                scan_workspace(root)

        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(root)
            admin = _worktree_admin_directory(worktree)
            (admin / "gitdir").write_bytes(
                b"x" * (secret_blocker.MAXIMUM_GIT_CONTROL_FILE_BYTES + 1)
            )
            with self.assertRaisesRegex(
                SecretMaterialReleaseBlock,
                "control file has unsafe metadata: gitdir",
            ):
                scan_workspace(root)

    def test_caller_git_environment_is_irrelevant_to_descriptor_registry(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(root)
            managed = worktree / "target/toolchains"
            managed.mkdir()
            (managed / "cache.pem").write_text("UPSTREAM FIXTURE", encoding="utf-8")
            with mock.patch.dict(
                os.environ,
                {
                    "GIT_DIR": str(root / "attacker-git-dir"),
                    "GIT_WORK_TREE": str(root / "attacker-work-tree"),
                    "GIT_CONFIG_GLOBAL": str(root / "attacker-config"),
                },
                clear=False,
            ):
                self.assertEqual(scan_workspace(root), [])

    def test_registry_authentication_never_opens_config_cache_or_candidate_files(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            worktree = _create_registered_release_worktree(root)
            managed = worktree / "target/toolchains"
            managed.mkdir()
            (managed / "cache.pem").write_text("UPSTREAM FIXTURE", encoding="utf-8")
            candidate = root / "target/candidates/private.key"
            candidate.parent.mkdir(parents=True)
            candidate.write_text("PRIVATE", encoding="utf-8")
            (root / ".git/config").write_text(
                f"[include]\n\tpath = {candidate}\n", encoding="utf-8"
            )

            system_open = os.open

            def reject_non_control_open(path, flags, *args, **kwargs):
                rendered = os.fsdecode(path)
                if rendered.endswith("config") or "candidates" in rendered:
                    raise AssertionError(
                        f"scanner attempted to open non-control path: {rendered}"
                    )
                if "toolchains" in rendered:
                    raise AssertionError(
                        f"scanner attempted to open managed cache: {rendered}"
                    )
                return system_open(path, flags, *args, **kwargs)

            with mock.patch.object(
                secret_blocker.os, "open", side_effect=reject_non_control_open
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
