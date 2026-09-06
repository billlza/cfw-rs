from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from scripts import release_rust_toolchain
from scripts.release_rust_toolchain import (
    EXPECTED_COMPONENTS,
    ReleaseRustToolchainError,
    build_toolchain_surface,
    validate_recorded_surface,
    verify_pinned_toolchain,
)


CHANNEL = "1.97.1"


class RustToolchainFixture:
    def __init__(self, base: Path) -> None:
        self.repository = base / "repository"
        self.root = base / f"{CHANNEL}-aarch64-apple-darwin"
        (self.repository / "scripts").mkdir(parents=True)
        (self.root / "bin").mkdir(parents=True)
        rustlib = self.root / "lib/rustlib"
        rustlib.mkdir(parents=True)
        payloads = {
            EXPECTED_COMPONENTS[0]: "bin/cargo",
            EXPECTED_COMPONENTS[1]: "bin/clippy-driver",
            EXPECTED_COMPONENTS[2]: "bin/rust-std-fixture",
            EXPECTED_COMPONENTS[3]: "bin/rustc",
            EXPECTED_COMPONENTS[4]: "bin/rustfmt",
        }
        for component, relative in payloads.items():
            payload = self.root / relative
            payload.write_bytes((component + "\n").encode("utf-8"))
            payload.chmod(0o755 if relative in {"bin/cargo", "bin/rustc"} else 0o644)
            (rustlib / f"manifest-{component}").write_text(
                f"file:{relative}\n", encoding="utf-8"
            )
        (rustlib / "components").write_text(
            "\n".join(EXPECTED_COMPONENTS) + "\n", encoding="utf-8"
        )
        for name in (
            "multirust-channel-manifest.toml",
            "multirust-config.toml",
            "rust-installer-version",
        ):
            (rustlib / name).write_text(f"fixture-{name}\n", encoding="utf-8")
        self.surface = build_toolchain_surface(self.root)
        self.write_repository_contract(self.surface["sha256"])

    def write_repository_contract(self, digest: str) -> None:
        (self.repository / "rust-toolchain.toml").write_text(
            "[toolchain]\n"
            f'channel = "{CHANNEL}"\n'
            'components = ["rustfmt", "clippy"]\n'
            'profile = "minimal"\n',
            encoding="utf-8",
        )
        (self.repository / "scripts/dependency_pins.env").write_text(
            f"RUST_VERSION={CHANNEL}\n"
            f"RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256={digest}\n",
            encoding="utf-8",
        )
        (self.repository / "scripts/pinned_build_inputs.json").write_text(
            json.dumps(
                {
                    "tools": {
                        "RUST_VERSION": CHANNEL,
                        "RUST_RELEASE_TOOLCHAIN_BUILD_SURFACE_SHA256": digest,
                    }
                }
            ),
            encoding="utf-8",
        )


class ReleaseRustToolchainTests(unittest.TestCase):
    def fixture(self) -> tuple[tempfile.TemporaryDirectory[str], RustToolchainFixture]:
        temporary = tempfile.TemporaryDirectory()
        return temporary, RustToolchainFixture(Path(temporary.name).resolve())

    def test_exact_surface_and_repository_pin_are_accepted(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        verified = verify_pinned_toolchain(fixture.repository, fixture.root)
        self.assertEqual(verified.channel, CHANNEL)
        self.assertEqual(verified.surface, fixture.surface)
        self.assertEqual(verified.cargo, fixture.root / "bin/cargo")
        self.assertEqual(verified.rustc, fixture.root / "bin/rustc")

    def test_extra_file_and_directory_are_rejected(self) -> None:
        for relative in ("extra-file", "extra-directory/member"):
            with self.subTest(relative=relative):
                temporary, fixture = self.fixture()
                self.addCleanup(temporary.cleanup)
                path = fixture.root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("unexpected\n", encoding="utf-8")
                with self.assertRaisesRegex(
                    ReleaseRustToolchainError, "differs from its component manifests"
                ):
                    build_toolchain_surface(fixture.root)

    def test_symlink_special_file_and_hardlink_are_rejected(self) -> None:
        mutations = ("symlink", "fifo", "hardlink")
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                temporary, fixture = self.fixture()
                self.addCleanup(temporary.cleanup)
                target = fixture.root / f"unexpected-{mutation}"
                if mutation == "symlink":
                    target.symlink_to(fixture.root / "bin/cargo")
                    expected = "symbolic link"
                elif mutation == "fifo":
                    os.mkfifo(target)
                    expected = "special file"
                else:
                    os.link(fixture.root / "bin/cargo", target)
                    expected = "unsafe regular file"
                with self.assertRaisesRegex(ReleaseRustToolchainError, expected):
                    build_toolchain_surface(fixture.root)

    def test_group_writable_parent_directory_is_rejected(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        (fixture.root / "bin").chmod(0o775)
        with self.assertRaisesRegex(ReleaseRustToolchainError, "release-owned real directory"):
            build_toolchain_surface(fixture.root)

    def test_extra_component_and_unsafe_manifest_path_are_rejected(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        components = fixture.root / "lib/rustlib/components"
        components.write_text(
            "\n".join((*EXPECTED_COMPONENTS, "llvm-tools-preview-aarch64-apple-darwin"))
            + "\n",
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ReleaseRustToolchainError, "inventory is not exact"):
            build_toolchain_surface(fixture.root)

        temporary_two, fixture_two = self.fixture()
        self.addCleanup(temporary_two.cleanup)
        manifest = fixture_two.root / f"lib/rustlib/manifest-{EXPECTED_COMPONENTS[0]}"
        manifest.write_text("file:../outside\n", encoding="utf-8")
        with self.assertRaisesRegex(ReleaseRustToolchainError, "path is unsafe"):
            build_toolchain_surface(fixture_two.root)

    def test_component_inventory_order_is_semantically_canonical(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        components = fixture.root / "lib/rustlib/components"
        components.write_text(
            "\n".join(reversed(EXPECTED_COMPONENTS)) + "\n", encoding="utf-8"
        )
        self.assertEqual(build_toolchain_surface(fixture.root), fixture.surface)

    def test_component_inventory_rejects_noncanonical_serializations(self) -> None:
        variants = (
            "\n".join(EXPECTED_COMPONENTS),
            "\r\n".join(EXPECTED_COMPONENTS) + "\r\n",
            "\n".join(EXPECTED_COMPONENTS) + "\n\n",
            "\n".join(EXPECTED_COMPONENTS[:-1]) + "\n",
            "\n".join((*EXPECTED_COMPONENTS, EXPECTED_COMPONENTS[0])) + "\n",
            "\n".join((f" {EXPECTED_COMPONENTS[0]}", *EXPECTED_COMPONENTS[1:]))
            + "\n",
        )
        for value in variants:
            with self.subTest(value=value):
                temporary, fixture = self.fixture()
                self.addCleanup(temporary.cleanup)
                components = fixture.root / "lib/rustlib/components"
                components.write_text(value, encoding="utf-8", newline="")
                with self.assertRaisesRegex(
                    ReleaseRustToolchainError,
                    "component inventory",
                ):
                    build_toolchain_surface(fixture.root)

    def test_payload_byte_drift_changes_the_surface_digest(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        cargo = fixture.root / "bin/cargo"
        original = cargo.read_bytes()
        cargo.write_bytes(original[:-1] + bytes((original[-1] ^ 1,)))
        changed = build_toolchain_surface(fixture.root)
        self.assertEqual(changed["file_count"], fixture.surface["file_count"])
        self.assertEqual(changed["total_size"], fixture.surface["total_size"])
        self.assertNotEqual(changed["sha256"], fixture.surface["sha256"])

    def test_pin_and_declaration_drift_are_rejected(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        fixture.write_repository_contract("0" * 64)
        with self.assertRaisesRegex(
            ReleaseRustToolchainError,
            "differs from its pin.*expected_sha256=" + "0" * 64
            + ".*actual_sha256="
            + str(fixture.surface["sha256"])
            + ".*file_count="
            + str(fixture.surface["file_count"])
            + ".*total_size="
            + str(fixture.surface["total_size"]),
        ):
            verify_pinned_toolchain(fixture.repository, fixture.root)

        fixture.write_repository_contract(fixture.surface["sha256"])
        declaration = fixture.repository / "rust-toolchain.toml"
        declaration.write_text(
            declaration.read_text(encoding="utf-8").replace(
                'components = ["rustfmt", "clippy"]', 'components = ["clippy"]'
            ),
            encoding="utf-8",
        )
        with self.assertRaisesRegex(ReleaseRustToolchainError, "declaration is not exact"):
            verify_pinned_toolchain(fixture.repository, fixture.root)

    def test_recorded_surface_requires_exact_typed_fields(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        self.assertEqual(
            validate_recorded_surface(fixture.repository, fixture.surface), fixture.surface
        )
        extra = dict(fixture.surface, legacy=True)
        with self.assertRaisesRegex(ReleaseRustToolchainError, "unexpected fields"):
            validate_recorded_surface(fixture.repository, extra)
        boolean_count = dict(fixture.surface, file_count=True)
        with self.assertRaisesRegex(ReleaseRustToolchainError, "inconsistent"):
            validate_recorded_surface(fixture.repository, boolean_count)

    def test_binary_digests_are_streamed_without_regular_file_buffering(self) -> None:
        temporary, fixture = self.fixture()
        self.addCleanup(temporary.cleanup)
        cargo = fixture.root / "bin/cargo"
        cargo.write_bytes(b"cargo-streaming-fixture\n" * 100_000)
        original = release_rust_toolchain._read_regular

        def guarded(path: Path, maximum: int, label: str):
            if path == cargo:
                raise AssertionError("binary digest attempted to buffer the executable")
            return original(path, maximum, label)

        with mock.patch.object(release_rust_toolchain, "_read_regular", side_effect=guarded):
            surface = build_toolchain_surface(fixture.root)
        self.assertGreater(surface["total_size"], cargo.stat().st_size)


class ReleaseRustToolchainSelectionTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.fixture = RustToolchainFixture(self.base)
        self.home = self.base / "home"
        self.global_root = self.home / ".rustup/toolchains" / self.fixture.root.name
        self.private_root = (
            self.home / ".cfm-release-tooling/rust-toolchains" / self.fixture.root.name
        )
        self.global_root.parent.mkdir(parents=True)
        self.fixture.root.rename(self.global_root)

    def copy_private_toolchain(self) -> None:
        self.private_root.parent.mkdir(parents=True)
        shutil.copytree(self.global_root, self.private_root)

    def run_selection(self, selection: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [
                sys.executable,
                "-I", "-S", "-B", "-W", "error",
                str(Path(release_rust_toolchain.__file__).resolve()),
                "verify-selected",
                "--repository", str(self.fixture.repository),
                "--release-home", str(self.home),
                "--selection", selection,
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def test_selection_has_only_two_fixed_account_roots(self) -> None:
        for selection, expected in (
            ("global", self.global_root),
            ("private", self.private_root),
        ):
            with self.subTest(selection=selection):
                self.assertEqual(
                    release_rust_toolchain.selected_toolchain_root(
                        self.home, CHANNEL, selection
                    ),
                    expected,
                )

    def test_explicit_empty_and_unknown_selections_are_rejected(self) -> None:
        for selection in ("", "PRIVATE", " global", "private ", "../global"):
            with self.subTest(selection=selection), self.assertRaisesRegex(
                ReleaseRustToolchainError, "selection"
            ):
                release_rust_toolchain.selected_toolchain_root(
                    self.home, CHANNEL, selection
                )

    def test_unsafe_account_and_channel_cannot_change_the_selected_root(self) -> None:
        for home, channel in (
            (Path("relative-home"), CHANNEL),
            (self.home / ".." / "home", CHANNEL),
            (self.home, "../1.97.1"),
        ):
            with self.subTest(home=home, channel=channel), self.assertRaises(
                ReleaseRustToolchainError
            ):
                release_rust_toolchain.selected_toolchain_root(home, channel, "private")

    def test_private_exact_surface_works_when_global_has_optional_components(self) -> None:
        self.copy_private_toolchain()
        optional_component = "llvm-tools-preview-aarch64-apple-darwin"
        optional_payload = self.global_root / "lib/rustlib/aarch64-apple-darwin/bin/llvm-ar"
        optional_payload.parent.mkdir(parents=True)
        optional_payload.write_bytes(b"optional LLVM tool fixture\n")
        optional_payload.chmod(0o755)
        (self.global_root / "lib/rustlib" / f"manifest-{optional_component}").write_text(
            "file:lib/rustlib/aarch64-apple-darwin/bin/llvm-ar\n", encoding="utf-8"
        )
        components = self.global_root / "lib/rustlib/components"
        components.write_text(
            components.read_text(encoding="utf-8") + optional_component + "\n",
            encoding="utf-8",
        )

        completed = self.run_selection("private")

        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, str(self.private_root) + "\n")
        self.assertEqual(completed.stderr, "")
        self.assertEqual(
            verify_pinned_toolchain(self.fixture.repository, self.private_root).surface,
            self.fixture.surface,
        )
        rejected_global = self.run_selection("global")
        self.assertNotEqual(rejected_global.returncode, 0)
        self.assertEqual(rejected_global.stdout, "")
        self.assertIn("inventory is not exact", rejected_global.stderr)

    def test_global_selection_accepts_the_current_exact_surface(self) -> None:
        completed = self.run_selection("global")
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, str(self.global_root) + "\n")
        self.assertEqual(completed.stderr, "")
        self.assertFalse(self.private_root.exists())

    def test_missing_private_toolchain_does_not_fall_back_to_valid_global(self) -> None:
        completed = self.run_selection("private")
        self.assertNotEqual(completed.returncode, 0)
        self.assertEqual(completed.stdout, "")
        self.assertIn("Rust toolchain root is unavailable", completed.stderr)
        self.assertEqual(
            verify_pinned_toolchain(self.fixture.repository, self.global_root).surface,
            self.fixture.surface,
        )

    def test_invalid_private_toolchain_does_not_fall_back_to_valid_global(self) -> None:
        for mutation, expected_error in (
            ("payload", "surface differs from its pin"),
            ("extra", "differs from its component manifests"),
            ("symlink", "root is not canonical"),
        ):
            with self.subTest(mutation=mutation):
                if mutation == "symlink":
                    self.private_root.symlink_to(self.global_root, target_is_directory=True)
                else:
                    shutil.copytree(self.global_root, self.private_root)
                    if mutation == "payload":
                        (self.private_root / "bin/rustc").write_bytes(b"changed compiler\n")
                    else:
                        (self.private_root / "unexpected").write_bytes(b"extra\n")
                try:
                    completed = self.run_selection("private")
                    self.assertNotEqual(completed.returncode, 0)
                    self.assertEqual(completed.stdout, "")
                    self.assertIn(expected_error, completed.stderr)
                    self.assertEqual(
                        verify_pinned_toolchain(
                            self.fixture.repository, self.global_root
                        ).surface,
                        self.fixture.surface,
                    )
                finally:
                    if mutation == "symlink":
                        self.private_root.unlink()
                    else:
                        shutil.rmtree(self.private_root)

    def test_existing_explicit_root_verifier_remains_silent_and_compatible(self) -> None:
        self.copy_private_toolchain()
        completed = subprocess.run(
            [
                sys.executable,
                "-I", "-S", "-B", "-W", "error",
                str(Path(release_rust_toolchain.__file__).resolve()),
                "verify",
                "--repository", str(self.fixture.repository),
                "--toolchain-root", str(self.private_root),
            ],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        self.assertEqual(completed.stdout, "")
        self.assertEqual(completed.stderr, "")


if __name__ == "__main__":
    unittest.main()
