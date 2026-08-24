from __future__ import annotations

import json
import os
from pathlib import Path
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


if __name__ == "__main__":
    unittest.main()
