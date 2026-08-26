from __future__ import annotations

import plistlib
import tempfile
import unittest
from pathlib import Path

from scripts.release_build_identity import (
    ACTIVE_RELEASE_IDENTITY,
    BuildIdentityError,
    ReleaseIdentity,
    UNSIGNED_VALIDATION_BUILD,
    bundle_build_identity,
    candidate_native_derived_data_output,
    candidate_native_products_output,
    canonical_build_version,
    ga_pre_sign_native_products_root,
    ga_preflight_root,
    ga_root,
    ga_signed_root,
    ga_signed_native_products_root,
)


class ReleaseBuildIdentityTests(unittest.TestCase):
    def test_active_identity_is_one_fixed_ga_build(self) -> None:
        self.assertEqual(
            ACTIVE_RELEASE_IDENTITY,
            ReleaseIdentity("0.4.0", "40032"),
        )

    def test_release_identity_rejects_version_or_build_drift(self) -> None:
        for identity in (
            ("0.4.1", "40032"),
            ("0.4.0", "040032"),
            ("0.4.0", "0"),
        ):
            with self.subTest(identity=identity), self.assertRaises(
                BuildIdentityError
            ):
                ReleaseIdentity(*identity)

    def make_app(self, root: Path, builds: tuple[str, str, str, str]) -> Path:
        app = root / "Clash for Mac.app"
        paths = (
            app / "Contents/Info.plist",
            app / "Contents/Frameworks/CFWNativeBridge.framework/Versions/A/Resources/Info.plist",
            app / "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/Info.plist",
            app
            / "Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension/Contents/Info.plist",
        )
        for path, build in zip(paths, builds, strict=True):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleShortVersionString": "0.4.0",
                        "CFBundleVersion": build,
                    }
                )
            )
        return app

    def test_one_integer_build_is_shared_by_all_bundles(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            identity = bundle_build_identity(
                self.make_app(
                    Path(directory), ("40001", "40001", "40001", "40001")
                )
            )
            self.assertEqual(identity.build_version, "40001")

    def test_mismatched_nested_build_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = self.make_app(
                Path(directory), ("40001", "40001", "40001", "40000")
            )
            with self.assertRaisesRegex(BuildIdentityError, "differ"):
                bundle_build_identity(app)

    def test_noncanonical_integer_fails_closed(self) -> None:
        for value in ("0", "01", "1.2", "-1", " 1", 1):
            with self.subTest(value=value):
                with self.assertRaises(BuildIdentityError):
                    canonical_build_version(value)

    def test_build_bound_rejects_overflow_without_unbounded_integer_parsing(self) -> None:
        self.assertEqual(
            canonical_build_version("9223372036854775807"),
            "9223372036854775807",
        )
        for value in ("9223372036854775808", "9" * 5_000):
            with self.subTest(length=len(value)), self.assertRaisesRegex(
                BuildIdentityError, "signed 64-bit"
            ):
                canonical_build_version(value)

    def test_ga_paths_are_fixed_to_the_single_active_identity(self) -> None:
        repository = Path("/repo")
        self.assertEqual(
            ga_preflight_root(repository),
            Path("/repo/target/candidates/0.4.0/ga-preflight/40032"),
        )
        self.assertEqual(
            ga_root(repository),
            Path("/repo/target/candidates/0.4.0/ga/40032"),
        )
        self.assertEqual(
            ga_pre_sign_native_products_root(repository),
            Path(
                "/repo/target/candidates/0.4.0/ga-preflight/40032/native-products"
            ),
        )
        self.assertEqual(
            ga_signed_root(repository),
            Path("/repo/target/candidates/0.4.0/ga/40032/signed"),
        )
        self.assertEqual(
            ga_signed_native_products_root(repository),
            Path(
                "/repo/target/candidates/0.4.0/ga/40032/signing-output/signed-native-products"
            ),
        )

    def test_candidate_native_output_accepts_only_exact_build_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            accepted = (
                (
                    UNSIGNED_VALIDATION_BUILD,
                    repository / "target/candidates/0.4.0/unsigned/native-products",
                ),
                (
                    ACTIVE_RELEASE_IDENTITY.ga_build,
                    ga_pre_sign_native_products_root(repository),
                ),
            )
            for build, output in accepted:
                with self.subTest(build=build, output=output):
                    self.assertEqual(
                        candidate_native_products_output(
                            repository, str(output), build
                        ),
                        output,
                    )

    def test_candidate_native_output_rejects_legacy_paths_and_wrong_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            rejected = (
                (
                    "40032",
                    repository
                    / "target/candidates/0.4.0/validation/40032/native-products",
                ),
                (
                    "40032",
                    repository
                    / "target/candidates/0.4.0/release-build/40032/native-products",
                ),
                (
                    "40030",
                    repository
                    / "target/candidates/0.4.0/ga-preflight/40030/native-products",
                ),
                (
                    "40031",
                    repository
                    / "target/candidates/0.4.0/ga-preflight/40031/native-products",
                ),
                (
                    "40032",
                    repository
                    / "target/candidates/0.4.0/ga-preflight/../../../../tmp/escape/native-products",
                ),
            )
            for build, output in rejected:
                with self.subTest(build=build, output=output), self.assertRaises(
                    BuildIdentityError
                ):
                    candidate_native_products_output(
                        repository, str(output), build
                    )
            with self.assertRaises(BuildIdentityError):
                candidate_native_products_output(
                    repository,
                    str(repository)
                    + "/target/candidates/0.4.0/ga-preflight//40032/native-products",
                    "40032",
                )

    def test_candidate_native_output_rejects_a_symlink_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            target = repository / "target"
            target.mkdir()
            external = repository / "external"
            external.mkdir()
            (target / "candidates").symlink_to(external, target_is_directory=True)
            output = ga_pre_sign_native_products_root(repository)
            with self.assertRaisesRegex(BuildIdentityError, "real directory"):
                candidate_native_products_output(
                    repository, str(output), "40032"
                )

    def test_candidate_derived_data_is_the_exact_native_output_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            native_products = ga_pre_sign_native_products_root(repository)
            expected = native_products.parent / "xcode-derived-data"
            self.assertEqual(
                candidate_native_derived_data_output(
                    repository,
                    str(native_products),
                    str(expected),
                    "40032",
                ),
                expected,
            )
            for rejected in (
                repository / "tmp/arbitrary-derived-data",
                native_products.parent / "nested/../xcode-derived-data",
            ):
                with self.subTest(output=rejected), self.assertRaises(
                    BuildIdentityError
                ):
                    candidate_native_derived_data_output(
                        repository,
                        str(native_products),
                        str(rejected),
                        "40032",
                    )

    def test_candidate_derived_data_rejects_a_symlink_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            preflight_root = ga_preflight_root(repository)
            preflight_root.mkdir(parents=True)
            external = repository / "external"
            external.mkdir()
            (preflight_root / "xcode-derived-data").symlink_to(
                external, target_is_directory=True
            )
            native_products = preflight_root / "native-products"
            with self.assertRaisesRegex(BuildIdentityError, "real directory"):
                candidate_native_derived_data_output(
                    repository,
                    str(native_products),
                    str(preflight_root / "xcode-derived-data"),
                    "40032",
                )

    def test_native_builders_use_the_shared_candidate_output_contract(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        for relative in (
            "scripts/build_native_products.sh",
            "scripts/build_legacy_tombstone.sh",
        ):
            with self.subTest(script=relative):
                source = (repository / relative).read_text(encoding="utf-8")
                self.assertIn("candidate_native_products_output", source)
                self.assertIn("validate_candidate_output", source)
        native_source = (
            repository / "scripts/build_native_products.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("candidate_native_derived_data_output", native_source)
        self.assertIn("validate_candidate_derived_data", native_source)


if __name__ == "__main__":
    unittest.main()
