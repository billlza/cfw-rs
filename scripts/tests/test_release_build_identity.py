from __future__ import annotations

import plistlib
import tempfile
import unittest
from pathlib import Path

from scripts.release_build_identity import (
    BuildIdentityError,
    bundle_build_identity,
    candidate_native_derived_data_output,
    candidate_native_products_output,
    canonical_build_version,
    release_native_products_root,
    require_newer_build,
)


class ReleaseBuildIdentityTests(unittest.TestCase):
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

    def test_final_build_must_exceed_validated_candidate(self) -> None:
        require_newer_build("40001", "40000")
        for final in ("40000", "39999"):
            with self.assertRaisesRegex(BuildIdentityError, "strictly greater"):
                require_newer_build(final, "40000")

    def test_release_native_root_is_build_specific(self) -> None:
        root = release_native_products_root(Path("/repo"), "40001")
        self.assertEqual(
            root,
            Path("/repo/target/candidates/0.4.0/release-build/40001/native-products"),
        )

    def test_candidate_native_output_accepts_only_exact_build_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            accepted = (
                repository / "target/candidates/0.4.0/unsigned/native-products",
                repository
                / "target/candidates/0.4.0/validation/40028/native-products",
                repository
                / "target/candidates/0.4.0/release-build/40028/native-products",
            )
            for output in accepted:
                with self.subTest(output=output):
                    self.assertEqual(
                        candidate_native_products_output(
                            repository, str(output), "40028"
                        ),
                        output,
                    )

    def test_candidate_native_output_rejects_traversal_and_wrong_build(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            rejected = (
                repository
                / "target/candidates/0.4.0/validation/../../../../tmp/escape/native-products",
                repository
                / "target/candidates/0.4.0/validation/40029/native-products",
                repository / "target/candidates/0.4.0/arbitrary/native-products",
            )
            for output in rejected:
                with self.subTest(output=output), self.assertRaises(
                    BuildIdentityError
                ):
                    candidate_native_products_output(
                        repository, str(output), "40028"
                    )
            with self.assertRaises(BuildIdentityError):
                candidate_native_products_output(
                    repository,
                    str(repository)
                    + "/target/candidates/0.4.0/validation//40028/native-products",
                    "40028",
                )

    def test_candidate_native_output_rejects_a_symlink_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            target = repository / "target"
            target.mkdir()
            external = repository / "external"
            external.mkdir()
            (target / "candidates").symlink_to(external, target_is_directory=True)
            output = (
                repository
                / "target/candidates/0.4.0/validation/40028/native-products"
            )
            with self.assertRaisesRegex(BuildIdentityError, "real directory"):
                candidate_native_products_output(
                    repository, str(output), "40028"
                )

    def test_candidate_derived_data_is_the_exact_native_output_sibling(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            native_products = (
                repository
                / "target/candidates/0.4.0/validation/40028/native-products"
            )
            expected = native_products.parent / "xcode-derived-data"
            self.assertEqual(
                candidate_native_derived_data_output(
                    repository,
                    str(native_products),
                    str(expected),
                    "40028",
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
                        "40028",
                    )

    def test_candidate_derived_data_rejects_a_symlink_ancestor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            validation_root = (
                repository / "target/candidates/0.4.0/validation/40028"
            )
            validation_root.mkdir(parents=True)
            external = repository / "external"
            external.mkdir()
            (validation_root / "xcode-derived-data").symlink_to(
                external, target_is_directory=True
            )
            native_products = validation_root / "native-products"
            with self.assertRaisesRegex(BuildIdentityError, "real directory"):
                candidate_native_derived_data_output(
                    repository,
                    str(native_products),
                    str(validation_root / "xcode-derived-data"),
                    "40028",
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
