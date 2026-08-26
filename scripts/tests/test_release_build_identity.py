from __future__ import annotations

import os
import plistlib
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import verify_candidate_bundle
from scripts.release_build_identity import (
    ACTIVE_RELEASE_IDENTITY,
    BuildIdentityError,
    CandidateBundleContext,
    ReleaseIdentity,
    UNSIGNED_VALIDATION_BUILD,
    bundle_build_identity,
    candidate_bundle_verification_paths,
    candidate_native_derived_data_output,
    candidate_native_products_output,
    canonical_build_version,
    ga_pre_sign_native_products_root,
    ga_preflight_root,
    ga_root,
    ga_signed_root,
    ga_signed_native_products_root,
    ga_signing_attempt_output_root,
)


class ReleaseBuildIdentityTests(unittest.TestCase):
    def test_active_identity_is_one_fixed_ga_build(self) -> None:
        self.assertEqual(
            ACTIVE_RELEASE_IDENTITY,
            ReleaseIdentity("0.4.0", "40034"),
        )

    def test_release_identity_rejects_version_or_build_drift(self) -> None:
        for identity in (
            ("0.4.1", "40034"),
            ("0.4.0", "040034"),
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

    def make_private_pair(
        self,
        repository: Path,
        context: CandidateBundleContext,
        attempt_id: str = "00000001",
    ) -> tuple[Path, Path, Path]:
        stage = {
            CandidateBundleContext.SIGNING_ATTEMPT_WORK: "work",
            CandidateBundleContext.SIGNING_ATTEMPT_PUBLISH_READY: "publish-ready",
        }[context]
        attempt = (
            ga_root(repository)
            / "transactions/signing-attempts"
            / attempt_id
        )
        output = attempt / stage
        signing_input = output / "signing-input"
        native_products = output / "signed-native-products"
        native_products.mkdir(parents=True)
        signing_input.mkdir(exist_ok=True)
        attempts = attempt.parent
        transactions = attempts.parent
        for private in (
            transactions,
            attempts,
            attempt,
            output,
            signing_input,
            native_products,
        ):
            os.chmod(private, 0o700)
        app = self.make_app(
            signing_input,
            ("40034", "40034", "40034", "40034"),
        )
        return app, native_products, output

    @staticmethod
    def make_canonical_native_products(repository: Path) -> Path:
        native_products = ga_signed_native_products_root(repository)
        native_products.mkdir(parents=True)
        os.chmod(native_products.parent, 0o700)
        os.chmod(native_products, 0o700)
        return native_products

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
            Path("/repo/target/candidates/0.4.0/ga-preflight/40034"),
        )
        self.assertEqual(
            ga_root(repository),
            Path("/repo/target/candidates/0.4.0/ga/40034"),
        )
        self.assertEqual(
            ga_pre_sign_native_products_root(repository),
            Path(
                "/repo/target/candidates/0.4.0/ga-preflight/40034/native-products"
            ),
        )
        self.assertEqual(
            ga_signed_root(repository),
            Path("/repo/target/candidates/0.4.0/ga/40034/signed"),
        )
        self.assertEqual(
            ga_signed_native_products_root(repository),
            Path(
                "/repo/target/candidates/0.4.0/ga/40034/signing-output/signed-native-products"
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
                    "40034",
                    repository
                    / "target/candidates/0.4.0/validation/40034/native-products",
                ),
                (
                    "40034",
                    repository
                    / "target/candidates/0.4.0/release-build/40034/native-products",
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
                    / "target/candidates/0.4.0/ga-preflight/40032/native-products",
                ),
                (
                    "40033",
                    repository
                    / "target/candidates/0.4.0/ga-preflight/40033/native-products",
                ),
                (
                    "40034",
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
                    + "/target/candidates/0.4.0/ga-preflight//40034/native-products",
                    "40034",
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
                    repository, str(output), "40034"
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
                    "40034",
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
                        "40034",
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
                    "40034",
                )

    def test_bundle_context_accepts_exact_private_work_and_publish_ready(self) -> None:
        for context in (
            CandidateBundleContext.SIGNING_ATTEMPT_WORK,
            CandidateBundleContext.SIGNING_ATTEMPT_PUBLISH_READY,
        ):
            with self.subTest(context=context), tempfile.TemporaryDirectory() as directory:
                repository = Path(directory).resolve()
                app, native_products, _ = self.make_private_pair(
                    repository, context
                )
                paths = candidate_bundle_verification_paths(
                    repository, app, native_products, context
                )
                self.assertEqual(paths.app, app)
                self.assertEqual(paths.native_products, native_products)
                self.assertEqual(paths.context, context)
                self.assertEqual(paths.build_identity.build_version, "40034")

    def test_bundle_context_accepts_canonical_native_with_safe_app_copies(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            native_products = self.make_canonical_native_products(repository)
            for app_root in (
                ga_signed_root(repository),
                repository / "target/notarization/attempts/00000001/work",
                repository / "target/dmg/private-payload",
            ):
                with self.subTest(app_root=app_root):
                    app = self.make_app(
                        app_root,
                        ("40034", "40034", "40034", "40034"),
                    )
                    paths = candidate_bundle_verification_paths(
                        repository,
                        app,
                        native_products,
                        CandidateBundleContext.CANONICAL_NATIVE_CONTENT,
                    )
                    self.assertEqual(paths.app, app)
                    self.assertEqual(paths.native_products, native_products)

    def test_bundle_context_rejects_same_attempt_cross_stage_mixing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            work_app, work_native, _ = self.make_private_pair(
                repository, CandidateBundleContext.SIGNING_ATTEMPT_WORK
            )
            ready_app, ready_native, _ = self.make_private_pair(
                repository,
                CandidateBundleContext.SIGNING_ATTEMPT_PUBLISH_READY,
            )
            for app, native_products, context in (
                (
                    work_app,
                    ready_native,
                    CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                ),
                (
                    ready_app,
                    work_native,
                    CandidateBundleContext.SIGNING_ATTEMPT_PUBLISH_READY,
                ),
            ):
                with self.subTest(context=context), self.assertRaises(
                    BuildIdentityError
                ):
                    candidate_bundle_verification_paths(
                        repository, app, native_products, context
                    )

    def test_bundle_context_rejects_same_stage_cross_attempt_mixing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            first_app, first_native, _ = self.make_private_pair(
                repository,
                CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                "00000001",
            )
            second_app, second_native, _ = self.make_private_pair(
                repository,
                CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                "00000002",
            )
            for app, native_products in (
                (first_app, second_native),
                (second_app, first_native),
            ):
                with self.subTest(app=app), self.assertRaises(BuildIdentityError):
                    candidate_bundle_verification_paths(
                        repository,
                        app,
                        native_products,
                        CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                    )

    def test_bundle_context_rejects_private_and_canonical_provenance_mixing(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            work_app, _, _ = self.make_private_pair(
                repository, CandidateBundleContext.SIGNING_ATTEMPT_WORK
            )
            canonical_native = self.make_canonical_native_products(repository)
            for app, native_products, context in (
                (
                    work_app,
                    canonical_native,
                    CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                ),
                (
                    work_app,
                    canonical_native,
                    CandidateBundleContext.CANONICAL_NATIVE_CONTENT,
                ),
            ):
                with self.subTest(context=context), self.assertRaises(
                    BuildIdentityError
                ):
                    candidate_bundle_verification_paths(
                        repository, app, native_products, context
                    )

    def test_bundle_context_rejects_invalid_attempt_ids(self) -> None:
        for attempt_id in (
            "0000000",
            "000000000",
            "00000000",
            "0000000x",
            "0000000１",
        ):
            with self.subTest(attempt_id=attempt_id), tempfile.TemporaryDirectory() as directory:
                repository = Path(directory).resolve()
                app, native_products, _ = self.make_private_pair(
                    repository,
                    CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                    attempt_id,
                )
                with self.assertRaises(BuildIdentityError):
                    candidate_bundle_verification_paths(
                        repository,
                        app,
                        native_products,
                        CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                    )

    def test_bundle_context_rejects_each_non_private_attempt_directory(self) -> None:
        targets = {
            "transactions": lambda app, native, output: output.parent.parent.parent,
            "signing-attempts": lambda app, native, output: output.parent.parent,
            "attempt": lambda app, native, output: output.parent,
            "stage-output": lambda app, native, output: output,
            "signing-input": lambda app, native, output: app.parent,
            "native-products": lambda app, native, output: native,
        }
        for label, select_target in targets.items():
            with self.subTest(target=label), tempfile.TemporaryDirectory() as directory:
                repository = Path(directory).resolve()
                app, native_products, output = self.make_private_pair(
                    repository, CandidateBundleContext.SIGNING_ATTEMPT_WORK
                )
                os.chmod(select_target(app, native_products, output), 0o755)
                with self.assertRaisesRegex(BuildIdentityError, "0700"):
                    candidate_bundle_verification_paths(
                        repository,
                        app,
                        native_products,
                        CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                    )

    def test_bundle_context_rejects_each_non_private_canonical_directory(self) -> None:
        for label in ("signing-output", "native-products"):
            with self.subTest(target=label), tempfile.TemporaryDirectory() as directory:
                repository = Path(directory).resolve()
                native_products = self.make_canonical_native_products(repository)
                app = self.make_app(
                    ga_signed_root(repository),
                    ("40034", "40034", "40034", "40034"),
                )
                target = (
                    native_products.parent
                    if label == "signing-output"
                    else native_products
                )
                os.chmod(target, 0o755)
                with self.assertRaisesRegex(BuildIdentityError, "0700"):
                    candidate_bundle_verification_paths(
                        repository,
                        app,
                        native_products,
                        CandidateBundleContext.CANONICAL_NATIVE_CONTENT,
                    )

    def test_bundle_context_rejects_a_non_current_owner(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            app, native_products, _ = self.make_private_pair(
                repository, CandidateBundleContext.SIGNING_ATTEMPT_WORK
            )
            with patch(
                "scripts.release_build_identity.os.geteuid",
                return_value=os.geteuid() + 1,
            ), self.assertRaisesRegex(BuildIdentityError, "current-user"):
                candidate_bundle_verification_paths(
                    repository,
                    app,
                    native_products,
                    CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                )

    def test_bundle_context_rejects_alias_and_symlink_paths(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            native_products = self.make_canonical_native_products(repository)
            app = self.make_app(
                ga_signed_root(repository),
                ("40034", "40034", "40034", "40034"),
            )
            alias = str(app.parent / "nested/.." / app.name)
            with self.assertRaisesRegex(BuildIdentityError, "canonical absolute"):
                candidate_bundle_verification_paths(
                    repository,
                    alias,
                    native_products,
                    CandidateBundleContext.CANONICAL_NATIVE_CONTENT,
                )
            native_alias = repository / "native-alias"
            native_alias.symlink_to(native_products, target_is_directory=True)
            with self.assertRaisesRegex(BuildIdentityError, "canonical real"):
                candidate_bundle_verification_paths(
                    repository,
                    app,
                    native_alias,
                    CandidateBundleContext.CANONICAL_NATIVE_CONTENT,
                )

    def test_signing_attempt_output_root_rejects_non_positive_ascii_ids(self) -> None:
        repository = Path("/repo")
        for attempt_id in (
            "0000000",
            "000000000",
            "00000000",
            "0000000x",
            "0000000１",
        ):
            with self.subTest(attempt_id=attempt_id), self.assertRaises(
                BuildIdentityError
            ):
                ga_signing_attempt_output_root(
                    repository,
                    attempt_id,
                    CandidateBundleContext.SIGNING_ATTEMPT_WORK,
                )

    def test_candidate_cli_preserves_raw_paths_for_shared_admission(self) -> None:
        raw_app = "/private/tmp/candidate//Clash for Mac.app"
        raw_native = "/private/tmp/candidate/./signed-native-products"
        with patch.object(
            sys,
            "argv",
            [
                "verify_candidate_bundle.py",
                raw_app,
                "--native-products-root",
                raw_native,
                "--context",
                "canonical-native-content",
            ],
        ), patch.object(
            verify_candidate_bundle, "verify_candidate"
        ) as verifier:
            verify_candidate_bundle.main()
        self.assertEqual(verifier.call_args.args[1:3], (raw_app, raw_native))
        self.assertEqual(
            verifier.call_args.kwargs["context"],
            CandidateBundleContext.CANONICAL_NATIVE_CONTENT,
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
