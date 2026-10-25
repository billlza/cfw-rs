from __future__ import annotations

import os
import plistlib
import re
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import release_build_identity, verify_candidate_bundle
from scripts.release_build_identity import (
    ACTIVE_RELEASE_IDENTITY,
    PRODUCT_VERSION,
    RELEASE_IDENTITY_PATH,
    BundleBuildIdentity,
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
    load_release_identity,
    read_bundle_identity,
)
from scripts.release_git import run_release_git
from scripts.tests.release_identity_fixture import (
    NEXT_GA_BUILD,
    next_patch,
    noncanonical,
    retired_ga_builds,
)


GA_BUILD = ACTIVE_RELEASE_IDENTITY.ga_build
# The signed builder derives CFW_BUILD_NUMBER from the release identity
# between these two lines, before it creates any candidate directory.
SIGNED_BUILDER_DERIVATION_START = 'release_identity="$(PYTHONDONTWRITEBYTECODE=1 '
SIGNED_BUILDER_DERIVATION_END = 'export CFW_BUILD_NUMBER="$active_ga_build"'


class ReleaseIdentityFileTests(unittest.TestCase):
    """The active product version and GA build are read only from the
    byte-strict identity file."""

    VERSION = b"CFW_PRODUCT_VERSION=7.0.1\n"

    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "release_identity.env"

    def load(self, data: bytes) -> ReleaseIdentity:
        self.path.write_bytes(data)
        return load_release_identity(self.path)

    def test_active_identity_is_the_identity_file_record(self) -> None:
        self.assertEqual(
            RELEASE_IDENTITY_PATH,
            Path(release_build_identity.__file__).resolve().parent / "release_identity.env",
        )
        self.assertEqual(ACTIVE_RELEASE_IDENTITY, load_release_identity(RELEASE_IDENTITY_PATH))
        self.assertEqual(PRODUCT_VERSION, ACTIVE_RELEASE_IDENTITY.product_version)
        self.assertEqual(
            RELEASE_IDENTITY_PATH.read_bytes().splitlines()[-2:],
            [
                f"CFW_PRODUCT_VERSION={PRODUCT_VERSION}".encode("ascii"),
                f"CFW_GA_BUILD={GA_BUILD}".encode("ascii"),
            ],
        )

    def test_identity_file_admits_full_line_comments_and_one_record(self) -> None:
        for data, identity in (
            (self.VERSION + b"CFW_GA_BUILD=70001\n", ("7.0.1", "70001")),
            (b"# comment\n#\n" + self.VERSION + b"CFW_GA_BUILD=70001\n", ("7.0.1", "70001")),
            (b"CFW_PRODUCT_VERSION=0.0.0\nCFW_GA_BUILD=9223372036854775807\n",
             ("0.0.0", "9223372036854775807")),
            (b"CFW_PRODUCT_VERSION=999999999.999999999.999999999\nCFW_GA_BUILD=1\n",
             ("999999999.999999999.999999999", "1")),
        ):
            with self.subTest(data=data):
                self.assertEqual(self.load(data), ReleaseIdentity(*identity))

    def test_identity_file_rejects_every_noncanonical_shape(self) -> None:
        version = self.VERSION
        for data in (
            b"",
            version + b"CFW_GA_BUILD=70001",
            version + b"CFW_GA_BUILD=70001\r\n",
            b"# comment\r\n" + version + b"CFW_GA_BUILD=70001\n",
            version + b"CFW_GA_BUILD=70001\n\n",
            b"\n" + version + b"CFW_GA_BUILD=70001\n",
            version + b"CFW_GA_BUILD=70001\nCFW_GA_BUILD=70002\n",
            version + b"CFW_GA_BUILD=70001\n# trailing comment\n",
            version + b" CFW_GA_BUILD=70001\n",
            version + b"CFW_GA_BUILD = 70001\n",
            version + b"export CFW_GA_BUILD=70001\n",
            version + b"CFW_GA_BUILD=\"70001\"\n",
            version + b"CFW_GA_BUILD=070001\n",
            version + b"CFW_GA_BUILD=0\n",
            version + b"CFW_GA_BUILD=+70001\n",
            version + b"CFW_GA_BUILD=70001 # active\n",
            version + b"CFW_GA_BUILD=\n",
            version + b"cfw_ga_build=70001\n",
            "# caf\u00e9\n".encode("utf-8") + version + b"CFW_GA_BUILD=70001\n",
            b"#\tcomment\n" + version + b"CFW_GA_BUILD=70001\n",
            version + b"CFW_GA_BUILD=12345678901234567890\n",
            b"\xef\xbb\xbf" + version + b"CFW_GA_BUILD=70001\n",
            b"# only a comment\n",
            # The product version line: present, first, once and exact.
            b"CFW_GA_BUILD=70001\n",
            version,
            b"CFW_GA_BUILD=70001\n" + version,
            version + version + b"CFW_GA_BUILD=70001\n",
            version + b"# between\nCFW_GA_BUILD=70001\n",
            b"CFW_PRODUCT_VERSION=7.0\nCFW_GA_BUILD=70001\n",
            b"CFW_PRODUCT_VERSION=7.0.1.2\nCFW_GA_BUILD=70001\n",
            b"CFW_PRODUCT_VERSION=v7.0.1\nCFW_GA_BUILD=70001\n",
            b"CFW_PRODUCT_VERSION=7.0.1-beta\nCFW_GA_BUILD=70001\n",
            b"CFW_PRODUCT_VERSION=7.0.1 \nCFW_GA_BUILD=70001\n",
            b"CFW_PRODUCT_VERSION=\"7.0.1\"\nCFW_GA_BUILD=70001\n",
            b"CFW_PRODUCT_VERSION=1234567890.0.0\nCFW_GA_BUILD=70001\n",
            b"CFW_PRODUCT_VERSION=7..1\nCFW_GA_BUILD=70001\n",
            b"cfw_product_version=7.0.1\nCFW_GA_BUILD=70001\n",
        ):
            with self.subTest(data=data), self.assertRaisesRegex(
                BuildIdentityError,
                "not one canonical CFW_PRODUCT_VERSION and CFW_GA_BUILD record: "
                f"{re.escape(str(self.path))}",
            ):
                self.load(data)
        for data in (
            b"CFW_PRODUCT_VERSION=07.0.1\nCFW_GA_BUILD=70001\n",
            b"CFW_PRODUCT_VERSION=7.00.1\nCFW_GA_BUILD=70001\n",
            b"CFW_PRODUCT_VERSION=7.0.01\nCFW_GA_BUILD=70001\n",
        ):
            with self.subTest(data=data), self.assertRaisesRegex(
                BuildIdentityError,
                f"CFW_PRODUCT_VERSION in {re.escape(str(self.path))} must be one "
                "canonical MAJOR.MINOR.PATCH version",
            ):
                self.load(data)
        with self.assertRaisesRegex(
            BuildIdentityError,
            f"CFW_GA_BUILD in {re.escape(str(self.path))} exceeds the signed 64-bit",
        ):
            self.load(version + b"CFW_GA_BUILD=9223372036854775808\n")

    def test_a_missing_identity_file_names_its_path(self) -> None:
        with self.assertRaisesRegex(
            BuildIdentityError, f"unavailable: {re.escape(str(self.path))}"
        ) as raised:
            load_release_identity(self.path)
        self.assertIsInstance(raised.exception.__cause__, FileNotFoundError)
        self.path.mkdir()
        with self.assertRaisesRegex(
            BuildIdentityError, f"unavailable: {re.escape(str(self.path))}"
        ) as raised:
            load_release_identity(self.path)
        self.assertIsInstance(raised.exception.__cause__, IsADirectoryError)


# The release tools may name the active product version only in the identity
# file, in the allocation ledger policies, which hold every product version's
# history, and in the install-predecessor registry, whose profiles carry the
# product version they were installed as.
PRODUCT_VERSION_FILES = frozenset(
    {
        RELEASE_IDENTITY_PATH.relative_to(RELEASE_IDENTITY_PATH.parents[1]).as_posix(),
        "scripts/verify_release_build_allocations.py",
        "scripts/dormant_app_install.py",
    }
)
# Third-party inputs: upstream patches and lock files, licenses and fixtures.
THIRD_PARTY_PREFIXES = ("scripts/tests/fixtures/",)
THIRD_PARTY_SUFFIXES = (".patch",)


def release_tool_files_naming(version: str) -> list[str]:
    """The tracked release-tool files that name `version` as a whole version."""

    repository = RELEASE_IDENTITY_PATH.parents[1]
    listing = run_release_git(
        repository,
        ["ls-files", "-z", "--cached", "--", "scripts", ".github"],
        protected_roots=("scripts", ".github"),
    )
    pattern = re.compile(rb"(?<![0-9.])" + re.escape(version.encode("ascii")) + rb"(?![0-9])")
    return sorted(
        relative
        for raw in filter(None, listing.split(b"\0"))
        if not (relative := raw.decode("utf-8")).startswith(THIRD_PARTY_PREFIXES)
        and not relative.endswith(THIRD_PARTY_SUFFIXES)
        and pattern.search((repository / relative).read_bytes())
    )


class ProductVersionLiteralAuditTests(unittest.TestCase):
    """A new product version changes the identity file, not the release tools."""

    def test_no_release_tool_names_the_active_product_version(self) -> None:
        named = release_tool_files_naming(PRODUCT_VERSION)
        self.assertIn(RELEASE_IDENTITY_PATH.relative_to(RELEASE_IDENTITY_PATH.parents[1]).as_posix(), named)
        self.assertEqual(sorted(set(named) - PRODUCT_VERSION_FILES), [])


class ReleaseBuildIdentityTests(unittest.TestCase):
    def test_active_identity_is_one_fixed_ga_build(self) -> None:
        self.assertEqual(
            ACTIVE_RELEASE_IDENTITY,
            ReleaseIdentity(PRODUCT_VERSION, GA_BUILD),
        )

    def test_release_identity_rejects_a_noncanonical_version_or_build(self) -> None:
        for identity in (
            (f"0{PRODUCT_VERSION}", GA_BUILD),
            (PRODUCT_VERSION.rsplit(".", 1)[0], GA_BUILD),
            (f"{PRODUCT_VERSION}.0", GA_BUILD),
            (f"v{PRODUCT_VERSION}", GA_BUILD),
            (PRODUCT_VERSION, noncanonical(GA_BUILD)),
            (PRODUCT_VERSION, "0"),
        ):
            with self.subTest(identity=identity), self.assertRaises(
                BuildIdentityError
            ):
                ReleaseIdentity(*identity)

    @staticmethod
    def identity_plists(app: Path) -> tuple[Path, Path, Path, Path]:
        return (
            app / "Contents/Info.plist",
            app / "Contents/Frameworks/CFWNativeBridge.framework/Versions/A/Resources/Info.plist",
            app / "Contents/Library/LoginItems/CFWProxyAgent.app/Contents/Info.plist",
            app
            / "Contents/Library/SystemExtensions/com.bill.clashformac.packet-tunnel.systemextension/Contents/Info.plist",
        )

    def make_app(
        self,
        root: Path,
        builds: tuple[str, str, str, str],
        *,
        version: str = PRODUCT_VERSION,
    ) -> Path:
        app = root / "Clash for Mac.app"
        paths = self.identity_plists(app)
        for path, build in zip(paths, builds, strict=True):
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(
                plistlib.dumps(
                    {
                        "CFBundleShortVersionString": version,
                        "CFBundleVersion": build,
                    }
                )
            )
            path.chmod(0o644)
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
            (GA_BUILD,) * 4,
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

    def test_each_bundle_identity_plist_rejects_links(self) -> None:
        for index in range(4):
            for mutation in ("symlink", "hardlink"):
                with (
                    self.subTest(index=index, mutation=mutation),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    app = self.make_app(
                        Path(directory),
                        ("40001", "40001", "40001", "40001"),
                    )
                    path = self.identity_plists(app)[index]
                    sibling = path.with_name(path.name + ".linked")
                    if mutation == "symlink":
                        sibling.write_bytes(path.read_bytes())
                        sibling.chmod(0o644)
                        path.unlink()
                        path.symlink_to(sibling)
                    else:
                        os.link(path, sibling)

                    with self.assertRaisesRegex(
                        BuildIdentityError,
                        "bounded owned single-link regular file",
                    ):
                        bundle_build_identity(app)

    def test_each_bundle_identity_plist_requires_mode_0644(self) -> None:
        for index in range(4):
            for mode in (0o600, 0o664, 0o755):
                with (
                    self.subTest(index=index, mode=f"{mode:04o}"),
                    tempfile.TemporaryDirectory() as directory,
                ):
                    app = self.make_app(
                        Path(directory),
                        ("40001", "40001", "40001", "40001"),
                    )
                    self.identity_plists(app)[index].chmod(mode)

                    with self.assertRaisesRegex(
                        BuildIdentityError,
                        f"mode is {mode:04o}, expected 0644",
                    ):
                        bundle_build_identity(app)

    def test_bundle_identity_plist_size_parse_and_owner_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = self.make_app(
                Path(directory),
                ("40001", "40001", "40001", "40001"),
            )
            path = self.identity_plists(app)[0]
            original = path.read_bytes()

            path.write_bytes(
                original
                + b" "
                * (release_build_identity.MAX_BUNDLE_IDENTITY_PLIST_BYTES - len(original))
            )
            path.chmod(0o644)
            self.assertEqual(
                release_build_identity._read_plist(path, label="host")[
                    "CFBundleVersion"
                ],
                "40001",
            )

            path.write_bytes(b"")
            path.chmod(0o644)
            with self.assertRaisesRegex(
                BuildIdentityError,
                "bounded owned single-link regular file",
            ):
                release_build_identity._read_plist(path, label="host")

            path.write_bytes(
                b"x" * (release_build_identity.MAX_BUNDLE_IDENTITY_PLIST_BYTES + 1)
            )
            path.chmod(0o644)
            with self.assertRaisesRegex(
                BuildIdentityError,
                "bounded owned single-link regular file",
            ):
                release_build_identity._read_plist(path, label="host")

            path.write_bytes(b"not a plist")
            path.chmod(0o644)
            with self.assertRaisesRegex(BuildIdentityError, "cannot be parsed"):
                release_build_identity._read_plist(path, label="host")

            path.write_bytes(plistlib.dumps(["not", "a", "dictionary"]))
            path.chmod(0o644)
            with self.assertRaisesRegex(BuildIdentityError, "is not a dictionary"):
                release_build_identity._read_plist(path, label="host")

            path.write_bytes(original)
            path.chmod(0o644)
            with patch(
                "scripts.release_build_identity.os.geteuid",
                return_value=os.geteuid() + 1,
            ), self.assertRaisesRegex(
                BuildIdentityError,
                "bounded owned single-link regular file",
            ):
                release_build_identity._read_plist(path, label="host")

    def test_bundle_identity_plist_accepts_root_owned_0644_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = self.make_app(
                Path(directory),
                ("40001", "40001", "40001", "40001"),
            )
            path = self.identity_plists(app)[0]
            actual = path.stat()
            root_owned = SimpleNamespace(
                st_dev=actual.st_dev,
                st_ino=actual.st_ino,
                st_mode=actual.st_mode,
                st_nlink=actual.st_nlink,
                st_uid=0,
                st_gid=actual.st_gid,
                st_size=actual.st_size,
                st_mtime_ns=actual.st_mtime_ns,
            )
            with (
                patch.object(Path, "lstat", return_value=root_owned),
                patch.object(Path, "stat", return_value=root_owned),
                patch(
                    "scripts.release_regular_file.os.fstat",
                    return_value=root_owned,
                ),
            ):
                value = release_build_identity._read_plist(path, label="host")

            self.assertEqual(value["CFBundleVersion"], "40001")

    def test_bundle_identity_version_error_does_not_echo_untrusted_value(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = self.make_app(
                Path(directory),
                ("40001", "40001", "40001", "40001"),
            )
            path = self.identity_plists(app)[0]
            value = plistlib.loads(path.read_bytes())
            marker = "untrusted-version-marker"
            value["CFBundleShortVersionString"] = marker
            path.write_bytes(plistlib.dumps(value))
            path.chmod(0o644)

            with self.assertRaisesRegex(
                BuildIdentityError,
                "CFBundleShortVersionString must be one canonical MAJOR.MINOR.PATCH version",
            ) as raised:
                bundle_build_identity(app)

            self.assertNotIn(marker, str(raised.exception))

    def test_bundle_identity_plist_detects_open_and_read_rebinding(self) -> None:
        for operation in ("open", "read"):
            with (
                self.subTest(operation=operation),
                tempfile.TemporaryDirectory() as directory,
            ):
                app = self.make_app(
                    Path(directory),
                    ("40001", "40001", "40001", "40001"),
                )
                path = self.identity_plists(app)[0]
                parked = path.with_name(path.name + ".parked")
                replacement = path.with_name(path.name + ".replacement")
                replacement.write_bytes(
                    plistlib.dumps(
                        {
                            "CFBundleShortVersionString": PRODUCT_VERSION,
                            "CFBundleVersion": "40002",
                        }
                    )
                )
                replacement.chmod(0o644)
                rebound = False
                closed: list[int] = []
                original_open = os.open
                original_read = os.read
                original_close = os.close

                def rebinding_open(target: Path, flags: int) -> int:
                    nonlocal rebound
                    if not rebound and Path(target) == path:
                        rebound = True
                        path.rename(parked)
                        replacement.rename(path)
                    return original_open(target, flags)

                def rebinding_read(descriptor: int, count: int) -> bytes:
                    nonlocal rebound
                    chunk = original_read(descriptor, count)
                    if chunk and not rebound:
                        rebound = True
                        path.rename(parked)
                        replacement.rename(path)
                    return chunk

                def closing(descriptor: int) -> None:
                    closed.append(descriptor)
                    original_close(descriptor)

                patch_target = (
                    "scripts.release_regular_file.os.open"
                    if operation == "open"
                    else "scripts.release_regular_file.os.read"
                )
                patch_value = rebinding_open if operation == "open" else rebinding_read
                with (
                    patch(patch_target, side_effect=patch_value),
                    patch(
                        "scripts.release_regular_file.os.close",
                        side_effect=closing,
                    ),
                    self.assertRaisesRegex(
                        BuildIdentityError,
                        f"changed while {operation}ing"
                        if operation == "open"
                        else "changed while reading",
                    ),
                ):
                    release_build_identity._read_plist(path, label="host")
                self.assertTrue(rebound)
                self.assertEqual(len(closed), 1)

    def test_mismatched_nested_build_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = self.make_app(
                Path(directory), ("40001", "40001", "40001", "40000")
            )
            with self.assertRaisesRegex(BuildIdentityError, "differ"):
                bundle_build_identity(app)

    def test_the_reader_returns_the_product_version_the_bundles_record(self) -> None:
        # An installed predecessor records an earlier product version; only a
        # candidate must record the active one.
        other = next_patch(PRODUCT_VERSION)
        with tempfile.TemporaryDirectory() as directory:
            app = self.make_app(Path(directory), (GA_BUILD,) * 4, version=other)
            self.assertEqual(read_bundle_identity(app), BundleBuildIdentity(other, GA_BUILD))
            with self.assertRaisesRegex(
                BuildIdentityError, "CFBundleShortVersionString is not the fixed product version"
            ):
                bundle_build_identity(app)

    def test_mismatched_nested_product_version_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            app = self.make_app(Path(directory), (GA_BUILD,) * 4)
            path = self.identity_plists(app)[3]
            value = plistlib.loads(path.read_bytes())
            value["CFBundleShortVersionString"] = next_patch(PRODUCT_VERSION)
            path.write_bytes(plistlib.dumps(value))
            path.chmod(0o644)
            for read in (read_bundle_identity, bundle_build_identity):
                with self.subTest(reader=read.__name__):
                    with self.assertRaisesRegex(BuildIdentityError, "product versions differ"):
                        read(app)

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
            Path(f"/repo/target/candidates/{PRODUCT_VERSION}/ga-preflight/{GA_BUILD}"),
        )
        self.assertEqual(
            ga_root(repository),
            Path(f"/repo/target/candidates/{PRODUCT_VERSION}/ga/{GA_BUILD}"),
        )
        self.assertEqual(
            ga_pre_sign_native_products_root(repository),
            Path(
                f"/repo/target/candidates/{PRODUCT_VERSION}/ga-preflight/{GA_BUILD}/native-products"
            ),
        )
        self.assertEqual(
            ga_signed_root(repository),
            Path(f"/repo/target/candidates/{PRODUCT_VERSION}/ga/{GA_BUILD}/signed"),
        )
        self.assertEqual(
            ga_signed_native_products_root(repository),
            Path(
                f"/repo/target/candidates/{PRODUCT_VERSION}/ga/{GA_BUILD}/signing-output/signed-native-products"
            ),
        )

    def test_signed_builder_admits_the_active_build_before_preflight_creation(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        source = (repository / "scripts/build_signed_candidate.sh").read_text(
            encoding="utf-8"
        )
        operation_mappings = (
            (
                "  --ga)\n"
                '    [[ $# -eq 1 ]] || die "--ga accepts no additional arguments"\n'
                '    candidate_operation="build"'
            ),
            (
                "  --resume-signing)\n"
                '    [[ $# -eq 1 ]] || die "--resume-signing accepts no additional arguments"\n'
                '    candidate_operation="resume-signing"'
            ),
            (
                "  --recover-notarization-id)\n"
                "    [[ $# -eq 2 ]] || "
                'die "--recover-notarization-id requires one submission UUID"\n'
                '    [[ -n "$2" ]] ||\n'
                '      die "--recover-notarization-id requires one non-empty submission UUID"\n'
                '    candidate_operation="recover-notarization"'
            ),
        )
        for operation_mapping in operation_mappings:
            self.assertEqual(source.count(operation_mapping), 1)

        self.assertEqual(source.count(SIGNED_BUILDER_DERIVATION_START), 1)
        self.assertEqual(source.count(SIGNED_BUILDER_DERIVATION_END), 1)
        derivation_start = source.index(SIGNED_BUILDER_DERIVATION_START)
        derivation_end = source.index(SIGNED_BUILDER_DERIVATION_END)
        preflight_assignment = source.index(
            'preflight_root="$candidate_base/ga-preflight/$CFW_BUILD_NUMBER"'
        )
        candidate_parent_creation = source.index('mkdir -p "$parent"')
        preflight_creation = source.index('mkdir -m 0700 "$preflight_root"')

        self.assertLess(derivation_start, derivation_end)
        self.assertLess(derivation_end, preflight_assignment)
        self.assertLess(derivation_end, candidate_parent_creation)
        self.assertLess(derivation_end, preflight_creation)

    def run_signed_builder_derivation(
        self, preset: str | None, identity_repository: Path | None = None
    ) -> subprocess.CompletedProcess[str]:
        """Runs the signed builder's build derivation with an optional preset."""

        repository = Path(__file__).resolve().parents[2]
        source = (repository / "scripts/build_signed_candidate.sh").read_text(
            encoding="utf-8"
        )
        die_start = source.index("die() {\n")
        die_end = source.index("\n}\n", die_start) + len("\n}\n")
        start = source.index(SIGNED_BUILDER_DERIVATION_START)
        end = source.index(SIGNED_BUILDER_DERIVATION_END) + len(
            SIGNED_BUILDER_DERIVATION_END
        )
        script = (
            "set -euo pipefail\n"
            'repo_root="$1"\npython_bin="$2"\n'
            + source[die_start:die_end]
            + source[start:end]
            + "\n/usr/bin/printenv CFW_BUILD_NUMBER\n"
        )
        environment = {"PATH": "/usr/bin:/bin"}
        if preset is not None:
            environment["CFW_BUILD_NUMBER"] = preset
        return subprocess.run(
            [
                "/bin/bash",
                "-p",
                "-c",
                script,
                "signed-builder-build",
                str(identity_repository or repository),
                sys.executable,
            ],
            env=environment,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def test_signed_builder_derives_and_exports_the_active_build(self) -> None:
        for preset in (None, GA_BUILD):
            with self.subTest(preset=preset):
                completed = self.run_signed_builder_derivation(preset)
                self.assertEqual(completed.returncode, 0, completed.stderr)
                self.assertEqual(completed.stdout, f"{GA_BUILD}\n")
                self.assertEqual(completed.stderr, "")

    def test_signed_builder_refuses_a_preset_build_that_differs(self) -> None:
        for preset in (
            NEXT_GA_BUILD,
            *retired_ga_builds(),
            UNSIGNED_VALIDATION_BUILD,
            noncanonical(GA_BUILD),
            f"{GA_BUILD} ",
            "",
        ):
            with self.subTest(preset=preset):
                completed = self.run_signed_builder_derivation(preset)
                self.assertEqual(completed.returncode, 1)
                self.assertEqual(completed.stdout, "")
                self.assertIn(
                    f"differs from the active GA build {GA_BUILD}", completed.stderr
                )

    def test_signed_builder_refuses_an_unreadable_release_identity(self) -> None:
        repository = Path(__file__).resolve().parents[2]
        with tempfile.TemporaryDirectory() as directory:
            identity_repository = Path(directory).resolve()
            scripts = identity_repository / "scripts"
            scripts.mkdir()
            for name in ("release_build_identity.py", "release_regular_file.py"):
                (scripts / name).write_bytes((repository / "scripts" / name).read_bytes())
            (scripts / "release_identity.env").write_bytes(
                f"CFW_PRODUCT_VERSION={PRODUCT_VERSION}\n"
                f"CFW_GA_BUILD={noncanonical(GA_BUILD)}\n".encode("ascii")
            )
            completed = self.run_signed_builder_derivation(None, identity_repository)
        self.assertEqual(completed.returncode, 1)
        self.assertEqual(completed.stdout, "")
        self.assertIn(
            "not one canonical CFW_PRODUCT_VERSION and CFW_GA_BUILD record", completed.stderr
        )
        self.assertIn(
            "cannot read the active release identity from scripts/release_identity.env",
            completed.stderr,
        )

    def run_signing_helper(
        self, inherited_build: str | None
    ) -> subprocess.CompletedProcess[str]:
        """Runs the signing helper until its first refusal."""

        repository = Path(__file__).resolve().parents[2]
        environment = dict(os.environ)
        environment.pop("CFW_BUILD_NUMBER", None)
        environment.update(
            {
                "CFW_SIGNING_ATTEMPT_WORK": "/nonexistent/cfm-signing-attempt-work",
                "CFW_SIGNING_CERTIFICATE_SHA1": "A" * 40,
                "CFW_SIGNING_CERTIFICATE_SHA256": "B" * 64,
            }
        )
        if inherited_build is not None:
            environment["CFW_BUILD_NUMBER"] = inherited_build
        return subprocess.run(
            [
                "/bin/bash",
                "-p",
                str(repository / "scripts/run_ga_signing_attempt.sh"),
                "--transaction-owned",
            ],
            env=environment,
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )

    def test_signing_helper_requires_the_build_its_builder_exported(self) -> None:
        # The build check precedes the production environment seal, which
        # the hosted unsigned-validation role refuses next.
        accepted = self.run_signing_helper(GA_BUILD)
        self.assertEqual(accepted.returncode, 1)
        self.assertNotIn("inherited CFW_BUILD_NUMBER", accepted.stderr)
        if "CFW_UNSIGNED_VALIDATION_PYTHON" in os.environ:
            self.assertIn(
                "refuses an unsigned-validation Python selection", accepted.stderr
            )
        else:
            self.assertIn(
                "transaction work root is not a real directory", accepted.stderr
            )
        for inherited in (None, "", NEXT_GA_BUILD, noncanonical(GA_BUILD)):
            with self.subTest(inherited=inherited):
                refused = self.run_signing_helper(inherited)
                self.assertEqual(refused.returncode, 1)
                self.assertIn(
                    "inherited CFW_BUILD_NUMBER is not the active GA build "
                    f"{GA_BUILD}",
                    refused.stderr,
                )
                self.assertNotIn("transaction work root", refused.stderr)
                self.assertNotIn("unsigned-validation", refused.stderr)

    def test_candidate_native_output_accepts_only_exact_build_roots(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            repository = Path(directory).resolve()
            accepted = (
                (
                    UNSIGNED_VALIDATION_BUILD,
                    repository / f"target/candidates/{PRODUCT_VERSION}/unsigned/native-products",
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
                    GA_BUILD,
                    repository
                    / f"target/candidates/{PRODUCT_VERSION}/validation/{GA_BUILD}/native-products",
                ),
                (
                    GA_BUILD,
                    repository
                    / f"target/candidates/{PRODUCT_VERSION}/release-build/{GA_BUILD}/native-products",
                ),
                (
                    "40030",
                    repository
                    / f"target/candidates/{PRODUCT_VERSION}/ga-preflight/40030/native-products",
                ),
                (
                    "40031",
                    repository
                    / f"target/candidates/{PRODUCT_VERSION}/ga-preflight/40031/native-products",
                ),
                (
                    "40032",
                    repository
                    / f"target/candidates/{PRODUCT_VERSION}/ga-preflight/40032/native-products",
                ),
                (
                    "40033",
                    repository
                    / f"target/candidates/{PRODUCT_VERSION}/ga-preflight/40033/native-products",
                ),
                (
                    "40034",
                    repository
                    / f"target/candidates/{PRODUCT_VERSION}/ga-preflight/40034/native-products",
                ),
                (
                    "40035",
                    repository
                    / f"target/candidates/{PRODUCT_VERSION}/ga-preflight/40035/native-products",
                ),
                (
                    "40036",
                    repository
                    / f"target/candidates/{PRODUCT_VERSION}/ga-preflight/40036/native-products",
                ),
                (
                    "40037",
                    repository
                    / f"target/candidates/{PRODUCT_VERSION}/ga-preflight/40037/native-products",
                ),
                (
                    "40038",
                    repository
                    / f"target/candidates/{PRODUCT_VERSION}/ga-preflight/40038/native-products",
                ),
                (
                    GA_BUILD,
                    repository
                    / f"target/candidates/{PRODUCT_VERSION}/ga-preflight/../../../../tmp/escape/native-products",
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
                    + f"/target/candidates/{PRODUCT_VERSION}/ga-preflight//{GA_BUILD}/native-products",
                    GA_BUILD,
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
                    repository, str(output), GA_BUILD
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
                    GA_BUILD,
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
                        GA_BUILD,
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
                    GA_BUILD,
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
                self.assertEqual(paths.build_identity.build_version, GA_BUILD)

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
                        (GA_BUILD,) * 4,
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
                    (GA_BUILD,) * 4,
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
            with (
                patch(
                    "scripts.release_build_identity.bundle_build_identity",
                    return_value=BundleBuildIdentity(PRODUCT_VERSION, GA_BUILD),
                ),
                patch(
                    "scripts.release_build_identity.os.geteuid",
                    return_value=os.geteuid() + 1,
                ),
                self.assertRaisesRegex(BuildIdentityError, "current-user"),
            ):
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
                (GA_BUILD,) * 4,
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
        legacy_source = (
            repository / "scripts/build_legacy_tombstone.sh"
        ).read_text(encoding="utf-8")
        self.assertIn("--algorithm sha256-tree-v1", legacy_source)


if __name__ == "__main__":
    unittest.main()
