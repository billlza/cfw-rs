from __future__ import annotations

import plistlib
import tempfile
import unittest
from pathlib import Path

from scripts.release_build_identity import (
    BuildIdentityError,
    bundle_build_identity,
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
            / "Contents/Library/SystemExtensions/CFWPacketTunnel.systemextension/Contents/Info.plist",
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


if __name__ == "__main__":
    unittest.main()
