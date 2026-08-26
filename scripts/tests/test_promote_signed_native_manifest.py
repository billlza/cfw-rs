from __future__ import annotations

import json
import os
from pathlib import Path
import tempfile
import unittest

from scripts.hash_artifact import build_manifest
from scripts import promote_signed_native_manifest as promotion


class SignedNativeManifestTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.unsigned = self.root / "CFWProxyAgent.app"
        self.unsigned.mkdir()
        (self.unsigned / "binary").write_bytes(b"unsigned")
        self.metadata = {
            "artifactKind": "native-proxy-agent-v1",
            "buildNumber": "40034",
            "signingMode": "pre-sign",
        }
        self.manifest = self.root / "CFWProxyAgent.app.manifest.json"
        self.manifest.write_text(
            json.dumps(
                build_manifest(self.unsigned, metadata=self.metadata),
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        self.signed = self.root / "signed/CFWProxyAgent.app"
        self.signed.mkdir(parents=True)
        (self.signed / "binary").write_bytes(b"signed")
        (self.signed / "_CodeSignature").write_bytes(b"signature")

    def tearDown(self) -> None:
        self.temporary.cleanup()

    def test_signed_manifest_preserves_metadata_and_binds_pre_sign_input(self) -> None:
        value = promotion.promote_manifest(
            self.unsigned, self.manifest, self.signed
        )

        metadata = value["metadata"]
        self.assertEqual(metadata["artifactKind"], "native-proxy-agent-v1")
        self.assertEqual(metadata["buildNumber"], "40034")
        self.assertEqual(metadata["signingMode"], "developer-id")
        self.assertRegex(metadata["preSignArtifactSha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(metadata["preSignManifestSha256"], r"^[0-9a-f]{64}$")
        self.assertEqual(value["root"], self.signed.name)

    def test_unsigned_artifact_drift_is_rejected(self) -> None:
        (self.unsigned / "binary").write_bytes(b"drift")
        with self.assertRaisesRegex(
            promotion.SignedNativeManifestError, "differs from its manifest"
        ):
            promotion.promote_manifest(self.unsigned, self.manifest, self.signed)

    def test_pre_sign_mode_is_required(self) -> None:
        value = json.loads(self.manifest.read_bytes())
        value["metadata"]["signingMode"] = "developer-id"
        self.manifest.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(
            promotion.SignedNativeManifestError, "metadata is invalid"
        ):
            promotion.promote_manifest(self.unsigned, self.manifest, self.signed)

    def test_signed_product_name_must_match(self) -> None:
        renamed = self.signed.with_name("Substitute.app")
        self.signed.rename(renamed)
        with self.assertRaisesRegex(
            promotion.SignedNativeManifestError, "name differs"
        ):
            promotion.promote_manifest(self.unsigned, self.manifest, renamed)

    def test_manifest_symlink_and_hardlink_are_rejected(self) -> None:
        original = self.manifest.read_bytes()
        self.manifest.unlink()
        target = self.root / "target.json"
        target.write_bytes(original)
        self.manifest.symlink_to(target)
        with self.assertRaisesRegex(
            promotion.SignedNativeManifestError, "regular file"
        ):
            promotion.promote_manifest(self.unsigned, self.manifest, self.signed)

        self.manifest.unlink()
        os.link(target, self.manifest)
        with self.assertRaisesRegex(
            promotion.SignedNativeManifestError, "regular file"
        ):
            promotion.promote_manifest(self.unsigned, self.manifest, self.signed)


if __name__ == "__main__":
    unittest.main()
