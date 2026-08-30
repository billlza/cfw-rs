from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

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
            "buildNumber": "40039",
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
        pre_sign = json.loads(self.manifest.read_bytes())
        self.assertEqual(metadata["artifactKind"], "native-proxy-agent-v1")
        self.assertEqual(metadata["buildNumber"], "40039")
        self.assertEqual(metadata["signingMode"], "developer-id")
        self.assertEqual(metadata["preSignArtifactSha256"], pre_sign["sha256"])
        self.assertEqual(
            metadata["preSignManifestSha256"],
            hashlib.sha256(self.manifest.read_bytes()).hexdigest(),
        )
        self.assertEqual(value["root"], self.signed.name)

    def write_signed_manifest(self) -> Path:
        value = promotion.promote_manifest(
            self.unsigned, self.manifest, self.signed
        )
        path = self.root / "signed/CFWProxyAgent.app.manifest.json"
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        return path

    def test_exact_promoted_manifest_is_verified(self) -> None:
        signed_manifest = self.write_signed_manifest()

        observed = promotion.verify_promoted_manifest(
            self.unsigned,
            self.manifest,
            self.signed,
            signed_manifest,
        )

        self.assertEqual(observed, json.loads(signed_manifest.read_bytes()))

    def test_promoted_lineage_and_field_mutations_are_rejected(self) -> None:
        for mutation in ("artifact", "manifest", "missing", "extra"):
            with self.subTest(mutation=mutation):
                signed_manifest = self.write_signed_manifest()
                value = json.loads(signed_manifest.read_bytes())
                if mutation == "artifact":
                    value["metadata"]["preSignArtifactSha256"] = "0" * 64
                elif mutation == "manifest":
                    value["metadata"]["preSignManifestSha256"] = "0" * 64
                elif mutation == "missing":
                    del value["metadata"]["preSignManifestSha256"]
                else:
                    value["metadata"]["unexpected"] = "value"
                signed_manifest.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaisesRegex(
                    promotion.SignedNativeManifestError,
                    "differs from the exact pre-sign promotion",
                ):
                    promotion.verify_promoted_manifest(
                        self.unsigned,
                        self.manifest,
                        self.signed,
                        signed_manifest,
                    )

    def test_signed_manifest_symlink_hardlink_and_duplicate_keys_are_rejected(
        self,
    ) -> None:
        signed_manifest = self.write_signed_manifest()
        original = signed_manifest.read_bytes()
        target = self.root / "signed-manifest-target.json"
        target.write_bytes(original)

        signed_manifest.unlink()
        signed_manifest.symlink_to(target)
        with self.assertRaisesRegex(
            promotion.SignedNativeManifestError, "single-link regular file"
        ):
            promotion.verify_promoted_manifest(
                self.unsigned, self.manifest, self.signed, signed_manifest
            )

        signed_manifest.unlink()
        os.link(target, signed_manifest)
        with self.assertRaisesRegex(
            promotion.SignedNativeManifestError, "single-link regular file"
        ):
            promotion.verify_promoted_manifest(
                self.unsigned, self.manifest, self.signed, signed_manifest
            )

        signed_manifest.unlink()
        target.unlink()
        signed_manifest.write_text(
            '{"algorithm":"sha256-tree-v1","algorithm":"sha256-tree-v1"}',
            encoding="utf-8",
        )
        with self.assertRaisesRegex(
            promotion.SignedNativeManifestError, "repeats field"
        ):
            promotion.verify_promoted_manifest(
                self.unsigned, self.manifest, self.signed, signed_manifest
            )

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

    def test_pre_sign_lineage_fields_are_reserved_for_promotion(self) -> None:
        for field in ("preSignArtifactSha256", "preSignManifestSha256"):
            with self.subTest(field=field):
                value = json.loads(self.manifest.read_bytes())
                value["metadata"][field] = "0" * 64
                self.manifest.write_text(json.dumps(value), encoding="utf-8")
                with self.assertRaisesRegex(
                    promotion.SignedNativeManifestError, "metadata is invalid"
                ):
                    promotion.promote_manifest(
                        self.unsigned, self.manifest, self.signed
                    )
                self.manifest.write_text(
                    json.dumps(
                        build_manifest(self.unsigned, metadata=self.metadata),
                        indent=2,
                        sort_keys=True,
                    )
                    + "\n",
                    encoding="utf-8",
                )

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

    def test_manifest_reader_rejects_unsafe_size_and_mode(self) -> None:
        original = self.manifest.read_bytes()
        cases = ("group-writable", "empty", "oversize")
        for case in cases:
            with self.subTest(case=case):
                self.manifest.write_bytes(original)
                self.manifest.chmod(0o644)
                if case == "group-writable":
                    self.manifest.chmod(0o664)
                elif case == "empty":
                    self.manifest.write_bytes(b"")
                else:
                    with self.manifest.open("r+b") as handle:
                        handle.truncate(promotion.MAX_MANIFEST_BYTES + 1)
                with self.assertRaisesRegex(
                    promotion.SignedNativeManifestError,
                    "bounded owned single-link regular file",
                ):
                    promotion._read_regular(
                        self.manifest,
                        label="pre-sign native manifest",
                    )

    def test_manifest_reader_closes_after_open_identity_failure(self) -> None:
        original_close = os.close
        closed: list[int] = []

        def closing(descriptor: int) -> None:
            closed.append(descriptor)
            original_close(descriptor)

        with (
            patch(
                "scripts.release_regular_file._file_identity",
                side_effect=[(1,), (2,)],
            ),
            patch(
                "scripts.release_regular_file.os.close",
                side_effect=closing,
            ),
        ):
            with self.assertRaisesRegex(
                promotion.SignedNativeManifestError,
                "changed while opening",
            ):
                promotion._read_regular(
                    self.manifest,
                    label="pre-sign native manifest",
                )
        self.assertEqual(len(closed), 1)

    def test_manifest_reader_detects_link_and_path_races(self) -> None:
        self.manifest.write_bytes(b"a" * (2 * 1024 * 1024))
        original_read = os.read
        linked = False

        def linking_read(descriptor: int, count: int) -> bytes:
            nonlocal linked
            chunk = original_read(descriptor, count)
            if chunk and not linked:
                linked = True
                os.link(self.manifest, self.root / "manifest-hardlink.json")
            return chunk

        with patch(
            "scripts.release_regular_file.os.read",
            side_effect=linking_read,
        ):
            with self.assertRaisesRegex(
                promotion.SignedNativeManifestError,
                "changed while reading",
            ):
                promotion._read_regular(
                    self.manifest,
                    label="pre-sign native manifest",
                )

        self.manifest.unlink()
        (self.root / "manifest-hardlink.json").unlink()
        self.manifest.write_bytes(b"a" * (2 * 1024 * 1024))
        parked = self.root / "manifest-original.json"
        replacement = self.root / "manifest-replacement.json"
        replacement.write_bytes(b"b" * (2 * 1024 * 1024))
        rebound = False

        def rebinding_read(descriptor: int, count: int) -> bytes:
            nonlocal rebound
            chunk = original_read(descriptor, count)
            if chunk and not rebound:
                rebound = True
                self.manifest.rename(parked)
                replacement.rename(self.manifest)
            return chunk

        with patch(
            "scripts.release_regular_file.os.read",
            side_effect=rebinding_read,
        ):
            with self.assertRaisesRegex(
                promotion.SignedNativeManifestError,
                "changed while reading",
            ):
                promotion._read_regular(
                    self.manifest,
                    label="pre-sign native manifest",
                )

    def test_manifest_reader_requires_nonblocking_no_follow_open_semantics(self) -> None:
        for flag in ("O_NOFOLLOW", "O_CLOEXEC", "O_NONBLOCK"):
            with self.subTest(flag=flag), patch(
                f"scripts.release_regular_file.os.{flag}", None
            ):
                with self.assertRaisesRegex(
                    promotion.SignedNativeManifestError,
                    "requires O_NOFOLLOW, O_CLOEXEC, and O_NONBLOCK",
                ):
                    promotion._read_regular(
                        self.manifest,
                        label="pre-sign native manifest",
                    )

    def test_manifest_builder_translates_only_declared_input_errors(self) -> None:
        with patch.object(
            promotion,
            "build_manifest",
            side_effect=ValueError("declared artifact validation failure"),
        ):
            with self.assertRaisesRegex(
                promotion.SignedNativeManifestError,
                "pre-sign native artifact is invalid",
            ):
                promotion.promote_manifest(
                    self.unsigned,
                    self.manifest,
                    self.signed,
                )

        with patch.object(
            promotion,
            "build_manifest",
            side_effect=RuntimeError("unexpected implementation failure"),
        ):
            with self.assertRaisesRegex(
                RuntimeError,
                "unexpected implementation failure",
            ):
                promotion.promote_manifest(
                    self.unsigned,
                    self.manifest,
                    self.signed,
                )

if __name__ == "__main__":
    unittest.main()
