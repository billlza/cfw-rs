from pathlib import Path
import tempfile
import unittest

from scripts.release_artifact_set import (
    ArtifactSetError,
    _validate_isolated_release_verifier_lock,
)


class ReleaseVerifierLockTests(unittest.TestCase):
    def test_isolated_local_package_must_match_the_source_owned_identity(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "Cargo.lock"
            for version in ("0.4.0", "0.5.0"):
                with self.subTest(version=version):
                    path.write_text(
                        'version = 4\n[[package]]\nname = "cfw-release-verifier"\n'
                        f'version = "{version}"\n', encoding="utf-8"
                    )
                    expected = ("cfw-release-verifier", version)
                    digest = _validate_isolated_release_verifier_lock(path, {"crates": []}, expected)
                    self.assertRegex(digest, "^[0-9a-f]{64}$")
                    for wrong in (("different", version), ("cfw-release-verifier", "0.6.0")):
                        with self.assertRaisesRegex(ArtifactSetError, "unexpected local package"):
                            _validate_isolated_release_verifier_lock(path, {"crates": []}, wrong)
                    with path.open("a", encoding="utf-8") as stream:
                        stream.write('[[package]]\nname = "extra-local-package"\nversion = "1.0.0"\n')
                    with self.assertRaisesRegex(ArtifactSetError, "unexpected local package"):
                        _validate_isolated_release_verifier_lock(path, {"crates": []}, expected)


if __name__ == "__main__":
    unittest.main()
