from __future__ import annotations

import copy
import unittest

from scripts.publication.common import PublicationError
from scripts.publication.sbom import (
    build_cyclonedx,
    build_spdx,
    reject_unreviewed_values,
    validate_components,
)


def _component(copyright_text: str = "NOASSERTION") -> dict:
    return {
        "id": "cargo:fixture:0000000000000000",
        "name": "fixture",
        "version": "1.0.0",
        "ecosystem": "cargo",
        "scope": "runtime",
        "purl": "pkg:cargo/fixture@1.0.0",
        "license_expression": "MIT",
        "copyright_text": copyright_text,
        "license_files": [{"path": "licenses/fixture/LICENSE", "sha256": "1" * 64}],
        "source_path": "source/fixture",
        "source_sha256": "2" * 64,
    }


class PublicationSbomTests(unittest.TestCase):
    def test_exact_copyright_noassertion_is_spdx_only(self) -> None:
        components = validate_components([_component()])
        product = {
            "name": "Clash for Mac",
            "version": "0.4.0",
            "build_number": "40005",
        }
        spdx = build_spdx(product, components, [], [])
        cyclonedx = build_cyclonedx(product, components, [], [])

        self.assertEqual(spdx["packages"][0]["copyrightText"], "NOASSERTION")
        self.assertNotIn("copyright", cyclonedx["components"][0])
        reject_unreviewed_values(spdx)
        reject_unreviewed_values(cyclonedx)

    def test_nonexact_or_noncopyright_noassertion_is_rejected(self) -> None:
        for invalid in ("", "NONE", "UNKNOWN", "noassertion", "UNLICENSED"):
            with self.subTest(invalid=invalid), self.assertRaises(PublicationError):
                validate_components([_component(invalid)])

        invalid_license = _component("Copyright fixture authors")
        invalid_license["license_expression"] = "NOASSERTION"
        with self.assertRaisesRegex(PublicationError, "unreviewed license expression"):
            validate_components([invalid_license])

        spdx = build_spdx(
            {"name": "Fixture", "version": "1.0.0", "build_number": "1"},
            validate_components([_component()]),
            [],
            [],
        )
        forged = copy.deepcopy(spdx)
        forged["packages"][0]["licenseDeclared"] = "NOASSERTION"
        with self.assertRaisesRegex(PublicationError, "unreviewed SBOM value"):
            reject_unreviewed_values(forged)

        forged = copy.deepcopy(spdx)
        forged["packages"][0]["copyrightText"] = "NONE"
        with self.assertRaisesRegex(PublicationError, "unreviewed SBOM value"):
            reject_unreviewed_values(forged)


if __name__ == "__main__":
    unittest.main()
