from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from scripts.publication.common import PublicationError, canonical_json
from scripts.release_capability_inventory import (
    CAPABILITY_IDS,
    INVENTORY_PATH,
    REQUIREMENTS_PATH,
    expected_capability_levels,
    expected_report_contracts,
    require_complete_capability_set,
    require_fixed_evidence_mapping,
    validate_inventory,
)


REPOSITORY = Path(__file__).resolve().parent.parent.parent


class ReleaseCapabilityInventoryTests(unittest.TestCase):
    def test_direct_cli_invocation_uses_the_supported_import_mode(self) -> None:
        completed = subprocess.run(
            ["python3", "-B", "scripts/release_capability_inventory.py"],
            cwd=REPOSITORY,
            capture_output=True,
            text=True,
            check=True,
        )
        self.assertIn("capabilities=9 requirements=46", completed.stdout)

    def test_inventory_covers_every_numbered_requirement_exactly_once(self) -> None:
        inventory = validate_inventory(REPOSITORY)
        self.assertEqual(tuple(inventory), CAPABILITY_IDS)
        self.assertEqual(sum(map(len, inventory.values())), 46)

    def test_complete_set_is_required_independent_of_order(self) -> None:
        require_complete_capability_set(REPOSITORY, list(reversed(CAPABILITY_IDS)))
        with self.assertRaisesRegex(PublicationError, "missing="):
            require_complete_capability_set(REPOSITORY, list(CAPABILITY_IDS[:-1]))

    def test_inventory_cannot_omit_a_requirement_even_if_json_is_resealed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            inventory_path = repository / INVENTORY_PATH
            requirements_path = repository / REQUIREMENTS_PATH
            inventory_path.parent.mkdir(parents=True)
            requirements_path.parent.mkdir(parents=True)
            inventory = json.loads((REPOSITORY / INVENTORY_PATH).read_bytes())
            inventory["capabilities"][0]["requirements"].pop()
            inventory_path.write_bytes(canonical_json(inventory))
            requirements_path.write_bytes((REPOSITORY / REQUIREMENTS_PATH).read_bytes())
            with self.assertRaisesRegex(PublicationError, "does not exactly cover"):
                validate_inventory(repository)

    def test_noncanonical_inventory_bytes_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            inventory_path = repository / INVENTORY_PATH
            requirements_path = repository / REQUIREMENTS_PATH
            inventory_path.parent.mkdir(parents=True)
            requirements_path.parent.mkdir(parents=True)
            inventory = json.loads((REPOSITORY / INVENTORY_PATH).read_bytes())
            inventory_path.write_text(json.dumps(inventory, indent=2), encoding="utf-8")
            requirements_path.write_bytes((REPOSITORY / REQUIREMENTS_PATH).read_bytes())
            with self.assertRaisesRegex(PublicationError, "not canonical JSON"):
                validate_inventory(repository)

    def test_schema_version_rejects_float_and_bool(self) -> None:
        for invalid in (1.0, True):
            with self.subTest(invalid=invalid), tempfile.TemporaryDirectory() as temporary:
                repository = Path(temporary)
                inventory_path = repository / INVENTORY_PATH
                requirements_path = repository / REQUIREMENTS_PATH
                inventory_path.parent.mkdir(parents=True)
                requirements_path.parent.mkdir(parents=True)
                inventory = json.loads((REPOSITORY / INVENTORY_PATH).read_bytes())
                inventory["schema_version"] = invalid
                inventory_path.write_bytes(canonical_json(inventory))
                requirements_path.write_bytes((REPOSITORY / REQUIREMENTS_PATH).read_bytes())
                with self.assertRaisesRegex(PublicationError, "unsupported schema"):
                    validate_inventory(repository)

    def test_unknown_numbered_requirements_section_is_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            inventory_path = repository / INVENTORY_PATH
            requirements_path = repository / REQUIREMENTS_PATH
            inventory_path.parent.mkdir(parents=True)
            requirements_path.parent.mkdir(parents=True)
            inventory_path.write_bytes((REPOSITORY / INVENTORY_PATH).read_bytes())
            requirements_path.write_bytes(
                (REPOSITORY / REQUIREMENTS_PATH).read_bytes()
                + b"\n## 10.\n\n1. Added outside the inventory.\n"
            )
            with self.assertRaisesRegex(PublicationError, "unknown numbered section 10"):
                validate_inventory(repository)

    def test_fixed_report_mapping_rejects_cross_capability_substitution(self) -> None:
        value = {
            "reports": [dict(contract) for contract in expected_report_contracts()],
            "capabilities": [
                {
                    "id": capability,
                    "levels": expected_capability_levels(capability),
                }
                for capability in CAPABILITY_IDS
            ],
        }
        require_fixed_evidence_mapping(value)
        first, second = value["capabilities"][:2]
        first["levels"]["Source_Implemented"], second["levels"]["Source_Implemented"] = (
            second["levels"]["Source_Implemented"],
            first["levels"]["Source_Implemented"],
        )
        with self.assertRaisesRegex(PublicationError, "report policy drifted"):
            require_fixed_evidence_mapping(value)


if __name__ == "__main__":
    unittest.main()
