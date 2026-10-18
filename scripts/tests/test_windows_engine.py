from __future__ import annotations

import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "scripts"))
SPEC = importlib.util.spec_from_file_location("windows_engine", REPOSITORY / "scripts/windows_engine.py")
engine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(engine)


class WindowsEngineContractTests(unittest.TestCase):
    def test_component_notices_keep_actual_license_and_notice_bytes(self) -> None:
        import json
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, modules, output = root / "source", root / "modules", root / "output"
            sdk = root / "go"
            dependency = modules / "example.invalid/dep@v1.0.0"
            for directory in (source, dependency, output, sdk / "bin"):
                directory.mkdir(parents=True)
            (source / "LICENSE").write_bytes(b"application license\n")
            (dependency / "LICENSE").write_bytes(b"dependency license\n")
            (dependency / "NOTICE").write_bytes(b"preserve this upstream notice\n")
            (sdk / "LICENSE").write_bytes(b"Go license\n")
            packages = [{"Module": {"Path": "example.invalid/app", "Main": True, "Dir": str(source)}},
                        {"Module": {"Path": "example.invalid/dep", "Version": "v1.0.0", "Dir": str(dependency)}}]
            data = b"\n".join(json.dumps(item).encode() for item in packages)
            pins = {"GO_VERSION": "1.27.2", "SING_BOX_VERSION": "v1.14.2", "LIBBOX_BUILD_TAGS": "with_quic"}
            with patch.object(engine, "command", return_value=data):
                result = engine.bundle_notices(sdk / "bin/go.exe", source, output, {"GOMODCACHE": str(modules)}, pins)
            self.assertEqual(result["components"], 3)
            self.assertEqual(result["files"], 4)
            contents = {path.read_bytes() for path in (output / "licenses").rglob("*") if path.is_file()}
            self.assertIn(b"preserve this upstream notice\n", contents)
            index = json.loads((output / "third-party-notices.json").read_text())
            self.assertFalse(index["release_license_review_complete"])
            for component in index["components"]:
                for file in component["files"]:
                    self.assertEqual(engine.sha256(output / file["path"]), file["sha256"])

    def test_module_graph_keeps_checksums_and_versioned_replacements_without_local_paths(self) -> None:
        graph = engine.module_graph(b'{"Path":"example.invalid/main","Main":true,"Dir":"private-path"}\n{"Path":"example.invalid/dep","Version":"v1.0.0","Sum":"h1:zip","GoModSum":"h1:mod","Replace":{"Path":"example.invalid/replacement","Version":"v1.0.1","Sum":"h1:other","Dir":"another-private-path"}}\n')
        self.assertEqual(graph[0], {"Path": "example.invalid/main", "Main": True})
        self.assertEqual(graph[1]["GoModSum"], "h1:mod")
        self.assertEqual(graph[1]["Replace"], {"Path": "example.invalid/replacement", "Version": "v1.0.1", "Sum": "h1:other"})
        for invalid in (b'', b'{"Path":"p"}garbage', b'{"Path":"p","Replace":{"Path":"../local"}}'):
            with self.subTest(invalid=invalid), self.assertRaises((RuntimeError, ValueError)):
                engine.module_graph(invalid)

    def test_existing_mac_patch_and_test_contract_are_used_without_an_alternate_graph(self) -> None:
        pins = engine.read_pins(REPOSITORY)
        packages = engine.test_packages(REPOSITORY, pins)
        self.assertEqual(len(packages), len(set(packages)))
        self.assertIn("./experimental/libbox", packages)
        self.assertIn("./protocol/group", packages)
        self.assertIn("./dns", packages)
        for name in engine.PATCHES:
            path = engine.pinned_path(REPOSITORY, pins[f"SING_BOX_{name}_PATCH_PATH"])
            self.assertEqual(engine.sha256(path), pins[f"SING_BOX_{name}_PATCH_SHA256"])

    def test_a_changed_test_package_contract_is_rejected(self) -> None:
        pins = engine.read_pins(REPOSITORY)
        pins["LIBBOX_MODULE_CACHE_CONTRACT_SHA256"] = "0" * 64
        with self.assertRaisesRegex(RuntimeError, "contract digest mismatch"):
            engine.test_packages(REPOSITORY, pins)

    def test_source_byte_evidence_detects_edits_even_when_git_hides_them(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary).resolve()
            engine.git(source, "init", "--quiet")
            path = source / "tracked.go"
            path.write_bytes(b"package original\n")
            engine.git(source, "add", "tracked.go")
            engine.git(source, "-c", "user.name=CFW Fixture", "-c", "user.email=fixture@example.invalid",
                       "commit", "--quiet", "-m", "fixture")
            before = engine.source_files(source)
            engine.git(source, "update-index", "--assume-unchanged", "tracked.go")
            path.write_bytes(b"package modified\n")
            self.assertFalse(engine.git(source, "diff", "--", "tracked.go"))
            self.assertNotEqual(before, engine.source_files(source))

    def test_preparation_never_overwrites_an_existing_directory(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            source = Path(temporary)
            marker = source / "marker"
            marker.write_text("preserve", encoding="utf-8")
            with self.assertRaisesRegex(RuntimeError, "refusing to overwrite"):
                engine.prepare_source(REPOSITORY, source, engine.read_pins(REPOSITORY))
            self.assertEqual(marker.read_text(encoding="utf-8"), "preserve")

    def test_patch_paths_cannot_escape_the_repository(self) -> None:
        for path in ("../outside.patch", "/tmp/outside.patch", "native\\patch.patch"):
            with self.subTest(path=path), self.assertRaises(RuntimeError):
                engine.pinned_path(REPOSITORY, path)


if __name__ == "__main__":
    unittest.main()
