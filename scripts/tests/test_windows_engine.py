from __future__ import annotations

import importlib.util
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
import tempfile
import unittest
import zipfile
from unittest.mock import patch


REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY / "scripts"))
SPEC = importlib.util.spec_from_file_location("windows_engine", REPOSITORY / "scripts/windows_engine.py")
engine = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(engine)

ENGINE_ROOTS = ("github.com/sagernet/sing-box/cmd/sing-box", "github.com/sagernet/sing-box/cmd/cfw-engine-host")
AFFECTED_BY_NONE = ("Your code is affected by 0 vulnerabilities.\n"
                    "This scan also found 0 vulnerabilities in packages you import and 1\n"
                    "vulnerability in modules you require, but your code doesn't appear to call these\n"
                    "vulnerabilities.\n")


def scan_report_text(pins: dict[str, str], *, go: str | None = None, scanner: str | None = None,
                     database: str = "https://vuln.go.dev", updated: str = "DB updated: 2026-10-21 00:27:29 +0000 UTC",
                     roots: tuple[str, ...] = ENGINE_ROOTS, root_count: int | None = None,
                     modules: tuple[str, ...] = ("github.com/sagernet/sing-box", "filippo.io/age@v1.3.2",
                                                 "golang.org/x/crypto@v0.58.0"),
                     module_count: int | None = None, module_go: str | None = None,
                     conclusion: str = AFFECTED_BY_NONE, advisories: tuple[str, ...] = ("GO-2026-5932",)) -> str:
    """The govulncheck 1.9.0 text report of a verbose symbol scan, as the engine lane captures it."""
    go = go or f"go{pins['GO_VERSION']}"
    scanner = scanner or f"govulncheck@{pins['GOVULNCHECK_VERSION']}"
    root_count = len(roots) if root_count is None else root_count
    module_count = len(modules) if module_count is None else module_count
    module_go = module_go or go
    findings = "".join(f"Vulnerability #{index}: {advisory}\n    The golang.org/x/crypto/openpgp package is unmaintained\n"
                       f"  More info: https://pkg.go.dev/vuln/{advisory}\n  Module: golang.org/x/crypto\n"
                       "    Found in: golang.org/x/crypto@v0.58.0\n    Fixed in: N/A\n\n"
                       for index, advisory in enumerate(advisories, 1))
    return (f"Go: {go}\nScanner: {scanner}\nDB: {database}\n{updated}\n\n"
            "Fetching vulnerabilities from the database...\n\nChecking the code against the vulnerabilities...\n\n"
            f"The package pattern matched the following {root_count} root packages:\n"
            + "".join(f"  {root}\n" for root in roots)
            + f"Govulncheck scanned the following {module_count} modules and the {module_go} standard library:\n"
            + "".join(f"  {module}\n" for module in modules)
            + "\n=== Symbol Results ===\n\nNo vulnerabilities found.\n\n=== Package Results ===\n\n"
            "No other vulnerabilities found.\n\n=== Module Results ===\n\n" + findings + conclusion)


class WindowsEngineContractTests(unittest.TestCase):
    def test_real_windows_fixture_overlay_preserves_all_production_and_ga_bytes(self) -> None:
        pins = engine.read_pins(REPOSITORY)
        patch = engine.pinned_path(REPOSITORY, pins["SING_BOX_DNS_FAILOVER_PATCH_PATH"]).read_text()
        # This GA patch adds the entire fixture. Reconstruct that existing input
        # rather than keeping a second hand-maintained copy in the repository.
        section = patch.split("+++ b/dns/runtime_policy_test.go\n", 1)[1].split("diff --git ", 1)[0]
        original = "".join(line[1:] for line in section.splitlines(keepends=True) if line.startswith("+"))
        self.assertIn("NXDOMAIN was changed or retried", original)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            baseline = root / "ga-source"
            (baseline / "dns").mkdir(parents=True)
            (baseline / "dns/runtime_policy_test.go").write_bytes(original.encode())
            (baseline / "go.mod").write_bytes(b"module untouched\n")
            (baseline / "runtime.go").write_bytes(b"package unchanged\n")
            before = engine.source_files(baseline)
            source = root / "host-source"
            expected = engine.prepare_host_source(REPOSITORY, baseline, source)
            actual, receipt = engine.apply_test_overlay(REPOSITORY, source, expected)
            self.assertEqual(engine.source_files(baseline), before)
            self.assertEqual(engine.source_files(source), actual)
            self.assertEqual({name for name in actual if actual[name] != expected[name]}, {engine.WINDOWS_TEST_FILE})
            self.assertEqual(receipt["files"][engine.WINDOWS_TEST_FILE]["before_sha256"], before[engine.WINDOWS_TEST_FILE])
            self.assertEqual((source / "runtime.go").read_bytes(), b"package unchanged\n")
            self.assertNotIn(".git", {path.name for path in source.iterdir()})
            text = (source / engine.WINDOWS_TEST_FILE).read_text()
            self.assertIn("NXDOMAIN was changed or retried", text)
            self.assertIn("server failure did not reach the next configured resolver", text)
            self.assertIn("response write for %s: %v", text)
            self.assertIn("fixture writes did not complete", text)
            # The overlay is a zero-context diff bound to line numbers, so a GA
            # patch that grows the file would land its hunks outside the retry
            # test, which the digest checks above cannot see: pin where they land.
            start = text.index("func TestRuntimeDNSPoolRetriesSERVFAILButPreservesNegativeAnswers(")
            end = text.index("\n\t\t})\n\t}\n}\n", start)
            body = text[start:end]
            self.assertLess(body.index("writesDone := make(chan uint16, 3)"), body.index("server := &mdns.Server{"))
            self.assertIn("writesDone <- request.Question[0].Qtype", body)
            self.assertLess(body.index("server failure did not reach the next configured resolver"),
                            body.index("fixture writes did not complete"))
            self.assertNotIn("writesDone", text[:start])
            self.assertNotIn("writesDone", text[end:])

    def test_unchanged_source_check_names_the_added_changed_and_missing_paths(self) -> None:
        expected = {"daemon/a.go": "1", "daemon/b.go": "2", "gone.go": "3"}
        actual = {"daemon/a.go": "1", "daemon/b.go": "9", "daemon/cache.db": "4"}
        engine.require_unchanged(dict(expected), dict(expected), "unchanged")
        with self.assertRaises(RuntimeError) as failure:
            engine.require_unchanged(actual, expected, "build or tests changed engine source bytes")
        self.assertEqual(
            str(failure.exception),
            "build or tests changed engine source bytes: daemon/b.go, daemon/cache.db, gone.go",
        )

    def test_windows_fixture_overlay_rejects_a_production_file_change(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            patch = root / engine.WINDOWS_TEST_OVERLAY
            patch.parent.mkdir(parents=True)
            patch.write_bytes(b"diff --git a/runtime.go b/runtime.go\n--- a/runtime.go\n+++ b/runtime.go\n@@ -1 +1 @@\n-package original\n+package modified\n")
            source = root / "source"
            source.mkdir()
            (source / "runtime.go").write_bytes(b"package original\n")
            before = engine.source_files(source)
            with self.assertRaisesRegex(RuntimeError, "only the DNS test fixture"):
                engine.apply_test_overlay(root, source, before)
            self.assertEqual(engine.source_files(source), before)

    def test_host_source_is_an_exact_overlay_without_mutating_ga_baseline(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source = root / "ga-source"
            source.mkdir()
            (source / "go.mod").write_bytes(b"module unchanged\n")
            before = engine.source_files(source)
            destination = root / "host-source"
            expected = engine.prepare_host_source(REPOSITORY, source, destination)
            self.assertEqual(engine.source_files(source), before)
            self.assertEqual(engine.source_files(destination), expected)
            self.assertEqual((destination / "go.mod").read_bytes(), b"module unchanged\n")
            self.assertEqual((destination / "cmd/cfw-engine-host/main.go").read_bytes(),
                             (REPOSITORY / "native/windows/engine-host/main.go").read_bytes())
            with self.assertRaisesRegex(RuntimeError, "refusing to overwrite"):
                engine.prepare_host_source(REPOSITORY, source, destination)

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
                result = engine.bundle_notices(REPOSITORY, sdk / "bin/go.exe", source, output, {"GOMODCACHE": str(modules)}, pins)
            self.assertEqual(result["components"], 3)
            self.assertEqual(result["files"], 4)
            contents = {path.read_bytes() for path in (output / "licenses").rglob("*") if path.is_file()}
            self.assertIn(b"preserve this upstream notice\n", contents)
            index = json.loads((output / "third-party-notices.json").read_text())
            self.assertFalse(index["release_license_review_complete"])
            for component in index["components"]:
                for file in component["files"]:
                    self.assertEqual(engine.sha256(output / file["path"]), file["sha256"])
            with zipfile.ZipFile(output / result["archive"]["filename"]) as archive:
                self.assertEqual(archive.read("third-party-notices.json"), (output / "third-party-notices.json").read_bytes())
                self.assertEqual(len(archive.infolist()), result["files"] + 1)
                for component in index["components"]:
                    for file in component["files"]:
                        self.assertEqual(archive.read(file["path"]), (output / file["path"]).read_bytes())
            self.assertEqual(result["archive"]["sha256"], engine.sha256(output / result["archive"]["filename"]))

    def test_component_notices_accept_only_the_workspace_sing_replacement(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            workspace, modules, output, sdk = (root / name for name in ("workspace", "modules", "output", "go"))
            corrected = workspace / "cfw-dependencies/sing"
            for directory in (corrected, modules, output, sdk / "bin"):
                directory.mkdir(parents=True)
            (workspace / "LICENSE").write_bytes(b"application license\n")
            (corrected / "LICENSE").write_bytes(b"sing license\n")
            (sdk / "LICENSE").write_bytes(b"Go license\n")
            version = "v0.9.7-0.20261023115459-5dc452e537bf"
            main = {"Module": {"Path": "github.com/sagernet/sing-box", "Main": True, "Dir": str(workspace)}}
            sing = {"Module": {"Path": "github.com/sagernet/sing", "Version": version, "Dir": str(corrected),
                               "Replace": {"Path": "./cfw-dependencies/sing", "Dir": str(corrected)}}}
            pins = {"GO_VERSION": "1.27.3", "SING_BOX_VERSION": "v1.14.4", "LIBBOX_BUILD_TAGS": "with_quic"}
            environment = {"GOMODCACHE": str(modules)}

            def notices(packages):
                data = b"\n".join(json.dumps(item).encode() for item in packages)
                with patch.object(engine, "command", return_value=data):
                    return engine.bundle_notices(REPOSITORY, sdk / "bin/go.exe", workspace, output / str(len(list(output.iterdir()))), environment, pins)

            result = notices([main, sing])
            self.assertEqual((result["components"], result["files"]), (3, 3))
            index = json.loads((output / "0/third-party-notices.json").read_text())
            sing_component = [component for component in index["components"] if component["component"] == "github.com/sagernet/sing"]
            self.assertEqual(len(sing_component), 1)
            self.assertEqual(sing_component[0]["version"], version)
            self.assertEqual((output / "0" / sing_component[0]["files"][0]["path"]).read_bytes(), b"sing license\n")
            elsewhere = modules / "github.com/sagernet/sing@elsewhere"
            elsewhere.mkdir(parents=True)
            (elsewhere / "LICENSE").write_bytes(b"sing license\n")
            for rejected, message in (
                ({"Module": {**sing["Module"], "Dir": str(elsewhere), "Replace": {"Path": "./cfw-dependencies/sing", "Dir": str(elsewhere)}}},
                 "linked module replacement escaped the build workspace"),
                ({"Module": {**sing["Module"], "Replace": {"Path": "./cfw-dependencies/other", "Dir": str(corrected)}}},
                 "unexpected linked module replacement"),
                ({"Module": {**sing["Module"], "Path": "example.invalid/other"}}, "unexpected linked module replacement"),
                ({"Module": {**sing["Module"], "Replace": "./cfw-dependencies/sing"}}, "unexpected linked module replacement"),
            ):
                with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                    notices([main, rejected])

    def test_build_workspace_is_the_source_plus_the_corrected_sing_copy_and_one_replacement(self) -> None:
        version = "v0.9.7-0.20261023115459-5dc452e537bf"
        replace_line = f"\nreplace github.com/sagernet/sing {version} => ./cfw-dependencies/sing\n".encode()

        def layout(root: Path) -> tuple[Path, Path, Path, Path]:
            source, modules, output = root / "host-source", root / "modules", root / "workspace"
            module = modules / f"github.com/sagernet/sing@{version}"
            for directory in (source / "cmd/cfm-build-workspace", source / "common", module / "common/bufio"):
                directory.mkdir(parents=True)
            (source / "go.mod").write_bytes(b"module github.com/sagernet/sing-box\n\nrequire (\n\tgithub.com/sagernet/sing " + version.encode() + b"\n)\n")
            (source / "go.sum").write_bytes(b"github.com/sagernet/sing " + version.encode() + b" h1:zip\n")
            (source / "common/box.go").write_bytes(b"package common\n")
            (source / "cmd/cfm-build-workspace/main.go").write_bytes(b"package main\n")
            (module / "LICENSE").write_bytes(b"sing license\n")
            (module / "common/bufio/bind.go").write_bytes(b"package bufio // uncorrected\n")
            (module / "common/bufio/bind_wait.go").write_bytes(b"package bufio // wait\n")
            return source, modules, module, output

        def tool(source: Path, module: Path, output: Path, mutate=None) -> None:
            """What cmd/cfm-build-workspace does: copy, correct two files, append the replacement."""
            shutil.copytree(source, output)
            shutil.copytree(module, output / "cfw-dependencies/sing")
            (output / "cfw-dependencies/sing/common/bufio/bind.go").write_bytes(b"package bufio // corrected\n")
            (output / "cfw-dependencies/sing/common/bufio/bind_wait.go").write_bytes(b"package bufio // wait corrected\n")
            (output / "go.mod").write_bytes((source / "go.mod").read_bytes() + replace_line)
            if mutate is not None:
                mutate(output)

        def fake_command_for(source: Path, module: Path, output: Path, *, printed=None, replaced_after=True,
                             replaced_before=False, module_dir=None, mutate=None, calls=None):
            def fake_command(arguments, *, cwd=None, env=None, timeout=900):
                if calls is not None:
                    calls.append((arguments, cwd, env))
                if arguments[1:] == ["list", "-m", "-json", "github.com/sagernet/sing"] and cwd == source:
                    record = {"Path": "github.com/sagernet/sing", "Version": version, "Dir": str(module_dir or module), "Sum": "h1:zip"}
                    if replaced_before:
                        record["Replace"] = {"Path": "../elsewhere", "Dir": str(source.parent / "elsewhere")}
                    return json.dumps(record).encode()
                if arguments[1:4] == ["run", "./cmd/cfm-build-workspace", "-module-source"] and cwd == source:
                    self.assertEqual(arguments[4:], [str(module), "-output", str(output)])
                    tool(source, module, output, mutate)
                    return (printed if printed is not None else str(output)).encode() + b"\n"
                if arguments[1:] == ["list", "-m", "-json", "github.com/sagernet/sing"] and cwd == output:
                    record = {"Path": "github.com/sagernet/sing", "Version": version, "Dir": str(output / "cfw-dependencies/sing")}
                    if replaced_after:
                        record["Replace"] = {"Path": "./cfw-dependencies/sing", "Dir": str(output / "cfw-dependencies/sing")}
                    return json.dumps(record).encode()
                raise AssertionError((arguments, cwd))
            return fake_command

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, modules, module, output = layout(root)
            environment = {"GOMODCACHE": str(modules), "GOPROXY": "off", "GOFLAGS": "-mod=readonly", "PATH": "x"}
            calls: list = []
            go = root / "go/bin/go.exe"
            with patch.object(engine, "command", fake_command_for(source, module, output, calls=calls)):
                workspace, record, files = engine.prepare_build_workspace(go, source, environment, output)
            self.assertEqual(workspace, output)
            self.assertEqual([(arguments[1], cwd) for arguments, cwd, _ in calls],
                             [("list", source), ("run", source), ("list", output)])
            self.assertTrue(all(env is environment for _, _, env in calls))
            self.assertEqual(files, engine.source_files(output))
            self.assertEqual(record, {
                "module": "github.com/sagernet/sing", "version": version, "replacement": "./cfw-dependencies/sing",
                "corrected_files": {
                    "common/bufio/bind.go": {"before_sha256": hashlib.sha256(b"package bufio // uncorrected\n").hexdigest(),
                                             "after_sha256": hashlib.sha256(b"package bufio // corrected\n").hexdigest()},
                    "common/bufio/bind_wait.go": {"before_sha256": hashlib.sha256(b"package bufio // wait\n").hexdigest(),
                                                  "after_sha256": hashlib.sha256(b"package bufio // wait corrected\n").hexdigest()}},
                "files_sha256": hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()})
            self.assertEqual(engine.source_files(source)["go.mod"], hashlib.sha256((source / "go.mod").read_bytes()).hexdigest())
            with patch.object(engine, "command", fake_command_for(source, module, output)), \
                    self.assertRaisesRegex(RuntimeError, "refusing to overwrite a build workspace"):
                engine.prepare_build_workspace(go, source, environment, output)

        def drop_correction(workspace: Path) -> None:
            for name in ("bind.go", "bind_wait.go"):
                shutil.copyfile(module / "common/bufio" / name, workspace / "cfw-dependencies/sing/common/bufio" / name)

        cases = (
            (dict(replaced_before=True), "does not require the sing module from the verified cache"),
            (dict(module_dir=Path("/elsewhere") / f"github.com/sagernet/sing@{version}"), "sing module is not the verified cache copy"),
            (dict(printed="/somewhere/else"), "did not produce its exact output"),
            (dict(replaced_after=False), "resolved an unexpected sing replacement"),
            (dict(mutate=lambda workspace: (workspace / "go.mod").write_bytes((workspace / "go.mod").read_bytes() + b"// drift\n")),
             "changed go.mod beyond the relative replacement"),
            (dict(mutate=lambda workspace: (workspace / "common/box.go").write_bytes(b"package common // drift\n")),
             "changed engine source bytes: common/box.go"),
            (dict(mutate=lambda workspace: (workspace / "cfw-dependencies/sing/extra.go").write_bytes(b"package sing\n")),
             "changed the sing module's membership"),
            (dict(mutate=lambda workspace: ((workspace / "cfw-dependencies/other").mkdir(), (workspace / "cfw-dependencies/other/x.go").write_bytes(b"package other\n"))),
             "added unexpected dependencies"),
            (dict(mutate=drop_correction), "applied no correction"),
        )
        for options, message in cases:
            with tempfile.TemporaryDirectory() as temporary, self.subTest(message=message):
                root = Path(temporary).resolve()
                source, modules, module, output = layout(root)
                environment = {"GOMODCACHE": str(modules)}
                with patch.object(engine, "command", fake_command_for(source, module, output, **options)), \
                        self.assertRaisesRegex(RuntimeError, message):
                    engine.prepare_build_workspace(root / "go/bin/go.exe", source, environment, output)

    def test_module_graph_keeps_checksums_and_versioned_replacements_without_local_paths(self) -> None:
        graph = engine.module_graph(b'{"Path":"example.invalid/main","Main":true,"Dir":"private-path"}\n{"Path":"example.invalid/dep","Version":"v1.0.0","Sum":"h1:zip","GoModSum":"h1:mod","Replace":{"Path":"example.invalid/replacement","Version":"v1.0.1","Sum":"h1:other","Dir":"another-private-path"}}\n')
        self.assertEqual(graph[0], {"Path": "example.invalid/main", "Main": True})
        self.assertEqual(graph[1]["GoModSum"], "h1:mod")
        self.assertEqual(graph[1]["Replace"], {"Path": "example.invalid/replacement", "Version": "v1.0.1", "Sum": "h1:other"})
        for invalid in (b'', b'{"Path":"p"}garbage', b'{"Path":"p","Replace":{"Path":"../local"}}'):
            with self.subTest(invalid=invalid), self.assertRaises((RuntimeError, ValueError)):
                engine.module_graph(invalid)

    def test_module_graph_admits_only_the_named_relative_replacement_of_the_workspace(self) -> None:
        replacement = (engine.WORKSPACE_MODULE, engine.WORKSPACE_REPLACEMENT)
        corrected = (b'{"Path":"github.com/sagernet/sing-box","Main":true,"Dir":"workspace"}\n'
                     b'{"Path":"github.com/sagernet/sing","Version":"v0.9.7-0.20261023115459-5dc452e537bf",'
                     b'"Replace":{"Path":"./cfw-dependencies/sing","Dir":"workspace/cfw-dependencies/sing","GoMod":"g","GoVersion":"1.25.0"},'
                     b'"Dir":"workspace/cfw-dependencies/sing"}\n'
                     b'{"Path":"example.invalid/dep","Version":"v1.0.0","Sum":"h1:zip","GoModSum":"h1:mod"}\n')
        graph = engine.module_graph(corrected, local_replacement=replacement)
        self.assertEqual(graph[1], {"Path": "github.com/sagernet/sing", "Version": "v0.9.7-0.20261023115459-5dc452e537bf",
                                    "Replace": {"Path": "./cfw-dependencies/sing"}})
        self.assertEqual(graph[2], {"Path": "example.invalid/dep", "Version": "v1.0.0", "Sum": "h1:zip", "GoModSum": "h1:mod"})
        with self.assertRaisesRegex(RuntimeError, "unversioned local module replacement is not admitted"):
            engine.module_graph(corrected)
        for other in (("github.com/sagernet/sing", "./cfw-dependencies/other"), ("example.invalid/dep", "./cfw-dependencies/sing")):
            with self.subTest(other=other), self.assertRaisesRegex(RuntimeError, "unversioned local module replacement is not admitted"):
                engine.module_graph(corrected, local_replacement=other)
        foreign = corrected.replace(b'"Path":"github.com/sagernet/sing",', b'"Path":"example.invalid/other",')
        with self.assertRaisesRegex(RuntimeError, "unversioned local module replacement is not admitted"):
            engine.module_graph(foreign, local_replacement=replacement)
        with self.assertRaisesRegex(RuntimeError, "unversioned local module replacement is not admitted"):
            engine.module_graph(corrected.replace(b'"Replace":{', b'"Replace":{"Version":"",'), local_replacement=replacement)
        with self.assertRaisesRegex(RuntimeError, "invalid module replacement"):
            engine.module_graph(b'{"Path":"github.com/sagernet/sing","Replace":"./cfw-dependencies/sing"}\n', local_replacement=replacement)

    def test_linked_wintun_preserves_the_separate_official_binary_license(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            source, modules, output, sdk = (root / name for name in ("source", "modules", "output", "go"))
            dependency = modules / "sing-tun"
            package_root = dependency / "internal/wintun"
            for directory in (source, output, sdk / "bin", package_root / "amd64"):
                directory.mkdir(parents=True)
            for directory in (source, sdk, dependency):
                (directory / "LICENSE").write_bytes(b"source license fixture\n")
            binary = b"embedded-byte fixture; not executable or signature evidence"
            (package_root / "amd64/wintun.dll").write_bytes(binary)
            pins = engine.read_pins(REPOSITORY)
            pins["WINTUN_WINDOWS_AMD64_SHA256"] = hashlib.sha256(binary).hexdigest()
            packages = [{"Module": {"Path": "example.invalid/app", "Main": True, "Dir": str(source)}},
                        {"ImportPath": engine.WINTUN_PACKAGE, "Dir": str(package_root), "EmbedFiles": ["amd64/wintun.dll"],
                         "Module": {"Path": "github.com/sagernet/sing-tun", "Version": "v1.0.0", "Dir": str(dependency)}}]
            with patch.object(engine, "command", return_value=b"\n".join(json.dumps(p).encode() for p in packages)):
                result = engine.bundle_notices(REPOSITORY, sdk / "bin/go.exe", source, output, {"GOMODCACHE": str(modules)}, pins)
            self.assertEqual((result["components"], result["files"], result["embedded_binaries"]), (4, 4, 1))
            self.assertEqual((output / "wintun.dll").read_bytes(), binary)
            self.assertEqual(engine.sha256(output / "wintun.dll"), pins["WINTUN_WINDOWS_AMD64_SHA256"])
            index = json.loads((output / "third-party-notices.json").read_text())
            notice, = [item for item in index["components"] if item["component"] == "Wintun prebuilt DLL"]
            self.assertEqual(notice["embedded_binary"]["sha256"], pins["WINTUN_WINDOWS_AMD64_SHA256"])
            self.assertEqual(notice["distribution"]["sha256"], pins["WINTUN_ARCHIVE_SHA256"])
            self.assertEqual((output / notice["files"][0]["path"]).read_bytes(),
                             (REPOSITORY / pins["WINTUN_BINARY_LICENSE_PATH"]).read_bytes())
            self.assertFalse(notice["authenticode_verified"])
            self.assertFalse(notice["driver_runtime_verified"])
            self.assertFalse(index["release_license_review_complete"])
            self.assertNotIn(str(root), json.dumps(index))
            with zipfile.ZipFile(output / result["archive"]["filename"]) as archive:
                self.assertEqual(archive.read(notice["files"][0]["path"]), (REPOSITORY / pins["WINTUN_BINARY_LICENSE_PATH"]).read_bytes())

    def test_wintun_notice_rejects_changed_bytes_license_and_embed_membership(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            module = root / "module"
            directory = module / "internal/wintun"
            (directory / "amd64").mkdir(parents=True)
            (root / "outside").mkdir()
            dll = directory / "amd64/wintun.dll"
            binary = b"embedded-byte fixture"
            dll.write_bytes(binary)
            pins = engine.read_pins(REPOSITORY)
            pins["WINTUN_WINDOWS_AMD64_SHA256"] = hashlib.sha256(binary).hexdigest()
            package = {"ImportPath": engine.WINTUN_PACKAGE, "Dir": str(directory), "EmbedFiles": ["amd64/wintun.dll"]}
            for members in ([], ["../wintun.dll"], ["arm64/wintun.dll"], ["amd64/wintun.dll", "extra.dll"]):
                with self.subTest(members=members), self.assertRaisesRegex(RuntimeError, "embed files"):
                    engine.bundle_wintun_notice(REPOSITORY, {**package, "EmbedFiles": members}, module, root / "output", pins)
            with self.assertRaisesRegex(RuntimeError, "escaped its linked module"):
                engine.bundle_wintun_notice(REPOSITORY, {**package, "Dir": str(root / "outside")}, module, root / "output", pins)
            dll.write_bytes(binary + b"changed")
            with self.assertRaisesRegex(RuntimeError, "differs from the official binary"):
                engine.bundle_wintun_notice(REPOSITORY, package, module, root / "output", pins)
            dll.write_bytes(binary)
            with self.assertRaisesRegex(RuntimeError, "license digest mismatch"):
                engine.bundle_wintun_notice(REPOSITORY, package, module, root / "output", {**pins, "WINTUN_BINARY_LICENSE_SHA256": "0" * 64})
            self.assertFalse((root / "output").exists())

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

    def test_pins_bind_the_scanner_and_its_release_tools_module(self) -> None:
        pins = engine.read_pins(REPOSITORY)
        self.assertRegex(pins["GOVULNCHECK_VERSION"], r"^v\d+\.\d+\.\d+$")
        self.assertRegex(pins["GOVULNCHECK_MODULE_SUM"], r"^h1:[A-Za-z0-9+/]{43}=$")
        tools = REPOSITORY / "tools/go-release-tools"
        engine.verify_release_tools_source(tools, pins)
        for key in ("GO_RELEASE_TOOLS_GO_MOD_SHA256", "GO_RELEASE_TOOLS_GO_SUM_SHA256"):
            with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, "digest mismatch"):
                engine.verify_release_tools_source(tools, {**pins, key: "0" * 64})
        original = (REPOSITORY / "scripts/dependency_pins.env").read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory() as temporary:
            repository = Path(temporary)
            (repository / "scripts").mkdir()
            for key, value, message in (("GOVULNCHECK_VERSION", "1.9.0", "invalid scanner version"),
                                        ("GOVULNCHECK_MODULE_SUM", "h1:short=", "invalid scanner module sum"),
                                        ("GO_RELEASE_TOOLS_GO_SUM_SHA256", "abc", "invalid GO_RELEASE_TOOLS_GO_SUM_SHA256")):
                text, count = re.subn(rf"(?m)^{key}=.*$", f"{key}={value}", original)
                self.assertEqual(count, 1, key)
                (repository / "scripts/dependency_pins.env").write_text(text, encoding="utf-8")
                with self.subTest(key=key), self.assertRaisesRegex(RuntimeError, message):
                    engine.read_pins(repository)

    def test_hermetic_go_environment_owns_one_tree_and_drops_ambient_go_settings(self) -> None:
        ambient = {"GOFLAGS": "-mod=vendor", "GOPROXY": "direct", "CGO_ENABLED": "1", "GOOS": "linux",
                   "PATH": "ambient-path", "TMP": "ambient-tmp"}
        with patch.dict(engine.os.environ, ambient, clear=True):
            environment = engine.hermetic_go_environment(Path("/work"))
        self.assertEqual(environment, {
            "PATH": "ambient-path", "TMP": "ambient-tmp", "GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local",
            "GOTELEMETRY": "off", "CGO_ENABLED": "0", "GOPATH": str(Path("/work/gopath")),
            "GOMODCACHE": str(Path("/work/modules")), "GOCACHE": str(Path("/work/cache")),
            "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org", "GONOSUMDB": "", "GOPRIVATE": "",
            "GONOPROXY": "", "GOFLAGS": "-mod=readonly"})

    def test_scanner_identity_requires_the_pinned_go_scanner_and_module(self) -> None:
        pins = engine.read_pins(REPOSITORY)
        version, module_sum = pins["GOVULNCHECK_VERSION"], pins["GOVULNCHECK_MODULE_SUM"]
        info = (f"C:\\work\\scanner\\bin\\govulncheck.exe: go{pins['GO_VERSION']}\n"
                f"\tpath\t{engine.SCANNER_PACKAGE}\n"
                f"\tmod\t{engine.SCANNER_MODULE}\t{version}\t{module_sum}\n"
                "\tdep\tgolang.org/x/mod\tv0.42.0\th1:ICeL3t2L30ljSPHHxDnR4fqVcBt/zR2zJAb9juavmQg=\n"
                "\tbuild\t-buildmode=exe\n")
        engine.require_scanner_identity(info, pins)
        for broken, message in (
            (info.replace(f": go{pins['GO_VERSION']}", ": go1.26.0"), "not built by the pinned Go"),
            (info.replace(f"\t{version}\t", "\tv1.8.0\t"), "scanner module identity mismatch"),
            (info.replace(module_sum, "h1:" + "A" * 43 + "="), "scanner module identity mismatch"),
            (info.replace(f"\tpath\t{engine.SCANNER_PACKAGE}\n", "\tpath\tgolang.org/x/vuln/cmd/other\n"),
             "scanner package identity mismatch"),
            ("", "not built by the pinned Go"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                engine.require_scanner_identity(broken, pins)

    def test_scanner_installs_from_the_release_tools_module_into_its_own_tree(self) -> None:
        pins = engine.read_pins(REPOSITORY)
        tools = REPOSITORY / "tools/go-release-tools"
        calls: list[tuple[list[str], dict[str, str]]] = []

        def fake_command(arguments, *, cwd=None, env=None, timeout=900, module_sum=pins["GOVULNCHECK_MODULE_SUM"]):
            calls.append((arguments, env))
            if arguments[1:] == ["-C", str(tools), "install", "-mod=readonly", engine.SCANNER_PACKAGE]:
                Path(env["GOBIN"]).mkdir(parents=True)
                (Path(env["GOBIN"]) / "govulncheck.exe").write_bytes(b"MZ")
                return b""
            if arguments[1:] == ["env", "GOEXE"]:
                return b".exe\n"
            if arguments[1:3] == ["version", "-m"]:
                return (f"{arguments[3]}: go{pins['GO_VERSION']}\n\tpath\t{engine.SCANNER_PACKAGE}\n"
                        f"\tmod\t{engine.SCANNER_MODULE}\t{pins['GOVULNCHECK_VERSION']}\t{module_sum}\n").encode()
            raise AssertionError(arguments)

        with tempfile.TemporaryDirectory() as temporary:
            work = Path(temporary).resolve()
            go = work / "go/bin/go.exe"
            with patch.object(engine, "command", fake_command):
                scanner = engine.prepare_scanner(REPOSITORY, work, go, pins)
            self.assertEqual(scanner, work / "scanner/bin/govulncheck.exe")
            self.assertEqual([arguments[1:3] for arguments, _ in calls], [["-C", str(tools)], ["env", "GOEXE"], ["version", "-m"]])
            self.assertEqual(calls[0][0][0], str(go))
            self.assertEqual(calls[2][0][3], str(scanner))
            environment = calls[0][1]
            self.assertEqual(environment["GOBIN"], str(work / "scanner/bin"))
            self.assertEqual(environment["GOMODCACHE"], str(work / "scanner/modules"))
            self.assertEqual(environment["GOCACHE"], str(work / "scanner/cache"))
            self.assertEqual(environment["GOPROXY"], "https://proxy.golang.org")
            self.assertEqual(environment["GOSUMDB"], "sum.golang.org")
            self.assertEqual(environment["GOFLAGS"], "-mod=readonly")
            self.assertNotIn("GOOS", environment)
            with patch.object(engine, "command", fake_command), \
                    self.assertRaisesRegex(RuntimeError, "refusing to overwrite a scanner tree"):
                engine.prepare_scanner(REPOSITORY, work, go, pins)
            wrong_sum = lambda *arguments, **keywords: fake_command(*arguments, **keywords, module_sum="h1:" + "A" * 43 + "=")
            with patch.object(engine, "command", wrong_sum), \
                    self.assertRaisesRegex(RuntimeError, "scanner module identity mismatch"):
                engine.prepare_scanner(REPOSITORY, work / "second", go, pins)
            with patch.object(engine, "command", fake_command), \
                    self.assertRaisesRegex(RuntimeError, "release tools go.sum digest mismatch"):
                engine.prepare_scanner(REPOSITORY, work / "third", go, {**pins, "GO_RELEASE_TOOLS_GO_SUM_SHA256": "0" * 64})
            self.assertFalse((work / "third").exists())

    def test_scan_report_binds_the_pinned_scanner_database_and_program_roots(self) -> None:
        pins = engine.read_pins(REPOSITORY)
        self.assertEqual(engine.scan_report(scan_report_text(pins), pins), {
            "scanner": {"package": "golang.org/x/vuln/cmd/govulncheck", "version": pins["GOVULNCHECK_VERSION"],
                        "module_sum": pins["GOVULNCHECK_MODULE_SUM"]},
            "go_version": f"go{pins['GO_VERSION']}", "database": "https://vuln.go.dev",
            "database_updated": "2026-10-21 00:27:29 +0000 UTC", "mode": "source", "level": "symbol",
            "root_packages": list(ENGINE_ROOTS), "scanned_modules": 3, "called_vulnerabilities": 0,
            "uncalled_advisories": ["GO-2026-5932"]})
        sbom_only = scan_report_text(pins).split("\n=== Symbol Results ===")[0]
        clean = engine.scan_report(sbom_only + "\nNo vulnerabilities found.\n", pins)
        self.assertEqual((clean["called_vulnerabilities"], clean["uncalled_advisories"]), (0, []))
        for broken, message in (
            (scan_report_text(pins, go="go1.26.0"), "pinned Go, scanner and database"),
            (scan_report_text(pins, scanner="govulncheck@v1.8.0"), "pinned Go, scanner and database"),
            (scan_report_text(pins, database="https://example.invalid"), "pinned Go, scanner and database"),
            ("", "pinned Go, scanner and database"),
            (scan_report_text(pins, updated="DB updated: "), "database modification time"),
            (scan_report_text(pins, updated=""), "database modification time"),
            (scan_report_text(pins, roots=ENGINE_ROOTS[:1]), "exactly the engine and host programs"),
            (scan_report_text(pins, roots=ENGINE_ROOTS[::-1]), "exactly the engine and host programs"),
            (scan_report_text(pins, root_count=3), "exactly the engine and host programs"),
            (scan_report_text(pins, module_go="go1.26.0"), "scanned modules of the pinned Go"),
            (scan_report_text(pins, module_count=4), "module list is inconsistent"),
            (scan_report_text(pins, modules=("filippo.io/age@v1.3.2", "github.com/sagernet/sing-box")),
             "module list is inconsistent"),
            (scan_report_text(pins, conclusion="Your code is affected by 1 vulnerability from 1 module.\n"),
             "called vulnerabilities without its exit code"),
            (sbom_only, "did not conclude"),
        ):
            with self.subTest(message=message), self.assertRaisesRegex(RuntimeError, message):
                engine.scan_report(broken, pins)

    def test_scan_fails_closed_on_the_scanner_exit_code_and_keeps_its_report(self) -> None:
        pins = engine.read_pins(REPOSITORY)
        tags = pins["LIBBOX_BUILD_TAGS"]
        outcome = {"code": 0, "stdout": scan_report_text(pins).encode()}
        runs: list[tuple[list[str], dict[str, str]]] = []

        def fake_run(arguments, *, env, capture_output, timeout):
            self.assertTrue(capture_output)
            runs.append((arguments, env))
            return engine.subprocess.CompletedProcess(arguments, outcome["code"], outcome["stdout"], b"scanner stderr\n")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve()
            output, scanner, go, source = root / "artifacts", root / "scanner/bin/govulncheck.exe", root / "go/bin/go.exe", root / "host-source"
            output.mkdir()
            environment = {"PATH": "ambient-path", "GOOS": "windows", "GOPROXY": "off", "GOFLAGS": "-mod=readonly"}
            with patch.object(engine.subprocess, "run", fake_run):
                report = engine.scan_vulnerabilities(scanner, go, source, environment, tags, pins, output, "pinned")
            self.assertEqual((report["called_vulnerabilities"], report["scanned_modules"]), (0, 3))
            arguments, env = runs[0]
            self.assertEqual(arguments, [str(scanner), "-C", str(source), "-db", "https://vuln.go.dev", "-mode", "source",
                                         "-scan", "symbol", "-show", "version,verbose", "-tags", tags,
                                         "./cmd/sing-box", "./cmd/cfw-engine-host"])
            self.assertEqual(env, {**environment, "PATH": os.pathsep.join([str(go.parent), "ambient-path"])})
            self.assertEqual((output / "vulnerability-scan-pinned.txt").read_bytes(), outcome["stdout"])
            self.assertEqual((output / "vulnerability-scan-pinned.stderr.txt").read_bytes(), b"scanner stderr\n")
            outcome.update(code=3, stdout=b"Your code is affected by 1 vulnerability from 1 module.\n")
            with patch.object(engine.subprocess, "run", fake_run), \
                    self.assertRaisesRegex(RuntimeError, "calls known vulnerable code; inspect vulnerability-scan-corrected.txt"):
                engine.scan_vulnerabilities(scanner, go, source, environment, tags, pins, output, "corrected")
            self.assertEqual((output / "vulnerability-scan-corrected.txt").read_bytes(), outcome["stdout"])
            self.assertEqual((output / "vulnerability-scan-pinned.txt").read_bytes(), scan_report_text(pins).encode())
            outcome.update(code=1, stdout=b"")
            with patch.object(engine.subprocess, "run", fake_run), \
                    self.assertRaisesRegex(RuntimeError, r"vulnerability scan failed \(1\); inspect vulnerability-scan-pinned.stderr.txt"):
                engine.scan_vulnerabilities(scanner, go, source, environment, tags, pins, output, "pinned")
            with patch.object(engine.subprocess, "run", fake_run), self.assertRaisesRegex(RuntimeError, "no PATH"):
                engine.scan_vulnerabilities(scanner, go, source, {"GOOS": "windows"}, tags, pins, output, "pinned")
            self.assertEqual(len(runs), 3)


if __name__ == "__main__":
    unittest.main()
