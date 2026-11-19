from __future__ import annotations

import contextlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from unittest.mock import ANY, patch

from scripts.audit_rust_target import (
    AUDIT_TIMEOUT_SECONDS,
    AuditContractError,
    METADATA_TIMEOUT_SECONDS,
    OUTPUT_LIMIT_BYTES,
    main,
    parse_audit_result,
    reachable_package_ids,
    render_audit_lock,
    run,
    select_locked_packages,
    target_package_keys,
)
from scripts.publication.bounded_process import BoundedProcessError
from scripts.publication.rust_targets import MACOS_TARGET, WINDOWS_TARGET


REGISTRY = "registry+https://example.invalid/index"
APP = "path+file:///repo#app@0.4.0"


def declaration(name: str, *, rename=None, kind=None, optional=False) -> dict:
    return {"name": name, "rename": rename, "kind": kind, "target": None, "optional": optional}


def edge(name: str, identifier: str, *kinds) -> dict:
    return {
        "name": name,
        "pkg": identifier,
        "dep_kinds": [{"kind": kind, "target": None} for kind in kinds or (None,)],
    }


def graph(*packages) -> dict:
    """Build metadata from (id, features, resolved features, declarations, edges)."""
    return {
        "workspace_members": [APP],
        "resolve": {
            "nodes": [
                {"id": identifier, "features": resolved, "deps": edges}
                for identifier, _table, resolved, _declarations, edges in packages
            ]
        },
        "packages": [
            {
                "id": identifier,
                "name": identifier.rsplit("#", 1)[1].split("@")[0],
                "version": identifier.rsplit("@", 1)[1],
                "source": None if identifier == APP else REGISTRY,
                "features": table,
                "dependencies": declarations,
            }
            for identifier, table, _resolved, declarations, _edges in packages
        ],
    }


def metadata_fixture() -> dict:
    mac_only = f"{REGISTRY}#mac-only@1.0.0"
    return graph(
        (APP, {}, [], [declaration("mac-only")], [edge("mac_only", mac_only)]),
        (mac_only, {}, [], [], []),
    )


WITH = f"{REGISTRY}#with@3.24.0"
CHRONO = f"{REGISTRY}#chrono@0.4.45"
TRAITS = f"{REGISTRY}#num-traits@0.2.19"
WEAK_TABLE = {
    "alloc": ["chrono_0_4?/alloc"],
    "chrono_0_4": ["dep:chrono_0_4"],
    "default": ["alloc"],
}


def weak_feature_fixture(table=WEAK_TABLE, resolved=("alloc", "default")) -> dict:
    """A dependency that names chrono only through a weak feature, as serde_with does."""
    return graph(
        (APP, {}, [], [declaration("with")], [edge("with", WITH)]),
        (
            WITH,
            table,
            list(resolved),
            [declaration("chrono", rename="chrono_0_4", optional=True)],
            [edge("chrono_0_4", CHRONO)],
        ),
        (CHRONO, {"alloc": []}, ["alloc"], [declaration("num-traits")], [edge("num_traits", TRAITS)]),
        (TRAITS, {}, [], [], []),
    )


class TargetAuditTests(unittest.TestCase):
    def test_reachable_graph_starts_at_every_workspace_member(self) -> None:
        self.assertEqual(
            reachable_package_ids(metadata_fixture()),
            {
                "path+file:///repo#app@0.4.0",
                "registry+https://example.invalid/index#mac-only@1.0.0",
            },
        )

    def test_weak_feature_dependency_is_outside_the_audited_graph(self) -> None:
        self.assertEqual(reachable_package_ids(weak_feature_fixture()), {APP, WITH})

    def test_enabled_optional_dependency_is_audited(self) -> None:
        for label, table, resolved in (
            ("implicit feature", WEAK_TABLE, ("alloc", "chrono_0_4", "default")),
            ("dep: in another feature", {"clock": ["dep:chrono_0_4"]}, ("clock",)),
            ("strong feature", {"alloc": ["chrono_0_4/alloc"]}, ("alloc",)),
        ):
            with self.subTest(label):
                self.assertEqual(
                    reachable_package_ids(weak_feature_fixture(table, resolved)),
                    {APP, WITH, CHRONO, TRAITS},
                )

    def test_a_required_edge_audits_a_package_another_edge_skips(self) -> None:
        metadata = weak_feature_fixture()
        metadata["workspace_members"].append(APP)
        metadata["packages"][0]["dependencies"].append(declaration("chrono"))
        metadata["resolve"]["nodes"][0]["deps"].append(edge("chrono", CHRONO))
        self.assertEqual(reachable_package_ids(metadata), {APP, WITH, CHRONO, TRAITS})

    def test_required_declaration_keeps_an_optional_edge(self) -> None:
        metadata = weak_feature_fixture()
        package = metadata["packages"][1]
        package["dependencies"].append(declaration("chrono", rename="chrono_0_4", kind="build"))
        metadata["resolve"]["nodes"][1]["deps"] = [edge("chrono_0_4", CHRONO, None, "build")]
        self.assertEqual(reachable_package_ids(metadata), {APP, WITH, CHRONO, TRAITS})

    def test_only_the_resolved_declaration_counts(self) -> None:
        for kind, target in (("dev", None), (None, "cfg(windows)")):
            with self.subTest(kind=kind, target=target):
                metadata = weak_feature_fixture()
                required = declaration("chrono", rename="chrono_0_4", kind=kind)
                required["target"] = target
                metadata["packages"][1]["dependencies"].append(required)
                self.assertEqual(reachable_package_ids(metadata), {APP, WITH})

    def test_renamed_declarations_follow_their_own_features(self) -> None:
        first, second = f"{REGISTRY}#indexmap@1.9.3", f"{REGISTRY}#indexmap@2.14.2"
        metadata = graph(
            (APP, {}, [], [declaration("with")], [edge("with", WITH)]),
            (
                WITH,
                {"indexmap_1": ["dep:indexmap_1"], "indexmap_2": ["dep:indexmap_2"]},
                ["indexmap_1"],
                [
                    declaration("indexmap", rename="indexmap_1", optional=True),
                    declaration("indexmap", rename="indexmap_2", optional=True),
                ],
                [edge("indexmap_1", first), edge("indexmap_2", second)],
            ),
            (first, {}, [], [], []),
            (second, {}, [], [], []),
        )
        self.assertEqual(reachable_package_ids(metadata), {APP, WITH, first})

    def test_unaccountable_metadata_fails_closed(self) -> None:
        def undeclared(metadata):
            metadata["resolve"]["nodes"][1]["features"] = ["missing"]

        def featureless(metadata):
            del metadata["resolve"]["nodes"][1]["features"]

        def kindless(metadata):
            metadata["resolve"]["nodes"][1]["deps"][0]["dep_kinds"] = []

        def undeclared_edge(metadata):
            metadata["packages"][1]["dependencies"] = [declaration("other")]

        def ambiguous_optional(metadata):
            metadata["packages"][1]["dependencies"][0]["optional"] = None

        def missing_dependency(metadata):
            del metadata["packages"][2]

        def missing_member(metadata):
            del metadata["packages"][0]

        def no_inventory(metadata):
            metadata["packages"] = {}

        def invalid_package(metadata):
            metadata["packages"].append([])

        def anonymous_package(metadata):
            metadata["packages"].append({"name": "anonymous"})

        def duplicate_package(metadata):
            metadata["packages"].append(dict(metadata["packages"][0]))

        def no_resolve(metadata):
            del metadata["resolve"]

        def no_nodes(metadata):
            metadata["resolve"]["nodes"] = {}

        def invalid_node(metadata):
            metadata["resolve"]["nodes"].append([])

        def duplicate_node(metadata):
            metadata["resolve"]["nodes"].append(dict(metadata["resolve"]["nodes"][0]))

        def numeric_member(metadata):
            metadata["workspace_members"] = [1]

        def unresolved_member(metadata):
            metadata["workspace_members"].append("path+file:///repo#other@0.4.0")

        def no_dependency_list(metadata):
            metadata["resolve"]["nodes"][0]["deps"] = {}

        def invalid_edge(metadata):
            metadata["resolve"]["nodes"][0]["deps"] = [[]]

        def unnamed_dependency(metadata):
            metadata["packages"][1]["name"] = None

        def nameless_package(metadata):
            metadata["packages"].append({"id": f"{REGISTRY}#x@1.0.0", "version": "1.0.0"})

        for mutate, message in (
            (undeclared, "does not declare resolved feature 'missing'"),
            (featureless, "no resolved features"),
            (kindless, "invalid dependency"),
            (undeclared_edge, "no declaration for resolved dependency chrono_0_4"),
            (ambiguous_optional, "no declaration for resolved dependency chrono_0_4"),
            (missing_dependency, f"missing from metadata: {CHRONO}"),
            (missing_member, f"missing from metadata: {APP}"),
            (no_inventory, "no package inventory"),
            (invalid_package, "invalid package"),
            (anonymous_package, "identity is incomplete"),
            (duplicate_package, "duplicate cargo package identifier"),
            (nameless_package, "identity is incomplete"),
            (no_resolve, "no complete resolve graph"),
            (no_nodes, "resolve graph has no nodes"),
            (invalid_node, "invalid resolve node"),
            (duplicate_node, f"duplicate cargo resolve node: {APP}"),
            (numeric_member, "identifier is not a string"),
            (unresolved_member, "absent from target resolve graph"),
            (no_dependency_list, f"no dependency list: {APP}"),
            (invalid_edge, f"invalid dependency: {APP}"),
            (unnamed_dependency, f"invalid dependency: {APP}"),
        ):
            with self.subTest(mutate.__name__):
                metadata = weak_feature_fixture()
                mutate(metadata)
                with self.assertRaisesRegex(AuditContractError, re.escape(message)):
                    target_package_keys(metadata)

    def test_target_inventory_excludes_non_resolved_platform_package(self) -> None:
        keys = target_package_keys(metadata_fixture())
        selected = select_locked_packages(
            {
                "version": 4,
                "package": [
                    {"name": "app", "version": "0.4.0"},
                    {
                        "name": "mac-only",
                        "version": "1.0.0",
                        "source": "registry+https://example.invalid/index",
                        "checksum": "abc",
                    },
                    {
                        "name": "linux-only",
                        "version": "1.0.0",
                        "source": "registry+https://example.invalid/index",
                        "checksum": "def",
                    },
                ],
            },
            keys,
        )
        self.assertEqual([package["name"] for package in selected], ["app", "mac-only"])
        rendered = render_audit_lock(selected, "aarch64-apple-darwin")
        self.assertNotIn("linux-only", rendered)
        self.assertNotIn("dependencies =", rendered)

    def test_missing_target_package_fails_closed(self) -> None:
        with self.assertRaisesRegex(AuditContractError, "absent from Cargo.lock"):
            select_locked_packages(
                {"version": 4, "package": [{"name": "app", "version": "0.4.0"}]},
                {("app", "0.4.0", None), ("missing", "1.0.0", None)},
            )

    def test_audit_result_rejects_warnings(self) -> None:
        with self.assertRaisesRegex(AuditContractError, "1 warning"):
            parse_audit_result(
                '{"lockfile":{"dependency-count":2},'
                '"vulnerabilities":{"count":0},'
                '"warnings":{"unmaintained":[{"package":"x"}]}}',
                2,
            )

    def test_audit_result_requires_complete_inventory(self) -> None:
        with self.assertRaisesRegex(AuditContractError, "complete target inventory"):
            parse_audit_result(
                '{"lockfile":{"dependency-count":1},'
                '"vulnerabilities":{"count":0},"warnings":{}}',
                2,
            )


class TargetAuditExecutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.repository = Path(self.directory.name).resolve()
        (self.repository / "Cargo.lock").write_text(
            """version = 4

[[package]]
name = "app"
version = "0.4.0"

[[package]]
name = "mac-only"
version = "1.0.0"
source = "registry+https://example.invalid/index"
checksum = "abc"
""",
            encoding="utf-8",
        )
        self.metadata = json.dumps(metadata_fixture()).encode("utf-8")
        self.audit = json.dumps(
            {
                "lockfile": {"dependency-count": 2},
                "vulnerabilities": {"count": 0},
                "warnings": {},
            }
        ).encode("utf-8")
        self.environment = {
            "CFW_RELEASE_CARGO_EXECUTABLE": "/usr/bin/true",
            "CFW_RELEASE_CARGO_AUDIT_EXECUTABLE": "/usr/bin/false",
            "HOME": str(self.repository),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
        }

    def test_execution_is_bounded_warning_free_and_all_features(self) -> None:
        for no_fetch in (False, True):
            with self.subTest(no_fetch=no_fetch):
                calls = []

                def completed(command, *, cwd, environment, timeout, output_limit):
                    calls.append(
                        (list(command), cwd, dict(environment), timeout, output_limit)
                    )
                    stdout = self.metadata if len(calls) == 1 else self.audit
                    return subprocess.CompletedProcess(command, 0, stdout, b"")

                with patch.dict(os.environ, self.environment, clear=True), patch(
                    "scripts.audit_rust_target.run_bounded_process",
                    side_effect=completed,
                ):
                    self.assertEqual(run(self.repository, no_fetch=no_fetch, target=MACOS_TARGET), 0)

                self.assertEqual(len(calls), 2)
                metadata_command, metadata_cwd, _, metadata_timeout, metadata_limit = (
                    calls[0]
                )
                self.assertEqual(
                    metadata_command,
                    [
                        "/usr/bin/true",
                        "metadata",
                        "--locked",
                        "--all-features",
                        "--filter-platform",
                        "aarch64-apple-darwin",
                        "--format-version",
                        "1",
                    ],
                )
                self.assertEqual(metadata_cwd, self.repository)
                self.assertEqual(metadata_timeout, METADATA_TIMEOUT_SECONDS)
                self.assertEqual(metadata_limit, OUTPUT_LIMIT_BYTES)
                audit_command, _, _, audit_timeout, audit_limit = calls[1]
                self.assertIn("--quiet", audit_command)
                self.assertIn("--no-yanked", audit_command)
                self.assertEqual("--no-fetch" in audit_command, no_fetch)
                self.assertEqual(audit_timeout, AUDIT_TIMEOUT_SECONDS)
                self.assertEqual(audit_limit, OUTPUT_LIMIT_BYTES)

    def test_successful_stderr_is_release_blocking(self) -> None:
        for failing_call in (1, 2):
            with self.subTest(failing_call=failing_call):
                calls = 0

                def completed(command, **_arguments):
                    nonlocal calls
                    calls += 1
                    stdout = self.metadata if calls == 1 else self.audit
                    stderr = b"warning: diagnostic\n" if calls == failing_call else b""
                    return subprocess.CompletedProcess(command, 0, stdout, stderr)

                with patch.dict(os.environ, self.environment, clear=True), patch(
                    "scripts.audit_rust_target.run_bounded_process",
                    side_effect=completed,
                ), self.assertRaisesRegex(AuditContractError, "emitted diagnostics"):
                    run(self.repository, no_fetch=True, target=MACOS_TARGET)

    def test_timeout_and_output_limit_are_typed_failures(self) -> None:
        for reason in ("timeout", "output-limit"):
            with self.subTest(reason=reason), patch.dict(
                os.environ, self.environment, clear=True
            ), patch(
                "scripts.audit_rust_target.run_bounded_process",
                side_effect=BoundedProcessError(
                    reason,
                    "bounded failure",
                    stderr=b"bounded diagnostic",
                ),
            ), self.assertRaisesRegex(
                AuditContractError, f"{reason} boundary: bounded diagnostic"
            ):
                run(self.repository, no_fetch=True, target=MACOS_TARGET)

    def test_nonzero_audit_preserves_bounded_diagnostic(self) -> None:
        results = (
            subprocess.CompletedProcess([], 0, self.metadata, b""),
            subprocess.CompletedProcess([], 7, b"", b"registry unavailable\n"),
        )
        with patch.dict(os.environ, self.environment, clear=True), patch(
            "scripts.audit_rust_target.run_bounded_process", side_effect=results
        ), self.assertRaisesRegex(
            AuditContractError, "status 7: registry unavailable"
        ):
            run(self.repository, no_fetch=True, target=MACOS_TARGET)

    def test_windows_target_audits_the_windows_graph_and_lock(self) -> None:
        calls: list[list[str]] = []
        audit_locks: list[str] = []

        def completed(command, *, cwd, environment, timeout, output_limit):
            calls.append(list(command))
            if len(calls) == 1:
                return subprocess.CompletedProcess(command, 0, self.metadata, b"")
            lock_path = Path(command[command.index("--file") + 1])
            audit_locks.append(lock_path.read_text(encoding="utf-8"))
            return subprocess.CompletedProcess(command, 0, self.audit, b"")

        with patch.dict(os.environ, self.environment, clear=True), patch(
            "scripts.audit_rust_target.run_bounded_process", side_effect=completed
        ):
            self.assertEqual(
                run(self.repository, no_fetch=True, target=WINDOWS_TARGET), 0
            )

        self.assertEqual(len(calls), 2)
        metadata_command = calls[0]
        self.assertEqual(
            metadata_command[metadata_command.index("--filter-platform") + 1],
            WINDOWS_TARGET,
        )
        self.assertEqual(len(audit_locks), 1)
        self.assertIn(f"# target = {WINDOWS_TARGET}\n", audit_locks[0])
        self.assertNotIn(MACOS_TARGET, audit_locks[0])


class TargetAuditCommandLineTests(unittest.TestCase):
    def test_default_and_explicit_targets_reach_run(self) -> None:
        for argv, expected in (
            ([], (False, MACOS_TARGET)),
            (["--no-fetch", "--target", WINDOWS_TARGET], (True, WINDOWS_TARGET)),
        ):
            with self.subTest(argv=argv), patch(
                "scripts.audit_rust_target.run", return_value=0
            ) as run_mock, patch(
                "sys.argv", ["audit_rust_target.py", *argv]
            ), self.assertRaises(SystemExit) as exit_context:
                main()
            self.assertEqual(exit_context.exception.code, 0)
            run_mock.assert_called_once_with(ANY, *expected)

    def test_unknown_target_is_rejected_at_the_command_line(self) -> None:
        with patch("scripts.audit_rust_target.run") as run_mock, patch(
            "sys.argv", ["audit_rust_target.py", "--target", "x86_64-unknown-linux-gnu"]
        ), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(
            SystemExit
        ) as exit_context:
            main()
        self.assertEqual(exit_context.exception.code, 2)
        run_mock.assert_not_called()


if __name__ == "__main__":
    unittest.main()
