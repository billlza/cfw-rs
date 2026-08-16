#!/usr/bin/env python3
"""Fail closed until the production physical-capture source path is complete.

This is a source-readiness gate, not physical evidence.  It proves that the
four source-owned producers are present in one reachable collector flow, that
Packet is no longer a terminal stub, that lifecycle capture has distinct
pre-nonce and post-nonce stages, that every external adversarial controller has
a real SwiftPM target and source path, and that the final Host build includes a
reachable physical-evidence control path.

The command accepts no paths, fixtures, skips, or success overrides.  Missing,
dynamic, ambiguous, or malformed contracts are blockers.
"""

from __future__ import annotations

import argparse
import ast
from dataclasses import dataclass
import importlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import subprocess
import sys
import tomllib
from typing import Any, Final, Iterable, Mapping, Sequence

if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parent))
    import verify_pinned_build_inputs as _pinned_inputs
else:
    from . import verify_pinned_build_inputs as _pinned_inputs

PinnedInputError = _pinned_inputs.PinnedInputError
read_repository_regular_file = _pinned_inputs.read_repository_regular_file


MAX_SOURCE_BYTES: Final = 4 * 1024 * 1024
MAX_RUST_SOURCE_FILES: Final = 512
MAX_RUST_SOURCE_ENTRIES: Final = 2_048
MAX_RUST_SOURCE_TOTAL_BYTES: Final = 64 * 1024 * 1024
SWIFT_PACKAGE_TIMEOUT_SECONDS: Final = 60
SWIFT_PACKAGE_OUTPUT_LIMIT: Final = 4 * 1024 * 1024

PACKET_PATH: Final = "scripts/physical_capture/packet.py"
LIFECYCLE_CONTRACT_PATH: Final = "scripts/harness/lifecycle_matrix.py"
LIFECYCLE_PRODUCER_PATH: Final = "scripts/physical_capture/lifecycle.py"
ADVERSARIAL_PATH: Final = "scripts/physical_capture/adversarial.py"
COLLECTOR_PATH: Final = "scripts/physical_capture/collector.py"
SWIFT_PACKAGE_PATH: Final = "native/macos/Package.swift"
HOST_CARGO_PATH: Final = "apps/cfw-tauri-shell/Cargo.toml"
HOST_BUILD_PATH: Final = "scripts/tauri_host_skeleton.sh"
HOST_SOURCE_ROOT: Final = "apps/cfw-tauri-shell/src"
HOST_MAIN_PATH: Final = f"{HOST_SOURCE_ROOT}/main.rs"
HOST_PACKET_TRANSPORT_PATH: Final = f"{HOST_SOURCE_ROOT}/packet_evidence_transport.rs"
HOST_PACKET_ENGINE_PATH: Final = f"{HOST_SOURCE_ROOT}/engine/packet_evidence.rs"

EXPECTED_HARNESSES: Final = frozenset(
    {"adversarial", "lifecycle", "packet", "performance"}
)
EXPECTED_LIFECYCLE_PROBES: Final = frozenset(
    {
        "inside-out-signatures",
        "team-id",
        "bundle-identifiers",
        "entitlements",
        "provisioning",
        "daemon-registration-approval",
        "daemon-registration-denial",
        "system-extension-approval",
        "system-extension-pending",
        "system-extension-restart",
        "network-extension-approval",
        "network-extension-denial",
        "network-extension-pending",
        "renderer-ready-v2",
        "upgrade",
        "replacement",
        "downgrade-refusal",
        "install-cleanup",
        "uninstall-cleanup",
        "login",
        "logout",
        "lock",
        "fast-user-switching",
        "concurrent-starts",
        "cancellation",
        "sleep-wake",
        "wkwebview-850x603",
        "reboot-recovery",
        "host-crash",
        "global-authority-crash",
        "proxy-agent-crash",
        "provider-crash",
    }
)
EXPECTED_EXTERNAL_CASE_TO_FIXTURE: Final = {
    "wrong-uid": "root-owned-uid-launcher",
    "wrong-audit-session": "isolated-audit-session-controller",
    "stale-pid-evidence": "pid-reuse-window-controller",
    "stale-audit-evidence": "isolated-audit-session-controller",
    "inactive-console-user": "isolated-console-session-controller",
    "replayed-operation": "authority-operation-replay-controller",
    "replayed-start-ticket": "authority-operation-replay-controller",
    "duplicate-redemption": "authority-operation-replay-controller",
    "replay-cursor-rollback": "root-owned-authority-journal-snapshot",
    "authority-journal-truncation": "root-owned-authority-journal-snapshot",
    "authority-journal-tamper": "root-owned-authority-journal-snapshot",
    "authority-journal-symlink": "root-owned-authority-journal-snapshot",
    "request-flood": "bounded-authority-load-controller",
    "in-flight-saturation": "bounded-authority-load-controller",
    "event-queue-saturation": "bounded-authority-load-controller",
    "heartbeat-loss": "signed-owner-liveness-controller",
    "fast-user-switching-race": "fast-user-switch-controller",
    "late-callback": "signed-owner-liveness-controller",
    "secret-extraction-logs": "root-owned-secret-canary-scanner",
    "secret-extraction-preferences": "root-owned-secret-canary-scanner",
    "secret-extraction-journal": "root-owned-secret-canary-scanner",
    "secret-extraction-crash-records": "root-owned-secret-canary-scanner",
    "secret-extraction-snapshots": "root-owned-secret-canary-scanner",
    "secret-extraction-evidence": "root-owned-secret-canary-scanner",
}
EXPECTED_EXTERNAL_FIXTURES: Final = frozenset(
    EXPECTED_EXTERNAL_CASE_TO_FIXTURE.values()
)
EXPECTED_PRIVILEGED_FIXTURES: Final = frozenset(
    {
        "root-owned-uid-launcher",
        "isolated-audit-session-controller",
        "isolated-console-session-controller",
        "root-owned-authority-journal-snapshot",
        "fast-user-switch-controller",
        "root-owned-secret-canary-scanner",
    }
)
EXPECTED_RESET_FIXTURES: Final = frozenset(
    {
        "root-owned-uid-launcher",
        "isolated-audit-session-controller",
        "pid-reuse-window-controller",
        "isolated-console-session-controller",
        "root-owned-authority-journal-snapshot",
        "fast-user-switch-controller",
        "root-owned-secret-canary-scanner",
    }
)
EXPECTED_COLLECTOR_TARGETS: Final = {
    "adversarial": (
        "scripts.physical_capture.adversarial",
        "capture_adversarial_observations",
    ),
    "lifecycle": (
        "scripts.physical_capture.lifecycle",
        "capture_lifecycle_observations",
    ),
    "packet": (
        "scripts.physical_capture.packet",
        "capture_packet_observations",
    ),
    "performance": (
        "scripts.physical_capture.performance",
        "capture_performance_observations",
    ),
}
HOST_FEATURE: Final = "physical-release-evidence"
HOST_PACKET_ENTRYPOINT: Final = "run_packet_evidence_transaction"
HOST_PACKET_ENGINE_ENTRYPOINT: Final = "run_packet_evidence_staged_transaction"

_IDENTIFIER_RE: Final = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_TARGET_RE: Final = re.compile(r"^CFWAdversarial[A-Za-z0-9]{1,96}$")
_SHELL_COMMENT_RE: Final = re.compile(r"(^|\s)#[^\n]*")


class PhysicalCaptureReadinessError(RuntimeError):
    """A source input is missing or cannot be parsed safely."""


@dataclass(frozen=True, order=True, slots=True)
class Blocker:
    code: str
    path: str
    line: int
    detail: str


def _repository() -> Path:
    return Path(__file__).resolve().parent.parent


def _safe_path(repository: Path, relative: str) -> Path:
    candidate = PurePosixPath(relative)
    if (
        not relative
        or candidate.is_absolute()
        or any(component in {"", ".", ".."} for component in candidate.parts)
        or candidate.as_posix() != relative
    ):
        raise PhysicalCaptureReadinessError(
            f"unsafe repository-relative readiness path: {relative!r}"
        )
    return repository.joinpath(*candidate.parts)


def _read_text(repository: Path, relative: str) -> str:
    try:
        body = read_repository_regular_file(
            repository,
            relative,
            f"required readiness source {relative}",
            maximum_size=MAX_SOURCE_BYTES,
        )
    except PinnedInputError as error:
        raise PhysicalCaptureReadinessError(
            f"required readiness source is unavailable or unsafe: {relative}: {error}"
        ) from error
    try:
        return body.decode("utf-8", errors="strict")
    except UnicodeError as error:
        raise PhysicalCaptureReadinessError(
            f"required readiness source is not readable strict UTF-8: {relative}: {error}"
        ) from error


def _python_tree(source: str, relative: str) -> ast.Module:
    try:
        return ast.parse(source, filename=relative)
    except (SyntaxError, ValueError) as error:
        raise PhysicalCaptureReadinessError(
            f"required readiness Python source is invalid: {relative}: {error}"
        ) from error


def _direct_assignments(tree: ast.Module, name: str) -> list[ast.AST]:
    values: list[ast.AST] = []
    for statement in tree.body:
        if isinstance(statement, ast.Assign):
            if any(
                isinstance(target, ast.Name) and target.id == name
                for target in statement.targets
            ):
                if len(statement.targets) != 1:
                    raise PhysicalCaptureReadinessError(
                        f"{name} must have one direct assignment target"
                    )
                values.append(statement.value)
        elif isinstance(statement, ast.AnnAssign):
            if isinstance(statement.target, ast.Name) and statement.target.id == name:
                if statement.value is None:
                    raise PhysicalCaptureReadinessError(f"{name} has no assigned value")
                values.append(statement.value)
    return values


def _unique_assignment(tree: ast.Module, name: str) -> ast.AST:
    values = _direct_assignments(tree, name)
    if len(values) != 1:
        raise PhysicalCaptureReadinessError(
            f"{name} must have exactly one direct source assignment"
        )
    return values[0]


def _literal(node: ast.AST) -> Any:
    if isinstance(node, ast.Call):
        if (
            isinstance(node.func, ast.Name)
            and node.func.id in {"frozenset", "MappingProxyType"}
            and not node.keywords
            and len(node.args) <= 1
        ):
            if not node.args:
                return frozenset() if node.func.id == "frozenset" else {}
            value = _literal(node.args[0])
            return frozenset(value) if node.func.id == "frozenset" else value
        raise PhysicalCaptureReadinessError("source contract is not a literal closed value")
    try:
        return ast.literal_eval(node)
    except (TypeError, ValueError) as error:
        raise PhysicalCaptureReadinessError(
            "source contract is not a literal closed value"
        ) from error


def _literal_mapping_node(node: ast.AST, label: str) -> ast.Dict:
    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "MappingProxyType"
        and len(node.args) == 1
        and not node.keywords
    ):
        node = node.args[0]
    if not isinstance(node, ast.Dict):
        raise PhysicalCaptureReadinessError(
            f"{label} must be one literal MappingProxyType dictionary"
        )
    return node


def _literal_dict_keys(node: ast.AST, label: str) -> tuple[str, ...]:
    mapping = _literal_mapping_node(node, label)
    keys: list[str] = []
    for key in mapping.keys:
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            raise PhysicalCaptureReadinessError(f"{label} contains a dynamic key")
        keys.append(key.value)
    if len(keys) != len(set(keys)):
        raise PhysicalCaptureReadinessError(f"{label} repeats a key")
    return tuple(keys)


def _top_level_functions(tree: ast.Module) -> dict[str, ast.FunctionDef | ast.AsyncFunctionDef]:
    functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
    for statement in tree.body:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if statement.name in functions:
                raise PhysicalCaptureReadinessError(
                    f"Python source repeats function {statement.name!r}"
                )
            functions[statement.name] = statement
    return functions


def _imported_names(tree: ast.Module) -> dict[str, tuple[str, str]]:
    imports: dict[str, tuple[str, str]] = {}
    for statement in tree.body:
        if not isinstance(statement, ast.ImportFrom) or statement.module is None:
            continue
        for item in statement.names:
            local = item.asname or item.name
            imports[local] = (statement.module, item.name)
    return imports


def _call_name(call: ast.Call) -> str | None:
    if isinstance(call.func, ast.Name):
        return call.func.id
    if isinstance(call.func, ast.Attribute):
        return call.func.attr
    return None


def _name_references(node: ast.AST) -> set[str]:
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}


def _literal_boolean(node: ast.AST) -> bool | None:
    if isinstance(node, ast.Constant) and isinstance(node.value, bool):
        return node.value
    return None


def _expression_nodes(node: ast.AST) -> Iterable[ast.AST]:
    """Walk one expression without crossing into a nested statement block."""

    yield node
    for child in ast.iter_child_nodes(node):
        if not isinstance(child, ast.stmt):
            yield from _expression_nodes(child)


def _statement_expression_nodes(statement: ast.stmt) -> Iterable[ast.AST]:
    for _field, value in ast.iter_fields(statement):
        if isinstance(value, ast.AST) and not isinstance(value, ast.stmt):
            yield from _expression_nodes(value)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, ast.AST) and not isinstance(item, ast.stmt):
                    yield from _expression_nodes(item)


def _live_nodes(statements: Sequence[ast.stmt]) -> Iterable[ast.AST]:
    """Yield reachable nodes without entering nested functions or dead branches."""

    for statement in statements:
        if isinstance(statement, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            continue
        yield statement
        yield from _statement_expression_nodes(statement)
        if isinstance(statement, ast.If):
            condition = _literal_boolean(statement.test)
            if condition is True:
                yield from _live_nodes(statement.body)
            elif condition is False:
                yield from _live_nodes(statement.orelse)
            else:
                yield from _live_nodes(statement.body)
                yield from _live_nodes(statement.orelse)
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            yield from _live_nodes(statement.body)
            yield from _live_nodes(statement.orelse)
        elif isinstance(statement, ast.While):
            condition = _literal_boolean(statement.test)
            if condition is not False:
                yield from _live_nodes(statement.body)
            yield from _live_nodes(statement.orelse)
        elif isinstance(statement, ast.Try):
            yield from _live_nodes(statement.body)
            for handler in statement.handlers:
                yield from _live_nodes(handler.body)
            yield from _live_nodes(statement.orelse)
            yield from _live_nodes(statement.finalbody)
        elif isinstance(statement, (ast.With, ast.AsyncWith)):
            yield from _live_nodes(statement.body)
        elif isinstance(statement, ast.Match):
            for case in statement.cases:
                yield from _live_nodes(case.body)
        if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
            break


def _live_calls(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Call]:
    return [node for node in _live_nodes(function.body) if isinstance(node, ast.Call)]


def _live_returns(function: ast.FunctionDef | ast.AsyncFunctionDef) -> list[ast.Return]:
    return [node for node in _live_nodes(function.body) if isinstance(node, ast.Return)]


def _live_called_names(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> set[str]:
    return {
        name
        for call in _live_calls(function)
        for name in [_call_name(call)]
        if name is not None
    }


def _has_live_loop_over(statements: Sequence[ast.stmt], name: str) -> bool:
    for statement in statements:
        if isinstance(statement, ast.If):
            condition = _literal_boolean(statement.test)
            branches = (
                (statement.body,)
                if condition is True
                else (statement.orelse,)
                if condition is False
                else (statement.body, statement.orelse)
            )
            if any(_has_live_loop_over(branch, name) for branch in branches):
                return True
        elif isinstance(statement, (ast.For, ast.AsyncFor)):
            if name in _name_references(statement.iter):
                return True
            if _has_live_loop_over(statement.body, name) or _has_live_loop_over(
                statement.orelse, name
            ):
                return True
        elif isinstance(statement, ast.While):
            if _literal_boolean(statement.test) is not False and _has_live_loop_over(
                statement.body, name
            ):
                return True
            if _has_live_loop_over(statement.orelse, name):
                return True
        elif isinstance(statement, ast.Try):
            blocks = [statement.body, statement.orelse, statement.finalbody]
            blocks.extend(handler.body for handler in statement.handlers)
            if any(_has_live_loop_over(block, name) for block in blocks):
                return True
        if isinstance(statement, (ast.Return, ast.Raise)):
            break
    return False


def _empty_return(value: ast.AST | None) -> bool:
    if value is None or (isinstance(value, ast.Constant) and value.value is None):
        return True
    if isinstance(value, ast.Dict):
        return not value.keys
    return isinstance(value, (ast.List, ast.Set, ast.Tuple)) and not value.elts


def _function_arguments(function: ast.FunctionDef | ast.AsyncFunctionDef) -> set[str]:
    arguments = [*function.args.posonlyargs, *function.args.args, *function.args.kwonlyargs]
    if function.args.vararg is not None:
        arguments.append(function.args.vararg)
    if function.args.kwarg is not None:
        arguments.append(function.args.kwarg)
    return {argument.arg for argument in arguments}


def _packet_issues(source: str) -> tuple[int, list[str]]:
    tree = _python_tree(source, PACKET_PATH)
    issues: list[str] = []
    for name in ("UNRESOLVED_PACKET_CASES", "UNRESOLVED_PACKET_CONTROLS"):
        try:
            value = _literal(_unique_assignment(tree, name))
        except PhysicalCaptureReadinessError as error:
            issues.append(str(error))
            continue
        if not isinstance(value, (set, frozenset)) or value:
            issues.append(f"{name} must be one literal empty frozenset")

    functions = _top_level_functions(tree)
    function = functions.get("capture_packet_observations")
    if function is None:
        return 1, [*issues, "capture_packet_observations is missing"]
    calls = _live_calls(function)
    live_references = {
        node.id
        for node in _live_nodes(function.body)
        if isinstance(node, ast.Name)
    }
    matrix_loops = [
        node
        for node in _live_nodes(function.body)
        if isinstance(node, (ast.For, ast.AsyncFor))
        and isinstance(node.iter, ast.Name)
        and node.iter.id == "REQUIRED_CASES"
    ]
    if not any(
        isinstance(call.func, ast.Name)
        and call.func.id == "run_fixed_host_transaction"
        for loop in matrix_loops
        for call in (
            node for node in _live_nodes(loop.body) if isinstance(node, ast.Call)
        )
    ):
        issues.append(
            "Packet matrix does not directly run the authenticated Host transaction "
            "inside REQUIRED_CASES"
        )
    if not _has_live_loop_over(function.body, "REQUIRED_CASES"):
        issues.append("Packet matrix does not iterate the exact REQUIRED_CASES contract")
    if not {
        "EXPECTED_PACKET_RAW_SUBJECTS",
        "OPTIONAL_PACKET_RAW_SUBJECTS",
    }.issubset(live_references):
        issues.append("Packet matrix does not enforce the complete raw-subject contract")
    if not any(not _empty_return(statement.value) for statement in _live_returns(function)):
        issues.append("Packet matrix has no reachable non-empty production return")
    for call in calls:
        if _call_name(call) != "PacketCaptureAdapterError" or not call.args:
            continue
        if (
            isinstance(call.args[0], ast.Constant)
            and call.args[0].value == "packet_workflow_not_enabled"
        ):
            issues.append("Packet matrix still contains a reachable workflow-disabled stub")
            break
    return function.lineno, issues


def _packet_runtime_issues(repository: Path) -> list[str]:
    """Reopen Packet through the repository import path and validate its pins."""

    original_path = list(sys.path)
    def owned_module(name: str) -> bool:
        return name == "scripts" or name.startswith("scripts.")

    saved_modules = {
        name: module for name, module in sys.modules.items() if owned_module(name)
    }
    for name in list(saved_modules):
        sys.modules.pop(name, None)
    sys.path.insert(0, str(repository))
    try:
        packet = importlib.import_module("scripts.physical_capture.packet")
        packet._validate_endpoint_policy(packet.SOURCE_PINNED_ENDPOINTS)
    except Exception as error:
        return [
            "controlled Packet import/source-policy self-check failed: "
            f"{type(error).__name__}: {error}"
        ]
    finally:
        sys.path[:] = original_path
        for name in list(sys.modules):
            if owned_module(name):
                sys.modules.pop(name, None)
        sys.modules.update(saved_modules)
    return []


def _packet_lease_issues(source: str) -> list[str]:
    tree = _python_tree(source, PACKET_PATH)
    coordinator = next(
        (
            node
            for node in tree.body
            if isinstance(node, ast.ClassDef)
            and node.name == "_PacketCaseCoordinator"
        ),
        None,
    )
    if coordinator is None:
        return ["Packet source has no _PacketCaseCoordinator lease owner"]
    methods = {
        node.name: node
        for node in coordinator.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef))
    }
    required_methods = {
        "_admit_android_lan_peer",
        "_revalidate_android_peer_before_capture",
        "_revalidate_android_peer_after_capture",
        "_close_android_peer",
    }
    issues = [
        f"Packet coordinator is missing Android lease method {name}"
        for name in sorted(required_methods - set(methods))
    ]
    required_calls = {
        "_admit_android_lan_peer",
        "_revalidate_android_peer_before_capture",
        "_revalidate_android_peer_after_capture",
        "_close_android_peer",
    }
    observed_calls = {
        node.func.attr
        for method in methods.values()
        for node in ast.walk(method)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "self"
    }
    issues.extend(
        f"Packet coordinator does not call Android lease operation {name}"
        for name in sorted(required_calls - observed_calls)
    )
    return issues


def _registry_entries(node: ast.AST, label: str) -> dict[str, tuple[str, str]]:
    mapping = _literal_mapping_node(node, label)
    result: dict[str, tuple[str, str]] = {}
    for key, value in zip(mapping.keys, mapping.values, strict=True):
        if not isinstance(key, ast.Constant) or not isinstance(key.value, str):
            raise PhysicalCaptureReadinessError(f"{label} contains a dynamic key")
        if (
            not isinstance(value, ast.Tuple)
            or len(value.elts) != 2
            or any(not isinstance(item, ast.Name) for item in value.elts)
        ):
            raise PhysicalCaptureReadinessError(
                f"{label}[{key.value!r}] must name capture/materialize callables"
            )
        if key.value in result:
            raise PhysicalCaptureReadinessError(f"{label} repeats {key.value!r}")
        result[key.value] = (value.elts[0].id, value.elts[1].id)
    return result


def _registry_is_mutated(tree: ast.Module, name: str, assignment: ast.AST) -> bool:
    for node in ast.walk(tree):
        if node is assignment:
            continue
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign, ast.Delete)):
            targets: list[ast.AST] = []
            if isinstance(node, ast.Assign):
                targets.extend(node.targets)
            elif isinstance(node, ast.AnnAssign):
                targets.append(node.target)
            elif isinstance(node, ast.AugAssign):
                targets.append(node.target)
            else:
                targets.extend(node.targets)
            if any(
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == name
                for target in targets
            ):
                return True
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == name
            and node.func.attr
            in {"clear", "pop", "popitem", "setdefault", "update", "__setitem__"}
        ):
            return True
    return False


def _uses_registry_dispatch(
    function: ast.FunctionDef | ast.AsyncFunctionDef, registry: str
) -> bool:
    selected: set[str] = set()
    for node in _live_nodes(function.body):
        if isinstance(node, (ast.Assign, ast.AnnAssign)):
            value = node.value
            if (
                isinstance(value, ast.Subscript)
                and isinstance(value.value, ast.Name)
                and value.value.id == registry
            ):
                targets = node.targets if isinstance(node, ast.Assign) else [node.target]
                for target in targets:
                    if isinstance(target, ast.Name):
                        selected.add(target.id)
                    elif isinstance(target, (ast.Tuple, ast.List)):
                        selected.update(
                            item.id for item in target.elts if isinstance(item, ast.Name)
                        )
        if isinstance(node, ast.Call):
            if (
                isinstance(node.func, ast.Subscript)
                and isinstance(node.func.value, ast.Name)
                and node.func.value.id == registry
            ):
                return True
            if isinstance(node.func, ast.Name) and node.func.id in selected:
                return True
    return False


def _lifecycle_issues(
    contract_source: str,
    producer_source: str | None,
) -> tuple[int, list[str]]:
    contract_tree = _python_tree(contract_source, LIFECYCLE_CONTRACT_PATH)
    issues: list[str] = []
    try:
        probes = frozenset(
            _literal_dict_keys(
                _unique_assignment(contract_tree, "PROBE_SPECS"), "PROBE_SPECS"
            )
        )
        if probes != EXPECTED_LIFECYCLE_PROBES:
            issues.append("lifecycle PROBE_SPECS differs from the exact 32-probe contract")
    except PhysicalCaptureReadinessError as error:
        issues.append(str(error))

    if producer_source is None:
        return 1, [*issues, "production lifecycle producer module is missing"]
    tree = _python_tree(producer_source, LIFECYCLE_PRODUCER_PATH)
    functions = _top_level_functions(tree)
    try:
        assignment = _unique_assignment(tree, "LIFECYCLE_PRODUCER_REGISTRY")
        registry = _registry_entries(assignment, "LIFECYCLE_PRODUCER_REGISTRY")
        if set(registry) != EXPECTED_LIFECYCLE_PROBES:
            issues.append("lifecycle producer registry is not the exact 32-probe closure")
        if _registry_is_mutated(tree, "LIFECYCLE_PRODUCER_REGISTRY", assignment):
            issues.append("lifecycle producer registry is mutable after declaration")
        available = set(functions) | set(_imported_names(tree))
        for probe, callables in registry.items():
            if any(name not in available for name in callables):
                issues.append(f"lifecycle registry {probe!r} names an unavailable callable")
                break
    except PhysicalCaptureReadinessError as error:
        issues.append(str(error))

    capture = functions.get("capture_lifecycle_observations")
    if capture is None:
        issues.append("capture_lifecycle_observations is missing")
    else:
        arguments = _function_arguments(capture)
        if arguments & {"proof", "nonce", "run_nonce"}:
            issues.append("pre-nonce lifecycle capture accepts proof or nonce material")
        if not _uses_registry_dispatch(capture, "LIFECYCLE_PRODUCER_REGISTRY"):
            issues.append("pre-nonce lifecycle capture does not execute its exact registry")
        if "observation_capture" not in {_call_name(call) for call in _live_calls(capture)}:
            issues.append("pre-nonce lifecycle capture bypasses ObservationCapture")
        if not any(not _empty_return(item.value) for item in _live_returns(capture)):
            issues.append("pre-nonce lifecycle capture has no non-empty production return")

    materialize = functions.get("materialize_lifecycle_events")
    if materialize is None:
        issues.append("materialize_lifecycle_events is missing")
    else:
        if "proof" not in _function_arguments(materialize):
            issues.append("post-nonce lifecycle materializer has no proof input")
        if not _uses_registry_dispatch(materialize, "LIFECYCLE_PRODUCER_REGISTRY"):
            issues.append("post-nonce lifecycle materializer does not execute its registry")
        materialize_calls = {_call_name(call) for call in _live_calls(materialize)}
        if "load_observation_manifest" not in materialize_calls:
            issues.append("post-nonce lifecycle materializer does not reopen the frozen manifest")
        if not materialize_calls & {"validate_lifecycle_event", "compose_lifecycle_report"}:
            issues.append("post-nonce lifecycle materializer bypasses lifecycle validation")
        if not any(not _empty_return(item.value) for item in _live_returns(materialize)):
            issues.append("post-nonce lifecycle materializer has no non-empty return")
    line = min(
        (function.lineno for function in (capture, materialize) if function is not None),
        default=1,
    )
    return line, issues


def _swift_package_document(repository: Path) -> dict[str, Any]:
    package_root = _safe_path(repository, "native/macos")
    environment = {
        "HOME": os.environ.get("HOME", "/private/var/empty"),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    }
    try:
        result = subprocess.run(
            [
                "/usr/bin/swift",
                "package",
                "--package-path",
                str(package_root),
                "dump-package",
            ],
            cwd=str(repository),
            env=environment,
            capture_output=True,
            check=False,
            timeout=SWIFT_PACKAGE_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise PhysicalCaptureReadinessError(
            f"SwiftPM package contract cannot be inspected: {error}"
        ) from error
    if (
        result.returncode != 0
        or len(result.stdout) > SWIFT_PACKAGE_OUTPUT_LIMIT
        or len(result.stderr) > SWIFT_PACKAGE_OUTPUT_LIMIT
    ):
        raise PhysicalCaptureReadinessError(
            "SwiftPM package contract failed or exceeded its bounded output"
        )
    try:
        value = json.loads(result.stdout)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise PhysicalCaptureReadinessError(
            "SwiftPM package contract is not strict JSON"
        ) from error
    if not isinstance(value, dict):
        raise PhysicalCaptureReadinessError("SwiftPM package contract is not an object")
    return value


def _fixture_specs(node: ast.AST) -> dict[str, dict[str, Any]]:
    value = _literal(node)
    if not isinstance(value, dict) or set(value) != EXPECTED_EXTERNAL_FIXTURES:
        raise PhysicalCaptureReadinessError(
            "EXTERNAL_FIXTURE_SPECS is not the exact ten-controller closure"
        )
    result: dict[str, dict[str, Any]] = {}
    fields = {"target", "source_path", "executable", "privileged", "reset_required"}
    for fixture_id, spec in value.items():
        if not isinstance(fixture_id, str) or not isinstance(spec, dict) or set(spec) != fields:
            raise PhysicalCaptureReadinessError(
                f"external fixture spec is malformed: {fixture_id!r}"
            )
        target = spec["target"]
        source_path = spec["source_path"]
        if (
            not isinstance(target, str)
            or _TARGET_RE.fullmatch(target) is None
            or not isinstance(source_path, str)
            or source_path != f"native/macos/PhysicalFixtures/{target}/main.swift"
            or spec["executable"] != "CFWAdversarialFixture"
            or type(spec["privileged"]) is not bool
            or spec["privileged"] != (fixture_id in EXPECTED_PRIVILEGED_FIXTURES)
            or type(spec["reset_required"]) is not bool
            or spec["reset_required"] != (fixture_id in EXPECTED_RESET_FIXTURES)
        ):
            raise PhysicalCaptureReadinessError(
                f"external fixture spec differs from its fixed contract: {fixture_id}"
            )
        result[fixture_id] = dict(spec)
    targets = {spec["target"] for spec in result.values()}
    if len(targets) != len(result):
        raise PhysicalCaptureReadinessError("external fixtures reuse a Swift target")
    return result


def _adversarial_issues(
    source: str,
    repository: Path,
    package: Mapping[str, Any] | None,
) -> tuple[int, list[str]]:
    tree = _python_tree(source, ADVERSARIAL_PATH)
    issues: list[str] = []
    try:
        mapping = _literal(_unique_assignment(tree, "SOURCE_FIXED_PRECONDITIONS"))
        if mapping != EXPECTED_EXTERNAL_CASE_TO_FIXTURE:
            issues.append("external adversarial case-to-fixture mapping is not exact")
    except PhysicalCaptureReadinessError as error:
        issues.append(str(error))
    try:
        specs = _fixture_specs(_unique_assignment(tree, "EXTERNAL_FIXTURE_SPECS"))
    except PhysicalCaptureReadinessError as error:
        return 1, [*issues, str(error)]

    for fixture_id, spec in specs.items():
        try:
            _read_text(repository, spec["source_path"])
        except PhysicalCaptureReadinessError as error:
            issues.append(f"{fixture_id}: {error}")

    if package is None:
        issues.append("SwiftPM package contract is unavailable")
        return 1, issues
    products = {
        entry.get("name"): entry
        for entry in package.get("products", [])
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }
    targets = {
        entry.get("name"): entry
        for entry in package.get("targets", [])
        if isinstance(entry, dict) and isinstance(entry.get("name"), str)
    }
    for fixture_id, spec in specs.items():
        target_name = spec["target"]
        product = products.get(target_name)
        target = targets.get(target_name)
        expected_path = PurePosixPath(spec["source_path"]).relative_to(
            "native/macos"
        ).parent.as_posix()
        if (
            not isinstance(product, dict)
            or product.get("targets") != [target_name]
            or not isinstance(product.get("type"), dict)
            or set(product["type"]) != {"executable"}
            or not isinstance(target, dict)
            or target.get("type") != "executable"
            or target.get("path") != expected_path
        ):
            issues.append(
                f"{fixture_id} has no exact executable SwiftPM product/target/path binding"
            )
    return 1, issues


def _collector_registry(node: ast.AST) -> dict[str, str]:
    mapping = _literal_mapping_node(node, "PRODUCER_REGISTRY")
    result: dict[str, str] = {}
    for key, value in zip(mapping.keys, mapping.values, strict=True):
        if (
            not isinstance(key, ast.Constant)
            or not isinstance(key.value, str)
            or not isinstance(value, ast.Name)
        ):
            raise PhysicalCaptureReadinessError(
                "PRODUCER_REGISTRY must map literal harness IDs to named handlers"
            )
        if key.value in result:
            raise PhysicalCaptureReadinessError("PRODUCER_REGISTRY repeats a harness")
        result[key.value] = value.id
    if set(result) != EXPECTED_HARNESSES:
        raise PhysicalCaptureReadinessError(
            "PRODUCER_REGISTRY is not the exact four-harness closure"
        )
    return result


def _function_call_graph(
    functions: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef]
) -> dict[str, set[str]]:
    return {
        name: _live_called_names(function) & set(functions)
        for name, function in functions.items()
    }


def _reachable_names(graph: Mapping[str, set[str]], root: str) -> set[str]:
    pending = [root]
    reached: set[str] = set()
    while pending:
        name = pending.pop()
        if name in reached:
            continue
        reached.add(name)
        pending.extend(sorted(graph.get(name, set()) - reached))
    return reached


def _handler_reaches_import(
    handler: str,
    expected: tuple[str, str],
    functions: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef],
    imports: Mapping[str, tuple[str, str]],
) -> bool:
    graph = _function_call_graph(functions)
    for function_name in _reachable_names(graph, handler):
        function = functions.get(function_name)
        if function is None:
            continue
        for call_name in _live_called_names(function):
            if imports.get(call_name) == expected:
                return True
    return False


def _collector_commands(
    functions: Mapping[str, ast.FunctionDef | ast.AsyncFunctionDef],
    reachable: set[str],
) -> tuple[set[str], bool]:
    commands: set[str] = set()
    generic_harness = False
    for function_name in reachable:
        function = functions.get(function_name)
        if function is None:
            continue
        for node in _live_calls(function):
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr == "add_parser" and len(node.args) == 1:
                argument = node.args[0]
                if isinstance(argument, ast.Constant) and isinstance(argument.value, str):
                    commands.add(argument.value)
            if node.func.attr == "add_argument" and node.args:
                argument = node.args[0]
                if isinstance(argument, ast.Constant) and argument.value == "--harness":
                    for keyword in node.keywords:
                        if keyword.arg != "choices":
                            continue
                        names = _name_references(keyword.value)
                        if "PRODUCER_REGISTRY" in names:
                            generic_harness = True
    return commands, generic_harness


def _collector_issues(source: str) -> tuple[int, list[str]]:
    tree = _python_tree(source, COLLECTOR_PATH)
    issues: list[str] = []
    functions = _top_level_functions(tree)
    imports = _imported_names(tree)
    try:
        assignment = _unique_assignment(tree, "PRODUCER_REGISTRY")
        registry = _collector_registry(assignment)
        if _registry_is_mutated(tree, "PRODUCER_REGISTRY", assignment):
            issues.append("collector producer registry is mutable after declaration")
    except PhysicalCaptureReadinessError as error:
        return 1, [str(error)]

    for harness, handler in registry.items():
        if handler not in functions:
            issues.append(f"collector {harness} handler {handler!r} is unavailable")
            continue
        if not _handler_reaches_import(
            handler, EXPECTED_COLLECTOR_TARGETS[harness], functions, imports
        ):
            issues.append(
                f"collector {harness} handler does not reach its production capture callable"
            )

    main = functions.get("main")
    if main is None:
        issues.append("collector main entrypoint is missing")
        return 1, issues
    graph = _function_call_graph(functions)
    reachable = _reachable_names(graph, "main")
    if not any(
        _uses_registry_dispatch(functions[name], "PRODUCER_REGISTRY")
        for name in reachable
        if name in functions
    ):
        issues.append("collector main flow does not dispatch through PRODUCER_REGISTRY")
    commands, generic_harness = _collector_commands(functions, reachable)
    explicit = {f"collect-{harness}" for harness in EXPECTED_HARNESSES}
    if not (explicit <= commands or ("collect" in commands and generic_harness)):
        issues.append("collector CLI cannot select the exact four-harness closure")
    if not any(
        "complete_observations" in _live_called_names(functions[name])
        for name in reachable
        if name in functions
    ):
        issues.append("collector production flow never freezes the complete raw union")
    return main.lineno, issues


def _logical_shell_lines(source: str) -> tuple[str, ...]:
    lines: list[str] = []
    current = ""
    for raw in source.splitlines():
        stripped = _SHELL_COMMENT_RE.sub("", raw).strip()
        if not stripped:
            continue
        continued = stripped.endswith("\\")
        if continued:
            stripped = stripped[:-1].rstrip()
        current = f"{current} {stripped}".strip()
        if not continued:
            lines.append(current)
            current = ""
    if current:
        lines.append(current)
    return tuple(lines)


def _host_build_has_feature(source: str) -> bool:
    candidates = [
        line
        for line in _logical_shell_lines(source)
        if '"$contract_tauri_host_bin" build' in line
    ]
    if len(candidates) != 1:
        return False
    line = candidates[0]
    return (
        line.count("--features") == 1
        and re.search(
            rf"(?:^|\s)--features\s+{re.escape(HOST_FEATURE)}(?:\s|$)", line
        )
        is not None
    )


def _rust_sanitized(source: str) -> str:
    output = list(source)
    index = 0
    depth = 0
    mode = "code"
    while index < len(output):
        current = source[index]
        following = source[index + 1] if index + 1 < len(output) else ""
        if mode == "code" and current == "/" and following == "/":
            mode = "line-comment"
            output[index] = output[index + 1] = " "
            index += 2
            continue
        if mode == "code" and current == "/" and following == "*":
            mode = "block-comment"
            depth = 1
            output[index] = output[index + 1] = " "
            index += 2
            continue
        if mode == "line-comment":
            if current == "\n":
                mode = "code"
            else:
                output[index] = " "
            index += 1
            continue
        if mode == "block-comment":
            output[index] = " "
            if current == "/" and following == "*":
                output[index + 1] = " "
                depth += 1
                index += 2
                continue
            if current == "*" and following == "/":
                output[index + 1] = " "
                depth -= 1
                index += 2
                if depth == 0:
                    mode = "code"
                continue
            index += 1
            continue
        if mode == "code":
            raw = re.match(r"(?:br|r)(?P<hashes>#{0,255})\"", source[index:])
            if raw is not None:
                terminator = '"' + raw.group("hashes")
                closing = source.find(terminator, index + raw.end())
                end = len(source) if closing < 0 else closing + len(terminator)
                output[index:end] = " " * (end - index)
                index = end
                continue
        if mode == "code" and current == '"':
            quote = current
            output[index] = " "
            index += 1
            while index < len(output):
                char = source[index]
                output[index] = " "
                if char == "\\":
                    if index + 1 < len(output):
                        output[index + 1] = " "
                    index += 2
                    continue
                index += 1
                if char == quote:
                    break
            continue
        index += 1
    return "".join(output)


def _matching_brace(source: str, opening: int) -> int | None:
    depth = 0
    for index in range(opening, len(source)):
        if source[index] == "{":
            depth += 1
        elif source[index] == "}":
            depth -= 1
            if depth == 0:
                return index
    return None


def _rust_test_ranges(source: str) -> list[tuple[int, int]]:
    ranges: list[tuple[int, int]] = []
    pattern = re.compile(r"#\s*\[\s*cfg\s*\(\s*test\s*\)\s*\]\s*(?:pub\s+)?mod\s+\w+\s*\{")
    for match in pattern.finditer(source):
        opening = source.find("{", match.start(), match.end())
        closing = _matching_brace(source, opening)
        if closing is not None:
            ranges.append((match.start(), closing + 1))
    return ranges


def _inside_ranges(position: int, ranges: Sequence[tuple[int, int]]) -> bool:
    return any(start <= position < end for start, end in ranges)


def _rust_functions(source: str) -> dict[str, set[str]]:
    sanitized = _rust_sanitized(source)
    test_ranges = _rust_test_ranges(sanitized)
    functions: dict[str, set[str]] = {}
    pattern = re.compile(
        r"\b(?:pub(?:\([^)]*\))?\s+)?(?:async\s+)?fn\s+([A-Za-z_][A-Za-z0-9_]*)[^;{]*\{"
    )
    call_pattern = re.compile(
        r"\b((?:[A-Za-z_][A-Za-z0-9_]*::)*[A-Za-z_][A-Za-z0-9_]*)"
        r"\s*(?:!\s*)?\("
    )
    for match in pattern.finditer(sanitized):
        if _inside_ranges(match.start(), test_ranges):
            continue
        opening = sanitized.find("{", match.start(), match.end())
        closing = _matching_brace(sanitized, opening)
        if closing is None:
            continue
        body = sanitized[opening + 1 : closing]
        calls = set(call_pattern.findall(body))
        calls.discard(match.group(1))
        functions.setdefault(match.group(1), set()).update(calls)
    return functions


def _rust_reachable_calls(functions: Mapping[str, set[str]], root: str) -> set[str]:
    graph = {
        name: {call.rsplit("::", 1)[-1] for call in calls} & set(functions)
        for name, calls in functions.items()
    }
    return {
        call
        for name in _reachable_names(graph, root)
        for call in functions.get(name, set())
    }


def _host_control_path_ready(rust_sources: Mapping[str, str]) -> bool:
    required_paths = {
        HOST_MAIN_PATH,
        HOST_PACKET_TRANSPORT_PATH,
        HOST_PACKET_ENGINE_PATH,
    }
    if not required_paths <= set(rust_sources):
        return False

    main_functions = _rust_functions(rust_sources[HOST_MAIN_PATH])
    main_calls = _rust_reachable_calls(main_functions, "main")
    if (
        f"packet_evidence_transport::{HOST_PACKET_ENTRYPOINT}" not in main_calls
        or "packet_evidence_transport::run_packet_evidence_unavailable" in main_calls
    ):
        return False

    transport_functions = _rust_functions(rust_sources[HOST_PACKET_TRANSPORT_PATH])
    if HOST_PACKET_ENTRYPOINT not in transport_functions:
        return False
    transport_calls = _rust_reachable_calls(
        transport_functions, HOST_PACKET_ENTRYPOINT
    )
    if not any(
        call.rsplit("::", 1)[-1] == HOST_PACKET_ENGINE_ENTRYPOINT
        for call in transport_calls
    ):
        return False

    engine_functions = _rust_functions(rust_sources[HOST_PACKET_ENGINE_PATH])
    return HOST_PACKET_ENGINE_ENTRYPOINT in engine_functions


def _host_issues(
    cargo_source: str,
    build_source: str,
    rust_sources: Mapping[str, str],
) -> tuple[int, list[str]]:
    issues: list[str] = []
    try:
        cargo = tomllib.loads(cargo_source)
    except (tomllib.TOMLDecodeError, TypeError) as error:
        return 1, [f"Host Cargo contract is malformed: {error}"]
    features = cargo.get("features")
    if not isinstance(features, dict) or HOST_FEATURE not in features:
        issues.append(f"Host Cargo feature {HOST_FEATURE!r} is absent")
    if not _host_build_has_feature(build_source):
        issues.append("final Tauri Host build argv does not enable physical-release-evidence")

    if not _host_control_path_ready(rust_sources):
        issues.append(
            "Host main has no exact production transport path to the staged Packet evidence transaction"
        )
    return 1, issues


def _path_identity(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        metadata.st_mtime_ns,
        metadata.st_ctime_ns,
    )


def _rust_source_snapshot(repository: Path) -> dict[str, tuple[int, ...]]:
    root = _safe_path(repository, HOST_SOURCE_ROOT)
    try:
        paths = [root, *root.rglob("*")]
    except OSError as error:
        raise PhysicalCaptureReadinessError(
            f"Host Rust source closure cannot be listed: {error}"
        ) from error
    snapshot: dict[str, tuple[int, ...]] = {}
    rust_files = 0
    total_bytes = 0
    if len(paths) > MAX_RUST_SOURCE_ENTRIES:
        raise PhysicalCaptureReadinessError(
            "Host Rust source closure exceeds its entry-count bound"
        )
    for path in paths:
        relative = path.relative_to(repository).as_posix()
        try:
            metadata = path.lstat()
        except OSError as error:
            raise PhysicalCaptureReadinessError(
                f"Host Rust source closure changed while listed: {relative}: {error}"
            ) from error
        if stat.S_ISLNK(metadata.st_mode):
            raise PhysicalCaptureReadinessError(
                f"Host Rust source closure contains a symlink: {relative}"
            )
        if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
            raise PhysicalCaptureReadinessError(
                f"Host Rust source closure contains a non-file entry: {relative}"
            )
        if stat.S_ISREG(metadata.st_mode):
            if metadata.st_uid != os.geteuid() or metadata.st_mode & 0o022:
                raise PhysicalCaptureReadinessError(
                    f"Host Rust source closure contains an unsafe owner or mode: {relative}"
                )
            if metadata.st_nlink != 1:
                raise PhysicalCaptureReadinessError(
                    f"Host Rust source closure file must have exactly one hard link: {relative}"
                )
            if metadata.st_size > MAX_SOURCE_BYTES:
                raise PhysicalCaptureReadinessError(
                    f"Host Rust source closure file exceeds its byte bound: {relative}"
                )
            total_bytes += metadata.st_size
            if path.suffix == ".rs":
                rust_files += 1
        snapshot[relative] = _path_identity(metadata)
    if rust_files < 1 or rust_files > MAX_RUST_SOURCE_FILES:
        raise PhysicalCaptureReadinessError(
            "Host Rust source closure has no files or exceeds its file-count bound"
        )
    if total_bytes > MAX_RUST_SOURCE_TOTAL_BYTES:
        raise PhysicalCaptureReadinessError(
            "Host Rust source closure exceeds its total byte bound"
        )
    return snapshot


def _load_rust_sources(repository: Path) -> dict[str, str]:
    before = _rust_source_snapshot(repository)
    paths = sorted(
        relative
        for relative, identity in before.items()
        if relative.endswith(".rs") and stat.S_ISREG(identity[2])
    )
    values: dict[str, str] = {}
    for relative in paths:
        values[relative] = _read_text(repository, relative)
    after = _rust_source_snapshot(repository)
    if before != after:
        raise PhysicalCaptureReadinessError(
            "Host Rust source closure changed while it was read"
        )
    return values


def _blocker(code: str, path: str, line: int, issues: Sequence[str]) -> Blocker | None:
    normalized = tuple(dict.fromkeys(issue for issue in issues if issue))
    if not normalized:
        return None
    return Blocker(code, path, max(1, line), "; ".join(normalized))


def analyze_repository(repository: Path) -> tuple[Blocker, ...]:
    """Return every independent source-readiness blocker in stable order."""

    if not repository.is_absolute():
        raise PhysicalCaptureReadinessError(
            "physical capture readiness repository root must be absolute"
        )
    try:
        repository_metadata = repository.lstat()
    except OSError as error:
        raise PhysicalCaptureReadinessError(
            f"physical capture readiness repository root is unavailable: {error}"
        ) from error
    if stat.S_ISLNK(repository_metadata.st_mode) or not stat.S_ISDIR(
        repository_metadata.st_mode
    ):
        raise PhysicalCaptureReadinessError(
            "physical capture readiness repository root is a symlink or not a directory"
        )
    blockers: list[Blocker] = []

    try:
        packet_source = _read_text(repository, PACKET_PATH)
        line, issues = _packet_issues(packet_source)
        issues.extend(_packet_lease_issues(packet_source))
        issues.extend(_packet_runtime_issues(repository))
    except PhysicalCaptureReadinessError as error:
        line, issues = 1, [str(error)]
    blocker = _blocker("packet_producer_unready", PACKET_PATH, line, issues)
    if blocker is not None:
        blockers.append(blocker)

    try:
        contract_source = _read_text(repository, LIFECYCLE_CONTRACT_PATH)
        producer_source = _read_text(repository, LIFECYCLE_PRODUCER_PATH)
        line, issues = _lifecycle_issues(contract_source, producer_source)
    except PhysicalCaptureReadinessError as error:
        line, issues = 1, [str(error)]
    blocker = _blocker(
        "lifecycle_two_phase_producer_missing",
        LIFECYCLE_PRODUCER_PATH,
        line,
        issues,
    )
    if blocker is not None:
        blockers.append(blocker)

    try:
        adversarial_source = _read_text(repository, ADVERSARIAL_PATH)
        try:
            package = _swift_package_document(repository)
        except PhysicalCaptureReadinessError as error:
            package = None
            package_error = str(error)
        else:
            package_error = ""
        line, issues = _adversarial_issues(adversarial_source, repository, package)
        if package_error:
            issues.append(package_error)
    except PhysicalCaptureReadinessError as error:
        line, issues = 1, [str(error)]
    blocker = _blocker(
        "adversarial_helper_closure_incomplete",
        ADVERSARIAL_PATH,
        line,
        issues,
    )
    if blocker is not None:
        blockers.append(blocker)

    try:
        collector_source = _read_text(repository, COLLECTOR_PATH)
        line, issues = _collector_issues(collector_source)
    except PhysicalCaptureReadinessError as error:
        line, issues = 1, [str(error)]
    blocker = _blocker(
        "collector_production_flow_incomplete", COLLECTOR_PATH, line, issues
    )
    if blocker is not None:
        blockers.append(blocker)

    try:
        cargo_source = _read_text(repository, HOST_CARGO_PATH)
        build_source = _read_text(repository, HOST_BUILD_PATH)
        rust_sources = _load_rust_sources(repository)
        line, issues = _host_issues(cargo_source, build_source, rust_sources)
    except PhysicalCaptureReadinessError as error:
        line, issues = 1, [str(error)]
    blocker = _blocker(
        "host_evidence_path_unreachable", HOST_CARGO_PATH, line, issues
    )
    if blocker is not None:
        blockers.append(blocker)

    return tuple(sorted(blockers))


def _parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(description=__doc__)


def main(argv: Sequence[str] | None = None) -> int:
    _parser().parse_args(argv)
    try:
        blockers = analyze_repository(_repository())
    except (OSError, PhysicalCaptureReadinessError) as error:
        print(
            f"error[physical_capture_readiness_unavailable]: {error}",
            file=sys.stderr,
        )
        return 1
    if blockers:
        for blocker in sorted(blockers):
            print(
                f"error[{blocker.code}] {blocker.path}:{blocker.line}: {blocker.detail}",
                file=sys.stderr,
            )
        print(
            f"error[physical_capture_source_not_ready]: {len(blockers)} blocker classes remain",
            file=sys.stderr,
        )
        return 1
    print("physical capture source readiness verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = ["Blocker", "PhysicalCaptureReadinessError", "analyze_repository", "main"]
