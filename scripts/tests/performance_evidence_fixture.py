"""Deterministic raw performance-ledger fixtures for validator tests only."""

from __future__ import annotations

import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from typing import Any, Callable

from scripts.harness import performance_ledger as contract
from scripts.harness.performance_gates import HARNESS_VERSION, percentiles
from scripts.harness.raw_artifacts import canonical_json


WriteJson = Callable[[str, Any, str], dict[str, Any]]


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _oslog(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S.%f+0000")


def _log_query(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _command(
    role: str,
    argv: tuple[str, ...],
    started: datetime,
    completed: datetime,
    *,
    stdout: str = "",
    stderr: str = "",
) -> dict[str, Any]:
    stdout_bytes = stdout.encode("utf-8")
    stderr_bytes = stderr.encode("utf-8")
    return {
        "role": role,
        "argv": list(argv),
        "argv_sha256": hashlib.sha256(canonical_json(list(argv))).hexdigest(),
        "started_at": _utc(started),
        "completed_at": _utc(completed),
        "duration_ms": round((completed - started).total_seconds() * 1000),
        "exit_code": 0,
        "stdout_size": len(stdout_bytes),
        "stdout_sha256": hashlib.sha256(stdout_bytes).hexdigest(),
        "stdout": stdout,
        "stderr_size": len(stderr_bytes),
        "stderr_sha256": hashlib.sha256(stderr_bytes).hexdigest(),
        "stderr": stderr,
        "observer_executable_sha256": _sha(f"observer:{argv[0]}"),
    }


def _summary(samples: list[float]) -> dict[str, float]:
    return percentiles([float(sample) for sample in samples])


class _Builder:
    def __init__(
        self,
        *,
        write_json: WriteJson,
        run_name: str,
        proof: dict[str, Any],
        candidate: dict[str, Any],
        run: dict[str, Any],
        parameters: dict[str, Any],
        started_at: datetime,
    ) -> None:
        self.write_json = write_json
        self.run_name = run_name
        self.proof = proof
        self.candidate = candidate
        self.run = run
        self.parameters = parameters
        self.origin = started_at
        self.now = started_at
        self.samples: list[dict[str, Any]] = []
        self.event_sequence = 0
        self.generation = 0
        self.state: dict[str, Any] | None = None
        self.signing_values: list[dict[str, Any]] = []
        self.signing_by_component: dict[str, dict[str, Any]] = {}
        self.shaping_transactions: list[dict[str, Any]] = []
        self.weak_recovery: dict[str, list[float]] = {
            profile_id: [] for profile_id in contract.WEAK_NETWORK_PROFILES
        }
        self.host_pid = 4242
        self.owner_pids = {"proxy_agent": 4343, "packet_tunnel": 4444}
        self.process_starts = {
            "host": "Sun Jul 27 11:00:00 2026",
            "proxy_agent": "Sun Jul 27 11:00:01 2026",
            "packet_tunnel": "Sun Jul 27 11:00:02 2026",
        }

    def monotonic_ns(self, value: datetime) -> int:
        return 1_000_000_000_000 + round((value - self.origin).total_seconds() * 1_000_000_000)

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)

    def command(
        self,
        role: str,
        argv: tuple[str, ...],
        *,
        duration: float = 0.01,
        stdout: str = "",
        stderr: str = "",
    ) -> dict[str, Any]:
        started = self.now
        self.advance(duration)
        return _command(role, argv, started, self.now, stdout=stdout, stderr=stderr)

    def signing_observations(self) -> None:
        for component in sorted(contract.COMPONENT_IDENTITIES):
            expected = contract.COMPONENT_IDENTITIES[component]
            cdhash = _sha(f"{self.run_name}:{component}:cdhash")[:40]
            requirement = (
                f'identifier "{expected["signing_identifier"]}" and anchor apple generic '
                f'and certificate leaf[subject.OU] = "{contract.TEAM_ID}"'
            )
            identity = {
                "executable": expected["executable"],
                "team_id": contract.TEAM_ID,
                "signing_identifier": expected["signing_identifier"],
                "cdhash": cdhash,
                "designated_requirement_sha256": hashlib.sha256(
                    requirement.encode("utf-8")
                ).hexdigest(),
            }
            output = "\n".join(
                (
                    f"Executable={expected['executable']}",
                    f"Identifier={expected['signing_identifier']}",
                    f"TeamIdentifier={contract.TEAM_ID}",
                    f"CDHash={cdhash}",
                    f"designated => {requirement}",
                )
            ) + "\n"
            command = self.command(
                "performance-codesign",
                (
                    "/usr/bin/codesign",
                    "-d",
                    "-r-",
                    "--verbose=4",
                    expected["codesign_target"],
                ),
                stderr=output,
            )
            observation = {
                "component": component,
                "identity": identity,
                "command": command,
            }
            self.signing_values.append(observation)
            self.signing_by_component[component] = {
                "identity": identity,
                "sha256": hashlib.sha256(canonical_json(observation)).hexdigest(),
            }

    def set_state(self, mode: str) -> None:
        self.event_sequence += 1
        if self.state is not None:
            self.generation += 1
        elif mode != "off":
            self.generation = 1
        phase = contract._TERMINAL_PHASE[mode]
        owner = contract._ACTIVE_OWNER.get(mode)
        state = {
            "desired_mode": mode,
            "generation": self.generation,
            "config_digest": None if mode == "off" else _sha(
                f"{self.run_name}:config:{self.generation}:{mode}"
            ),
            "phase": phase,
            "owner": owner,
            "ready": mode != "off",
            "ipv6_enabled": True,
        }
        recorded_unix_ms = int(self.now.timestamp() * 1000)
        event = {
            "schema_version": 1,
            "document": contract.PRODUCT_OBSERVATION_DOCUMENT,
            "component": "host",
            "event": "engine_snapshot",
            "sequence": self.event_sequence,
            "recorded_unix_ms": recorded_unix_ms,
            "process": {
                "pid": self.host_pid,
                "start_unix_ms": int((self.origin - timedelta(hours=1)).timestamp() * 1000),
            },
            "candidate": {
                "version": self.candidate["version"],
                "build_number": self.candidate["build_number"],
            },
            "payload": {"state": state},
        }
        recorded_at = datetime.fromtimestamp(recorded_unix_ms / 1000, timezone.utc)
        log_entry = {
            "timestamp": _oslog(recorded_at),
            "machTimestamp": self.monotonic_ns(recorded_at),
            "processImagePath": contract.COMPONENT_IDENTITIES["host"]["executable"],
            "processID": self.host_pid,
            "subsystem": contract.PRODUCT_LOG_SUBSYSTEM,
            "category": contract.PRODUCT_LOG_CATEGORY,
            "eventMessage": contract.PRODUCT_OBSERVATION_PREFIX
            + canonical_json(event).decode("utf-8"),
        }
        material = {
            "host_process": event["process"],
            "generation": state["generation"],
            "desired_mode": state["desired_mode"],
            "phase": state["phase"],
            "config_digest": state["config_digest"],
        }
        self.state = {
            "state": state,
            "event": event,
            "log_entry": log_entry,
            "operation_id": hashlib.sha256(
                b"cfw-performance-operation-v1\0" + canonical_json(material)
            ).hexdigest(),
        }

    def _state_observation(
        self, query_started: datetime, query_completed: datetime
    ) -> dict[str, Any]:
        if self.state is None:
            raise AssertionError("fixture state must be initialized")
        event_time = datetime.fromtimestamp(
            self.state["event"]["recorded_unix_ms"] / 1000, timezone.utc
        )
        query_end = query_started
        query = _command(
            "product-observation-log",
            (
                "/usr/bin/log",
                "show",
                "--style",
                "ndjson",
                "--info",
                "--timezone",
                "UTC",
                "--start",
                _log_query(event_time - timedelta(milliseconds=1)),
                "--end",
                _log_query(query_end),
                "--predicate",
                contract.PRODUCT_LOG_PREDICATE,
            ),
            query_started,
            query_completed,
            stdout=canonical_json(self.state["log_entry"]).decode("utf-8") + "\n",
        )
        return {
            "log_entry": copy.deepcopy(self.state["log_entry"]),
            "event": copy.deepcopy(self.state["event"]),
            "query_command": query,
        }

    def _roster(
        self, started: datetime, completed: datetime
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]], dict[str, Any]]:
        if self.state is None:
            raise AssertionError("fixture state must be initialized")
        mode = self.state["state"]["desired_mode"]
        components = contract._EXPECTED_ROSTER[mode]
        pids = {
            "host": self.host_pid,
            "proxy_agent": self.owner_pids["proxy_agent"],
            "packet_tunnel": self.owner_pids["packet_tunnel"],
        }
        lines: list[str] = []
        roster: list[dict[str, Any]] = []
        discoveries: list[dict[str, Any]] = []
        event_sha256 = hashlib.sha256(canonical_json(self.state["event"])).hexdigest()
        for component in components:
            pid = pids[component]
            executable = contract.COMPONENT_IDENTITIES[component]["executable"]
            uid = 501
            lines.append(
                f"{pid} {uid} {self.process_starts[component]}     {executable}"
            )
            signing = self.signing_by_component[component]
            identity = signing["identity"]
            roster.append(
                {
                    "component": component,
                    "pid": pid,
                    "uid": uid,
                    "start_time": self.process_starts[component],
                    "executable": executable,
                    "team_id": identity["team_id"],
                    "signing_identifier": identity["signing_identifier"],
                    "cdhash": identity["cdhash"],
                    "designated_requirement_sha256": identity[
                        "designated_requirement_sha256"
                    ],
                    "product_event_sha256": event_sha256 if component == "host" else None,
                    "signing_observation_sha256": signing["sha256"],
                }
            )
            discovery_completed = started + timedelta(milliseconds=1)
            discoveries.append(
                _command(
                    "performance-owner-discovery",
                        (
                            "/usr/bin/pgrep",
                            "-x",
                            contract.PROCESS_NAMES[component],
                    ),
                    started,
                    discovery_completed,
                    stdout=f"{pid}\n",
                )
            )
            started = discovery_completed
        argv = (
            "/bin/ps",
            "-p",
            ",".join(str(pid) for pid in sorted(pids[item] for item in components)),
            "-o",
            "pid=,uid=,lstart=,comm=",
        )
        command = _command(
            "performance-process-roster",
            argv,
            started,
            started + timedelta(milliseconds=1),
            stdout="\n".join(lines) + "\n",
        )
        started += timedelta(milliseconds=1)
        for index, (component, process) in enumerate(zip(components, roster, strict=True)):
            identity = self.signing_by_component[component]["identity"]
            requirement = (
                f'identifier "{identity["signing_identifier"]}" and anchor apple generic '
                f'and certificate leaf[subject.OU] = "{identity["team_id"]}"'
            )
            runtime_completed = (
                completed
                if index == len(roster) - 1
                else started + timedelta(milliseconds=1)
            )
            output = "\n".join(
                (
                    f"Executable={process['executable']}",
                    f"Identifier={process['signing_identifier']}",
                    f"TeamIdentifier={process['team_id']}",
                    f"CDHash={process['cdhash']}",
                    f"designated => {requirement}",
                )
            ) + "\n"
            process["runtime_signing_command"] = _command(
                "performance-runtime-codesign",
                (
                    "/usr/bin/codesign",
                    "-d",
                    "-r-",
                    "--verbose=4",
                    process["executable"],
                ),
                started,
                runtime_completed,
                stderr=output,
            )
            started = runtime_completed
        return roster, discoveries, command

    def _network_command(
        self, started: datetime, completed: datetime, *, rtt: float, mbps: float
    ) -> dict[str, Any]:
        output = {
            "start_date": _utc(started),
            "end_date": _utc(completed),
            "interface_name": "en0",
            "base_rtt": rtt,
            "dl_throughput": mbps * 1_000_000,
        }
        return _command(
            "performance-network-quality",
            (
                "/usr/bin/networkQuality",
                "-c",
                "-M",
                str(contract.NETWORK_QUALITY_MAX_SECONDS),
            ),
            started,
            completed,
            stdout=json.dumps(output, sort_keys=True, separators=(",", ":")),
        )

    def _resource_command(
        self,
        started: datetime,
        completed: datetime,
        *,
        cpu: float,
        rss_mib: float,
    ) -> dict[str, Any]:
        if self.state is None:
            raise AssertionError("fixture state must be initialized")
        components = contract._EXPECTED_ROSTER[self.state["state"]["desired_mode"]]
        pids = sorted(
            self.host_pid if component == "host" else self.owner_pids[component]
            for component in components
        )
        cpu_each = cpu / len(pids)
        rss_each = round(rss_mib * 1024 / len(pids))
        stdout = "".join(f"{pid} {cpu_each:.6f} {rss_each}\n" for pid in pids)
        return _command(
            "performance-resource",
            (
                "/bin/ps",
                "-p",
                ",".join(str(pid) for pid in pids),
                "-o",
                "pid=,pcpu=,rss=",
            ),
            started,
            completed,
            stdout=stdout,
        )

    def _fd_command(
        self, started: datetime, completed: datetime, *, fd_count: int
    ) -> dict[str, Any]:
        if self.state is None:
            raise AssertionError("fixture state must be initialized")
        components = contract._EXPECTED_ROSTER[self.state["state"]["desired_mode"]]
        pids = sorted(
            self.host_pid if component == "host" else self.owner_pids[component]
            for component in components
        )
        lines = ["COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME"]
        for index in range(fd_count):
            lines.append(f"cfw {pids[index % len(pids)]} bill {index}r REG 1,1 0 1 /tmp/f{index}")
        return _command(
            "performance-file-descriptors",
            ("/usr/sbin/lsof", "-nP", "-a", "-p", ",".join(str(pid) for pid in pids)),
            started,
            completed,
            stdout="\n".join(lines) + "\n",
        )

    def sample(
        self,
        kind: str,
        measurement: dict[str, Any],
        *,
        target: datetime | None = None,
        measurement_commands: tuple[dict[str, Any], ...] = (),
    ) -> dict[str, Any]:
        if self.state is None:
            raise AssertionError("fixture state must be initialized")
        target = self.now + timedelta(milliseconds=30) if target is None else target
        event_time = datetime.fromtimestamp(
            self.state["event"]["recorded_unix_ms"] / 1000, timezone.utc
        )
        event_query_end = event_time.replace(microsecond=0) + timedelta(seconds=1)
        target = max(target, event_query_end + timedelta(milliseconds=20))
        query_started = target - timedelta(milliseconds=20)
        query_completed = target - timedelta(milliseconds=10)
        if measurement_commands and measurement_commands[-1]["completed_at"] > _utc(
            query_started
        ):
            raise AssertionError("fixture measurement command overlaps state query")
        observation = self._state_observation(query_started, query_completed)
        roster, discoveries, roster_command = self._roster(query_completed, target)
        state = self.state["state"]
        sample = {
            "sequence": len(self.samples),
            "kind": kind,
            "wall_time": _utc(target),
            "monotonic_ns": self.monotonic_ns(target),
            "operation_id": self.state["operation_id"],
            "generation": state["generation"],
            "mode": state["desired_mode"],
            "terminal_state": state["phase"],
            "state_observation": observation,
            "roster": roster,
            "roster_discovery_commands": discoveries,
            "roster_command": roster_command,
            "measurement": measurement,
        }
        self.samples.append(sample)
        self.now = target + timedelta(milliseconds=10)
        return sample

    def _original_shaping_state(self) -> tuple[dict[str, Any], dict[str, Any], datetime]:
        preflight = self.command(
            "performance-sudo-preflight", ("/usr/bin/sudo", "-n", "-v")
        )
        pf_status = self.command(
            "performance-pf-status",
            contract._pf_status_argv(),
            stdout="Status: Enabled for 0 days 00:10:00\n",
        )
        pf = self.command(
            "performance-pf-query", contract._pf_query_argv()
        )
        pipes = [
            self.command(
                "performance-dnctl-query",
                contract._pipe_query_argv(
                    contract.WEAK_NETWORK_PROFILES[profile_id]["pipe_id"]
                ),
            )
            for profile_id in sorted(contract.WEAK_NETWORK_PROFILES)
        ]
        created_at = self.now
        return (
            preflight,
            {
                "pf_status_query": pf_status,
                "pf_query": pf,
                "pipe_queries": pipes,
            },
            created_at,
        )

    def _effective_dnctl_output(self, profile_id: str) -> str:
        profile = contract.WEAK_NETWORK_PROFILES[profile_id]
        if profile["kind"] == "outage":
            return f"{profile['pipe_id']}: plr 1.000000\n"
        return (
            f"{profile['pipe_id']}: {profile['bandwidth_mbps']:.3f} Mbit/s "
            f"{profile['latency_ms']} ms plr {profile['loss_percent'] / 100:.6f}\n"
        )

    def shaping(self) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any]]:
        preflight, original_state, created_at = self._original_shaping_state()
        plan = [
            {"index": index, "profile_id": profile_id}
            for index, profile_id in enumerate(
                profile_id
                for profile_id in sorted(contract.WEAK_NETWORK_PROFILES)
                for _ in range(contract.SERIES_SAMPLE_COUNT)
            )
        ]
        intent = {
            "schema_version": 1,
            "document": contract.SHAPING_INTENT_DOCUMENT,
            "candidate": copy.deepcopy(self.candidate),
            "run": copy.deepcopy(self.run),
            "created_at": _utc(created_at),
            "privilege_preflight": preflight,
            "anchor": contract.PF_ANCHOR,
            "profiles": [
                {"id": profile_id, **contract.WEAK_NETWORK_PROFILES[profile_id]}
                for profile_id in sorted(contract.WEAK_NETWORK_PROFILES)
            ],
            "original_state": original_state,
            "transactions": plan,
        }
        intent_descriptor = self.write_json(
            f"{self.run_name}/performance/shaping-intent.json",
            intent,
            contract.SHAPING_KIND,
        )
        self.advance(0.01)
        self.set_state("tunnel")
        for planned in plan:
            profile_id = planned["profile_id"]
            profile = contract.WEAK_NETWORK_PROFILES[profile_id]
            pipe_id = profile["pipe_id"]
            applied_at = self.now
            apply = [
                self.command(
                    "performance-dnctl-apply", contract._dnctl_apply_argv(profile_id)
                ),
                self.command(
                    "performance-pf-apply", contract._pf_apply_argv(profile_id)
                ),
            ]
            effective = [
                self.command(
                    "performance-dnctl-query",
                    contract._pipe_query_argv(pipe_id),
                    stdout=self._effective_dnctl_output(profile_id),
                ),
                self.command(
                    "performance-pf-query",
                    contract._pf_query_argv(),
                    stdout=(
                        f"dummynet in quick all pipe {pipe_id}\n"
                        f"dummynet out quick all pipe {pipe_id}\n"
                    ),
                ),
            ]
            if profile["kind"] == "outage":
                self.advance(29.92)
            restore_argvs = contract._restore_argvs(pipe_id)
            restore = [
                self.command("performance-pf-restore", restore_argvs[0]),
                self.command("performance-dnctl-restore", restore_argvs[1]),
            ]
            restored_queries = [
                self.command(
                    "performance-dnctl-query", contract._pipe_query_argv(pipe_id)
                ),
                self.command("performance-pf-query", contract._pf_query_argv()),
            ]
            restored_at = self.now
            transaction = {
                "index": planned["index"],
                "profile_id": profile_id,
                "applied_monotonic_ns": self.monotonic_ns(applied_at),
                "restored_monotonic_ns": self.monotonic_ns(restored_at),
                "apply_commands": apply,
                "effective_queries": effective,
                "restore_commands": restore,
                "restoration_queries": restored_queries,
            }
            self.shaping_transactions.append(transaction)
            target = restored_at + timedelta(milliseconds=200)
            traffic = self._network_command(
                target - timedelta(milliseconds=140),
                target - timedelta(milliseconds=20),
                rtt=25.0,
                mbps=92.0,
            )
            sample = self.sample(
                "weak-recovery",
                {
                    "transaction_index": planned["index"],
                    "profile_id": profile_id,
                    "command": traffic,
                    "base_rtt_ms": 25.0,
                    "download_mbps": 92.0,
                },
                target=target,
                measurement_commands=(traffic,),
            )
            self.weak_recovery[profile_id].append(
                (
                    sample["monotonic_ns"]
                    - transaction["restored_monotonic_ns"]
                )
                / 1_000_000
            )
        restoration = {
            "schema_version": 1,
            "document": contract.SHAPING_RESTORATION_DOCUMENT,
            "candidate": copy.deepcopy(self.candidate),
            "run": copy.deepcopy(self.run),
            "intent_artifact": intent_descriptor,
            "completed_at": self.shaping_transactions[-1]["restoration_queries"][-1][
                "completed_at"
            ],
            "transactions": self.shaping_transactions,
        }
        restoration_descriptor = self.write_json(
            f"{self.run_name}/performance/shaping-restoration.json",
            restoration,
            contract.SHAPING_KIND,
        )
        return intent_descriptor, restoration_descriptor, restoration

    def transitions(self) -> dict[str, list[float]]:
        self.advance(0.01)
        self.set_state("off")
        connect: list[float] = []
        disconnect: list[float] = []
        for index in range(contract.SERIES_SAMPLE_COUNT):
            start = self.sample("connect-start", {"pair_index": index})
            self.advance(0.01)
            self.set_state("tunnel")
            connected = self.sample(
                "connect-end",
                {"pair_index": index},
                target=self.now + timedelta(seconds=1),
            )
            stopping = self.sample("disconnect-start", {"pair_index": index})
            self.advance(0.01)
            self.set_state("off")
            ended = self.sample(
                "disconnect-end",
                {"pair_index": index},
                target=self.now + timedelta(milliseconds=500),
            )
            connect.append(
                (connected["monotonic_ns"] - start["monotonic_ns"]) / 1_000_000
            )
            disconnect.append(
                (ended["monotonic_ns"] - stopping["monotonic_ns"]) / 1_000_000
            )
        return {"connect_ms": connect, "disconnect_ms": disconnect}

    def networks(self) -> dict[str, list[float]]:
        baseline: list[float] = []
        measured: list[float] = []
        added_latency: list[float] = []
        for index in range(contract.SERIES_SAMPLE_COUNT):
            if (
                self.state is None
                or self.state["state"]["desired_mode"] != "system_proxy"
            ):
                self.advance(0.01)
                self.set_state("system_proxy")
            target = self.now + timedelta(milliseconds=150)
            baseline_command = self._network_command(
                target - timedelta(milliseconds=140),
                target - timedelta(milliseconds=20),
                rtt=20.0,
                mbps=100.0,
            )
            self.sample(
                "network-baseline",
                {
                    "pair_index": index,
                    "command": baseline_command,
                    "base_rtt_ms": 20.0,
                    "download_mbps": 100.0,
                },
                target=target,
                measurement_commands=(baseline_command,),
            )
            self.advance(0.01)
            self.set_state("tunnel")
            target = self.now + timedelta(milliseconds=150)
            measured_command = self._network_command(
                target - timedelta(milliseconds=140),
                target - timedelta(milliseconds=20),
                rtt=20.4,
                mbps=95.0,
            )
            self.sample(
                "network-measured",
                {
                    "pair_index": index,
                    "command": measured_command,
                    "base_rtt_ms": 20.4,
                    "download_mbps": 95.0,
                },
                target=target,
                measurement_commands=(measured_command,),
            )
            baseline.append(100.0)
            measured.append(95.0)
            added_latency.append(max(0.0, 100.0 * (20.4 - 20.0) / 20.0))
        return {
            "baseline_mbps": baseline,
            "measured_mbps": measured,
            "added_latency_percent": added_latency,
        }

    def resources(self) -> dict[str, list[float]]:
        cpu_values: list[float] = []
        rss_values: list[float] = []
        for index in range(contract.SERIES_SAMPLE_COUNT):
            target = self.now + timedelta(milliseconds=60)
            command = self._resource_command(
                target - timedelta(milliseconds=40),
                target - timedelta(milliseconds=20),
                cpu=0.4,
                rss_mib=60.0,
            )
            self.sample(
                "resource",
                {
                    "index": index,
                    "command": command,
                    "cpu_percent": 0.4,
                    "rss_mib": 60.0,
                },
                target=target,
                measurement_commands=(command,),
            )
            cpu_values.append(0.4)
            rss_values.append(60.0)
        return {
            "active_idle_cpu_percent": cpu_values,
            "active_rss_mib": rss_values,
        }

    def switches(self) -> dict[str, Any]:
        rss_values: list[float] = []
        fd_values: list[int] = []
        for index in range(contract.SWITCH_SAMPLE_COUNT):
            self.advance(0.01)
            self.set_state("system_proxy" if index % 2 == 0 else "tunnel")
            rss = 50.0 if index == 0 else 51.0
            fd_count = 10 if index == 0 else 11
            target = self.now + timedelta(milliseconds=80)
            resource = self._resource_command(
                target - timedelta(milliseconds=60),
                target - timedelta(milliseconds=40),
                cpu=0.4,
                rss_mib=rss,
            )
            fds = self._fd_command(
                target - timedelta(milliseconds=40),
                target - timedelta(milliseconds=20),
                fd_count=fd_count,
            )
            self.sample(
                "switch",
                {
                    "index": index,
                    "resource_command": resource,
                    "fd_command": fds,
                    "cpu_percent": 0.4,
                    "rss_mib": rss,
                    "fd_count": fd_count,
                },
                target=target,
                measurement_commands=(resource, fds),
            )
            rss_values.append(rss)
            fd_values.append(fd_count)
        return {
            "switch_count": len(rss_values) - 1,
            "rss_growth_mib": max(rss_values) - rss_values[0],
            "fd_growth": max(fd_values) - fd_values[0],
        }

    def _diagnostic_command(
        self, started: datetime, completed: datetime
    ) -> dict[str, Any]:
        return _command(
            "performance-diagnostic-inventory",
            (
                "/usr/bin/find",
                "-s",
                "/Library/Logs/DiagnosticReports",
                "/Users/bill/Library/Logs/DiagnosticReports",
                "-maxdepth",
                "1",
                "-type",
                "f",
                "(",
                "-iname",
                "*clash*",
                "-o",
                "-iname",
                "*cfw*",
                ")",
                "-print",
            ),
            started,
            completed,
        )

    def _crash_log_command(
        self,
        started: datetime,
        completed: datetime,
        *,
        window_start: datetime,
        window_end: datetime,
    ) -> dict[str, Any]:
        return _command(
            "performance-crash-log",
            (
                "/usr/bin/log",
                "show",
                "--style",
                "ndjson",
                "--info",
                "--timezone",
                "UTC",
                "--start",
                _log_query(window_start),
                "--end",
                _log_query(
                    window_end.replace(microsecond=0)
                    + timedelta(seconds=1)
                ),
                "--predicate",
                contract.CRASH_LOG_PREDICATE,
            ),
            started,
            completed,
        )

    def _crash_sample(
        self,
        stage: str,
        *,
        target: datetime,
        window_start: datetime,
        window_end: datetime,
    ) -> dict[str, Any]:
        diagnostic = self._diagnostic_command(
            target - timedelta(milliseconds=60),
            target - timedelta(milliseconds=40),
        )
        crash_log = self._crash_log_command(
            target - timedelta(milliseconds=40),
            target - timedelta(milliseconds=20),
            window_start=window_start,
            window_end=window_end,
        )
        return self.sample(
            f"crash-{stage}",
            {
                "stage": stage,
                "diagnostic_command": diagnostic,
                "crash_log_command": crash_log,
                "diagnostic_paths": [],
                "crash_log_entries": [],
            },
            target=target,
            measurement_commands=(diagnostic, crash_log),
        )

    def soak(self) -> dict[str, Any]:
        self.advance(0.01)
        self.set_state("tunnel")
        soak_origin = self.now.replace(microsecond=0) + timedelta(seconds=2)
        heartbeat_targets = [
            soak_origin + timedelta(seconds=300.5 * index)
            for index in range(contract.SOAK_HEARTBEAT_COUNT)
        ]
        traffic_targets = [
            soak_origin + timedelta(seconds=0.5 + 900 * index)
            for index in range(contract.SOAK_TRAFFIC_COUNT)
        ]
        self._crash_sample(
            "baseline",
            target=soak_origin - timedelta(seconds=0.5),
            window_start=soak_origin - timedelta(seconds=3),
            window_end=soak_origin - timedelta(seconds=2),
        )
        scheduled = [
            *((target, "heartbeat", index) for index, target in enumerate(heartbeat_targets)),
            *((target, "traffic", index) for index, target in enumerate(traffic_targets)),
        ]
        for target, sample_type, index in sorted(scheduled):
            if sample_type == "heartbeat":
                self.sample(
                    "soak-heartbeat", {"index": index}, target=target
                )
            else:
                command = self._network_command(
                    target - timedelta(milliseconds=140),
                    target - timedelta(milliseconds=20),
                    rtt=22.0,
                    mbps=94.0,
                )
                self.sample(
                    "soak-traffic",
                    {
                        "index": index,
                        "command": command,
                        "base_rtt_ms": 22.0,
                        "download_mbps": 94.0,
                    },
                    target=target,
                    measurement_commands=(command,),
                )
        self._crash_sample(
            "final",
            target=heartbeat_targets[-1] + timedelta(seconds=1.5),
            window_start=soak_origin - timedelta(milliseconds=100),
            window_end=heartbeat_targets[-1],
        )
        duration_hours = (
            heartbeat_targets[-1] - heartbeat_targets[0]
        ).total_seconds() / 3600
        return {
            "duration_hours": duration_hours,
            "heartbeat_count": len(heartbeat_targets),
            "traffic_count": len(traffic_targets),
            "crash_count": 0,
        }

    def build(self, *, signed_at: str) -> tuple[dict[str, Any], list[dict[str, Any]]]:
        self.signing_observations()
        intent_descriptor, restoration_descriptor, _restoration = self.shaping()
        latency = self.transitions()
        network = self.networks()
        resources = self.resources()
        switch = self.switches()
        soak = self.soak()
        completed_at = self.samples[-1]["wall_time"]
        ledger = {
            "schema_version": contract.LEDGER_SCHEMA_VERSION,
            "document": contract.LEDGER_DOCUMENT,
            "candidate": copy.deepcopy(self.candidate),
            "run": copy.deepcopy(self.run),
            "parameters": copy.deepcopy(self.parameters),
            "captured_at": _utc(self.origin),
            "completed_at": completed_at,
            "heartbeat_interval_seconds": contract.SOAK_HEARTBEAT_INTERVAL_SECONDS,
            "traffic_interval_seconds": contract.SOAK_TRAFFIC_INTERVAL_SECONDS,
            "signing_observations": self.signing_values,
            "shaping": {
                "intent_artifact": intent_descriptor,
                "restoration_artifact": restoration_descriptor,
            },
            "samples": self.samples,
        }
        ledger_descriptor = self.write_json(
            f"{self.run_name}/performance/sample-ledger.json",
            ledger,
            contract.LEDGER_KIND,
        )
        weak = [
            {
                "id": profile_id,
                "control": {
                    key: value
                    for key, value in contract.WEAK_NETWORK_PROFILES[profile_id].items()
                    if key != "pipe_id"
                },
                "recovery_ms": _summary(self.weak_recovery[profile_id]),
            }
            for profile_id in sorted(contract.WEAK_NETWORK_PROFILES)
        ]
        report = {
            "schema_version": 3,
            "harness_version": HARNESS_VERSION,
            "captured_at": _utc(self.origin),
            "completed_at": completed_at,
            "signed_at": signed_at,
            "proof": copy.deepcopy(self.proof),
            "parameters": copy.deepcopy(self.parameters),
            "weak_network": weak,
            "latency": {
                "connect_ms": _summary(latency["connect_ms"]),
                "disconnect_ms": _summary(latency["disconnect_ms"]),
                "added_latency_percent": _summary(network["added_latency_percent"]),
            },
            "throughput": {
                "baseline_mbps": _summary(network["baseline_mbps"])["p50"],
                "measured_mbps": _summary(network["measured_mbps"])["p50"],
                "ratio_percent": 95.0,
            },
            "resources": {
                key: _summary(values) for key, values in resources.items()
            },
            "switch_cycle": switch,
            "soak": soak,
            "ledger_artifact": ledger_descriptor,
            "shaping_intent_artifact": intent_descriptor,
            "shaping_restoration_artifact": restoration_descriptor,
        }
        bindings = [
            {
                "harness": "performance",
                "subject": contract.LEDGER_SUBJECT,
                "descriptor": ledger_descriptor,
            },
            {
                "harness": "performance",
                "subject": contract.SHAPING_INTENT_SUBJECT,
                "descriptor": intent_descriptor,
            },
            {
                "harness": "performance",
                "subject": contract.SHAPING_RESTORATION_SUBJECT,
                "descriptor": restoration_descriptor,
            },
        ]
        return report, bindings


def build_performance_report(
    *,
    write_json: WriteJson,
    run_name: str,
    proof: dict[str, Any],
    candidate: dict[str, Any],
    machine: str,
    boot_environment: str,
    os_label: str,
    macos_version: str,
    macos_build: str,
    started_at: str,
    signed_at: str,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    run = {
        "os": os_label,
        "macos_version": macos_version,
        "macos_build": macos_build,
        "machine_sha256": machine,
        "machine_identity_scheme": contract.MACHINE_IDENTITY_SCHEME,
        "hardware_model": "Mac16,1",
        "virtualization_present": False,
        "boot_environment_sha256": boot_environment,
        "boot_environment_scheme": contract.BOOT_ENVIRONMENT_SCHEME,
        "clean_install": True,
        "run_id": proof["run_id"],
    }
    parameters = {
        "machine": {
            "architecture": "arm64",
            "macos_version": macos_version,
            "macos_build": macos_build,
            "hardware_model": "Mac16,1",
            "machine_sha256": machine,
            "clean_install": True,
        },
        "network": {"description": "isolated shaping bridge", "uplink_mbps": 1000},
        "power": {"source": "ac", "low_power_mode": False},
    }
    origin = datetime.fromisoformat(started_at[:-1] + "+00:00")
    return _Builder(
        write_json=write_json,
        run_name=run_name,
        proof=proof,
        candidate=candidate,
        run=run,
        parameters=parameters,
        started_at=origin,
    ).build(signed_at=signed_at)
