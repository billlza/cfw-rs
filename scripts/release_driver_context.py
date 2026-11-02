"""What every stage of the release driver runs with.

The operator entry point (scripts/release_driver.py) and its stage modules
(scripts/release_driver_acceptance.py, scripts/release_driver_review.py) share
one refusal type, the fixed paths of a GA build, the driver's own records, the
machine through which every observation and command passes, the guards common
to every stage and the logged execution of one release entry point. They live
here, below the stage modules: the entry point imports the stages, and no stage
module imports the entry point, which the release launcher runs as __main__.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import plistlib
import re
import shlex
import shutil
import subprocess
import sys
from typing import Final, Mapping, Sequence

from scripts.release_build_identity import (
    ACTIVE_RELEASE_IDENTITY,
    SIGNED_APP_NAME,
    canonical_build_version,
    ga_root,
)


class DriverError(Exception):
    """A stage cannot run. ``status`` is the process exit status."""

    def __init__(self, message: str, status: int = 2) -> None:
        super().__init__(message)
        self.status = status


# Exit statuses shared with the per-release launchers this driver replaces:
# 2 usage, 94 network, 95 another release command or machine state, 96 a
# missing prerequisite, 97 a checkout. A release tool's own failure is passed
# through unchanged.
USAGE: Final = 2
NETWORK: Final = 94
MACHINE: Final = 95
PREREQUISITE: Final = 96
CHECKOUT: Final = 97

RELEASE_HOME_RELATIVE: Final = Path(".cfm-release-tooling/releases")
DEVELOPER_DIR: Final = "/Applications/Xcode.app/Contents/Developer"
SYSTEM_PATH: Final = "/usr/bin:/bin:/usr/sbin:/sbin"
INSTALLED_APP: Final = Path("/Applications") / SIGNED_APP_NAME
MIN_FREE_GIB: Final = 10
RELEASE_COMMAND_PATTERN: Final = (
    "run_release_ci_gate[.]sh|build_unsigned_candidate[.]sh|build_signed_candidate[.]sh"
)
COMMIT_RE: Final = re.compile(r"^[0-9a-f]{40}$")
PIN_LINE_RE: Final = re.compile(r"^([A-Z][A-Z0-9_]*)=(.*)$")


def load_pins(path: Path) -> dict[str, str]:
    """Read the KEY=value lines of scripts/dependency_pins.env."""

    pins: dict[str, str] = {}
    for line in path.read_text(encoding="ascii").splitlines():
        if not line or line.startswith("#"):
            continue
        match = PIN_LINE_RE.fullmatch(line)
        if match is None:
            raise DriverError(f"unreadable pin line in {path}: {line!r}", PREREQUISITE)
        pins[match.group(1)] = match.group(2)
    return pins


def path_present(path: Path) -> bool:
    """Whether anything, even a dangling symbolic link, is at ``path``.

    Only absence answers False: an unreadable state is an error, not absence.
    """

    try:
        path.lstat()
    except FileNotFoundError:
        return False
    return True


@dataclass(frozen=True)
class Release:
    """The fixed paths of one GA build on the release Mac."""

    version: str
    build: str
    home: Path
    sing_box_version: str

    @property
    def operator(self) -> Path:
        return self.home / f"operator-{self.build}"

    @property
    def artifact(self) -> Path:
        return self.operator / "target/release-worktrees" / self.build

    @property
    def ga(self) -> Path:
        return self.artifact / ga_root(Path("."))

    @property
    def stage_inputs(self) -> Path:
        return self.ga / "stage-inputs"

    @property
    def acceptance(self) -> Path:
        return self.stage_inputs / "ga-acceptance"

    @property
    def signed_app(self) -> Path:
        return self.ga / "signed" / SIGNED_APP_NAME

    @property
    def libbox_source(self) -> Path:
        return self.artifact / f"target/sources/sing-box-{self.sing_box_version}-patched"

    @property
    def logs(self) -> Path:
        return self.home / "logs" / self.build

    @property
    def records(self) -> Path:
        return self.home / "records" / self.build

    @property
    def review(self) -> Path:
        return self.home / "review" / self.build

    @property
    def history(self) -> Path:
        return self.home / "history"

    @property
    def preserved_publication(self) -> Path:
        return self.history / f"publication-prepared-{self.build}"

    def package_seal(self, kind: str) -> Path:
        names = {
            "dmg": "dmg-set.seal.json",
            "updater": "updater-set.seal.json",
            "distribution": "distribution-set.seal.json",
        }
        return self.ga / "packages" / kind / f"v{self.version}" / names[kind]


def release_for(repository: Path, home: Path) -> Release:
    pins = load_pins(repository / "scripts/dependency_pins.env")
    sing_box = pins.get("SING_BOX_VERSION")
    if not sing_box:
        raise DriverError("dependency_pins.env does not name SING_BOX_VERSION", PREREQUISITE)
    identity = ACTIVE_RELEASE_IDENTITY
    return Release(
        version=identity.product_version,
        build=canonical_build_version(identity.ga_build, "active GA build"),
        home=home / RELEASE_HOME_RELATIVE / identity.product_version,
        sing_box_version=sing_box,
    )


# --- driver records -------------------------------------------------------
#
# A record is the driver's own bookkeeping for a step that leaves no artifact
# of its own (the preparation lanes, the selected hosted CI run, each install
# transaction). Release tools never read records; a missing record only means
# the driver will offer that step again, and every release tool refuses a
# repeat that would change published state.


def read_record(release: Release, name: str) -> dict[str, object] | None:
    path = release.records / f"{name}.json"
    try:
        data = path.read_bytes()
    except FileNotFoundError:
        return None
    try:
        value = json.loads(data)
    except ValueError as error:
        raise DriverError(f"driver record {path} is not JSON: {error}", PREREQUISITE) from error
    if not isinstance(value, dict) or value.get("build") != release.build:
        raise DriverError(f"driver record {path} does not belong to build {release.build}", PREREQUISITE)
    return value


def write_record(release: Release, name: str, values: Mapping[str, object]) -> Path:
    release.records.mkdir(mode=0o700, parents=True, exist_ok=True)
    path = release.records / f"{name}.json"
    document = {
        "build": release.build,
        "version": release.version,
        "recorded_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        **values,
    }
    temporary = path.with_name(f".{path.name}.pending")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(document, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
    return path


# --- the machine ------------------------------------------------------------


@dataclass(frozen=True)
class Completed:
    """A finished observation. Only ``stdout`` is ever parsed: tools such as
    gcloud print notices on stderr whenever they decide to."""

    status: int
    stdout: str
    stderr: str

    def reason(self) -> str:
        """The command's last diagnostic line, for a refusal message."""

        lines = self.stderr.strip().splitlines()
        return lines[-1] if lines else f"exit status {self.status}"


class Machine:
    """Every observation and command the driver makes, in one replaceable place."""

    def __init__(self, home: Path) -> None:
        self.home = home

    def read(self, argv: Sequence[str], *, timeout: float = 60, cwd: Path | None = None) -> Completed:
        try:
            result = subprocess.run(
                list(argv),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                text=True,
                timeout=timeout,
                env=self.closed_environment({}),
                cwd=cwd,
                check=False,
            )
        except FileNotFoundError as error:
            raise DriverError(f"cannot start {shlex.join(argv)}: {error}", PREREQUISITE) from error
        except subprocess.TimeoutExpired as error:
            raise DriverError(f"{shlex.join(argv)} did not finish within {timeout:g} s", MACHINE) from error
        return Completed(result.returncode, result.stdout, result.stderr)

    def closed_environment(self, extra: Mapping[str, str]) -> dict[str, str]:
        environment = {
            "HOME": str(self.home),
            "LANG": "C",
            "LC_ALL": "C",
            "PATH": SYSTEM_PATH,
            "DEVELOPER_DIR": DEVELOPER_DIR,
            "CFW_RELEASE_RUST_TOOLCHAIN": "private",
        }
        environment.update(extra)
        return environment

    def execute(
        self,
        argv: Sequence[str],
        *,
        cwd: Path,
        log: Path,
        extra_environment: Mapping[str, str] = {},
        attach_terminal: bool = False,
        keep_awake: bool = True,
    ) -> int:
        """Run one release entry point and append its output to ``log``."""

        command = (["/usr/bin/caffeinate", "-i"] if keep_awake else []) + list(argv)
        environment = self.closed_environment(extra_environment)
        with log.open("ab") as stream:
            header = f"$ {shlex.join(argv)}  (cwd {cwd})\n"
            stream.write(header.encode())
            stream.flush()
            if not attach_terminal:
                return subprocess.run(
                    command,
                    cwd=cwd,
                    env=environment,
                    stdin=subprocess.DEVNULL,
                    stdout=stream,
                    stderr=subprocess.STDOUT,
                    umask=0o022,
                    check=False,
                ).returncode
            # Prompts and operator instructions must reach the terminal; the
            # log receives the same bytes. The pipe's reader is closed with
            # the process once the child has finished; left open, Python
            # reports it when the driver exits.
            with subprocess.Popen(
                command,
                cwd=cwd,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                umask=0o022,
            ) as process:
                assert process.stdout is not None
                for chunk in iter(lambda: process.stdout.read1(4096), b""):
                    sys.stdout.buffer.write(chunk)
                    sys.stdout.buffer.flush()
                    stream.write(chunk)
                    stream.flush()
                return process.wait()

    def free_gib(self) -> float:
        usage = shutil.disk_usage("/")
        return usage.free / (1024**3)

    def stdin_is_terminal(self) -> bool:
        return sys.stdin.isatty() and sys.stdout.isatty()

    def over_ssh(self) -> bool:
        return bool(os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY"))


# --- guards -----------------------------------------------------------------


def git(machine: Machine, checkout: Path, *arguments: str) -> str:
    result = machine.read(["/usr/bin/env", "GIT_OPTIONAL_LOCKS=0", "/usr/bin/git", "-C", str(checkout), *arguments])
    if result.status != 0:
        raise DriverError(f"git {' '.join(arguments)} failed in {checkout}: {result.reason()}", CHECKOUT)
    return result.stdout.strip()


def require_clean_checkout(machine: Machine, checkout: Path, commit: str) -> None:
    head = git(machine, checkout, "rev-parse", "--verify", "HEAD")
    if head != commit:
        raise DriverError(f"{checkout} is at {head}, not the release commit {commit}", CHECKOUT)
    if git(machine, checkout, "status", "--porcelain"):
        raise DriverError(f"{checkout} has uncommitted or untracked changes", CHECKOUT)


def require_no_release_command(machine: Machine) -> None:
    running = machine.read(["/usr/bin/pgrep", "-f", RELEASE_COMMAND_PATTERN])
    pids = running.stdout.split()
    if pids:
        raise DriverError(
            f"a release build or gate is running on this Mac (pids {' '.join(pids)}); wait for it to finish",
            MACHINE,
        )


def require_pinned_xcode(machine: Machine, pins: Mapping[str, str]) -> None:
    expected = f"Xcode {pins['XCODE_VERSION']}\nBuild version {pins['XCODE_BUILD_VERSION']}"
    result = machine.read(["/usr/bin/xcodebuild", "-version"])
    if result.status != 0 or result.stdout.strip() != expected:
        found = " ".join(result.stdout.split()) or result.reason()
        raise DriverError(
            f"the release pins {' '.join(expected.split())}, but {DEVELOPER_DIR} reports {found}",
            PREREQUISITE,
        )


def require_free_space(machine: Machine, minimum_gib: int) -> None:
    free = machine.free_gib()
    if free < minimum_gib:
        raise DriverError(f"only {free:.1f} GiB is free on /; {minimum_gib} GiB is required", PREREQUISITE)


def require_desktop_terminal(machine: Machine) -> None:
    if machine.over_ssh():
        raise DriverError("run this stage in Terminal on the logged-in desktop, not over SSH", USAGE)
    if not machine.stdin_is_terminal():
        raise DriverError("this stage needs an interactive terminal on stdin and stdout", USAGE)


def installed_build(machine: Machine) -> str | None:
    try:
        with (INSTALLED_APP / "Contents/Info.plist").open("rb") as stream:
            value = plistlib.load(stream).get("CFBundleVersion")
    except FileNotFoundError:
        return None
    return value if isinstance(value, str) else None


# --- the stage context --------------------------------------------------------


@dataclass
class Context:
    release: Release
    repository: Path
    pins: Mapping[str, str]
    machine: Machine
    commit: str | None = None
    arguments: Sequence[str] = field(default_factory=tuple)

    def require_commit(self) -> str:
        if self.commit is None:
            enrollment = read_record(self.release, "enroll")
            commit = enrollment.get("commit") if enrollment else None
            if not isinstance(commit, str) or not COMMIT_RE.fullmatch(commit):
                raise DriverError("the release is not enrolled; run the enroll stage first", PREREQUISITE)
            self.commit = commit
        return self.commit

    def new_log(self, stage: str) -> Path:
        self.release.logs.mkdir(mode=0o700, parents=True, exist_ok=True)
        existing = sorted(self.release.logs.glob("[0-9][0-9][0-9]-*.log"))
        number = int(existing[-1].name[:3]) + 1 if existing else 1
        path = self.release.logs / f"{number:03d}-{stage}.log"
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(descriptor)
        return path


def common_guards(context: Context, *, free_gib: int = MIN_FREE_GIB) -> str:
    commit = context.require_commit()
    for checkout in (context.release.operator, context.release.artifact):
        require_clean_checkout(context.machine, checkout, commit)
    require_no_release_command(context.machine)
    require_pinned_xcode(context.machine, context.pins)
    require_free_space(context.machine, free_gib)
    return commit


def run_logged(
    context: Context,
    stage: str,
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    extra_environment: Mapping[str, str] = {},
    attach_terminal: bool = False,
) -> tuple[int, Path]:
    log = context.new_log(stage)
    status = context.machine.execute(
        argv,
        cwd=cwd or context.release.operator,
        log=log,
        extra_environment=extra_environment,
        attach_terminal=attach_terminal,
    )
    print(f"{stage}: {shlex.join(argv)} exit={status} log={log}")
    if not attach_terminal:
        _print_tail(log, 8)
    return status, log


def run_entry(
    context: Context,
    stage: str,
    argv: Sequence[str],
    *,
    cwd: Path | None = None,
    extra_environment: Mapping[str, str] = {},
    attach_terminal: bool = False,
) -> int:
    return run_logged(
        context,
        stage,
        argv,
        cwd=cwd,
        extra_environment=extra_environment,
        attach_terminal=attach_terminal,
    )[0]


def _print_tail(log: Path, lines: int) -> None:
    text = log.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in text[-lines:]:
        print(f"  {line[:240]}")
