#!/usr/bin/env python3
"""Drive one Clash for Mac GA release from the state its artifacts record.

The driver is the only operator entry point of a release (RELEASE.md). It owns
no release logic: every stage runs one existing, reviewed entry point in the
closed release environment. What it adds is the order. Each stage knows how to
recognise that it is complete from the files the release tools publish, so
``next`` always names the one step that the recorded state allows, and ``run``
refuses a stage that is already complete or whose predecessor is not. An old
command copied from a chat or a log can therefore never repeat or skip a step.

Commands (through scripts/cfm_release.sh):
  status            every stage with its state
  next              the one stage to run now, who runs it and what it needs
  run STAGE [...]   run that stage after its guards pass
  preflight         the CI workflow's inline content checks, before pushing
  shipped [--add]   list or register shipped releases

What every stage shares lives in scripts/release_driver_context.py. This module
is the only one that imports the stage modules, and none of them imports it:
the release launcher runs it as __main__.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import shlex
import sys
from typing import Callable, Final, Iterator, Mapping, Sequence

REPOSITORY = Path(__file__).resolve().parent.parent
if str(REPOSITORY) not in sys.path:
    sys.path.insert(0, str(REPOSITORY))

from scripts.publication.review_carryover import (  # noqa: E402
    APPROVAL,
    REVIEWED,
    Release as ReviewRelease,
)
from scripts.release_build_identity import (  # noqa: E402
    SIGNED_APP_NAME,
    BuildIdentityError,
    canonical_build_version,
)
from scripts.release_driver_acceptance import run_acceptance  # noqa: E402
from scripts.release_driver_context import (  # noqa: E402
    MACHINE,
    MIN_FREE_GIB,
    PREREQUISITE,
    USAGE,
    Context,
    DriverError,
    Machine,
    Release,
    common_guards,
    git,
    installed_build,
    load_pins,
    path_present,
    read_record,
    release_for,
    require_clean_checkout,
    require_desktop_terminal,
    require_free_space,
    require_no_release_command,
    run_entry,
    run_logged,
    write_record,
)
from scripts.release_driver_review import (  # noqa: E402
    add_shipped,
    read_ledger,
    review_release,
    run_component_review,
    run_legal_review,
)

BUILD_FREE_GIB: Final = 12

# Release-owned signing configuration. None of these values is secret: the
# identity name, the profile UUIDs and the Keychain profile name only select
# credentials that macOS releases after its own prompts.
SIGNING_ENVIRONMENT: Final[Mapping[str, str]] = {
    "NOTARY_PROFILE": "clashformac-notary",
    "MACOS_SIGN_IDENTITY": "Developer ID Application: Zi ang Li (YKUPL7Z869)",
    "PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER": "379ef639-4fff-4301-b083-3e49578f0910",
    "PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER": "3f275eaf-0fca-4af6-97a3-c93c4e83dc15",
}
HOST_PROFILE_RELATIVE: Final = Path(
    "Library/Developer/Xcode/UserData/Provisioning Profiles/"
    "e693a49a-7e25-4cd8-beea-0a8cdf22936e.provisionprofile"
)
NOTARY_ENVIRONMENT: Final[Mapping[str, str]] = {"NOTARY_PROFILE": "clashformac-notary"}

# Inputs a release checkout receives from a development worktree whose gates
# passed on the same commit. The artifact's own preparation lanes revalidate
# every one of them before anything is built.
ENROLLMENT_INPUTS: Final = (
    "target/toolchains",
    "target/native-dependencies",
    "apps/cfw-tauri-shell/node_modules",
)
PREPARATION_GATES: Final = (
    "prepare-cargo-workspace-inputs",
    "bootstrap-release-toolchain",
    "prepare-ui-dependencies",
    "build-script-boundary",
    "rust-metadata",
    "verify-xcode-project",
    "version-contract",
    "ci-no-masking",
    "cargo-deny",
    "rust-target-audit",
)


# --- stages -----------------------------------------------------------------

OWNER: Final = "owner"
ANYONE: Final = "anyone"


@dataclass(frozen=True)
class Stage:
    name: str
    summary: str
    actor: str
    needs: str
    is_done: Callable[[Context], bool]
    run: Callable[[Context], int]
    # A stage that applies only to some releases says so; a skipped stage
    # counts as complete.
    applies: Callable[[Context], bool] = lambda context: True
    # Read-only explanation of a partially complete stage, if it can be one.
    partial: Callable[[Context], str | None] = lambda context: None
    # Arguments the operator must add to ``run STAGE``.
    usage: str = ""


def _existing_path(value: Path, what: str) -> Path:
    """An operator's path argument, resolved; one that names nothing is a usage error."""

    try:
        return value.resolve(strict=True)
    except FileNotFoundError as error:
        raise DriverError(f"{what} does not exist: {value}", USAGE) from error


# enroll ----------------------------------------------------------------------


def _enroll_done(context: Context) -> bool:
    return read_record(context.release, "enroll") is not None and path_present(context.release.artifact / "target")


def _enroll(context: Context) -> int:
    parser = argparse.ArgumentParser(prog="cfm_release.sh run enroll")
    parser.add_argument("--inputs", required=True, type=Path, help="development worktree whose gates passed on this commit")
    options = parser.parse_args(context.arguments)
    release = context.release
    source = context.repository
    commit = git(context.machine, source, "rev-parse", "--verify", "HEAD")
    require_clean_checkout(context.machine, source, commit)
    inputs = _existing_path(options.inputs, "the input worktree")
    if git(context.machine, inputs, "rev-parse", "--verify", "HEAD") != commit:
        raise DriverError(f"the input worktree {inputs} is not at the release commit {commit}", PREREQUISITE)
    sources = [Path(path) for path in ENROLLMENT_INPUTS] + [
        Path(f"target/sources/sing-box-{release.sing_box_version}-patched")
    ]
    for relative in sources:
        candidate = inputs / relative
        if not candidate.is_dir() or candidate.is_symlink():
            raise DriverError(f"the input worktree lacks {relative}", PREREQUISITE)
    if path_present(release.operator):
        raise DriverError(f"refusing to replace {release.operator}", PREREQUISITE)
    require_no_release_command(context.machine)
    require_free_space(context.machine, MIN_FREE_GIB)
    release.home.mkdir(mode=0o700, parents=True, exist_ok=True)
    common_dir = git(context.machine, source, "rev-parse", "--path-format=absolute", "--git-common-dir")
    steps: list[list[str]] = [
        ["/usr/bin/git", "clone", "--quiet", "--no-checkout", common_dir, str(release.operator)],
        ["/usr/bin/git", "-C", str(release.operator), "-c", "advice.detachedHead=false", "checkout", "--quiet", "--detach", commit],
        ["/usr/bin/git", "-C", str(release.operator), "worktree", "add", "--quiet", "--detach",
         f"target/release-worktrees/{release.build}", commit],
        ["/bin/mkdir", "-m", "0700", str(release.artifact / "target")],
        ["/bin/mkdir", "-m", "0755", str(release.artifact / "target/sources")],
    ]
    for relative in sources:
        steps.append(["/bin/cp", "-Rpc", str(inputs / relative), str(release.artifact / relative)])
    log = context.new_log("enroll")
    for argv in steps:
        status = context.machine.execute(argv, cwd=source, log=log, keep_awake=False)
        if status != 0:
            print(f"enroll: {shlex.join(argv)} exit={status} log={log}")
            return status
    for checkout in (release.operator, release.artifact):
        require_clean_checkout(context.machine, checkout, commit)
    write_record(release, "enroll", {"commit": commit, "inputs": str(inputs)})
    print(f"enrolled {release.version} GA build {release.build} at {commit}: {release.artifact}")
    return 0


# prepare -----------------------------------------------------------------------


def _prepare_done(context: Context) -> bool:
    record = read_record(context.release, "prepare")
    return record is not None and record.get("commit") == context.require_commit()


def _prepare(context: Context) -> int:
    commit = common_guards(context)
    artifact = context.release.artifact
    status = run_entry(context, "prepare-verify-environment", ["./scripts/verify_release_environment.sh"], cwd=artifact)
    if status != 0:
        return status
    for gate in PREPARATION_GATES:
        status = run_entry(context, f"prepare-{gate}", ["./scripts/run_release_ci_gate.sh", gate], cwd=artifact)
        if status != 0:
            return status
    status = run_entry(
        context,
        "prepare-libbox-vulnerability-scan",
        ["./scripts/run_release_ci_gate.sh", "libbox-vulnerability-scan", str(context.release.libbox_source)],
        cwd=artifact,
    )
    if status != 0:
        return status
    write_record(context.release, "prepare", {"commit": commit})
    return 0


# build ---------------------------------------------------------------------------


def _build_done(context: Context) -> bool:
    signed = context.release.ga / "signed"
    return all(path_present(signed / name) for name in (SIGNED_APP_NAME, "notarization.json", "gatekeeper.json"))


def _build_partial(context: Context) -> str | None:
    if path_present(context.release.ga / "candidate-freeze/intent.json"):
        return (
            "the candidate is frozen but not yet signed and notarized. Never rerun the builder with --ga: "
            "an interrupted signing attempt resumes only with `run build --resume-signing`, a lost notary "
            "reply only with `run build --recover-notarization-id UUID`, and either only after the "
            "attempt's recorded state has been read (RELEASE.md, step 4)."
        )
    if path_present(context.release.artifact / f"target/candidates/{context.release.version}/ga-preflight"):
        return (
            "an earlier builder run stopped before candidate freeze. Keep its preflight directory: move it "
            "to a private history path before the next attempt (RELEASE.md, single-GA sequence)."
        )
    return None


def _build(context: Context) -> int:
    arguments = list(context.arguments) or ["--ga"]
    if arguments[0] not in ("--ga", "--resume-signing", "--recover-notarization-id"):
        raise DriverError("build accepts --ga, --resume-signing or --recover-notarization-id UUID", USAGE)
    frozen = path_present(context.release.ga / "candidate-freeze/intent.json")
    if arguments == ["--ga"] and frozen:
        raise DriverError("the candidate is already frozen; read `next` for the only allowed recovery", PREREQUISITE)
    if arguments[0] != "--ga" and not frozen:
        raise DriverError("there is no frozen candidate to resume", PREREQUISITE)
    require_desktop_terminal(context.machine)
    common_guards(context, free_gib=BUILD_FREE_GIB)
    if arguments == ["--ga"]:
        _require_hosted_ci_selected(context)
    profile = context.machine.home / HOST_PROFILE_RELATIVE
    if not profile.is_file():
        raise DriverError(f"the Host Developer ID profile is missing: {profile}", PREREQUISITE)
    return run_entry(
        context,
        "build",
        ["./scripts/build_signed_candidate.sh", *arguments],
        cwd=context.release.artifact,
        extra_environment={**SIGNING_ENVIRONMENT, "HOST_PROVISIONING_PROFILE_PATH": str(profile)},
        attach_terminal=True,
    )


def _require_hosted_ci_selected(context: Context) -> int:
    record = read_record(context.release, "ci")
    if record is None or record.get("commit") != context.require_commit():
        raise DriverError("hosted CI has not passed on the release commit; run the ci stage first", PREREQUISITE)
    run_id = record.get("run_id")
    if not isinstance(run_id, int):
        raise DriverError("the ci record names no workflow run", PREREQUISITE)
    return run_id


# receipt -------------------------------------------------------------------------


def _receipt_done(context: Context) -> bool:
    return path_present(context.release.stage_inputs / "hosted-ci.json")


def _receipt(context: Context) -> int:
    run_id = _require_hosted_ci_selected(context)
    commit = common_guards(context)
    if not _build_done(context):
        raise DriverError("the candidate is not signed and notarized yet", PREREQUISITE)
    status = run_entry(
        context,
        "receipt",
        ["/bin/bash", "-p", "./scripts/release_publication_gate.sh", "--capture-hosted-ci", str(run_id)],
    )
    if status != 0:
        return status
    # The ci stage selected a run of the release commit itself, so the receipt
    # never needs the tested-source exception for a later test-only commit.
    receipt = json.loads((context.release.stage_inputs / "hosted-ci.json").read_bytes())
    tested = receipt.get("tested_source", {}).get("repository_commit")
    if tested != commit:
        raise DriverError(f"the captured run tested {tested}, not the release commit {commit}", PREREQUISITE)
    return 0


# publication evidence ----------------------------------------------------------


def _publication_done(context: Context) -> bool:
    return path_present(context.release.stage_inputs / "publication/inventory.json")


def _preserved(context: Context) -> bool:
    return path_present(context.release.preserved_publication / "tree-identity.json")


def _review_template_done(context: Context) -> bool:
    return path_present(context.release.stage_inputs / "component-review.json")


def _review_template(context: Context) -> int:
    common_guards(context)
    return run_entry(
        context,
        "review-template",
        ["/bin/bash", "-p", "./scripts/prepare_publication_evidence.sh", "review-template",
         "--libbox-source", str(context.release.libbox_source)],
    )


def _reviewed_components_done(context: Context) -> bool:
    return path_present(context.release.review / REVIEWED)


def _prepare_publication_done(context: Context) -> bool:
    return path_present(context.release.stage_inputs / "publication-prepared") or _publication_done(context)


def _prepare_publication(context: Context) -> int:
    common_guards(context)
    reviewed = context.release.review / REVIEWED
    if not reviewed.is_file():
        raise DriverError(f"the reviewed component input is missing: {reviewed}", PREREQUISITE)
    return run_entry(
        context,
        "publication-prepare",
        ["/bin/bash", "-p", "./scripts/prepare_publication_evidence.sh", "prepare",
         "--libbox-source", str(context.release.libbox_source), "--reviewed-components", str(reviewed)],
    )


def _draft_done(context: Context) -> bool:
    return path_present(context.release.stage_inputs / "machine-closure.draft.json") or _publication_done(context)


def _draft(context: Context) -> int:
    common_guards(context)
    inputs = context.release.stage_inputs
    return run_entry(
        context,
        "publication-draft",
        ["/bin/bash", "-p", "./scripts/run_publication_evidence.sh", "draft",
         "--prepared", str(inputs / "publication-prepared"),
         "--app", str(context.release.signed_app),
         "--output", str(inputs / "machine-closure.draft.json")],
    )


def _legal_review_done(context: Context) -> bool:
    return path_present(context.release.stage_inputs / "legal-review.json") and path_present(
        context.release.review / APPROVAL
    )


def _finalize(context: Context) -> int:
    common_guards(context)
    inputs = context.release.stage_inputs
    if not _legal_review_done(context):
        raise DriverError("the legal review of the draft closure is missing", PREREQUISITE)
    return run_entry(
        context,
        "publication-finalize",
        ["/bin/bash", "-p", "./scripts/run_publication_evidence.sh", "finalize",
         "--prepared", str(inputs / "publication-prepared"),
         "--app", str(context.release.signed_app),
         "--review", str(inputs / "legal-review.json"),
         "--output", str(inputs / "publication")],
    )


def _preserve(context: Context) -> int:
    """Move publication-prepared out of the workspace and record its tree identity."""

    common_guards(context)
    release = context.release
    source = release.stage_inputs / "publication-prepared"
    target = release.preserved_publication
    if not source.is_dir() or source.is_symlink():
        raise DriverError(f"publication-prepared is not in the stage inputs: {source}", PREREQUISITE)
    if path_present(target):
        raise DriverError(f"refusing to reuse an existing history directory: {target}", PREREQUISITE)
    release.history.mkdir(mode=0o700, parents=True, exist_ok=True)
    if os.stat(release.history).st_dev != os.stat(source).st_dev:
        raise DriverError("the history root is on another volume; the move must be one rename", PREREQUISITE)
    verify = ["/bin/bash", "-p", "./scripts/run_publication_evidence.sh", "verify",
              "--evidence", str(release.stage_inputs / "publication"), "--app", str(release.signed_app)]
    status = run_entry(context, "preserve-verify-before", verify)
    if status != 0:
        return status
    target.mkdir(mode=0o700)
    python = _release_python(context)
    status = run_entry(
        context,
        "preserve-hash-before",
        [python, "-I", "-B", "./scripts/hash_artifact.py", str(source),
         "--algorithm", "sha256-tree-v2", "--output", str(target / "source-tree-v2.json")],
    )
    if status != 0:
        return status
    os.rename(source, target / "publication-prepared")
    status = run_entry(
        context,
        "preserve-hash-after",
        [python, "-I", "-B", "./scripts/hash_artifact.py", str(target / "publication-prepared"),
         "--algorithm", "sha256-tree-v2", "--output", str(target / "retained-tree-v2.json")],
    )
    if status != 0:
        return status
    before = (target / "source-tree-v2.json").read_bytes()
    after = (target / "retained-tree-v2.json").read_bytes()
    if before != after:
        raise DriverError(
            f"the moved tree differs from the source tree; inspect {target} and move nothing back", PREREQUISITE
        )
    manifest = json.loads(after)
    identity = {
        "source": str(source),
        "moved_to": str(target / "publication-prepared"),
        "algorithm": manifest["algorithm"],
        "identity": {
            "root_mode": manifest["rootMode"],
            "entries": len(manifest["entries"]),
            "tree_sha256": manifest["sha256"],
        },
    }
    descriptor = os.open(target / "tree-identity.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(identity, stream)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps(identity))
    return run_entry(context, "preserve-verify-after", verify)


def _release_python(context: Context) -> str:
    series = context.pins["PYTHON_VERSION"].rsplit(".", 1)[0]
    executable = (
        f"/opt/homebrew/Cellar/python@{series}/{context.pins['PYTHON_VERSION']}"
        f"/Frameworks/Python.framework/Versions/{series}/bin/python{series}"
    )
    if not os.access(executable, os.X_OK):
        raise DriverError(f"the pinned release Python is unavailable: {executable}", PREREQUISITE)
    return executable


# sealing and packaging ----------------------------------------------------------


def _gate(context: Context, stage: str, option: str, *extra: str) -> int:
    common_guards(context)
    return run_entry(context, stage, ["/bin/bash", "-p", "./scripts/release_publication_gate.sh", option, *extra])


def _prepackage_done(context: Context) -> bool:
    return path_present(context.release.ga / "prepackage/manifest.json")


def _dmg(context: Context) -> int:
    arguments = list(context.arguments)
    if arguments and arguments[0] != "--recover-submission-id":
        raise DriverError("dmg accepts only --recover-submission-id UUID", USAGE)
    require_desktop_terminal(context.machine)
    common_guards(context)
    return run_entry(
        context,
        "dmg",
        ["./scripts/make_dmg.sh", *arguments],
        extra_environment=NOTARY_ENVIRONMENT,
        attach_terminal=True,
    )


def _updater(context: Context) -> int:
    require_desktop_terminal(context.machine)
    common_guards(context)
    return run_entry(context, "updater", ["./scripts/make_updater_manifest.sh"], attach_terminal=True)


# install -------------------------------------------------------------------------
#
# The install sequence is four fixed transactions. Each has its own journal and
# refuses to repeat a completed transaction, so the driver records each success
# and resumes after the last one. A failure is never retried automatically:
# every transaction has exactly one documented recovery (RELEASE.md step 6).

INSTALL_STEPS: Final = (
    ("archive-history", ("./scripts/run_archive_install_history.sh", "--previous-build", "{previous}")),
    ("decommission", ("./scripts/run_current_service_transaction.sh", "--decommission")),
    ("install", ("./scripts/run_dormant_app_install.sh", "--install")),
    ("recommission", ("./scripts/run_current_service_transaction.sh", "--recommission")),
)
INSTALL_STEP_NAMES: Final = frozenset(name for name, _ in INSTALL_STEPS)
INSTALL_RECOVERY: Final = {
    "archive-history": "rerun `run install`; the archiver resumes its own two renames",
    "decommission": "run `run install --recover-service`",
    "install": "run `run install --recover-install`; never retry the install itself",
    "recommission": "if it reports journal_not_terminal, finish the install with `run install --recover-install` first; "
    "otherwise run `run install --recover-service`",
}


@dataclass(frozen=True)
class InstallRecovery:
    """One documented recovery and the result lines that prove what it completed.

    Both transactions recover forward only, so a successful recovery reports
    the step it finished; that step is recorded, and ``run install`` then
    resumes after it instead of repeating a completed transaction.
    """

    stage: str
    argv: tuple[str, ...]
    proofs: tuple[tuple[re.Pattern[str], str], ...]


INSTALL_RECOVERIES: Final = {
    "--recover-install": InstallRecovery(
        "install-recover",
        ("./scripts/run_dormant_app_install.sh", "--recover"),
        ((re.compile(r"^dormant install transaction installed: ", re.MULTILINE), "install"),),
    ),
    "--recover-service": InstallRecovery(
        "install-recover-service",
        ("./scripts/run_current_service_transaction.sh", "--recover"),
        (
            (re.compile(r"^current-service transaction decommissioned: ", re.MULTILINE), "decommission"),
            (re.compile(r"^current-service transaction recommissioned: ", re.MULTILINE), "recommission"),
        ),
    ),
    # Records a DNS observation continuation; it completes no transaction.
    "--continue-after-dns-change": InstallRecovery(
        "install-continue-after-dns-change",
        ("./scripts/run_current_service_transaction.sh", "--continue-after-dns-change"),
        (),
    ),
}


def _previous_build(context: Context) -> str:
    """The active migration predecessor that the installed release must be."""

    # Imported here only: the installer module loads the whole migration
    # toolchain, which no other stage or command needs.
    from scripts.dormant_app_install import ACTIVE_PREDECESSOR

    return ACTIVE_PREDECESSOR.build_number


def _install_done(context: Context) -> bool:
    record = read_record(context.release, "install") or {}
    return all(record.get(name) is True for name, _ in INSTALL_STEPS)


def _install(context: Context) -> int:
    arguments = list(context.arguments)
    if len(arguments) > 1 or (arguments and arguments[0] not in INSTALL_RECOVERIES):
        raise DriverError(f"install accepts no argument or one of {', '.join(INSTALL_RECOVERIES)}", USAGE)
    for name in ("seal-prepackage", "dmg", "updater"):
        if not STAGES_BY_NAME[name].is_done(context):
            raise DriverError(f"the {name} stage has not completed; nothing is installed before packaging", PREREQUISITE)
    common_guards(context)
    record = dict(read_record(context.release, "install") or {})
    if arguments:
        return _recover_install(context, INSTALL_RECOVERIES[arguments[0]], record)
    previous = _previous_build(context)
    for name, template in INSTALL_STEPS:
        if record.get(name) is True:
            continue
        argv = [part.format(previous=previous) for part in template]
        status = run_entry(context, f"install-{name}", argv)
        if status != 0:
            print(f"install stopped at {name}: {INSTALL_RECOVERY[name]}")
            return status
        _record_install_step(context, record, name)
    _require_installed_release(context)
    return 0


def _recover_install(context: Context, recovery: InstallRecovery, record: dict[str, object]) -> int:
    status, log = run_logged(context, recovery.stage, recovery.argv)
    if status != 0 or not recovery.proofs:
        return status
    output = log.read_text(encoding="utf-8", errors="replace")
    completed = [step for pattern, step in recovery.proofs if pattern.search(output)]
    if len(completed) != 1:
        raise DriverError(
            f"{recovery.stage} succeeded but did not report which transaction it completed; see {log}",
            PREREQUISITE,
        )
    _record_install_step(context, record, completed[0])
    print(f"{recovery.stage}: {completed[0]} is complete; `next` names the step to run now")
    if all(record.get(name) is True for name in INSTALL_STEP_NAMES):
        _require_installed_release(context)
    return 0


def _record_install_step(context: Context, record: dict[str, object], name: str) -> None:
    record[name] = True
    write_record(context.release, "install", {key: value for key, value in record.items() if key in INSTALL_STEP_NAMES})


def _require_installed_release(context: Context) -> None:
    build = installed_build(context.machine)
    if build != context.release.build:
        raise DriverError(f"/Applications holds build {build}, not {context.release.build}", MACHINE)


def _export_done(context: Context) -> bool:
    return path_present(context.release.acceptance / "migration-journals")


def _export(context: Context) -> int:
    arguments = list(context.arguments) or ["--export"]
    if arguments not in (["--export"], ["--recover"], ["--verify"]):
        raise DriverError("export accepts --recover or --verify", USAGE)
    common_guards(context)
    return run_entry(context, "export", ["./scripts/run_ga_acceptance_journal_export.sh", *arguments])


# acceptance --------------------------------------------------------------------


def _acceptance_done(context: Context) -> bool:
    return path_present(context.release.acceptance / "runtime-acceptance.json")


def _acceptance_partial(context: Context) -> str | None:
    if path_present(context.release.acceptance / "runtime-evidence"):
        return "raw evidence is published but not sealed: run `run acceptance --resume-seal` (repeatable); never recover"
    if path_present(context.release.acceptance / "runtime-collection"):
        return "a collection is unfinished: run `run acceptance --recover`, then a fresh `run acceptance`"
    return None


def _acceptance(context: Context) -> int:
    common_guards(context)
    return run_acceptance(context)


# publication -----------------------------------------------------------------


def _ga_acceptance_sealed(context: Context) -> bool:
    return path_present(context.release.ga / "ga-acceptance/manifest.json")


def _publication_sealed(context: Context) -> bool:
    return path_present(context.release.ga / "publication/manifest.json") and path_present(
        context.release.package_seal("distribution")
    )


def _publish_done(context: Context) -> bool:
    return read_record(context.release, "publish") is not None


def _publish(context: Context) -> int:
    """Print the exact upload allowlist and the owner's GitHub commands.

    The upload itself is the owner's GitHub action. This stage completes once
    the allowlist has been printed; verify-remote then proves what was uploaded.
    """

    status = _gate(context, "upload-allowlist", "--upload-assets", context.release.version)
    if status != 0:
        return status
    write_record(context.release, "publish", {"allowlist": "printed"})
    commit = context.require_commit()
    tag = f"v{context.release.version}"
    print(
        "\nPublish only the allowlisted files above, from your own account:\n"
        f"  gh release create {tag} --repo billlza/cfw-rs --target {commit} --draft --title "
        f"'Clash for Mac {context.release.version}' --notes-file <release notes>\n"
        f"  gh release upload {tag} --repo billlza/cfw-rs <each allowlisted file>\n"
        f"  gh release edit {tag} --repo billlza/cfw-rs --draft=false\n"
        "Then run `run verify-remote --trusted-distribution-seal PATH --sha256 HEX` with the offline copy of "
        f"{context.release.package_seal('distribution').name}."
    )
    return 0


def _verify_remote_done(context: Context) -> bool:
    return read_record(context.release, "verify-remote") is not None


def _verify_remote(context: Context) -> int:
    parser = argparse.ArgumentParser(prog="cfm_release.sh run verify-remote")
    parser.add_argument("--trusted-distribution-seal", required=True, type=Path)
    parser.add_argument("--sha256", required=True)
    options = parser.parse_args(context.arguments)
    if not re.fullmatch(r"[0-9a-f]{64}", options.sha256):
        raise DriverError("--sha256 must be 64 lowercase hex digits", USAGE)
    seal = _existing_path(options.trusted_distribution_seal, "the offline distribution seal")
    if seal.read_bytes() != context.release.package_seal("distribution").read_bytes():
        raise DriverError("the offline distribution seal differs from the locally sealed one", PREREQUISITE)
    common_guards(context)
    status = run_entry(
        context,
        "verify-remote",
        ["./scripts/run_verify_remote_release.sh", "--version", context.release.version,
         "--trusted-distribution-seal", str(seal), "--trusted-distribution-seal-sha256", options.sha256],
        cwd=context.release.artifact,
    )
    if status == 0:
        # The ledger entry is the release's terminal state, so it is written
        # first: the next release carries this build's approved decisions
        # forward from it, and a refused entry leaves verify-remote pending.
        add_shipped(context.machine.home, review_release(context.release))
        write_record(context.release, "verify-remote", {"seal_sha256": options.sha256})
        print(f"{context.release.version} build {context.release.build} is registered as shipped")
    return status


# ci ---------------------------------------------------------------------------------


def _ci_done(context: Context) -> bool:
    record = read_record(context.release, "ci")
    return record is not None and record.get("commit") == context.require_commit()


PREFLIGHT_RESULT_RE: Final = re.compile(
    r"^hosted CI preflight passed: run=([1-9][0-9]{0,19}) attempt=[1-9][0-9]* head=([0-9a-f]{40}) jobs=3$",
    re.MULTILINE,
)


def _ci(context: Context) -> int:
    """Select the hosted run that passed on the release commit, before any freeze."""

    commit = common_guards(context)
    status, log = run_logged(
        context, "ci", ["./scripts/run_hosted_ci_preflight.sh"], cwd=context.release.artifact
    )
    if status != 0:
        return status
    matches = PREFLIGHT_RESULT_RE.findall(log.read_text(encoding="utf-8", errors="replace"))
    if len(matches) != 1 or matches[0][1] != commit:
        raise DriverError(f"the hosted CI preflight did not report one run of {commit}; see {log}", PREREQUISITE)
    run_id = int(matches[0][0])
    write_record(context.release, "ci", {"commit": commit, "run_id": run_id})
    print(f"hosted CI run {run_id} passed on {commit}")
    return 0


def _owner_session(session: Callable[[Context], int]) -> Callable[[Context], int]:
    def run(context: Context) -> int:
        require_desktop_terminal(context.machine)
        common_guards(context)
        return session(context)

    return run


STAGES: Final[tuple[Stage, ...]] = (
    Stage("enroll", "operator clone, artifact worktree and inputs", ANYONE,
          "a development worktree at the release commit whose gates passed",
          _enroll_done, _enroll, usage="--inputs DEVELOPMENT_WORKTREE"),
    Stage("prepare", "artifact environment and preparation lanes", ANYONE, "network for Cargo and advisories",
          _prepare_done, _prepare),
    Stage("ci", "hosted CI passed on the exact release commit", ANYONE,
          "the release commit pushed as the head of the release pull request",
          _ci_done, _ci),
    Stage("build", "freeze, sign and notarize", OWNER,
          "Terminal on the desktop; Keychain prompts for Developer ID, the notary profile and the updater key",
          _build_done, _build, partial=_build_partial),
    Stage("receipt", "hosted CI receipt", ANYONE, "GitHub API", _receipt_done, _receipt),
    Stage("review-template", "component review template", ANYONE, "", _review_template_done, _review_template),
    Stage("review", "carry approved component decisions forward", OWNER,
          "Terminal; your decision for every new or changed manual license item",
          _reviewed_components_done, _owner_session(run_component_review)),
    Stage("publication-prepare", "publication inputs", ANYONE, "Apple notarization lookups",
          _prepare_publication_done, _prepare_publication),
    Stage("draft", "draft machine closure", ANYONE, "", _draft_done, _draft),
    Stage("legal-review", "legal review of the exact closure", OWNER,
          "Terminal; you type the closure digest and confirm both reviews",
          _legal_review_done, _owner_session(run_legal_review)),
    Stage("finalize", "finalized publication evidence", ANYONE, "", _publication_done, _finalize),
    Stage("preserve", "publication-prepared moved to private history", ANYONE, "", _preserved, _preserve),
    Stage("seal-prepackage", "prepackage seal", ANYONE, "GitHub API and Apple",
          _prepackage_done, lambda context: _gate(context, "seal-prepackage", "--seal-prepackage")),
    Stage("dmg", "signed, notarized DMG", OWNER, "Terminal on the desktop; Keychain prompts; Apple notarization",
          lambda context: path_present(context.release.package_seal("dmg")), _dmg),
    Stage("updater", "signed updater archive", OWNER, "Terminal; allow the updater key prompt within 15 seconds",
          lambda context: path_present(context.release.package_seal("updater")), _updater),
    Stage("install", "install on the release Mac", OWNER,
          "Clash for Mac quit with Cmd-Q and Off; App Management approval",
          _install_done, _install),
    Stage("export", "migration journal export", ANYONE, "", _export_done, _export),
    Stage("acceptance", "GA runtime acceptance", OWNER,
          "Terminal; administrator password; system extension approval; Cmd-Q at the end",
          _acceptance_done, _acceptance, partial=_acceptance_partial),
    Stage("seal-ga-acceptance", "GA acceptance seal", ANYONE, "Clash for Mac not running",
          _ga_acceptance_sealed, lambda context: _gate(context, "seal-ga-acceptance", "--seal-ga-acceptance")),
    Stage("seal-publication", "publication seal and distribution set", ANYONE, "GitHub API and Apple",
          _publication_sealed, lambda context: _gate(context, "seal-publication", "--seal-publication")),
    Stage("publish", "upload the allowlisted files", OWNER, "your GitHub account; explicit publication decision",
          _publish_done, _publish),
    Stage("verify-remote", "independent remote-byte verification", ANYONE,
          "the offline copy of the distribution seal and its digest",
          _verify_remote_done, _verify_remote, usage="--trusted-distribution-seal PATH --sha256 HEX"),
)
STAGES_BY_NAME: Final = {stage.name: stage for stage in STAGES}


def first_pending(context: Context) -> Stage | None:
    for stage in STAGES:
        if stage.applies(context) and not stage.is_done(context):
            return stage
    return None


def _state_line(context: Context, stage: Stage, pending: Stage | None) -> str:
    if not stage.applies(context):
        state = "skip"
    elif stage.is_done(context):
        state = "done"
    elif stage is pending:
        state = "NEXT"
    else:
        state = "    "
    return f"[{state}] {stage.name:<20} {stage.summary}"


def _shipped(context: Context) -> bool:
    return any(entry.get("build") == context.release.build for entry in read_ledger(context.machine.home))


SHIPPED_MESSAGE: Final = (
    "Clash for Mac {version} build {build} is shipped and verified. The next release starts with a new "
    "product version and a GA build allocation (RELEASE.md, allocating a GA build)."
)


def command_status(context: Context) -> int:
    release = context.release
    if _shipped(context):
        print(SHIPPED_MESSAGE.format(version=release.version, build=release.build))
        return 0
    print(f"Clash for Mac {release.version} GA build {release.build}")
    print(f"release home: {release.home}")
    enrolled = read_record(release, "enroll")
    if enrolled is None:
        pending = STAGES[0]
    else:
        context.commit = str(enrolled["commit"])
        print(f"release commit: {context.commit}")
        pending = first_pending(context)
    for stage in STAGES:
        if enrolled is None and stage is not STAGES[0]:
            print(f"[    ] {stage.name:<20} {stage.summary}")
        else:
            print(_state_line(context, stage, pending))
    return 0


def command_next(context: Context) -> int:
    release = context.release
    if _shipped(context):
        print(SHIPPED_MESSAGE.format(version=release.version, build=release.build))
        return 0
    enrolled = read_record(release, "enroll")
    if enrolled is not None:
        context.commit = str(enrolled["commit"])
        stage = first_pending(context)
    else:
        stage = STAGES[0]
    if stage is None:
        print(f"Clash for Mac {release.version} build {release.build} is released and verified.")
        return 0
    where = release.operator if enrolled is not None else context.repository
    print(f"next: {stage.name} - {stage.summary}")
    print(f"who:  {'you, at the release Mac' if stage.actor == OWNER else 'anyone with the release account'}")
    if stage.needs:
        print(f"needs: {stage.needs}")
    explanation = stage.partial(context) if enrolled is not None else None
    if explanation:
        print(f"state: {explanation}")
    else:
        suffix = f" {stage.usage}" if stage.usage else ""
        print(f"run:  cd {shlex.quote(str(where))} && scripts/cfm_release.sh run {stage.name}{suffix}")
    return 0


@contextmanager
def _exclusive_run(release: Release) -> Iterator[None]:
    """Hold the release's run lock: one ``run`` at a time, released on any exit.

    Every release tool guards its own transaction, but the driver's records and
    the evidence instances that ``acceptance`` starts and stops belong to the
    run, so a second run of the same release in another terminal is refused.
    """

    release.home.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(release.home / ".run.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
    try:
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as error:
            raise DriverError(
                "another `cfm_release.sh run` of this release is in progress; wait for it to finish", MACHINE
            ) from error
        yield
    finally:
        os.close(descriptor)


def command_run(context: Context, name: str) -> int:
    stage = STAGES_BY_NAME.get(name)
    if stage is None:
        raise DriverError(f"unknown stage {name}; stages: {', '.join(STAGES_BY_NAME)}", USAGE)
    if _shipped(context):
        raise DriverError(SHIPPED_MESSAGE.format(version=context.release.version, build=context.release.build),
                          PREREQUISITE)
    with _exclusive_run(context.release):
        if stage is not STAGES[0]:
            context.require_commit()
            pending = first_pending(context)
            if stage.is_done(context) and stage.name not in REPEATABLE_WHEN_DONE:
                raise DriverError(f"the {name} stage is already complete; `next` names the step to run now",
                                  PREREQUISITE)
            if pending is not None and pending is not stage and not stage.is_done(context):
                raise DriverError(f"run {pending.name} first; `next` explains it", PREREQUISITE)
        elif stage.is_done(context):
            raise DriverError("the release is already enrolled", PREREQUISITE)
        return stage.run(context)


# Read-only or idempotent modes a completed stage still accepts.
REPEATABLE_WHEN_DONE: Final = frozenset({"export"})


# The CI workflow's own steps that check repository content outside the gate
# lanes (.github/workflows/ci.yml). ``preflight`` runs each of them locally
# before a release commit is pushed; scripts/tests/test_release_driver.py
# fails when the workflow gains another such step.
SHELLCHECK: Final = "/opt/homebrew/bin/shellcheck"
INLINE_CONTENT_STEPS: Final = ("Validate shell scripts", "Lint shell scripts with pinned ShellCheck")


def command_preflight(context: Context) -> int:
    """Run the workflow's inline content checks on this checkout."""

    repository = context.repository
    failures: list[str] = []
    scripts = sorted(path for path in (repository / "scripts").rglob("*.sh") if path.is_file())
    for script in scripts:
        for shell in ("/bin/bash", "/bin/zsh"):
            result = context.machine.read([shell, "-n", str(script)], cwd=repository)
            if result.status != 0:
                failures.append(f"{shell} -n {script.relative_to(repository)}: {result.stderr.strip()}")
    print(f"{INLINE_CONTENT_STEPS[0]}: {len(scripts)} scripts, {len(failures)} failures")
    pinned = context.pins.get("SHELLCHECK_VERSION")
    version = context.machine.read([SHELLCHECK, "--version"])
    if version.status != 0 or f"version: {pinned}" not in version.stdout:
        raise DriverError(f"the workflow pins ShellCheck {pinned}; {SHELLCHECK} is not that version", PREREQUISITE)
    targets = sorted(
        str(path.relative_to(repository))
        for pattern in ("scripts/*.sh", "scripts/tests/*.sh")
        for path in repository.glob(pattern)
    )
    lint = context.machine.read([SHELLCHECK, "-x", *targets], cwd=repository, timeout=600)
    print(f"{INLINE_CONTENT_STEPS[1]}: exit {lint.status}")
    if lint.status != 0:
        failures.append((lint.stdout + lint.stderr).strip())
    for failure in failures:
        print(failure)
    if failures:
        return 1
    print("preflight passed: the workflow's inline content checks pass on this checkout")
    return 0


def _arguments(argv: Sequence[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="cfm_release.sh", description=__doc__.split("\n\n")[0])
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("status")
    commands.add_parser("next")
    run = commands.add_parser("run")
    run.add_argument("stage")
    run.add_argument("stage_arguments", nargs=argparse.REMAINDER)
    commands.add_parser("preflight", help="the CI workflow's inline content checks, before pushing")
    shipped = commands.add_parser("shipped", help="list or register shipped releases")
    shipped.add_argument("--add", nargs=4, metavar=("VERSION", "BUILD", "ARTIFACT", "REVIEW"))
    return parser.parse_args(argv)


def command_shipped(home: Path, add: Sequence[str] | None) -> int:
    if add:
        version, build, artifact, review = add
        try:
            canonical_build_version(build, "the shipped build")
        except BuildIdentityError as error:
            raise DriverError(str(error), USAGE) from error
        add_shipped(home, ReviewRelease(
            version,
            build,
            _existing_path(Path(artifact), "the shipped artifact checkout"),
            _existing_path(Path(review), "the shipped review directory"),
        ))
    for entry in read_ledger(home):
        print(f"{entry['version']} build {entry['build']}: artifact {entry['artifact']}; review {entry['review']}")
    return 0


def main(argv: Sequence[str] | None = None, *, machine: Machine | None = None) -> int:
    arguments = _arguments(sys.argv[1:] if argv is None else argv)
    if os.geteuid() == 0:
        raise DriverError("run the release driver as the owning account, never through sudo", USAGE)
    home = Path(os.environ.get("HOME", ""))
    if not home.is_absolute():
        raise DriverError("HOME must be the absolute home of the release account", USAGE)
    selected = machine or Machine(home)
    context = Context(
        release=release_for(REPOSITORY, selected.home),
        repository=REPOSITORY,
        pins=load_pins(REPOSITORY / "scripts/dependency_pins.env"),
        machine=selected,
        arguments=tuple(getattr(arguments, "stage_arguments", ()) or ()),
    )
    if arguments.command == "shipped":
        return command_shipped(selected.home, arguments.add)
    if arguments.command == "preflight":
        return command_preflight(context)
    if arguments.command == "status":
        return command_status(context)
    if arguments.command == "next":
        return command_next(context)
    return command_run(context, arguments.stage)


if __name__ == "__main__":
    try:
        sys.exit(main())
    except DriverError as error:
        print(f"refusing: {error}", file=sys.stderr)
        sys.exit(error.status)
