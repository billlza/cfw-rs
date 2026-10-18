"""Build the GA-pinned engine on Windows; this is not release admission.

The source is created in an absent, task-owned directory. We reuse the existing
upstream, patch, module and combined-diff pins rather than accepting a second
definition of the CFM engine. No existing checkout or global tool is modified.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import platform
import re
import shutil
import subprocess
import tempfile
import urllib.request
import zipfile

from publication.license_resolution import candidate_license_files


PATCHES = ("SECURITY", "RAW_PACKET", "DNS_FAILOVER", "ENDPOINT_CONFLICT", "PROFILE_PROBE", "SOCKS_LIFECYCLE")
DIFF_OPTIONS = [
    "-c", "diff.interHunkContext=0", "-c", "diff.suppressBlankEmpty=false",
    "diff", "--no-color", "--no-ext-diff", "--no-textconv", "--binary",
    "--full-index", "--no-renames", "--no-indent-heuristic", "--diff-algorithm=myers",
    "--unified=3", f"-O{os.devnull}", "--src-prefix=a/", "--dst-prefix=b/",
]


def sha256(path: Path) -> str:
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def source_files(source: Path) -> dict[str, str]:
    """Read actual bytes, independently of Git's index/stat optimization flags."""
    result = {}
    for directory, names, files in os.walk(source, followlinks=False):
        root = Path(directory)
        if root == source:
            names[:] = [name for name in names if name != ".git"]
        for name in names:
            require(not (root / name).is_symlink(), "engine source contains a directory symlink")
        for name in files:
            path = root / name
            regular_file(path)
            result[path.relative_to(source).as_posix()] = sha256(path)
    return result


def require(condition: bool, message: str) -> None:
    if not condition:
        raise RuntimeError(message)


def read_pins(repository: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in (repository / "scripts/dependency_pins.env").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=([^\s#]+)", line)
        if match:
            key, value = match.groups()
            require(key not in pins, f"duplicate dependency pin: {key}")
            pins[key] = value
    for key in ("GO_VERSION", "PYTHON_VERSION", "RUST_VERSION"):
        require(bool(re.fullmatch(r"\d+\.\d+\.\d+", pins[key])), f"invalid {key}")
    require(bool(re.fullmatch(r"[a-f0-9]{40}", pins["SING_BOX_COMMIT"])), "invalid engine commit")
    require(bool(re.fullmatch(r"v\d+\.\d+\.\d+", pins["SING_BOX_VERSION"])), "invalid engine version")
    require(bool(re.fullmatch(r"[a-z0-9_,]+", pins["LIBBOX_BUILD_TAGS"])), "invalid engine build tags")
    for key in ["GO_WINDOWS_AMD64_SHA256", "LIBBOX_MODULE_CACHE_CONTRACT_SHA256",
                "SING_BOX_COMBINED_DIFF_SHA256", "SING_BOX_PATCHED_DIFF_SHA256",
                "SING_BOX_UPSTREAM_GO_MOD_SHA256", "SING_BOX_UPSTREAM_GO_SUM_SHA256",
                "SING_BOX_PATCHED_GO_MOD_SHA256", "SING_BOX_PATCHED_GO_SUM_SHA256",
                *[f"SING_BOX_{name}_PATCH_SHA256" for name in PATCHES]]:
        require(bool(re.fullmatch(r"[a-f0-9]{64}", pins[key])), f"invalid {key}")
    return pins


def regular_file(path: Path) -> None:
    require(path.is_file() and not path.is_symlink(), f"expected a regular file: {path}")


def pinned_path(repository: Path, value: str) -> Path:
    relative = PurePosixPath(value)
    require(not relative.is_absolute() and ".." not in relative.parts and "\\" not in value,
            "pin must be a repository-relative path")
    path = repository.joinpath(*relative.parts)
    require(path.resolve().is_relative_to(repository.resolve()), "pin escapes the repository")
    regular_file(path)
    return path


def command(arguments: list[str], *, cwd: Path | None = None,
            env: dict[str, str] | None = None, timeout: int = 900) -> bytes:
    result = subprocess.run(arguments, cwd=cwd, env=env, capture_output=True, timeout=timeout)
    if result.returncode:
        # Only build/fixture inputs reach this command runner, never user secrets.
        raise RuntimeError(f"{Path(arguments[0]).name} {arguments[1]} failed ({result.returncode}):\n"
                           + result.stdout.decode("utf-8", errors="replace")
                           + result.stderr.decode("utf-8", errors="replace"))
    return result.stdout


def json_objects(data: bytes) -> list[dict[str, object]]:
    text = data.decode("utf-8")
    decoder = json.JSONDecoder()
    result = []
    while text.strip():
        text = text.lstrip()
        value, end = decoder.raw_decode(text)
        require(isinstance(value, dict), "invalid Go JSON object stream")
        result.append(value)
        text = text[end:]
    require(bool(result), "empty Go JSON object stream")
    return result


def module_graph(data: bytes) -> list[dict[str, object]]:
    result = []
    for module in json_objects(data):
        require(isinstance(module.get("Path"), str), "invalid Go module metadata")
        identity = {key: module[key] for key in ("Path", "Version", "Sum", "GoModSum", "Main") if key in module}
        if "Replace" in module:
            replacement = module["Replace"]
            require(isinstance(replacement, dict) and bool(replacement.get("Version")),
                    "unversioned local module replacement is not admitted")
            identity["Replace"] = {key: replacement[key] for key in ("Path", "Version", "Sum", "GoModSum") if key in replacement}
        result.append(identity)
    return result


def bundle_notices(go: Path, source: Path, output: Path, environment: dict[str, str], pins: dict[str, str]) -> dict[str, object]:
    packages = json_objects(command([str(go), "list", "-deps", "-json", "-tags", pins["LIBBOX_BUILD_TAGS"],
                                     "./cmd/sing-box", "./cmd/cfw-engine-host"], cwd=source, env=environment))
    roots: dict[tuple[str, str], Path] = {("Go", pins["GO_VERSION"]): go.parent.parent.resolve()}
    for package in packages:
        module = package.get("Module")
        if module is None:
            continue
        require(isinstance(module, dict) and "Replace" not in module, "unexpected linked module replacement")
        name = module.get("Path")
        version = pins["SING_BOX_VERSION"] if module.get("Main") is True else module.get("Version")
        directory = module.get("Dir")
        require(isinstance(name, str) and isinstance(version, str) and isinstance(directory, str),
                "linked module lacks a source identity for license collection")
        root = Path(directory).resolve(strict=True)
        allowed = source.resolve() if module.get("Main") is True else Path(environment["GOMODCACHE"]).resolve()
        require(root.is_relative_to(allowed), "linked module source escaped the verified build inputs")
        key = (name, version)
        require(key not in roots or roots[key] == root, "linked module has conflicting source roots")
        roots[key] = root
    records = []
    for (name, version), root in sorted(roots.items()):
        # Keep actual upstream license/notice files, including nested vendored
        # notices. This preserves texts; SPDX resolution and final distribution
        # review remain part of the full Windows release publication boundary.
        files = candidate_license_files(root, maximum_depth=12)
        require(bool(files), f"no source license texts found for {name} {version}")
        directory = hashlib.sha256(f"{name}@{version}".encode()).hexdigest()
        entries = []
        for path in files:
            relative = path.relative_to(root)
            destination = output / "licenses" / directory / relative
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
            entries.append({"path": destination.relative_to(output).as_posix(), "sha256": sha256(destination)})
        records.append({"component": name, "version": version, "files": entries})
    index = {"schema_version": 1, "scope": "linked Go modules and Go toolchain source notices",
             "release_license_review_complete": False, "components": records}
    index_path = output / "third-party-notices.json"
    index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    return {"components": len(records), "files": sum(len(record["files"]) for record in records),
            "index_sha256": sha256(index_path)}


def git(source: Path, *arguments: str, index: Path | None = None) -> bytes:
    executable = shutil.which("git")
    require(executable is not None, "Git is required")
    environment = {key: value for key, value in os.environ.items() if not key.upper().startswith("GIT_")}
    environment.update({"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_SYSTEM": os.devnull,
                        "GIT_CONFIG_NOSYSTEM": "1", "GIT_ATTR_NOSYSTEM": "1",
                        "GIT_NO_REPLACE_OBJECTS": "1", "GIT_NO_LAZY_FETCH": "1",
                        "GIT_LITERAL_PATHSPECS": "1", "GIT_TERMINAL_PROMPT": "0",
                        "GIT_OPTIONAL_LOCKS": "0", "LC_ALL": "C", "LANG": "C"})
    if index is not None:
        environment["GIT_INDEX_FILE"] = str(index)
    return command([executable, "--no-pager", "-C", str(source),
                    "-c", "core.autocrlf=false", "-c", "core.fileMode=false",
                    "-c", "core.ignoreCase=false", "-c", "core.fsmonitor=false",
                    "-c", "core.untrackedCache=false", "-c", "core.sparseCheckout=false",
                    "-c", "core.symlinks=true", "-c", f"core.attributesFile={os.devnull}",
                    "-c", f"core.excludesFile={os.devnull}", "-c", f"core.hooksPath={os.devnull}",
                    *arguments], env=environment)


def verify_source(repository: Path, source: Path, pins: dict[str, str], *, patched: bool) -> None:
    require(git(source, "rev-parse", "HEAD").decode().strip() == pins["SING_BOX_COMMIT"],
            "upstream engine commit mismatch")
    require(not git(source, "ls-files", "--others", "--ignored", "--exclude-standard"),
            "engine source contains ignored files")
    phase = "PATCHED" if patched else "UPSTREAM"
    for name in ("go.mod", "go.sum"):
        regular_file(source / name)
        key = f"SING_BOX_{phase}_{name.upper().replace('.', '_')}_SHA256"
        require(sha256(source / name) == pins[key], f"{phase.lower()} {name} mismatch")
    if not patched:
        require(not git(source, "status", "--porcelain=v1", "--untracked-files=all"),
                "upstream source is not clean")
        return
    dependencies = git(source, *DIFF_OPTIONS, "--", "go.mod", "go.sum")
    require(hashlib.sha256(dependencies).hexdigest() == pins["SING_BOX_PATCHED_DIFF_SHA256"],
            "patched module diff mismatch")
    with tempfile.TemporaryDirectory(prefix="cfw-engine-index-") as temporary:
        index = Path(temporary).resolve() / "index"
        git(source, "read-tree", "HEAD", index=index)
        git(source, "add", "-A", "--", ".", index=index)
        combined = git(source, *DIFF_OPTIONS, "--cached", "HEAD", "--", index=index)
    require(hashlib.sha256(combined).hexdigest() == pins["SING_BOX_COMBINED_DIFF_SHA256"],
            "combined engine diff differs from the CFM GA pin")


def prepare_source(repository: Path, source: Path, pins: dict[str, str]) -> None:
    require(not source.exists(), "refusing to overwrite an engine checkout")
    source.mkdir(parents=False)
    with tempfile.TemporaryDirectory(prefix="cfw-empty-git-template-") as temporary:
        git(source, "init", "--quiet", f"--template={Path(temporary).resolve()}")
    git(source, "fetch", "--depth=1", "https://github.com/SagerNet/sing-box.git", pins["SING_BOX_COMMIT"])
    git(source, "checkout", "--detach", "--quiet", pins["SING_BOX_COMMIT"])
    verify_source(repository, source, pins, patched=False)
    patches = []
    for name in PATCHES:
        path = pinned_path(repository, pins[f"SING_BOX_{name}_PATCH_PATH"])
        require(sha256(path) == pins[f"SING_BOX_{name}_PATCH_SHA256"], f"{name} patch digest mismatch")
        patches.append(str(path))
    git(source, "apply", "--whitespace=error-all", "--unidiff-zero", "--check", *patches)
    git(source, "apply", "--whitespace=error-all", "--unidiff-zero", *patches)
    verify_source(repository, source, pins, patched=True)


def prepare_host_source(repository: Path, source: Path, destination: Path) -> dict[str, str]:
    """Add our process entry point in a separate tree; never change the GA pins."""
    require(not destination.exists(), "refusing to overwrite a host build tree")
    baseline = source_files(source)
    host = repository / "native/windows/engine-host"
    additions = source_files(host)
    require("main.go" in additions and "main_test.go" in additions, "missing Windows host source")
    require(all(re.fullmatch(r"[a-z_]+\.go", name) for name in additions), "unexpected host source member")
    expected = {**baseline, **{f"cmd/cfw-engine-host/{name}": digest for name, digest in additions.items()}}
    require(len(expected) == len(baseline) + len(additions), "host entry point collides with upstream source")
    destination.mkdir()
    for name in baseline:
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source / name, target)
    for name in additions:
        target = destination / "cmd/cfw-engine-host" / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(host / name, target)
    require(source_files(destination) == expected, "host build source copy changed bytes")
    return expected


def test_packages(repository: Path, pins: dict[str, str]) -> list[str]:
    path = pinned_path(repository, pins["LIBBOX_MODULE_CACHE_CONTRACT_PATH"])
    require(sha256(path) == pins["LIBBOX_MODULE_CACHE_CONTRACT_SHA256"], "module/test contract digest mismatch")
    text = path.read_text(encoding="utf-8")
    packages = []
    for name in ("LIBBOX_RACE_TEST_PACKAGES", "LIBBOX_TEST_PACKAGES"):
        matches = re.findall(rf"(?m)^{name}=\(\n((?:[^\n]*\n)*?)\)", text)
        require(len(matches) == 1, f"missing or ambiguous {name}")
        for line in matches[0].splitlines():
            match = re.fullmatch(r'  "(\.|\./[a-z0-9_/]+)"', line)
            require(match is not None, f"invalid package in {name}")
            if match[1] not in packages:
                packages.append(match[1])
    return packages


def prepare_go(work: Path, pins: dict[str, str]) -> Path:
    version = pins["GO_VERSION"]
    archive = work / f"go{version}.windows-amd64.zip"
    with urllib.request.urlopen(f"https://go.dev/dl/{archive.name}", timeout=60) as response, archive.open("xb") as output:
        total = 0
        while block := response.read(1024 * 1024):
            total += len(block)
            require(total <= 128 * 1024 * 1024, "Go archive exceeds download limit")
            output.write(block)
    require(sha256(archive) == pins["GO_WINDOWS_AMD64_SHA256"], "Windows Go archive digest mismatch")
    with zipfile.ZipFile(archive) as bundle:
        require(sum(info.file_size for info in bundle.infolist()) <= 1024 * 1024 * 1024,
                "Go archive exceeds unpacked limit")
        for info in bundle.infolist():
            path = PurePosixPath(info.filename)
            require(not path.is_absolute() and path.parts[0] == "go" and ".." not in path.parts
                    and "\\" not in info.filename and ":" not in info.filename,
                    "invalid Go archive member")
        bundle.extractall(work)
    go = work / "go/bin/go.exe"
    require(command([str(go), "version"]).decode().strip() == f"go version go{version} windows/amd64",
            "Go tool identity mismatch")
    return go


def build(repository: Path, work: Path, pins: dict[str, str]) -> None:
    require(platform.system() == "Windows" and platform.machine().lower() in ("amd64", "x86_64"),
            "native Windows x64 is required for this build lane")
    require(platform.python_version() == pins["PYTHON_VERSION"], "Python tool identity mismatch")
    require(not git(repository, "status", "--porcelain=v1", "--untracked-files=all"),
            "engine CI build requires a clean product checkout")
    require(not work.exists(), "build directory already exists; preserve it and select a new directory")
    work.mkdir(parents=False)
    print("Preparing the hash-pinned Windows Go toolchain", flush=True)
    go = prepare_go(work, pins)
    baseline_source = work / "source"
    print("Materializing the unchanged CFM GA engine source and six patches", flush=True)
    prepare_source(repository, baseline_source, pins)
    baseline_files = source_files(baseline_source)
    source = work / "host-source"
    expected_files = prepare_host_source(repository, baseline_source, source)
    output = work / "artifacts"
    output.mkdir()
    fixture_directory = work / "dns-projections"
    fixture_environment = {**os.environ, "CFW_DNS_PROJECTED_FIXTURE_DIR": str(fixture_directory)}
    cargo = shutil.which("cargo")
    require(cargo is not None, "the pinned Rust toolchain is required for projection fixtures")
    require(command([cargo, "--version"]).decode().startswith(f"cargo {pins['RUST_VERSION']} "),
            "Rust tool identity mismatch")
    print("Generating the actual Rust DNS projections used by the GA integration tests", flush=True)
    fixture_result = command([cargo, "test", "--locked", "-p", "cfw-singbox-config", "--lib", "tests::dns_policy"],
                             cwd=repository, env=fixture_environment)
    (output / "rust-projections.txt").write_bytes(fixture_result)
    fixture_hashes = {}
    for name in ("mixed.json", "tunnel.json", "filter.json", "named.json"):
        path = fixture_directory / name
        regular_file(path)
        require(path.stat().st_size > 0, f"missing Rust projection fixture: {name}")
        fixture_hashes[name] = sha256(path)
    environment = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith(("GO", "CGO"))}
    environment.update({"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local",
                        "GOTELEMETRY": "off", "GOOS": "windows", "GOARCH": "amd64",
                        "CGO_ENABLED": "0", "GOPATH": str(work / "gopath"),
                        "GOMODCACHE": str(work / "modules"), "GOCACHE": str(work / "cache"),
                        "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org",
                        "GONOSUMDB": "", "GOPRIVATE": "", "GONOPROXY": "",
                        "GOFLAGS": "-mod=readonly"})
    environment["CFW_DNS_PROJECTED_FIXTURE_DIR"] = str(fixture_directory)
    tags = pins["LIBBOX_BUILD_TAGS"]
    packages = test_packages(repository, pins)
    packages.append("./cmd/cfw-engine-host")
    print("Resolving the locked Windows build and test package closure", flush=True)
    command([str(go), "list", "-deps", "-test", "-tags", tags, "./cmd/sing-box", *packages],
            cwd=source, env=environment, timeout=1200)
    # Package pruning does not necessarily fetch the go.mod metadata needed by
    # `go mod verify` for the complete selected graph. Resolve it explicitly
    # before entering the offline build phase, without changing module pins.
    modules = module_graph(command([str(go), "list", "-m", "-json", "all"], cwd=source, env=environment))
    (output / "module-graph.json").write_text(json.dumps(modules, indent=2) + "\n", encoding="utf-8")
    verify_source(repository, baseline_source, pins, patched=True)
    require(source_files(baseline_source) == baseline_files, "GA baseline source bytes changed")
    require(source_files(source) == expected_files, "module resolution changed engine source bytes")
    environment.update({"GOPROXY": "off", "GOSUMDB": "off"})
    command([str(go), "mod", "verify"], cwd=source, env=environment)
    executable = output / "cfw-engine.exe"
    flags = f"-s -w -buildid= -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version={pins['SING_BOX_VERSION'][1:]} -X internal/godebug.defaultGODEBUG=multipathtcp=0"
    arguments = [str(go), "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags", tags, "-ldflags", flags]
    print("Building the native Windows engine without network resolution", flush=True)
    command([*arguments, "-o", str(executable), "./cmd/sing-box"], cwd=source, env=environment, timeout=1200)
    host_executable = output / "cfw-engine-host.exe"
    command([*arguments, "-o", str(host_executable), "./cmd/cfw-engine-host"], cwd=source, env=environment, timeout=1200)
    print("Checking an independent build cache produces identical bytes", flush=True)
    environment["GOCACHE"] = str(work / "second-cache")
    second = work / "second-engine.exe"
    command([*arguments, "-o", str(second), "./cmd/sing-box"], cwd=source, env=environment, timeout=1200)
    require(sha256(executable) == sha256(second), "Windows engine build is not reproducible across caches")
    second_host = work / "second-engine-host.exe"
    command([*arguments, "-o", str(second_host), "./cmd/cfw-engine-host"], cwd=source, env=environment, timeout=1200)
    require(sha256(host_executable) == sha256(second_host), "Windows host build is not reproducible across caches")
    print("Running the GA engine test package union on Windows (without race instrumentation)", flush=True)
    # Match the GA engine's Go linker contract; the Mac-only external clang
    # linker is omitted because this Windows component does not use CGO.
    result = subprocess.run([str(go), "test", "-json", "-count=1", "-timeout=5m", "-ldflags=-checklinkname=0", "-tags", tags, *packages],
                            cwd=source, env=environment, capture_output=True, timeout=1200)
    (output / "go-tests.jsonl").write_bytes(result.stdout)
    (output / "go-tests.stderr.txt").write_bytes(result.stderr)
    require(result.returncode == 0, "native Windows engine tests failed; inspect go-tests.jsonl and go-tests.stderr.txt")
    test_events = [json.loads(line) for line in result.stdout.splitlines() if line]
    passed_tests = [event for event in test_events if event.get("Action") == "pass" and "Test" in event]
    skipped_tests = [{"package": event["Package"], "test": event["Test"]} for event in test_events
                     if event.get("Action") == "skip" and "Test" in event]
    require(not skipped_tests, "native engine tests were skipped; inspect the complete Go test event log")
    packages_without_tests = [event["Package"] for event in test_events if event.get("Action") == "skip" and "Test" not in event]
    verify_source(repository, baseline_source, pins, patched=True)
    require(source_files(baseline_source) == baseline_files, "GA baseline source bytes changed")
    require(source_files(source) == expected_files, "build or tests changed engine source bytes")
    version = command([str(executable), "version"]).decode("utf-8")
    info = command([str(go), "version", "-m", str(executable)], env=environment).decode("utf-8")
    (output / "build-info.txt").write_text(info, encoding="utf-8")
    host_info = command([str(go), "version", "-m", str(host_executable)], env=environment).decode("utf-8")
    (output / "host-build-info.txt").write_text(host_info, encoding="utf-8")
    shutil.copyfile(source / "LICENSE", output / "LICENSE")
    command([str(go), "mod", "verify"], cwd=source, env=environment)
    print("Collecting source license and notice texts for the linked Windows engine", flush=True)
    notices = bundle_notices(go, source, output, environment, pins)
    receipt = {"schema_version": 1, "product_source": git(repository, "rev-parse", "HEAD").decode().strip(),
               "component": "windows-engine", "platform": "windows-amd64", "release_accepted": False,
               "engine_version": pins["SING_BOX_VERSION"], "engine_commit": pins["SING_BOX_COMMIT"],
               "combined_diff_sha256": pins["SING_BOX_COMBINED_DIFF_SHA256"],
               "source_files_sha256": hashlib.sha256(json.dumps(baseline_files, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
               "host_source_files_sha256": hashlib.sha256(json.dumps(expected_files, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
               "host_source_additions": source_files(repository / "native/windows/engine-host"),
               "go_version": pins["GO_VERSION"], "go_archive_sha256": pins["GO_WINDOWS_AMD64_SHA256"],
               "build_tags": tags.split(","), "cgo_enabled": False, "independent_cache_builds_equal": True,
               "test_packages": packages, "tests_passed": len(passed_tests), "tests_skipped": skipped_tests,
               "packages_without_tests": packages_without_tests, "source_notices": notices,
               "module_graph_sha256": sha256(output / "module-graph.json"),
               "rust_version": pins["RUST_VERSION"], "rust_dns_fixture_sha256": fixture_hashes,
               "race_instrumentation": False, "version_output": version,
               "artifact": {"filename": executable.name, "size": executable.stat().st_size, "sha256": sha256(executable)},
               "host_artifact": {"filename": host_executable.name, "size": host_executable.stat().st_size, "sha256": sha256(host_executable)}}
    (output / "build-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(receipt, indent=2), flush=True)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("prepare-source", "build"))
    parser.add_argument("--repository", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    arguments = parser.parse_args()
    repository = arguments.repository.resolve(strict=True)
    output = arguments.output.absolute()
    pins = read_pins(repository)
    if arguments.command == "prepare-source":
        prepare_source(repository, output, pins)
        print(f"Verified GA-equivalent source: {output}")
    else:
        build(repository, output, pins)


if __name__ == "__main__":
    main()
