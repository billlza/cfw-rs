"""Build the GA-pinned engine on Windows; this is not release admission.

The source is created in an absent, task-owned directory. We reuse the existing
upstream, patch, module and combined-diff pins rather than accepting a second
definition of the CFM engine. No existing checkout or global tool is modified.
Both programs are built from a private workspace that carries the sing
packet-address correction of every macOS build, and before the build the pinned
vulnerability scanner checks the exact linked graph, pinned and corrected,
against the official Go vulnerability database.
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
WINDOWS_TEST_OVERLAY = "native/windows/engine-tests/dns-response-lifecycle.patch"
WINDOWS_TEST_FILE = "dns/runtime_policy_test.go"
WINTUN_PACKAGE = "github.com/sagernet/sing-tun/internal/wintun"
# The two programs this lane links: the engine and our process entry point.
ENGINE_MODULE = "github.com/sagernet/sing-box"
ENGINE_PACKAGE = "./cmd/sing-box"
HOST_PACKAGE = "./cmd/cfw-engine-host"
# The socks-lifecycle patch adds this tool to the engine source; it copies the
# source into a workspace whose sing module carries the packet-address
# correction through one relative replacement, as every macOS build does.
WORKSPACE_TOOL = "./cmd/cfm-build-workspace"
WORKSPACE_MODULE = "github.com/sagernet/sing"
WORKSPACE_DEPENDENCIES = "cfw-dependencies"
WORKSPACE_REPLACEMENT = f"./{WORKSPACE_DEPENDENCIES}/sing"
SCANNER_MODULE = "golang.org/x/vuln"
SCANNER_PACKAGE = "golang.org/x/vuln/cmd/govulncheck"
VULNERABILITY_DATABASE = "https://vuln.go.dev"
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


def require_unchanged(actual: dict[str, str], expected: dict[str, str], message: str) -> None:
    """Name the paths whose bytes or membership differ, so a stray test write is diagnosable."""
    changed = sorted(name for name in expected.keys() | actual.keys() if expected.get(name) != actual.get(name))
    require(not changed, f"{message}: {', '.join(changed[:16])}" + (" …" if len(changed) > 16 else ""))


def read_pins(repository: Path) -> dict[str, str]:
    pins: dict[str, str] = {}
    for line in (repository / "scripts/dependency_pins.env").read_text(encoding="utf-8").splitlines():
        match = re.fullmatch(r"([A-Z][A-Z0-9_]*)=([^\s#]+)", line)
        if match:
            key, value = match.groups()
            require(key not in pins, f"duplicate dependency pin: {key}")
            pins[key] = value
    for key in ("GO_VERSION", "PYTHON_VERSION", "RUST_VERSION", "WINTUN_VERSION"):
        require(bool(re.fullmatch(r"\d+\.\d+\.\d+", pins[key])), f"invalid {key}")
    require(bool(re.fullmatch(r"[a-f0-9]{40}", pins["SING_BOX_COMMIT"])), "invalid engine commit")
    require(bool(re.fullmatch(r"v\d+\.\d+\.\d+", pins["SING_BOX_VERSION"])), "invalid engine version")
    require(bool(re.fullmatch(r"[a-z0-9_,]+", pins["LIBBOX_BUILD_TAGS"])), "invalid engine build tags")
    require(bool(re.fullmatch(r"v\d+\.\d+\.\d+", pins["GOVULNCHECK_VERSION"])), "invalid scanner version")
    require(bool(re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", pins["GOVULNCHECK_MODULE_SUM"])), "invalid scanner module sum")
    for key in ["GO_WINDOWS_AMD64_SHA256", "LIBBOX_MODULE_CACHE_CONTRACT_SHA256",
                "GO_RELEASE_TOOLS_GO_MOD_SHA256", "GO_RELEASE_TOOLS_GO_SUM_SHA256",
                "WINTUN_ARCHIVE_SHA256", "WINTUN_WINDOWS_AMD64_SHA256", "WINTUN_BINARY_LICENSE_SHA256",
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


def module_graph(data: bytes, *, local_replacement: tuple[str, str] | None = None) -> list[dict[str, object]]:
    """Module identities of `go list -m -json all`.

    A versioned replacement keeps its checksums. A replacement without a version
    is a local directory with neither checksum nor advisory version: only the
    build workspace's own relative replacement is admitted, by module and path,
    and only when the caller names it.
    """
    result = []
    for module in json_objects(data):
        require(isinstance(module.get("Path"), str), "invalid Go module metadata")
        identity = {key: module[key] for key in ("Path", "Version", "Sum", "GoModSum", "Main") if key in module}
        if "Replace" in module:
            replacement = module["Replace"]
            require(isinstance(replacement, dict), "invalid module replacement")
            if "Version" not in replacement:
                require(local_replacement is not None and (module["Path"], replacement.get("Path")) == local_replacement,
                        "unversioned local module replacement is not admitted")
                identity["Replace"] = {"Path": replacement["Path"]}
            else:
                require(bool(replacement["Version"]), "unversioned local module replacement is not admitted")
                identity["Replace"] = {key: replacement[key] for key in ("Path", "Version", "Sum", "GoModSum") if key in replacement}
        result.append(identity)
    return result


def bundle_wintun_notice(repository: Path, package: dict[str, object], root: Path,
                         output: Path, pins: dict[str, str]) -> dict[str, object]:
    """Bind the embedded DLL to the official archive without executing it.

    The linked module's source license does not describe its embedded prebuilt
    DLL. Preserve that binary's original license separately. This byte proof
    is not an Authenticode or driver-installation receipt.
    """
    require(package.get("ImportPath") == WINTUN_PACKAGE, "unexpected embedded binary package")
    require(package.get("EmbedFiles") == ["amd64/wintun.dll"], "unexpected linked Wintun embed files")
    directory = package.get("Dir")
    require(isinstance(directory, str), "Wintun package has no source directory")
    directory = Path(directory).resolve(strict=True)
    require(directory == root / "internal/wintun", "Wintun package escaped its linked module")
    dll = directory / "amd64/wintun.dll"
    regular_file(dll)
    require(dll.stat().st_size <= 2 * 1024 * 1024, "embedded Wintun DLL exceeds its bound")
    binary_digest = sha256(dll)
    require(binary_digest == pins["WINTUN_WINDOWS_AMD64_SHA256"], "embedded Wintun differs from the official binary")
    license_source = pinned_path(repository, pins["WINTUN_BINARY_LICENSE_PATH"])
    require(sha256(license_source) == pins["WINTUN_BINARY_LICENSE_SHA256"], "Wintun binary license digest mismatch")
    # The authority needs the same official image as a protected MSI payload.
    # Copy only after both binary and license admission, and recheck the copy.
    # The notice archive remains texts only; packaging never executes this DLL.
    payload = output / "wintun.dll"
    require(not payload.exists(), "refusing to replace a Wintun payload")
    output.mkdir(parents=True, exist_ok=True)
    with dll.open("rb") as source, payload.open("xb") as destination_file:
        shutil.copyfileobj(source, destination_file)
    require(sha256(payload) == binary_digest, "copied Wintun payload changed")
    destination = output / "licenses" / f"wintun-{pins['WINTUN_VERSION']}" / "LICENSE.txt"
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(license_source, destination)
    require(sha256(destination) == pins["WINTUN_BINARY_LICENSE_SHA256"], "copied Wintun binary license changed")
    return {"component": "Wintun prebuilt DLL", "version": pins["WINTUN_VERSION"],
            "files": [{"path": destination.relative_to(output).as_posix(), "sha256": sha256(destination)}],
            "distribution": {"url": f"https://www.wintun.net/builds/wintun-{pins['WINTUN_VERSION']}.zip",
                             "sha256": pins["WINTUN_ARCHIVE_SHA256"]},
            "embedded_binary": {"package": WINTUN_PACKAGE, "path": "amd64/wintun.dll", "architecture": "amd64",
                                "bytes": dll.stat().st_size, "sha256": binary_digest},
            "authenticode_verified": False, "driver_runtime_verified": False}


def bundle_notices(repository: Path, go: Path, source: Path, output: Path,
                   environment: dict[str, str], pins: dict[str, str]) -> dict[str, object]:
    packages = json_objects(command([str(go), "list", "-deps", "-json", "-tags", pins["LIBBOX_BUILD_TAGS"],
                                     ENGINE_PACKAGE, HOST_PACKAGE], cwd=source, env=environment))
    roots: dict[tuple[str, str], Path] = {("Go", pins["GO_VERSION"]): go.parent.parent.resolve()}
    main_root = source.resolve()
    workspace_copy = (source / WORKSPACE_REPLACEMENT).resolve()
    embedded = []
    for package in packages:
        module = package.get("Module")
        if module is None:
            continue
        require(isinstance(module, dict), "invalid linked module metadata")
        name = module.get("Path")
        version = pins["SING_BOX_VERSION"] if module.get("Main") is True else module.get("Version")
        directory = module.get("Dir")
        require(isinstance(name, str) and isinstance(version, str) and isinstance(directory, str),
                "linked module lacks a source identity for license collection")
        root = Path(directory).resolve(strict=True)
        if "Replace" in module:
            # The workspace replaces one module with its corrected copy; its
            # license texts are that copy's, under the upstream version.
            replacement = module["Replace"]
            require(isinstance(replacement, dict) and (name, replacement.get("Path")) == (WORKSPACE_MODULE, WORKSPACE_REPLACEMENT),
                    "unexpected linked module replacement")
            require(root == workspace_copy, "linked module replacement escaped the build workspace")
        else:
            allowed = main_root if module.get("Main") is True else Path(environment["GOMODCACHE"]).resolve()
            require(root.is_relative_to(allowed), "linked module source escaped the verified build inputs")
        key = (name, version)
        require(key not in roots or roots[key] == root, "linked module has conflicting source roots")
        roots[key] = root
        if package.get("ImportPath") == WINTUN_PACKAGE:
            require(not embedded, "duplicate linked Wintun package")
            embedded.append(bundle_wintun_notice(repository, package, root, output, pins))
    records = []
    for (name, version), root in sorted(roots.items()):
        # Keep actual upstream license/notice files, including nested vendored
        # notices. This preserves texts; SPDX resolution and final distribution
        # review remain part of the full Windows release publication boundary.
        # The replaced copy under the main module is its own component above.
        files = [path for path in candidate_license_files(root, maximum_depth=12)
                 if root != main_root or path.relative_to(root).parts[:1] != (WORKSPACE_DEPENDENCIES,)]
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
    records.extend(embedded)
    index = {"schema_version": 1, "scope": "linked Go modules, embedded Windows binaries and Go toolchain notices",
             "release_license_review_complete": False, "components": records}
    index_path = output / "third-party-notices.json"
    index_path.write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")
    # One installer payload keeps every original notice byte and its index,
    # without rewriting licenses into a generated summary or dropping nested files.
    members = {"third-party-notices.json": sha256(index_path)}
    for record in records:
        for entry in record["files"]:
            require(entry["path"] not in members, "duplicate notice archive member")
            members[entry["path"]] = entry["sha256"]
    require(len(members) <= 4096, "notice archive has too many members")
    archive_path = output / "engine-third-party-notices.zip"
    total = 0
    with zipfile.ZipFile(archive_path, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=9, allowZip64=False) as archive:
        for name, digest in sorted(members.items()):
            path = output / name
            regular_file(path)
            require(path.stat().st_size <= 2 * 1024 * 1024, "notice file exceeds its bound")
            data = path.read_bytes()
            total += len(data)
            require(total <= 64 * 1024 * 1024, "notice archive exceeds its total bound")
            require(hashlib.sha256(data).hexdigest() == digest, "notice changed before packaging")
            member = zipfile.ZipInfo(name, date_time=(1980, 1, 1, 0, 0, 0))
            member.create_system = 3
            member.external_attr = 0o100644 << 16
            archive.writestr(member, data, compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return {"components": len(records), "files": sum(len(record["files"]) for record in records),
            "embedded_binaries": len(embedded),
            "index_sha256": sha256(index_path),
            "archive": {"filename": archive_path.name, "bytes": archive_path.stat().st_size,
                        "sha256": sha256(archive_path)}}


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


def apply_test_overlay(repository: Path, source: Path, expected: dict[str, str]) -> tuple[dict[str, str], dict[str, object]]:
    """Synchronize a Windows fixture without changing any GA production bytes."""
    require_unchanged(source_files(source), expected, "host source changed before test overlay")
    patch = pinned_path(repository, WINDOWS_TEST_OVERLAY)
    # A separate temporary Git directory makes apply behave identically inside
    # and outside a product checkout. No Git metadata enters the source tree.
    with tempfile.TemporaryDirectory(prefix="cfw-test-overlay-") as temporary:
        control = Path(temporary).resolve()
        template = control / "empty-template"
        template.mkdir()
        git(control, "init", "--quiet", f"--template={template}")
        prefix = (f"--git-dir={control / '.git'}", f"--work-tree={source.resolve()}")
        changes = git(source, *prefix, "apply", "--numstat", str(patch)).decode().splitlines()
        require(len(changes) == 1 and changes[0].split("\t")[-1] == WINDOWS_TEST_FILE,
                "Windows test overlay may change only the DNS test fixture")
        git(source, *prefix, "apply", "--whitespace=error-all", "--unidiff-zero", "--check", str(patch))
        git(source, *prefix, "apply", "--whitespace=error-all", "--unidiff-zero", str(patch))
    actual = source_files(source)
    changed = {name for name in expected.keys() | actual.keys() if expected.get(name) != actual.get(name)}
    require(actual.keys() == expected.keys() and changed == {WINDOWS_TEST_FILE},
            "Windows test overlay changed production bytes or source membership")
    return actual, {"path": WINDOWS_TEST_OVERLAY, "sha256": sha256(patch),
                    "files": {WINDOWS_TEST_FILE: {"before_sha256": expected[WINDOWS_TEST_FILE],
                                                   "after_sha256": actual[WINDOWS_TEST_FILE]}}}


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


def sing_module(go: Path, directory: Path, environment: dict[str, str]) -> dict[str, object]:
    """The sing module as the directory's go.mod resolves it."""
    modules = json_objects(command([str(go), "list", "-m", "-json", WORKSPACE_MODULE], cwd=directory, env=environment))
    require(len(modules) == 1 and modules[0].get("Path") == WORKSPACE_MODULE, "sing module resolution is ambiguous")
    return modules[0]


def prepare_build_workspace(go: Path, source: Path, environment: dict[str, str],
                            output: Path) -> tuple[Path, dict[str, object], dict[str, str]]:
    """Copy the verified source into a private workspace whose sing module carries the packet-address correction.

    The engine source's own tool validates the module's bytes, rewrites the
    corrected files and adds one relative replacement; it runs on the host with
    the given environment. This binds its result: the workspace is the source
    plus that go.mod line and the corrected module copy, and nothing else.
    Returns the workspace, its receipt record and its file digests.
    """
    require(not output.exists(), "refusing to overwrite a build workspace")
    pinned = sing_module(go, source, environment)
    require("Replace" not in pinned and isinstance(pinned.get("Version"), str) and isinstance(pinned.get("Dir"), str),
            "the engine source does not require the sing module from the verified cache")
    version = pinned["Version"]
    module_dir = Path(pinned["Dir"]).resolve()
    require(module_dir == (Path(environment["GOMODCACHE"]) / f"{WORKSPACE_MODULE}@{version}").resolve(),
            "sing module is not the verified cache copy")
    printed = command([str(go), "run", WORKSPACE_TOOL, "-module-source", str(module_dir), "-output", str(output)],
                      cwd=source, env=environment, timeout=600).decode("utf-8").strip()
    require(printed == str(output) and output.is_dir() and not output.is_symlink(), "build workspace did not produce its exact output")
    corrected = sing_module(go, output, environment)
    replacement = corrected.get("Replace")
    require(isinstance(replacement, dict) and replacement.get("Path") == WORKSPACE_REPLACEMENT and corrected.get("Version") == version
            and Path(str(replacement.get("Dir", ""))).resolve() == (output / WORKSPACE_REPLACEMENT).resolve(),
            "build workspace resolved an unexpected sing replacement")
    expected_go_mod = (source / "go.mod").read_bytes() + f"\nreplace {WORKSPACE_MODULE} {version} => {WORKSPACE_REPLACEMENT}\n".encode()
    require((output / "go.mod").read_bytes() == expected_go_mod, "build workspace changed go.mod beyond the relative replacement")
    files = source_files(output)
    dependencies = WORKSPACE_DEPENDENCIES + "/"
    prefix = WORKSPACE_REPLACEMENT[2:] + "/"
    copied = {name: digest for name, digest in files.items() if name != "go.mod" and not name.startswith(dependencies)}
    expected = {name: digest for name, digest in source_files(source).items() if name != "go.mod"}
    require_unchanged(copied, expected, "build workspace changed engine source bytes")
    require(all(name.startswith(prefix) for name in files if name.startswith(dependencies)),
            "build workspace added unexpected dependencies")
    original = source_files(module_dir)
    copy = {name[len(prefix):]: digest for name, digest in files.items() if name.startswith(prefix)}
    require(copy.keys() == original.keys(), "build workspace changed the sing module's membership")
    corrections = {name: {"before_sha256": original[name], "after_sha256": copy[name]}
                   for name in sorted(copy) if copy[name] != original[name]}
    require(bool(corrections), "build workspace applied no correction")
    record = {"module": WORKSPACE_MODULE, "version": version, "replacement": WORKSPACE_REPLACEMENT,
              "corrected_files": corrections,
              "files_sha256": hashlib.sha256(json.dumps(files, sort_keys=True, separators=(",", ":")).encode()).hexdigest()}
    return output, record, files


def hermetic_go_environment(root: Path) -> dict[str, str]:
    """One Go phase owns one tree for its workspace, modules and build cache.

    Ambient Go and cgo settings are dropped. Modules resolve through the public
    proxy and checksum database, read-only against the module files, until the
    caller switches the phase offline.
    """
    environment = {key: value for key, value in os.environ.items()
                   if not key.upper().startswith(("GO", "CGO"))}
    environment.update({"GOENV": "off", "GOWORK": "off", "GOTOOLCHAIN": "local",
                        "GOTELEMETRY": "off", "CGO_ENABLED": "0", "GOPATH": str(root / "gopath"),
                        "GOMODCACHE": str(root / "modules"), "GOCACHE": str(root / "cache"),
                        "GOPROXY": "https://proxy.golang.org", "GOSUMDB": "sum.golang.org",
                        "GONOSUMDB": "", "GOPRIVATE": "", "GONOPROXY": "",
                        "GOFLAGS": "-mod=readonly"})
    return environment


def verify_release_tools_source(tools: Path, pins: dict[str, str]) -> None:
    """The release tools module files are the only inputs that select the scanner's graph."""
    for name, key in (("go.mod", "GO_RELEASE_TOOLS_GO_MOD_SHA256"), ("go.sum", "GO_RELEASE_TOOLS_GO_SUM_SHA256")):
        path = tools / name
        regular_file(path)
        require(sha256(path) == pins[key], f"release tools {name} digest mismatch")


def require_scanner_identity(build_info: str, pins: dict[str, str]) -> None:
    """`go version -m` must name the pinned Go, the scanner package and its pinned module."""
    lines = build_info.splitlines()
    require(bool(lines) and lines[0].endswith(f": go{pins['GO_VERSION']}"), "scanner was not built by the pinned Go")
    require(f"\tpath\t{SCANNER_PACKAGE}" in lines[1:], "scanner package identity mismatch")
    require(f"\tmod\t{SCANNER_MODULE}\t{pins['GOVULNCHECK_VERSION']}\t{pins['GOVULNCHECK_MODULE_SUM']}" in lines[1:],
            "scanner module identity mismatch")


def prepare_scanner(repository: Path, work: Path, go: Path, pins: dict[str, str]) -> Path:
    """Install the pinned scanner from the release tools module into its own tree.

    The scanner's graph never enters the engine's module cache, and this install
    is the scan's only networked module resolution: the scan itself reads the
    engine's verified cache offline.
    """
    tools = repository / "tools/go-release-tools"
    verify_release_tools_source(tools, pins)
    root = work / "scanner"
    require(not root.exists(), "refusing to overwrite a scanner tree")
    environment = hermetic_go_environment(root)
    environment["GOBIN"] = str(root / "bin")
    command([str(go), "-C", str(tools), "install", "-mod=readonly", SCANNER_PACKAGE], env=environment, timeout=1200)
    verify_release_tools_source(tools, pins)
    suffix = command([str(go), "env", "GOEXE"], env=environment).decode("utf-8").strip()
    scanner = root / "bin" / f"govulncheck{suffix}"
    regular_file(scanner)
    require_scanner_identity(command([str(go), "version", "-m", str(scanner)], env=environment).decode("utf-8"), pins)
    return scanner


def scan_report(text: str, pins: dict[str, str]) -> dict[str, object]:
    """Bind the scanner's verbose text report to the pinned Go, scanner, database and program roots."""
    lines = text.splitlines()
    require(lines[:3] == [f"Go: go{pins['GO_VERSION']}", f"Scanner: govulncheck@{pins['GOVULNCHECK_VERSION']}",
                          f"DB: {VULNERABILITY_DATABASE}"],
            "vulnerability scan did not report the pinned Go, scanner and database")
    require(len(lines) > 3 and lines[3].startswith("DB updated: ") and lines[3] != "DB updated: ",
            "vulnerability scan did not report the database modification time")
    roots = re.search(r"^The package pattern matched the following (\d+) root packages:\n((?:  \S+\n)+)", text, re.MULTILINE)
    require(roots is not None, "vulnerability scan did not list its root packages")
    root_packages = roots[2].split()
    require(len(root_packages) == int(roots[1])
            and root_packages == [f"{ENGINE_MODULE}/{package[2:]}" for package in (ENGINE_PACKAGE, HOST_PACKAGE)],
            "vulnerability scan did not cover exactly the engine and host programs")
    modules = re.search(r"^Govulncheck scanned the following (\d+) modules and the (go\S+) standard library:\n((?:  \S+\n)+)",
                        text, re.MULTILINE)
    require(modules is not None and modules[2] == f"go{pins['GO_VERSION']}",
            "vulnerability scan did not list the scanned modules of the pinned Go")
    scanned = modules[3].split()
    require(len(scanned) == int(modules[1]) and scanned[0] == ENGINE_MODULE, "vulnerability scan module list is inconsistent")
    affected = re.search(r"^Your code is affected by (\d+) vulnerabilit(?:y|ies)", text, re.MULTILINE)
    if affected is None:
        require("No vulnerabilities found." in lines, "vulnerability scan did not conclude")
    called = 0 if affected is None else int(affected[1])
    require(called == 0, "vulnerability scan reported called vulnerabilities without its exit code")
    return {"scanner": {"package": SCANNER_PACKAGE, "version": pins["GOVULNCHECK_VERSION"],
                        "module_sum": pins["GOVULNCHECK_MODULE_SUM"]},
            "go_version": lines[0].removeprefix("Go: "), "database": VULNERABILITY_DATABASE,
            "database_updated": lines[3].removeprefix("DB updated: "), "mode": "source", "level": "symbol",
            "root_packages": root_packages, "scanned_modules": len(scanned), "called_vulnerabilities": called,
            "uncalled_advisories": re.findall(r"^Vulnerability #\d+: (GO-\d{4}-\d+)$", text, re.MULTILINE)}


def scan_vulnerabilities(scanner: Path, go: Path, source: Path, environment: dict[str, str], tags: str,
                         pins: dict[str, str], output: Path, graph: str) -> dict[str, object]:
    """Fail when the linked engine graph calls known vulnerable code; keep the scanner's own report.

    `graph` names the report: the pinned graph of the verified source, or the
    corrected build workspace, whose local replacement carries no advisory
    version and so needs the pinned graph scanned as well.
    """
    report = output / f"vulnerability-scan-{graph}.txt"
    errors = output / f"vulnerability-scan-{graph}.stderr.txt"
    # The scanner resolves `go` through PATH, both for the toolchain it reports
    # and for loading packages, so the pinned toolchain goes first.
    require(bool(environment.get("PATH")), "the scan environment has no PATH")
    scan_environment = {**environment, "PATH": os.pathsep.join([str(go.parent), environment["PATH"]])}
    arguments = [str(scanner), "-C", str(source), "-db", VULNERABILITY_DATABASE, "-mode", "source",
                 "-scan", "symbol", "-show", "version,verbose", "-tags", tags, ENGINE_PACKAGE, HOST_PACKAGE]
    result = subprocess.run(arguments, env=scan_environment, capture_output=True, timeout=1200)
    report.write_bytes(result.stdout)
    errors.write_bytes(result.stderr)
    require(result.returncode != 3, f"the linked Windows engine calls known vulnerable code; inspect {report.name}")
    require(result.returncode == 0, f"vulnerability scan failed ({result.returncode}); inspect {errors.name}")
    return scan_report(result.stdout.decode("utf-8"), pins)


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
    print("Installing the pinned vulnerability scanner from the release tools module", flush=True)
    scanner = prepare_scanner(repository, work, go, pins)
    baseline_source = work / "source"
    print("Materializing the unchanged CFM GA engine source and six patches", flush=True)
    prepare_source(repository, baseline_source, pins)
    baseline_files = source_files(baseline_source)
    source = work / "host-source"
    expected_files = prepare_host_source(repository, baseline_source, source)
    expected_files, test_overlay = apply_test_overlay(repository, source, expected_files)
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
    # The workspace tool runs on the host; everything else targets Windows.
    host_environment = hermetic_go_environment(work)
    environment = {**host_environment, "GOOS": "windows", "GOARCH": "amd64",
                   "CFW_DNS_PROJECTED_FIXTURE_DIR": str(fixture_directory)}
    tags = pins["LIBBOX_BUILD_TAGS"]
    packages = test_packages(repository, pins)
    packages.extend((HOST_PACKAGE, WORKSPACE_TOOL))
    print("Resolving the locked Windows build and test package closure", flush=True)
    command([str(go), "list", "-deps", "-test", "-tags", tags, ENGINE_PACKAGE, *packages],
            cwd=source, env=environment, timeout=1200)
    # Package pruning does not necessarily fetch the go.mod metadata needed by
    # `go mod verify` for the complete selected graph. Resolve it explicitly
    # before entering the offline build phase, without changing module pins.
    modules = module_graph(command([str(go), "list", "-m", "-json", "all"], cwd=source, env=environment))
    (output / "module-graph.json").write_text(json.dumps(modules, indent=2) + "\n", encoding="utf-8")
    verify_source(repository, baseline_source, pins, patched=True)
    require_unchanged(source_files(baseline_source), baseline_files, "GA baseline source bytes changed")
    require_unchanged(source_files(source), expected_files, "module resolution changed engine source bytes")
    for phase in (host_environment, environment):
        phase.update({"GOPROXY": "off", "GOSUMDB": "off"})
    command([str(go), "mod", "verify"], cwd=source, env=environment)
    print("Scanning the pinned Windows engine graph for known vulnerabilities", flush=True)
    pinned_scan = scan_vulnerabilities(scanner, go, source, environment, tags, pins, output, "pinned")
    print("Preparing the build workspace with the source-bound sing correction", flush=True)
    workspace, workspace_record, workspace_files = prepare_build_workspace(go, source, host_environment, work / "workspace")
    command([str(go), "mod", "verify"], cwd=workspace, env=environment)
    corrected_modules = module_graph(command([str(go), "list", "-m", "-json", "all"], cwd=workspace, env=environment),
                                     local_replacement=(WORKSPACE_MODULE, WORKSPACE_REPLACEMENT))
    (output / "workspace-module-graph.json").write_text(json.dumps(corrected_modules, indent=2) + "\n", encoding="utf-8")
    print("Scanning the corrected Windows engine graph for known vulnerabilities", flush=True)
    corrected_scan = scan_vulnerabilities(scanner, go, workspace, environment, tags, pins, output, "corrected")
    executable = output / "cfw-engine.exe"
    flags = f"-s -w -buildid= -checklinkname=0 -X github.com/sagernet/sing-box/constant.Version={pins['SING_BOX_VERSION'][1:]} -X internal/godebug.defaultGODEBUG=multipathtcp=0"
    arguments = [str(go), "build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-tags", tags, "-ldflags", flags]
    print("Building the native Windows engine from the workspace without network resolution", flush=True)
    command([*arguments, "-o", str(executable), ENGINE_PACKAGE], cwd=workspace, env=environment, timeout=1200)
    host_executable = output / "cfw-engine-host.exe"
    command([*arguments, "-o", str(host_executable), HOST_PACKAGE], cwd=workspace, env=environment, timeout=1200)
    print("Checking an independent build cache produces identical bytes", flush=True)
    environment["GOCACHE"] = str(work / "second-cache")
    second = work / "second-engine.exe"
    command([*arguments, "-o", str(second), ENGINE_PACKAGE], cwd=workspace, env=environment, timeout=1200)
    require(sha256(executable) == sha256(second), "Windows engine build is not reproducible across caches")
    second_host = work / "second-engine-host.exe"
    command([*arguments, "-o", str(second_host), HOST_PACKAGE], cwd=workspace, env=environment, timeout=1200)
    require(sha256(host_executable) == sha256(second_host), "Windows host build is not reproducible across caches")
    print("Running the GA engine test package union on Windows (without race instrumentation)", flush=True)
    # Match the GA engine's Go linker contract; the Mac-only external clang
    # linker is omitted because this Windows component does not use CGO.
    result = subprocess.run([str(go), "test", "-json", "-count=1", "-timeout=5m", "-ldflags=-checklinkname=0", "-tags", tags, *packages],
                            cwd=workspace, env=environment, capture_output=True, timeout=1200)
    (output / "go-tests.jsonl").write_bytes(result.stdout)
    (output / "go-tests.stderr.txt").write_bytes(result.stderr)
    require(result.returncode == 0, "native Windows engine tests failed; inspect go-tests.jsonl and go-tests.stderr.txt")
    test_events = [json.loads(line) for line in result.stdout.splitlines() if line]
    passed_tests = [event for event in test_events if event.get("Action") == "pass" and "Test" in event]
    skipped_tests = [{"package": event["Package"], "test": event["Test"]} for event in test_events
                     if event.get("Action") == "skip" and "Test" in event]
    require(not skipped_tests, "native engine tests were skipped; inspect the complete Go test event log")
    packages_without_tests = [event["Package"] for event in test_events if event.get("Action") == "skip" and "Test" not in event]
    print("Repeating the synchronized DNS response fixture on native Windows", flush=True)
    stress_name = "TestRuntimeDNSPoolRetriesSERVFAILButPreservesNegativeAnswers"
    stress = subprocess.run([str(go), "test", "-json", "-count=200", "-timeout=5m",
                             "-ldflags=-checklinkname=0", "-tags", tags, "./dns", "-run", f"^{stress_name}$"],
                            cwd=workspace, env=environment, capture_output=True, timeout=360)
    (output / "dns-fixture-stress.jsonl").write_bytes(stress.stdout)
    (output / "dns-fixture-stress.stderr.txt").write_bytes(stress.stderr)
    require(stress.returncode == 0, "Windows DNS fixture stress failed; inspect dns-fixture-stress.jsonl")
    stress_events = [json.loads(line) for line in stress.stdout.splitlines() if line]
    stress_passed = sum(event.get("Action") == "pass" and "Test" in event for event in stress_events)
    require(stress_passed == 800 and not any(event.get("Action") in ("fail", "skip") for event in stress_events),
            "Windows DNS fixture stress did not execute all 200 complete cases")
    verify_source(repository, baseline_source, pins, patched=True)
    require_unchanged(source_files(baseline_source), baseline_files, "GA baseline source bytes changed")
    require_unchanged(source_files(source), expected_files, "build or tests changed engine source bytes")
    require_unchanged(source_files(workspace), workspace_files, "build or tests changed workspace bytes")
    version = command([str(executable), "version"]).decode("utf-8")
    info = command([str(go), "version", "-m", str(executable)], env=environment).decode("utf-8")
    (output / "build-info.txt").write_text(info, encoding="utf-8")
    host_info = command([str(go), "version", "-m", str(host_executable)], env=environment).decode("utf-8")
    (output / "host-build-info.txt").write_text(host_info, encoding="utf-8")
    shutil.copyfile(workspace / "LICENSE", output / "LICENSE")
    command([str(go), "mod", "verify"], cwd=workspace, env=environment)
    print("Collecting source license and notice texts for the linked Windows engine", flush=True)
    notices = bundle_notices(repository, go, workspace, output, environment, pins)
    require(notices["embedded_binaries"] == 1, "fixed Windows engine omitted its embedded Wintun notice")
    wintun = output / "wintun.dll"
    receipt = {"schema_version": 1, "product_source": git(repository, "rev-parse", "HEAD").decode().strip(),
               "component": "windows-engine", "platform": "windows-amd64", "release_accepted": False,
               "engine_version": pins["SING_BOX_VERSION"], "engine_commit": pins["SING_BOX_COMMIT"],
               "combined_diff_sha256": pins["SING_BOX_COMBINED_DIFF_SHA256"],
               "source_files_sha256": hashlib.sha256(json.dumps(baseline_files, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
               "host_source_files_sha256": hashlib.sha256(json.dumps(expected_files, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
               "host_source_additions": source_files(repository / "native/windows/engine-host"),
               "windows_test_overlay": test_overlay,
               "dns_fixture_stress": {"test": stress_name, "repetitions": 200, "passed_events": stress_passed},
               "go_version": pins["GO_VERSION"], "go_archive_sha256": pins["GO_WINDOWS_AMD64_SHA256"],
               "build_tags": tags.split(","), "cgo_enabled": False, "independent_cache_builds_equal": True,
               "test_packages": packages, "tests_passed": len(passed_tests), "tests_skipped": skipped_tests,
               "packages_without_tests": packages_without_tests, "source_notices": notices,
               "wintun_artifact": {"filename": wintun.name, "size": wintun.stat().st_size,
                                   "sha256": sha256(wintun), "version": pins["WINTUN_VERSION"]},
               "module_graph_sha256": sha256(output / "module-graph.json"),
               "build_workspace": workspace_record,
               "workspace_module_graph_sha256": sha256(output / "workspace-module-graph.json"),
               "vulnerability_scans": {"pinned": pinned_scan, "corrected": corrected_scan},
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
