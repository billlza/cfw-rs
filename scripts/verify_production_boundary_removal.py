"""Static production-boundary removal gate.

Fails a Release/production build when the shipped product data plane still
contains any of the retired or forbidden constructs the macOS 15 Network
Extension migration removed:

* direct Tunnel configuration/credential payload transport
  (``TunnelStartPayloadCodec`` / ``tunnelStartPayloadOptionKey`` wired into a
  Release start path);
* provider-local acceptance/lease authority in production
  (``SandboxConfigurationAcceptanceStore`` / ``CrossProcessEngineLeaseStore``
  constructed outside explicitly named test fixtures);
* durable App Group storage of secret-bearing runtime configuration in a
  production owner path (``AppGroupConfigurationStore(...)``);
* root data-plane behavior or retired privileged-helper startup
  (``SMJobBless`` / ``AuthorizationExecuteWithPrivileges``);
* alternate or downloaded cores and executable-launch fallbacks
  (``Process(`` / ``NSTask`` / ``posix_spawn`` / ``dlopen`` / ``dlsym`` in the
  Swift/ObjC data plane);
* private Network Extension access (KVC into ``packetFlow`` /
  ``socket.fileDescriptor`` and other undocumented symbols);
* insecure Authority overrides
  (``CFW_ALLOW_INSECURE_*``, ``CFW_GLOBAL_AUTHORITY_REQUIRED=0``,
  ``allowInsecureAuthority``, ``globalAuthorityFallback`` and similar);
* fail-closed placeholders composed into a shipped start path instead of a
  concrete ProxyAgent/Provider Authority owner and effective-state observer;
* permanently unproven Authority release gates or an opt-in signed-channel
  boolean whose production default is false; and
* private ``NSXPCConnection.auditToken`` selector access, including protocol
  ``unsafeBitCast`` dispatch.  Peer identity must come from a documented XPC
  transport API rather than a selector that is absent from the public SDK.

Cleanup/tombstone references are permitted only where they cannot start or
authorize a data plane.  This is enforced two ways: comments and string
literals are stripped before the structural scan (so prose that *names* a
forbidden construct while forbidding it never trips the gate), and the
structural rules match activation/construction forms (a call, a constructor,
a member access) rather than the bare identifier.  The Rust coordinator loads
the app's own signed native-bridge framework through ``libc::dlopen`` and runs
read-only inspection tools (``/bin/ps``, ``/usr/sbin/netstat``) during legacy
cleanup, so executable-launch and dynamic-loading rules are scoped to the
Swift/ObjC data plane where an alternate core or private-API fallback would
actually live; the cross-language rule that does apply to Rust is the
insecure-Authority-override rule.

The gate fails closed: a missing production root, an unreadable file, or a file
that is not valid UTF-8 raises rather than silently passing.
"""

from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path


class ProductionBoundaryViolation(RuntimeError):
    """Raised when a production source violates the removal boundary or an
    input required by the scan is unavailable, unreadable, or malformed."""


# Production data-plane roots that ship inside the Release product.  Each must
# exist; a missing root is treated as an unavailable input and fails closed.
PRODUCTION_ROOTS: tuple[str, ...] = (
    "native/macos/Sources",
    "native/macos/SystemExtension",
    "apps/cfw-tauri-shell/src",
    "crates",
)

_SWIFT_SUFFIXES = {".swift"}
_OBJC_SUFFIXES = {".m", ".mm", ".h"}
_RUST_SUFFIXES = {".rs"}


def language_for(relative_path: str) -> str | None:
    """Return the source language for a path, or None if it is not scanned."""
    suffix = Path(relative_path).suffix
    if suffix in _SWIFT_SUFFIXES:
        return "swift"
    if suffix in _OBJC_SUFFIXES:
        return "objc"
    if suffix in _RUST_SUFFIXES:
        return "rust"
    return None


def is_test_fixture(relative_path: str) -> bool:
    """Explicitly named test fixtures are allowed to reference retired
    constructs (e.g. the local lease store with a `testingPort:` initializer)."""
    parts = [part.lower() for part in Path(relative_path).parts]
    if any(part in {"tests", "test", "__pycache__"} for part in parts):
        return True
    name = Path(relative_path).name
    return bool(
        re.search(r"(?:Tests?|Mock|Fake|Fixture|Stub)s?\.(?:swift|m|mm|rs)$", name)
    )


@dataclass(frozen=True)
class Finding:
    relative_path: str
    line: int
    category: str
    detail: str

    def __str__(self) -> str:
        return f"{self.relative_path}:{self.line}: {self.category}: {self.detail}"


def strip_comments_and_strings(
    text: str, language: str, *, strip_strings: bool = True
) -> str:
    """Blank out comments and, by default, string literals while preserving
    newlines and length so line numbers stay accurate.

    Handles Swift/Rust ``//`` and nested ``/* */`` comments, normal
    double-quoted strings with escapes, Swift multiline ``\"\"\"`` strings,
    Swift raw strings (``#"..."#``), and Rust raw strings (``r"..."`` /
    ``r#"..."#``).  With ``strip_strings=False`` it still skips over strings
    while scanning, so comment markers inside a literal remain data, but leaves
    the string bytes intact for the exact audit-token selector rule.
    """
    out = list(text)
    n = len(text)

    def blank(start: int, end: int) -> None:
        for index in range(start, end):
            if out[index] != "\n":
                out[index] = " "

    i = 0
    while i < n:
        char = text[i]

        # Line comment.
        if char == "/" and i + 1 < n and text[i + 1] == "/":
            j = i
            while j < n and text[j] != "\n":
                j += 1
            blank(i, j)
            i = j
            continue

        # Nested block comment.
        if char == "/" and i + 1 < n and text[i + 1] == "*":
            depth = 1
            j = i + 2
            while j < n and depth > 0:
                if text[j] == "/" and j + 1 < n and text[j + 1] == "*":
                    depth += 1
                    j += 2
                    continue
                if text[j] == "*" and j + 1 < n and text[j + 1] == "/":
                    depth -= 1
                    j += 2
                    continue
                j += 1
            blank(i, j)
            i = j
            continue

        # Rust raw string: r"..." or r#"..."# (any number of hashes).
        if language == "rust" and char == "r" and i + 1 < n and text[i + 1] in {'"', "#"}:
            k = i + 1
            hashes = 0
            while k < n and text[k] == "#":
                hashes += 1
                k += 1
            if k < n and text[k] == '"':
                closing = '"' + "#" * hashes
                end = text.find(closing, k + 1)
                end = n if end < 0 else end + len(closing)
                if strip_strings:
                    blank(i, end)
                i = end
                continue

        # Swift raw string: #"..."# / ##"..."## (optionally with """).
        if language in {"swift", "objc"} and char == "#":
            k = i
            hashes = 0
            while k < n and text[k] == "#":
                hashes += 1
                k += 1
            if k < n and text[k] == '"':
                triple = text.startswith('"""', k)
                open_quote = '"""' if triple else '"'
                closing = open_quote + "#" * hashes
                end = text.find(closing, k + len(open_quote))
                end = n if end < 0 else end + len(closing)
                if strip_strings:
                    blank(i, end)
                i = end
                continue

        # Swift multiline string literal.
        if language in {"swift", "objc"} and text.startswith('"""', i):
            end = text.find('"""', i + 3)
            end = n if end < 0 else end + 3
            if strip_strings:
                blank(i, end)
            i = end
            continue

        # Normal double-quoted string with backslash escapes (single line).
        if char == '"':
            j = i + 1
            while j < n and text[j] != '"' and text[j] != "\n":
                if text[j] == "\\":
                    j += 2
                    continue
                j += 1
            if j < n and text[j] == '"':
                j += 1
            if strip_strings:
                blank(i, j)
            i = j
            continue

        i += 1

    return "".join(out)


# Structural rules run over comment/string-stripped code.  Each rule is a
# (category, compiled pattern, languages, allow-line pattern) tuple.
_STRUCTURAL_RULES: tuple[tuple[str, re.Pattern[str], frozenset[str], re.Pattern[str] | None], ...] = (
    (
        "fail-closed production composition",
        re.compile(
            r"\b(?:FailClosedProxyOwnerAuthorityClient|"
            r"FailClosedProxyOwnerCapabilitySource|"
            r"FailClosedEffectiveSystemProxyObserver|"
            r"FailClosedEngineOwnerAuthorityClient)\s*(?:\.init\s*)?\("
        ),
        frozenset({"swift", "objc"}),
        None,
    ),
    (
        "unproven signed Authority channel",
        re.compile(
            r"\bsignedChannelProven\s*(?:"
            r":\s*false\b|"
            r":\s*Bool\s*=\s*false\b|"
            r"=\s*false\b)"
        ),
        frozenset({"swift", "objc"}),
        None,
    ),
    (
        "permanently unavailable Authority release gate",
        re.compile(r"\bvalidate\s*\(\s*\.availabilityUnproven\s*\)"),
        frozenset({"swift", "objc"}),
        None,
    ),
    (
        "private NSXPCConnection audit-token access",
        re.compile(
            r"\bunsafeBitCast\s*\([^,\n]+,\s*to\s*:\s*"
            r"CFWXPCAuditTokenProviding\.self\s*\)"
        ),
        frozenset({"swift", "objc"}),
        None,
    ),
    (
        "private NSXPCConnection audit-token access",
        re.compile(r"\.\s*auditToken\b"),
        frozenset({"swift", "objc"}),
        None,
    ),
    (
        "direct Tunnel payload transport",
        re.compile(r"\bTunnelStartPayloadCodec\s*\."),
        frozenset({"swift", "objc"}),
        None,
    ),
    (
        "direct Tunnel payload transport",
        re.compile(r"\btunnelStartPayloadOptionKey\b"),
        frozenset({"swift", "objc"}),
        re.compile(r"\blet\s+tunnelStartPayloadOptionKey\s*="),
    ),
    (
        "provider-local acceptance authority",
        re.compile(r"\bSandboxConfigurationAcceptanceStore\s*(?:\.init\s*)?\("),
        frozenset({"swift", "objc"}),
        None,
    ),
    (
        "provider-local lease authority",
        re.compile(r"\bCrossProcessEngineLeaseStore\s*(?:\.init\s*)?\("),
        frozenset({"swift", "objc"}),
        None,
    ),
    (
        "durable runtime configuration fallback",
        re.compile(r"\bAppGroupConfigurationStore\s*(?:\.init\s*)?\("),
        frozenset({"swift", "objc"}),
        None,
    ),
    (
        "retired helper / root data-plane startup",
        re.compile(r"\bSMJobBless\b|\bAuthorizationExecuteWithPrivileges\b"),
        frozenset({"swift", "objc"}),
        None,
    ),
    (
        "executable-launch or alternate-core fallback",
        re.compile(
            r"\bProcess\s*\(|\bNSTask\b|\bposix_spawn\w*\s*\(|\bdlopen\s*\(|\bdlsym\s*\("
        ),
        frozenset({"swift", "objc"}),
        None,
    ),
    (
        "private Network Extension access",
        re.compile(r"\bsocket\.fileDescriptor\b"),
        frozenset({"swift", "objc"}),
        None,
    ),
    (
        "private Network Extension access",
        re.compile(r"\bpacketFlow\b[^\n]*\.value\s*\(\s*forKey"),
        frozenset({"swift", "objc"}),
        None,
    ),
    (
        "private Network Extension access",
        re.compile(r"\bpacketFlow\b[^\n]*\.setValue\s*\("),
        frozenset({"swift", "objc"}),
        None,
    ),
)

# The insecure-Authority-override rule runs over raw text (the tokens routinely
# live in build symbols and would be blanked by string stripping) and applies to
# every scanned language, including Rust.
_INSECURE_OVERRIDE = re.compile(
    r"CFW_(?:ALLOW_INSECURE|BYPASS|DISABLE|SKIP)[A-Z0-9_]*AUTHORITY|"
    r"CFW_GLOBAL_AUTHORITY_REQUIRED\s*=\s*(?:0|NO|false)|"
    r"allowInsecureAuthority|globalAuthority(?:Fallback|Bypass|Optional)|"
    r"authorityErrorFallback",
    re.IGNORECASE,
)

# The selector name is a string literal and therefore intentionally scanned in
# raw text.  Limit the rule to the exact private NSXPCConnection audit-token
# accessor so ordinary documented selector use elsewhere is not conflated with
# this release-blocking identity boundary.
_PRIVATE_XPC_AUDIT_TOKEN_SELECTOR = re.compile(
    r"\bNSSelectorFromString\s*\(\s*(?:#+)?[\"']auditToken[\"'](?:#+)?\s*\)"
)


def scan_source(relative_path: str, text: str) -> list[Finding]:
    """Return every production-boundary violation in a single source file.

    Explicitly named test fixtures and non-source files are exempt and return
    no findings.
    """
    language = language_for(relative_path)
    if language is None or is_test_fixture(relative_path):
        return []

    findings: list[Finding] = []
    raw_lines = text.splitlines()
    stripped_lines = strip_comments_and_strings(text, language).splitlines()
    selector_lines = strip_comments_and_strings(
        text, language, strip_strings=False
    ).splitlines()

    for line_number, stripped in enumerate(stripped_lines, start=1):
        for category, pattern, languages, allow in _STRUCTURAL_RULES:
            if language not in languages:
                continue
            match = pattern.search(stripped)
            if not match:
                continue
            if allow is not None and allow.search(stripped):
                continue
            findings.append(
                Finding(relative_path, line_number, category, match.group(0).strip())
            )

    for line_number, (raw, selector_source) in enumerate(
        zip(raw_lines, selector_lines, strict=True), start=1
    ):
        match = _INSECURE_OVERRIDE.search(raw)
        if match:
            findings.append(
                Finding(
                    relative_path,
                    line_number,
                    "insecure Authority override",
                    match.group(0).strip(),
                )
            )
        private_selector = _PRIVATE_XPC_AUDIT_TOKEN_SELECTOR.search(selector_source)
        if private_selector:
            findings.append(
                Finding(
                    relative_path,
                    line_number,
                    "private NSXPCConnection audit-token access",
                    private_selector.group(0).strip(),
                )
            )

    return findings


def read_source(path: Path) -> str:
    """Read a source file, failing closed on unreadable or malformed input."""
    try:
        data = path.read_bytes()
    except OSError as error:
        raise ProductionBoundaryViolation(
            f"unreadable production source {path}: {error}"
        ) from error
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ProductionBoundaryViolation(
            f"malformed (non-UTF-8) production source {path}: {error}"
        ) from error


def iter_production_files(root: Path) -> list[Path]:
    """Return every scannable source file under a production root."""
    files: list[Path] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        if language_for(path.name) is None:
            continue
        files.append(path)
    return files


def verify_repository(root: Path) -> None:
    """Scan every production root and raise on any violation or missing input."""
    findings: list[Finding] = []
    scanned = 0
    for relative_root in PRODUCTION_ROOTS:
        source_root = root / relative_root
        if not source_root.is_dir():
            raise ProductionBoundaryViolation(
                f"required production root is unavailable: {relative_root}"
            )
        for path in iter_production_files(source_root):
            relative = path.relative_to(root).as_posix()
            text = read_source(path)
            findings.extend(scan_source(relative, text))
            scanned += 1

    if scanned == 0:
        raise ProductionBoundaryViolation(
            "no production sources were scanned; inputs are unavailable"
        )

    if findings:
        detail = "\n".join(f"  {finding}" for finding in findings)
        raise ProductionBoundaryViolation(
            "production products still contain retired data-plane constructs:\n" + detail
        )


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    try:
        verify_repository(root)
    except ProductionBoundaryViolation as error:
        print(f"error: {error}", file=sys.stderr)
        return 1
    print("Production data-plane removal boundary verified")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
