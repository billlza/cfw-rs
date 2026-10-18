#!/usr/bin/env python3
"""Re-download and verify the complete public GitHub release asset set.

This is deliberately a read-only, post-publication verifier.  Its trust root is
an offline copy of ``distribution-set.seal.json`` plus that file's independently
retained SHA-256.  It never discovers assets through the GitHub API, consumes
credentials, uploads bytes, or treats the publication channel as its own trust
root.

The trusted distribution seal was produced only after the authoritative local
``release_artifact_set`` validators passed.  This tool reuses that module's
canonical schema helpers, fixed names, fixed size bounds, and artifact-record
validator to prove that the fifteen public objects are byte-for-byte identical
to the locally authorized upload set.  It does not create a second signing,
notarization, Gatekeeper, or publication-semantic validator.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import http.client
import os
from pathlib import Path
import ssl
import stat
import tempfile
import time
from typing import Callable, Protocol
from urllib.parse import quote, urlsplit

if __package__:
    from . import release_artifact_set as artifact_set
else:  # pragma: no cover - exercised by the command-line entry point
    import release_artifact_set as artifact_set


INITIAL_HOST = "github.com"
REDIRECT_HOST = "release-assets.githubusercontent.com"
ALLOWED_REDIRECT_STATUSES = frozenset({301, 302, 303, 307, 308})
MAX_REDIRECTS = 2
CONNECT_TIMEOUT_SECONDS = 30.0
ASSET_TIMEOUT_SECONDS = 30.0 * 60.0
DOWNLOAD_CHUNK_BYTES = 1024 * 1024
MAX_REDIRECT_URL_BYTES = 16 * 1024
USER_AGENT = "cfw-remote-release-verifier/1"
FORBIDDEN_REQUEST_HEADERS = frozenset({"Authorization", "Cookie", "Range"})


class RemoteReleaseError(RuntimeError):
    """The remote public release cannot be proven from the offline trust root."""


class _Response(Protocol):
    status: int
    headers: object

    def read(self, amount: int | None = None) -> bytes: ...

    def close(self) -> None: ...


class _Connection(Protocol):
    sock: object

    def request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None: ...

    def getresponse(self) -> _Response: ...

    def close(self) -> None: ...


ConnectionFactory = Callable[[str, int, float, ssl.SSLContext], _Connection]


@dataclass(frozen=True)
class ExpectedAsset:
    identifier: str
    filename: str
    maximum: int
    record: dict[str, object]

    @property
    def size(self) -> int:
        value = self.record["size"]
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            raise RemoteReleaseError("trusted release asset size is malformed")
        return value

    @property
    def sha256(self) -> str:
        value = self.record["sha256"]
        if not isinstance(value, str) or not artifact_set.SHA256_RE.fullmatch(value):
            raise RemoteReleaseError("trusted release asset digest is malformed")
        return value


@dataclass(frozen=True)
class TrustRoot:
    assets: tuple[ExpectedAsset, ...]
    build_number: str
    distribution_seal: dict[str, object]
    distribution_seal_bytes: bytes
    distribution_seal_sha256: str
    repository_commit: str
    release_source_sha256: str
    version: str


def _repository() -> Path:
    return Path(__file__).resolve().parent.parent


def _current_clean_source_identity(repository: Path) -> dict[str, str]:
    try:
        return artifact_set._canonical_source_identity(
            artifact_set.current_identity(repository, require_clean=True)
        )
    except (
        artifact_set.ArtifactSetError,
        artifact_set.SourceIdentityError,
        OSError,
        ValueError,
    ) as error:
        raise RemoteReleaseError(
            "cannot prove the verifier checkout's clean source identity"
        ) from error


def _header_values(response: _Response, name: str) -> list[str]:
    headers = response.headers
    getter = getattr(headers, "get_all", None)
    if not callable(getter):
        raise RemoteReleaseError("HTTPS response headers are not inspectable")
    values = getter(name, [])
    if not isinstance(values, list) or any(
        not isinstance(value, str) for value in values
    ):
        raise RemoteReleaseError(f"HTTPS response has malformed {name} headers")
    return values


def _one_header(response: _Response, name: str, *, required: bool) -> str | None:
    values = _header_values(response, name)
    if not values:
        if required:
            raise RemoteReleaseError(f"HTTPS response omits required {name}")
        return None
    if len(values) != 1:
        raise RemoteReleaseError(f"HTTPS response repeats {name}")
    return values[0]


def _validated_url(url: str, *, initial: bool) -> tuple[str, int, str]:
    if (
        not isinstance(url, str)
        or not url
        or len(url.encode("utf-8")) > MAX_REDIRECT_URL_BYTES
        or any(not 0x21 <= ord(character) <= 0x7E for character in url)
        or "\\" in url
    ):
        raise RemoteReleaseError("release asset URL is not bounded canonical text")
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError as error:
        raise RemoteReleaseError("release asset URL has an invalid port") from error
    expected_host = INITIAL_HOST if initial else REDIRECT_HOST
    if (
        parsed.scheme != "https"
        or parsed.hostname != expected_host
        or parsed.username is not None
        or parsed.password is not None
        or port not in (None, 443)
        or parsed.fragment
        or not parsed.path.startswith("/")
        or (initial and parsed.query)
    ):
        boundary = "official GitHub" if initial else "GitHub release-asset"
        raise RemoteReleaseError(f"release asset URL left the {boundary} HTTPS boundary")
    target = parsed.path
    if parsed.query:
        target = f"{target}?{parsed.query}"
    return expected_host, 443, target


def _official_asset_url(version: str, filename: str) -> str:
    expected_origin = "https://github.com/billlza/cfw-rs/releases/download"
    if artifact_set.OFFICIAL_RELEASE_ORIGIN != expected_origin:
        raise RemoteReleaseError("official release origin contract drifted")
    if Path(filename).name != filename or filename in {"", ".", ".."}:
        raise RemoteReleaseError("release asset allowlist contains an unsafe filename")
    encoded = quote(filename, safe="-._~")
    return f"{artifact_set.OFFICIAL_RELEASE_ORIGIN}/v{version}/{encoded}"


def _default_connection_factory(
    host: str, port: int, timeout: float, context: ssl.SSLContext
) -> _Connection:
    return http.client.HTTPSConnection(
        host,
        port=port,
        timeout=timeout,
        context=context,
    )


class HTTPSDownloader:
    """A credential-free HTTPS GET client with a fixed redirect boundary."""

    def __init__(
        self,
        *,
        connection_factory: ConnectionFactory = _default_connection_factory,
        connect_timeout: float = CONNECT_TIMEOUT_SECONDS,
        asset_timeout: float = ASSET_TIMEOUT_SECONDS,
    ) -> None:
        if connect_timeout <= 0 or asset_timeout <= 0:
            raise RemoteReleaseError("HTTPS timeouts must be positive")
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        self._connection_factory = connection_factory
        self._connect_timeout = connect_timeout
        self._asset_timeout = asset_timeout
        self._context = context

    @staticmethod
    def _set_read_timeout(connection: _Connection, remaining: float) -> None:
        sock = getattr(connection, "sock", None)
        setter = getattr(sock, "settimeout", None)
        if callable(setter):
            setter(max(0.001, remaining))

    def download(
        self,
        url: str,
        stream,
        *,
        expected_size: int,
        expected_sha256: str,
    ) -> None:
        if (
            not isinstance(expected_size, int)
            or isinstance(expected_size, bool)
            or expected_size <= 0
            or not isinstance(expected_sha256, str)
            or not artifact_set.SHA256_RE.fullmatch(expected_sha256)
        ):
            raise RemoteReleaseError("download expectation is malformed")

        current_url = url
        initial = True
        deadline = time.monotonic() + self._asset_timeout
        redirects = 0
        while True:
            host, port, target = _validated_url(current_url, initial=initial)
            connection: _Connection | None = None
            response: _Response | None = None
            try:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise RemoteReleaseError("release asset download exceeded its deadline")
                connection = self._connection_factory(
                    host,
                    port,
                    min(self._connect_timeout, remaining),
                    self._context,
                )
                # These are the complete caller-supplied headers.  In particular,
                # no token, cookie, referrer, range, or ambient credential is used.
                request_headers = {
                    "Accept": "application/octet-stream",
                    "Accept-Encoding": "identity",
                    "Connection": "close",
                    "User-Agent": USER_AGENT,
                }
                if set(request_headers) & FORBIDDEN_REQUEST_HEADERS:
                    raise RemoteReleaseError("credential-free request policy drifted")
                connection.request(
                    "GET",
                    target,
                    body=None,
                    headers=request_headers,
                )
                response = connection.getresponse()
                if response.status in ALLOWED_REDIRECT_STATUSES:
                    redirects += 1
                    if redirects > MAX_REDIRECTS:
                        raise RemoteReleaseError("release asset exceeded the redirect limit")
                    location = _one_header(response, "Location", required=True)
                    if location is None:  # pragma: no cover - required=True owns this
                        raise RemoteReleaseError("release asset redirect has no location")
                    # Relative redirects are intentionally refused.  The only
                    # accepted transition is github.com -> the documented fixed
                    # GitHub release-asset host over certificate-validated HTTPS.
                    _validated_url(location, initial=False)
                    current_url = location
                    initial = False
                    continue
                if response.status != 200:
                    raise RemoteReleaseError(
                        f"release asset GET returned unexpected HTTP status {response.status}"
                    )
                if initial:
                    raise RemoteReleaseError(
                        "official GitHub asset did not redirect to the release-asset host"
                    )
                if _one_header(response, "Content-Range", required=False) is not None:
                    raise RemoteReleaseError("release asset response is partial content")
                if _one_header(response, "Transfer-Encoding", required=False) is not None:
                    raise RemoteReleaseError("release asset response uses transfer encoding")
                content_encoding = _one_header(
                    response, "Content-Encoding", required=False
                )
                if content_encoding is not None and content_encoding.lower() != "identity":
                    raise RemoteReleaseError("release asset response transforms its payload")
                content_length = _one_header(response, "Content-Length", required=True)
                if content_length != str(expected_size):
                    raise RemoteReleaseError(
                        "release asset Content-Length differs from the trusted seal"
                    )

                digest = hashlib.sha256()
                received = 0
                while received < expected_size:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise RemoteReleaseError(
                            "release asset download exceeded its deadline"
                        )
                    self._set_read_timeout(connection, remaining)
                    chunk = response.read(
                        min(DOWNLOAD_CHUNK_BYTES, expected_size - received)
                    )
                    if not isinstance(chunk, bytes):
                        raise RemoteReleaseError("release asset response yielded non-bytes")
                    if not chunk:
                        raise RemoteReleaseError("release asset response is truncated")
                    if len(chunk) > expected_size - received:
                        raise RemoteReleaseError("release asset response exceeds its sealed size")
                    received += len(chunk)
                    digest.update(chunk)
                    if stream.write(chunk) != len(chunk):
                        raise RemoteReleaseError(
                            "temporary release asset write was incomplete"
                        )
                if response.read(1) != b"":
                    raise RemoteReleaseError("release asset response has an unsealed suffix")
                if digest.hexdigest() != expected_sha256:
                    raise RemoteReleaseError(
                        "release asset SHA-256 differs from the trusted seal"
                    )
                stream.flush()
                os.fsync(stream.fileno())
                return
            except RemoteReleaseError:
                raise
            except (OSError, ssl.SSLError, http.client.HTTPException) as error:
                raise RemoteReleaseError("release asset HTTPS transfer failed") from error
            finally:
                if response is not None:
                    response.close()
                if connection is not None:
                    connection.close()


class SecureDownloadDirectory:
    """Private temporary storage addressed through one stable directory fd."""

    def __init__(self) -> None:
        self.path: Path | None = None
        self._descriptor = -1
        self._identity: tuple[int, int] | None = None
        self._file_identities: dict[str, tuple[int, int]] = {}

    def __enter__(self) -> "SecureDownloadDirectory":
        required_flags = ("O_DIRECTORY", "O_NOFOLLOW")
        if any(not hasattr(os, name) for name in required_flags):
            raise RemoteReleaseError("platform lacks required no-follow directory flags")
        path = Path(tempfile.mkdtemp(prefix="cfw-remote-release."))
        descriptor = -1
        try:
            os.chmod(path, 0o700)
            flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            if hasattr(os, "O_CLOEXEC"):
                flags |= os.O_CLOEXEC
            descriptor = os.open(path, flags)
            opened = os.fstat(descriptor)
            observed = path.lstat()
            if (
                not stat.S_ISDIR(opened.st_mode)
                or not stat.S_ISDIR(observed.st_mode)
                or opened.st_uid != os.geteuid()
                or stat.S_IMODE(opened.st_mode) != 0o700
                or (opened.st_dev, opened.st_ino)
                != (observed.st_dev, observed.st_ino)
            ):
                raise RemoteReleaseError("temporary download directory is not private")
        except BaseException:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                path.rmdir()
            except OSError:
                pass
            raise
        self.path = path
        self._descriptor = descriptor
        self._identity = (opened.st_dev, opened.st_ino)
        return self

    def _assert_identity(self) -> None:
        if self.path is None or self._descriptor < 0 or self._identity is None:
            raise RemoteReleaseError("temporary download directory is not open")
        opened = os.fstat(self._descriptor)
        observed = self.path.lstat()
        if (
            self._identity != (opened.st_dev, opened.st_ino)
            or self._identity != (observed.st_dev, observed.st_ino)
            or not stat.S_ISDIR(opened.st_mode)
            or not stat.S_ISDIR(observed.st_mode)
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o700
        ):
            raise RemoteReleaseError("temporary download directory identity changed")

    def create(self, filename: str):
        self._assert_identity()
        if Path(filename).name != filename or filename in {"", ".", ".."}:
            raise RemoteReleaseError("download filename is unsafe")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW
        if hasattr(os, "O_CLOEXEC"):
            flags |= os.O_CLOEXEC
        try:
            descriptor = os.open(
                filename,
                flags,
                0o600,
                dir_fd=self._descriptor,
            )
        except OSError as error:
            raise RemoteReleaseError(
                f"cannot create exclusive download file: {filename}"
            ) from error
        opened = os.fstat(descriptor)
        if (
            not stat.S_ISREG(opened.st_mode)
            or opened.st_nlink != 1
            or opened.st_uid != os.geteuid()
            or stat.S_IMODE(opened.st_mode) != 0o600
        ):
            os.close(descriptor)
            raise RemoteReleaseError("download file is not private and single-link")
        self._file_identities[filename] = (opened.st_dev, opened.st_ino)
        return os.fdopen(descriptor, "wb")

    def file_path(self, filename: str) -> Path:
        self._assert_identity()
        if self.path is None:  # pragma: no cover - _assert_identity owns this
            raise RemoteReleaseError("temporary download directory is not open")
        via_descriptor = os.stat(
            filename,
            dir_fd=self._descriptor,
            follow_symlinks=False,
        )
        via_path = (self.path / filename).lstat()
        if (
            not stat.S_ISREG(via_descriptor.st_mode)
            or via_descriptor.st_nlink != 1
            or via_descriptor.st_uid != os.geteuid()
            or stat.S_IMODE(via_descriptor.st_mode) != 0o600
            or self._file_identities.get(filename)
            != (via_descriptor.st_dev, via_descriptor.st_ino)
            or (via_descriptor.st_dev, via_descriptor.st_ino)
            != (via_path.st_dev, via_path.st_ino)
        ):
            raise RemoteReleaseError("download file identity changed")
        return self.path / filename

    def inventory(self) -> set[str]:
        self._assert_identity()
        return set(os.listdir(self._descriptor))

    def __exit__(self, _exception_type, _exception, _traceback) -> bool:
        cleanup_error: OSError | None = None
        if self._descriptor >= 0:
            try:
                for name in os.listdir(self._descriptor):
                    metadata = os.stat(
                        name,
                        dir_fd=self._descriptor,
                        follow_symlinks=False,
                    )
                    try:
                        if stat.S_ISDIR(metadata.st_mode):
                            os.rmdir(name, dir_fd=self._descriptor)
                        else:
                            os.unlink(name, dir_fd=self._descriptor)
                    except OSError as error:
                        cleanup_error = cleanup_error or error
            except OSError as error:
                cleanup_error = cleanup_error or error
            finally:
                os.close(self._descriptor)
                self._descriptor = -1
        if self.path is not None:
            try:
                self.path.rmdir()
            except OSError as error:
                cleanup_error = cleanup_error or error
            self.path = None
        if cleanup_error is not None:
            raise RemoteReleaseError(
                "cannot remove temporary release downloads"
            ) from cleanup_error
        return False


def _record_shape(
    value: object,
    *,
    filename: str,
    maximum: int,
    label: str,
) -> dict[str, object]:
    record = artifact_set._require_exact_keys(
        value, {"filename", "sha256", "size"}, label
    )
    if record["filename"] != filename:
        raise RemoteReleaseError(f"{label} has the wrong filename")
    artifact_set._require_sha256(record["sha256"], f"{label} digest")
    size = record["size"]
    if (
        not isinstance(size, int)
        or isinstance(size, bool)
        or size <= 0
        or size > maximum
    ):
        raise RemoteReleaseError(f"{label} size is outside its fixed limit")
    return record


def load_trust_root(
    trusted_seal_path: Path,
    trusted_seal_sha256: str,
    version: str,
) -> TrustRoot:
    try:
        version = artifact_set._require_semver(version)
    except artifact_set.ArtifactSetError as error:
        raise RemoteReleaseError(str(error)) from error
    if (
        not isinstance(trusted_seal_sha256, str)
        or not artifact_set.SHA256_RE.fullmatch(trusted_seal_sha256)
    ):
        raise RemoteReleaseError("trusted distribution seal SHA-256 is not canonical")
    if trusted_seal_path.name != artifact_set.DISTRIBUTION_SEAL_NAME:
        raise RemoteReleaseError(
            f"trusted seal must be named {artifact_set.DISTRIBUTION_SEAL_NAME}"
        )
    try:
        trusted_record = artifact_set._artifact_record(
            trusted_seal_path, artifact_set.MAX_SMALL_DOCUMENT_BYTES
        )
        if trusted_record["sha256"] != trusted_seal_sha256:
            raise RemoteReleaseError(
                "offline distribution seal differs from its independently retained SHA-256"
            )
        seal, seal_bytes = artifact_set._load_strict_json(
            trusted_seal_path, artifact_set.MAX_SMALL_DOCUMENT_BYTES
        )
        seal = artifact_set._require_exact_keys(
            seal,
            {
                "build_number",
                "candidate_app",
                "document",
                "product",
                "publication_closure",
                "release_assets",
                "repository",
                "schema_version",
                "sealed_at",
                "set_seals",
                "version",
            },
            "trusted distribution release seal",
        )
        artifact_set._require_canonical_document(
            trusted_seal_path,
            seal,
            seal_bytes,
            "trusted distribution release seal",
        )
        if (
            type(seal["schema_version"]) is not int
            or seal["schema_version"] != 1
            or seal["document"] != artifact_set.DISTRIBUTION_SEAL_DOCUMENT
            or seal["product"] != artifact_set.PRODUCT
            or seal["version"] != version
        ):
            raise RemoteReleaseError("trusted distribution seal identity is inconsistent")
        source = artifact_set._source_identity(seal["repository"])
        build_number = artifact_set._require_positive_decimal(
            seal["build_number"], "trusted distribution build number"
        )
        artifact_set._require_utc_timestamp(
            seal["sealed_at"], "trusted distribution seal time"
        )

        # Derive the public inventory from the existing release artifact set.
        # The pseudo roots are never touched; only each authoritative basename
        # and maximum are consumed here.
        expected_paths = artifact_set._release_asset_paths(
            Path("/release-root"),
            version,
            distribution_directory=Path("/distribution-root"),
        )
        release_assets = artifact_set._require_exact_keys(
            seal["release_assets"], set(expected_paths), "trusted release assets"
        )
        assets: list[ExpectedAsset] = []
        for identifier, (path, maximum) in sorted(expected_paths.items()):
            record = _record_shape(
                release_assets[identifier],
                filename=path.name,
                maximum=maximum,
                label=f"trusted release asset {identifier}",
            )
            assets.append(ExpectedAsset(identifier, path.name, maximum, record))

        set_seals = artifact_set._require_exact_keys(
            seal["set_seals"], {"dmg", "updater"}, "trusted component seals"
        )
        for identifier, filename in (
            ("dmg_set_seal", artifact_set.DMG_SEAL_NAME),
            ("updater_set_seal", artifact_set.UPDATER_SEAL_NAME),
        ):
            key = "dmg" if identifier == "dmg_set_seal" else "updater"
            record = _record_shape(
                set_seals[key],
                filename=filename,
                maximum=artifact_set.MAX_SMALL_DOCUMENT_BYTES,
                label=f"trusted {key} set seal",
            )
            assets.append(
                ExpectedAsset(
                    identifier,
                    filename,
                    artifact_set.MAX_SMALL_DOCUMENT_BYTES,
                    record,
                )
            )

        assets.append(
            ExpectedAsset(
                "distribution_set_seal",
                artifact_set.DISTRIBUTION_SEAL_NAME,
                artifact_set.MAX_SMALL_DOCUMENT_BYTES,
                trusted_record,
            )
        )
        filenames = [asset.filename for asset in assets]
        if len(assets) != 15 or len(set(filenames)) != 15:
            raise RemoteReleaseError(
                "public release allowlist is not exactly 15 unique paths"
            )
    except artifact_set.ArtifactSetError as error:
        raise RemoteReleaseError(f"trusted distribution seal is invalid: {error}") from error

    # Verify the remote trust-root object first; the remaining order is stable
    # and deterministic but has no trust significance.
    ordered = tuple(
        sorted(
            assets,
            key=lambda asset: (
                asset.identifier != "distribution_set_seal",
                asset.filename,
            ),
        )
    )
    return TrustRoot(
        assets=ordered,
        build_number=build_number,
        distribution_seal=seal,
        distribution_seal_bytes=seal_bytes,
        distribution_seal_sha256=trusted_seal_sha256,
        repository_commit=source["repository_commit"],
        release_source_sha256=source["release_source_sha256"],
        version=version,
    )


def verify_remote_release(
    trusted_seal_path: Path,
    trusted_seal_sha256: str,
    version: str,
    *,
    downloader: HTTPSDownloader | None = None,
) -> dict[str, object]:
    trust = load_trust_root(trusted_seal_path, trusted_seal_sha256, version)
    current_source = _current_clean_source_identity(_repository())
    trusted_source = {
        "release_source_sha256": trust.release_source_sha256,
        "repository_commit": trust.repository_commit,
    }
    if current_source != trusted_source:
        raise RemoteReleaseError(
            "verifier checkout source identity differs from the trusted distribution seal"
        )
    downloader = HTTPSDownloader() if downloader is None else downloader
    expected_filenames = {asset.filename for asset in trust.assets}

    with SecureDownloadDirectory() as downloads:
        for asset in trust.assets:
            with downloads.create(asset.filename) as stream:
                downloader.download(
                    _official_asset_url(trust.version, asset.filename),
                    stream,
                    expected_size=asset.size,
                    expected_sha256=asset.sha256,
                )
            path = downloads.file_path(asset.filename)
            try:
                # Reuse the release-set validator after the streaming check.  It
                # reopens the file no-follow, rechecks single-link/size bounds,
                # and recomputes the authoritative record from disk.
                artifact_set._validate_artifact_record(
                    asset.record,
                    path,
                    asset.maximum,
                    f"remote release asset {asset.identifier}",
                )
            except artifact_set.ArtifactSetError as error:
                raise RemoteReleaseError(str(error)) from error

        if downloads.inventory() != expected_filenames:
            raise RemoteReleaseError("remote release download set is partial or contains extras")

        remote_seal_path = downloads.file_path(artifact_set.DISTRIBUTION_SEAL_NAME)
        try:
            remote_seal, remote_seal_bytes = artifact_set._load_strict_json(
                remote_seal_path, artifact_set.MAX_SMALL_DOCUMENT_BYTES
            )
            artifact_set._require_canonical_document(
                remote_seal_path,
                remote_seal,
                remote_seal_bytes,
                "remote distribution release seal",
            )
        except artifact_set.ArtifactSetError as error:
            raise RemoteReleaseError(str(error)) from error
        if (
            remote_seal != trust.distribution_seal
            or remote_seal_bytes != trust.distribution_seal_bytes
        ):
            raise RemoteReleaseError(
                "remote distribution seal differs from the offline trust root"
            )

        # Close the download interval with a second complete record pass.  A
        # concurrent mutation cannot hide between an early per-file check and
        # the final release-set decision.
        for asset in trust.assets:
            try:
                artifact_set._validate_artifact_record(
                    asset.record,
                    downloads.file_path(asset.filename),
                    asset.maximum,
                    f"remote release asset {asset.identifier}",
                )
            except artifact_set.ArtifactSetError as error:
                raise RemoteReleaseError(str(error)) from error

    return {
        "asset_count": 15,
        "build_number": trust.build_number,
        "distribution_seal_sha256": trust.distribution_seal_sha256,
        "repository_commit": trust.repository_commit,
        "release_source_sha256": trust.release_source_sha256,
        "version": trust.version,
    }


def parser() -> argparse.ArgumentParser:
    result = argparse.ArgumentParser(description=__doc__)
    result.add_argument("--version", required=True)
    result.add_argument(
        "--trusted-distribution-seal",
        type=Path,
        required=True,
        help="offline distribution-set.seal.json retained before publication",
    )
    result.add_argument(
        "--trusted-distribution-seal-sha256",
        required=True,
        help="independently retained lowercase SHA-256 of the offline seal",
    )
    return result


def main() -> None:
    arguments = parser().parse_args()
    try:
        result = verify_remote_release(
            arguments.trusted_distribution_seal,
            arguments.trusted_distribution_seal_sha256,
            arguments.version,
        )
    except (OSError, RemoteReleaseError) as error:
        raise SystemExit(f"error: remote release verification: {error}") from error
    print(
        "remote public release verified: "
        f"version={result['version']} build={result['build_number']} "
        f"assets={result['asset_count']} "
        f"distribution_seal_sha256={result['distribution_seal_sha256']} "
        f"repository_commit={result['repository_commit']} "
        f"release_source_sha256={result['release_source_sha256']}"
    )


if __name__ == "__main__":
    main()
