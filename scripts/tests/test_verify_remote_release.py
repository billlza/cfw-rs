from __future__ import annotations

from email.message import Message
import hashlib
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
from urllib.parse import quote, unquote, urlsplit

REPOSITORY = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPOSITORY))

from scripts import release_artifact_set as artifact_set  # noqa: E402
from scripts.verify_remote_release import (  # noqa: E402
    HTTPSDownloader,
    RemoteReleaseError,
    SecureDownloadDirectory,
    load_trust_root,
    verify_remote_release,
)


VERSION = "0.4.0"
BUILD_NUMBER = "40002"
REPOSITORY_COMMIT = "a" * 40
RELEASE_SOURCE_SHA256 = "b" * 64


def _record(filename: str, body: bytes) -> dict[str, object]:
    return {
        "filename": filename,
        "sha256": hashlib.sha256(body).hexdigest(),
        "size": len(body),
    }


class ReleaseFixture:
    def __init__(self, root: Path) -> None:
        self.root = root
        expected_paths = artifact_set._release_asset_paths(
            Path("/release-root"),
            VERSION,
            distribution_directory=Path("/distribution-root"),
        )
        self.bodies: dict[str, bytes] = {}
        release_assets: dict[str, dict[str, object]] = {}
        for identifier, (path, _maximum) in sorted(expected_paths.items()):
            body = f"fixture release asset {identifier}\n".encode()
            self.bodies[path.name] = body
            release_assets[identifier] = _record(path.name, body)

        component_bodies = {
            artifact_set.DMG_SEAL_NAME: b'{"fixture":"dmg seal"}\n',
            artifact_set.UPDATER_SEAL_NAME: b'{"fixture":"updater seal"}\n',
        }
        self.bodies.update(component_bodies)
        seal = {
            "build_number": BUILD_NUMBER,
            "candidate_app": {
                "build_number": BUILD_NUMBER,
                "manifest": {
                    "filename": artifact_set.CANDIDATE_APP_MANIFEST_NAME,
                    "sha256": "c" * 64,
                    "size": 1,
                },
                "path": artifact_set.CANDIDATE_APP_RELATIVE,
                "signed_app_tree_sha256": "d" * 64,
                "tree_algorithm": "sha256-tree-v2",
            },
            "document": artifact_set.DISTRIBUTION_SEAL_DOCUMENT,
            "product": artifact_set.PRODUCT,
            "publication_closure": {"fixture": "already locally authorized"},
            "release_assets": release_assets,
            "repository": {
                "release_source_sha256": RELEASE_SOURCE_SHA256,
                "repository_commit": REPOSITORY_COMMIT,
            },
            "schema_version": 1,
            "sealed_at": "2026-07-29T12:00:00Z",
            "set_seals": {
                "dmg": _record(
                    artifact_set.DMG_SEAL_NAME,
                    component_bodies[artifact_set.DMG_SEAL_NAME],
                ),
                "updater": _record(
                    artifact_set.UPDATER_SEAL_NAME,
                    component_bodies[artifact_set.UPDATER_SEAL_NAME],
                ),
            },
            "version": VERSION,
        }
        self.seal_bytes = artifact_set.canonical_json(seal)
        self.seal_path = root / artifact_set.DISTRIBUTION_SEAL_NAME
        self.seal_path.write_bytes(self.seal_bytes)
        self.seal_sha256 = hashlib.sha256(self.seal_bytes).hexdigest()
        self.bodies[artifact_set.DISTRIBUTION_SEAL_NAME] = self.seal_bytes


class FakeSocket:
    def __init__(self) -> None:
        self.timeouts: list[float] = []

    def settimeout(self, timeout: float) -> None:
        self.timeouts.append(timeout)


class FakeResponse:
    def __init__(
        self,
        status: int,
        body: bytes = b"",
        headers: list[tuple[str, str]] | None = None,
    ) -> None:
        self.status = status
        self.body = body
        self.offset = 0
        self.closed = False
        self.headers = Message()
        for name, value in headers or []:
            self.headers[name] = value

    def read(self, amount: int | None = None) -> bytes:
        if amount is None:
            amount = len(self.body) - self.offset
        result = self.body[self.offset : self.offset + amount]
        self.offset += len(result)
        return result

    def close(self) -> None:
        self.closed = True


class FakeConnection:
    def __init__(self, server: "MaliciousHTTPFixture", host: str) -> None:
        self.server = server
        self.host = host
        self.sock = FakeSocket()
        self.request_data: tuple[str, str, bytes | None, dict[str, str]] | None = None
        self.closed = False

    def request(
        self,
        method: str,
        url: str,
        body: bytes | None = None,
        headers: dict[str, str] | None = None,
    ) -> None:
        assert headers is not None
        self.request_data = (method, url, body, dict(headers))
        self.server.requests.append((self.host, method, url, dict(headers)))

    def getresponse(self) -> FakeResponse:
        assert self.request_data is not None
        _method, target, _body, _headers = self.request_data
        return self.server.response(self.host, target)

    def close(self) -> None:
        self.closed = True


class MaliciousHTTPFixture:
    """Scripted HTTPS responses; faults model an untrusted publication channel."""

    def __init__(self, bodies: dict[str, bytes]) -> None:
        self.bodies = dict(bodies)
        self.faults: dict[str, str] = {}
        self.requests: list[tuple[str, str, str, dict[str, str]]] = []

    def factory(self, host, _port, _timeout, _context) -> FakeConnection:
        return FakeConnection(self, host)

    @staticmethod
    def _filename(target: str) -> str:
        path = urlsplit(target).path
        return unquote(path.rsplit("/", 1)[-1])

    def response(self, host: str, target: str) -> FakeResponse:
        filename = self._filename(target)
        fault = self.faults.get(filename)
        if host == "github.com":
            if fault == "http-redirect":
                location = f"http://release-assets.githubusercontent.com/assets/{filename}"
            elif fault == "foreign-redirect":
                location = f"https://attacker.example/assets/{filename}"
            elif fault == "relative-redirect":
                location = f"/assets/{filename}"
            elif fault == "initial-200":
                body = self.bodies[filename]
                return FakeResponse(
                    200,
                    body,
                    [("Content-Length", str(len(body)))],
                )
            else:
                location = (
                    "https://release-assets.githubusercontent.com/assets/"
                    f"{quote(filename, safe='-._~')}?token=fixture"
                )
            return FakeResponse(302, headers=[("Location", location)])

        body = self.bodies[filename]
        headers = [("Content-Length", str(len(body)))]
        status = 200
        if fault == "truncated":
            body = body[:-1]
        elif fault == "tampered":
            body = bytes([body[0] ^ 1]) + body[1:]
        elif fault == "suffix":
            body += b"unsealed"
        elif fault == "partial-status":
            status = 206
            headers.append(("Content-Range", f"bytes 0-{len(body)-1}/{len(body)}"))
        elif fault == "wrong-length":
            headers = [("Content-Length", str(len(body) + 1))]
        elif fault == "duplicate-length":
            headers.append(("Content-Length", str(len(body))))
        elif fault == "content-encoding":
            headers.append(("Content-Encoding", "gzip"))
        elif fault == "redirect-loop":
            return FakeResponse(
                302,
                headers=[
                    (
                        "Location",
                        "https://release-assets.githubusercontent.com/assets/"
                        f"{quote(filename, safe='-._~')}?token=again",
                    )
                ],
            )
        return FakeResponse(status, body, headers)


class RemoteReleaseTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.release = ReleaseFixture(self.root)

    def downloader(self, fixture: MaliciousHTTPFixture) -> HTTPSDownloader:
        return HTTPSDownloader(
            connection_factory=fixture.factory,
            connect_timeout=1,
            asset_timeout=30,
        )

    def verify(self, fixture: MaliciousHTTPFixture) -> dict[str, object]:
        with patch.object(
            artifact_set,
            "current_identity",
            return_value={
                "releaseSourceSha256": RELEASE_SOURCE_SHA256,
                "repositoryCommit": REPOSITORY_COMMIT,
            },
        ) as current_identity:
            result = verify_remote_release(
                self.release.seal_path,
                self.release.seal_sha256,
                VERSION,
                downloader=self.downloader(fixture),
            )
        current_identity.assert_called_once_with(REPOSITORY, require_clean=True)
        return result

    def test_exact_fifteen_asset_set_is_verified_without_authentication(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        old_token = os.environ.get("GITHUB_TOKEN")
        os.environ["GITHUB_TOKEN"] = "must-not-be-read"
        self.addCleanup(
            lambda: (
                os.environ.pop("GITHUB_TOKEN", None)
                if old_token is None
                else os.environ.__setitem__("GITHUB_TOKEN", old_token)
            )
        )

        result = self.verify(fixture)

        self.assertEqual(result["asset_count"], 15)
        self.assertEqual(result["build_number"], BUILD_NUMBER)
        self.assertEqual(result["repository_commit"], REPOSITORY_COMMIT)
        self.assertEqual(result["release_source_sha256"], RELEASE_SOURCE_SHA256)
        self.assertEqual(len(fixture.requests), 30)
        self.assertEqual(
            {request[0] for request in fixture.requests},
            {"github.com", "release-assets.githubusercontent.com"},
        )
        for _host, method, _target, headers in fixture.requests:
            self.assertEqual(method, "GET")
            self.assertEqual(headers["Accept-Encoding"], "identity")
            self.assertNotIn("Authorization", headers)
            self.assertNotIn("Cookie", headers)
            self.assertNotIn("Range", headers)

    def test_wrong_offline_seal_hash_is_rejected_before_http(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        with self.assertRaisesRegex(RemoteReleaseError, "independently retained"):
            verify_remote_release(
                self.release.seal_path,
                "0" * 64,
                VERSION,
                downloader=self.downloader(fixture),
            )
        self.assertEqual(fixture.requests, [])

    def test_trusted_seal_schema_version_requires_a_json_integer(self) -> None:
        for invalid in (1.0, True):
            with self.subTest(invalid=invalid):
                document = json.loads(self.release.seal_bytes)
                document["schema_version"] = invalid
                data = artifact_set.canonical_json(document)
                self.release.seal_path.write_bytes(data)
                digest = hashlib.sha256(data).hexdigest()
                with self.assertRaisesRegex(RemoteReleaseError, "identity is inconsistent"):
                    load_trust_root(self.release.seal_path, digest, VERSION)

    def test_source_identity_drift_is_rejected_before_http(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        with patch.object(
            artifact_set,
            "current_identity",
            return_value={
                "releaseSourceSha256": RELEASE_SOURCE_SHA256,
                "repositoryCommit": "f" * 40,
            },
        ) as current_identity:
            with self.assertRaisesRegex(RemoteReleaseError, "source identity differs"):
                verify_remote_release(
                    self.release.seal_path,
                    self.release.seal_sha256,
                    VERSION,
                    downloader=self.downloader(fixture),
                )
        current_identity.assert_called_once_with(REPOSITORY, require_clean=True)
        self.assertEqual(fixture.requests, [])

    def test_dirty_checkout_is_rejected_before_http(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        with patch.object(
            artifact_set,
            "current_identity",
            side_effect=artifact_set.SourceIdentityError("repository is dirty"),
        ) as current_identity:
            with self.assertRaisesRegex(RemoteReleaseError, "clean source identity"):
                verify_remote_release(
                    self.release.seal_path,
                    self.release.seal_sha256,
                    VERSION,
                    downloader=self.downloader(fixture),
                )
        current_identity.assert_called_once_with(REPOSITORY, require_clean=True)
        self.assertEqual(fixture.requests, [])

    def test_truncated_response_is_rejected(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        filename = artifact_set.DISTRIBUTION_SEAL_NAME
        fixture.faults[filename] = "truncated"
        with self.assertRaisesRegex(RemoteReleaseError, "truncated"):
            self.verify(fixture)

    def test_same_size_tamper_is_rejected(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        filename = artifact_set.DISTRIBUTION_SEAL_NAME
        fixture.faults[filename] = "tampered"
        with self.assertRaisesRegex(RemoteReleaseError, "SHA-256"):
            self.verify(fixture)

    def test_unsealed_response_suffix_is_rejected(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        filename = artifact_set.DISTRIBUTION_SEAL_NAME
        fixture.faults[filename] = "suffix"
        with self.assertRaisesRegex(RemoteReleaseError, "unsealed suffix"):
            self.verify(fixture)

    def test_partial_content_status_is_rejected(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        filename = artifact_set.DISTRIBUTION_SEAL_NAME
        fixture.faults[filename] = "partial-status"
        with self.assertRaisesRegex(RemoteReleaseError, "status 206"):
            self.verify(fixture)

    def test_content_length_mismatch_is_rejected_before_body(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        filename = artifact_set.DISTRIBUTION_SEAL_NAME
        fixture.faults[filename] = "wrong-length"
        with self.assertRaisesRegex(RemoteReleaseError, "Content-Length"):
            self.verify(fixture)

    def test_duplicate_content_length_is_rejected(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        filename = artifact_set.DISTRIBUTION_SEAL_NAME
        fixture.faults[filename] = "duplicate-length"
        with self.assertRaisesRegex(RemoteReleaseError, "repeats Content-Length"):
            self.verify(fixture)

    def test_content_encoding_is_rejected(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        filename = artifact_set.DISTRIBUTION_SEAL_NAME
        fixture.faults[filename] = "content-encoding"
        with self.assertRaisesRegex(RemoteReleaseError, "transforms"):
            self.verify(fixture)

    def test_https_downgrade_redirect_is_rejected(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        filename = artifact_set.DISTRIBUTION_SEAL_NAME
        fixture.faults[filename] = "http-redirect"
        with self.assertRaisesRegex(RemoteReleaseError, "HTTPS boundary"):
            self.verify(fixture)

    def test_foreign_host_redirect_is_rejected(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        filename = artifact_set.DISTRIBUTION_SEAL_NAME
        fixture.faults[filename] = "foreign-redirect"
        with self.assertRaisesRegex(RemoteReleaseError, "HTTPS boundary"):
            self.verify(fixture)

    def test_relative_redirect_is_rejected(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        filename = artifact_set.DISTRIBUTION_SEAL_NAME
        fixture.faults[filename] = "relative-redirect"
        with self.assertRaisesRegex(RemoteReleaseError, "HTTPS boundary"):
            self.verify(fixture)

    def test_direct_initial_200_is_rejected(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        filename = artifact_set.DISTRIBUTION_SEAL_NAME
        fixture.faults[filename] = "initial-200"
        with self.assertRaisesRegex(RemoteReleaseError, "did not redirect"):
            self.verify(fixture)

    def test_redirect_loop_is_bounded(self) -> None:
        fixture = MaliciousHTTPFixture(self.release.bodies)
        filename = artifact_set.DISTRIBUTION_SEAL_NAME
        fixture.faults[filename] = "redirect-loop"
        with self.assertRaisesRegex(RemoteReleaseError, "redirect limit"):
            self.verify(fixture)

    def test_symlink_precreation_is_not_followed(self) -> None:
        external = self.root / "external"
        external.write_bytes(b"do not replace")
        with SecureDownloadDirectory() as downloads:
            assert downloads.path is not None
            destination = downloads.path / artifact_set.DISTRIBUTION_SEAL_NAME
            os.symlink(external, destination)
            with self.assertRaisesRegex(RemoteReleaseError, "exclusive"):
                downloads.create(artifact_set.DISTRIBUTION_SEAL_NAME)
        self.assertEqual(external.read_bytes(), b"do not replace")

    def test_trust_root_requires_exact_allowlist_fields(self) -> None:
        document = json.loads(self.release.seal_bytes)
        document["release_assets"]["unexpected"] = {
            "filename": "unexpected",
            "sha256": "e" * 64,
            "size": 1,
        }
        data = artifact_set.canonical_json(document)
        self.release.seal_path.write_bytes(data)
        digest = hashlib.sha256(data).hexdigest()
        with self.assertRaisesRegex(RemoteReleaseError, "unexpected field set"):
            load_trust_root(self.release.seal_path, digest, VERSION)


if __name__ == "__main__":
    unittest.main()
