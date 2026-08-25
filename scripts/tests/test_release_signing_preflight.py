from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import plistlib
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from scripts import release_signing_preflight as preflight


IDENTITY = f"Developer ID Application: Release Owner ({preflight.TEAM_ID})"
CERTIFICATE = b"fixture Developer ID public certificate DER"
CERTIFICATE_SHA1 = hashlib.sha1(CERTIFICATE).hexdigest().upper()
CERTIFICATE_SHA256 = hashlib.sha256(CERTIFICATE).hexdigest().upper()
NOW = datetime(2026, 8, 25, 12, 0, tzinfo=timezone.utc)
HOST_UUID = "11111111-1111-4111-8111-111111111111"
PACKET_UUID = "22222222-2222-4222-8222-222222222222"
PROXY_UUID = "33333333-3333-4333-8333-333333333333"


def _profile(
    role: str,
    profile_uuid: str,
    *,
    certificate: bytes = CERTIFICATE,
) -> dict[str, object]:
    bundle = {
        "host": preflight.HOST_BUNDLE_ID,
        "packet-tunnel": preflight.PACKET_TUNNEL_BUNDLE_ID,
        "proxy-agent": preflight.PROXY_AGENT_BUNDLE_ID,
    }[role]
    entitlements: dict[str, object] = {
        "com.apple.application-identifier": f"{preflight.TEAM_ID}.{bundle}",
        "com.apple.developer.team-identifier": preflight.TEAM_ID,
        "com.apple.security.application-groups": [
            "group.com.bill.clashformac",
            f"{preflight.TEAM_ID}.*",
        ],
        "keychain-access-groups": [f"{preflight.TEAM_ID}.*"],
    }
    if role in {"host", "packet-tunnel"}:
        entitlements[preflight.NETWORK_EXTENSION_KEY] = sorted(
            preflight.KNOWN_DEVELOPER_ID_NETWORK_EXTENSION_AUTHORIZATIONS
        )
    if role == "host":
        entitlements[preflight.SYSTEM_EXTENSION_INSTALL_KEY] = True
    return {
        "AppIDName": f"Clash for Mac {role}",
        "ApplicationIdentifierPrefix": [preflight.TEAM_ID],
        "CreationDate": (NOW - timedelta(days=30)).replace(tzinfo=None),
        "DER-Encoded-Profile": b"fixture DER profile metadata",
        "DeveloperCertificates": [certificate],
        "Entitlements": entitlements,
        "ExpirationDate": (NOW + timedelta(days=365)).replace(tzinfo=None),
        "IsXcodeManaged": False,
        "Name": f"Clash for Mac {role} Developer ID",
        "PPQCheck": False,
        "Platform": ["OSX"],
        "ProvisionsAllDevices": True,
        "TeamIdentifier": [preflight.TEAM_ID],
        "TeamName": "Release Owner",
        "TimeToLive": 395,
        "UUID": profile_uuid,
        "Version": 1,
    }


class Fixture:
    def __init__(self, root: Path) -> None:
        root = root.resolve(strict=True)
        self.root = root
        self.repository = root / "repository"
        self.repository.mkdir(mode=0o700)
        self.home = root / "home"
        self.home.mkdir(mode=0o700)
        self.library = self.home / "Library"
        self.library.mkdir(mode=0o700)

        application_support = self.library / "Application Support"
        application_support.mkdir(mode=0o700)
        release = application_support / "Clash for Mac Release"
        release.mkdir(mode=0o700)
        self.updater_directory = release / "Updater"
        self.updater_directory.mkdir(mode=0o700)
        self.updater_key = self.home / preflight.PRIVATE_KEY_RELATIVE
        self.updater_key.write_bytes(b"fixture private key bytes must not be read")
        self.updater_key.chmod(0o600)

        self.keychains = self.library / "Keychains"
        self.keychains.mkdir(mode=0o755)
        self.login_keychain = self.home / preflight.LOGIN_KEYCHAIN_RELATIVE
        self.login_keychain.write_bytes(b"fixture keychain database")
        self.login_keychain.chmod(0o644)

        cache = self.library / "Developer/Xcode/UserData/Provisioning Profiles"
        cache.mkdir(parents=True, mode=0o700)
        self.host = root / "Host.provisionprofile"
        self.packet = cache / f"{PACKET_UUID}.provisionprofile"
        self.proxy = cache / f"{PROXY_UUID}.provisionprofile"
        for path in (self.host, self.packet, self.proxy):
            path.write_bytes(f"CMS envelope for {path.name}".encode("ascii"))
            path.chmod(0o644)

        self.profiles = {
            self.host: _profile("host", HOST_UUID),
            self.packet: _profile("packet-tunnel", PACKET_UUID),
            self.proxy: _profile("proxy-agent", PROXY_UUID),
        }
        self.environment = {
            "HOST_PROVISIONING_PROFILE_PATH": str(self.host),
            "MACOS_SIGN_IDENTITY": IDENTITY,
            "NOTARY_PROFILE": preflight.NOTARY_PROFILE,
            "PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER": PACKET_UUID,
            "PROXY_AGENT_PROVISIONING_PROFILE_SPECIFIER": PROXY_UUID,
        }

    def keychain_metadata(self) -> bytes:
        return (
            f'keychain: "{self.login_keychain}"\n'
            'class: "genp"\n'
            "attributes:\n"
            f'    "acct"<blob>="{preflight.KEYCHAIN_ACCOUNT}"\n'
            f'    "svce"<blob>="{preflight.KEYCHAIN_SERVICE}"\n'
        ).encode("utf-8")


class FakeRunner:
    def __init__(self, fixture: Fixture) -> None:
        self.fixture = fixture
        self.calls: list[tuple[list[str], dict[str, object]]] = []
        self.stderr_for: str | None = None
        self.nonzero_for: str | None = None
        self.acl_grant = False
        self.synchronizable = False
        self.notary_payload: object = {
            "history": [
                {
                    "createdDate": "2026-08-25T00:00:00.000Z",
                    "id": "00000000-0000-4000-8000-000000000000",
                    "name": "must-not-enter-the-manifest.zip",
                    "status": "Accepted",
                }
            ],
            "message": "Successfully received submission history.",
        }

    @staticmethod
    def _tag(arguments: list[str]) -> str:
        if arguments[0] == preflight.LS:
            return "acl"
        if arguments[0] == preflight.XCRUN:
            return "notary"
        if arguments[1] == "find-identity":
            return "identity"
        if arguments[1] == "find-certificate":
            return "certificate"
        if arguments[1] == "cms":
            return "cms"
        if arguments[1] == "find-generic-password":
            return "keychain"
        raise AssertionError(f"unexpected command: {arguments!r}")

    def __call__(self, arguments: list[str], **kwargs: object):
        self.calls.append((list(arguments), dict(kwargs)))
        tag = self._tag(arguments)
        returncode = 9 if self.nonzero_for == tag else 0
        stderr = b"unexpected diagnostic\n" if self.stderr_for == tag else b""
        if tag == "acl":
            acl = b" 0: group:staff allow read\n" if self.acl_grant else b""
            stdout = b"-rw------- fixture\n" + acl
        elif tag == "identity":
            stdout = (
                f'  1) {CERTIFICATE_SHA1} "{IDENTITY}"\n'
                "     1 valid identities found\n"
            ).encode("utf-8")
        elif tag == "certificate":
            stdout = (
                b"-----BEGIN CERTIFICATE-----\n"
                + base64.b64encode(CERTIFICATE)
                + b"\n-----END CERTIFICATE-----\n"
            )
        elif tag == "cms":
            path = Path(arguments[-1])
            stdout = plistlib.dumps(self.fixture.profiles[path], sort_keys=True)
        elif tag == "notary":
            stdout = json.dumps(self.notary_payload, sort_keys=True).encode("utf-8")
        else:
            stdout = self.fixture.keychain_metadata()
            if self.synchronizable:
                stdout += b'    "sync"<uint32>=1\n'
        return subprocess.CompletedProcess(arguments, returncode, stdout, stderr)


class ReleaseSigningPreflightTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.fixture = Fixture(Path(self.temporary.name))
        self.runner = FakeRunner(self.fixture)

    def run_preflight(self) -> preflight.SigningPreflightResult:
        return preflight._run_preflight_with_runtime(
            source_environment=self.fixture.environment,
            home=self.fixture.home,
            repository=self.fixture.repository,
            runner=self.runner,
            now=NOW,
        )

    def test_success_emits_canonical_nonsecret_typed_manifest(self) -> None:
        result = self.run_preflight()
        data = result.canonical_manifest()
        value = json.loads(data)

        self.assertEqual(
            set(value),
            {"document", "identity", "notary", "profiles", "teamId", "updater"},
        )
        self.assertEqual(value["document"], preflight.DOCUMENT)
        self.assertEqual(value["teamId"], preflight.TEAM_ID)
        self.assertEqual(
            value["identity"],
            {
                "certificateSha1": CERTIFICATE_SHA1,
                "certificateSha256": CERTIFICATE_SHA256,
                "name": IDENTITY,
            },
        )
        self.assertEqual(
            set(value["profiles"]), {"host", "packet-tunnel", "proxy-agent"}
        )
        self.assertEqual(
            value["notary"],
            {"historyProbe": "passed", "profile": preflight.NOTARY_PROFILE},
        )
        self.assertNotIn(b"must-not-enter-the-manifest", data)
        self.assertNotIn(b"fixture private key", data)
        self.assertTrue(data.endswith(b"\n"))
        self.assertEqual(data, preflight.canonical_manifest(value))

    def test_manifest_output_is_private_exclusive_and_durable(self) -> None:
        result = self.run_preflight()
        output = self.fixture.repository / "signing-preflight.json"

        preflight.write_preflight_manifest(output, result)

        self.assertEqual(output.read_bytes(), result.canonical_manifest())
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o600)
        with self.assertRaisesRegex(
            preflight.SigningPreflightError, "durably create"
        ):
            preflight.write_preflight_manifest(output, result)

    def _materialized_profiles(
        self, result: preflight.SigningPreflightResult
    ) -> tuple[Path, dict[str, Path]]:
        manifest = self.fixture.repository / "signing-preflight.json"
        preflight.write_preflight_manifest(manifest, result)
        sources = {
            "host": self.fixture.host,
            "packet-tunnel": self.fixture.packet,
            "proxy-agent": self.fixture.proxy,
        }
        materialized: dict[str, Path] = {}
        for role, source in sources.items():
            destination = self.fixture.repository / f"{role}.provisionprofile"
            destination.write_bytes(source.read_bytes())
            destination.chmod(0o644)
            materialized[role] = destination
        return manifest, materialized

    def test_materialized_profiles_reopen_the_exact_preflight_bytes(self) -> None:
        result = self.run_preflight()
        manifest, materialized = self._materialized_profiles(result)

        verified = preflight.verify_materialized_profiles(manifest, materialized)
        custody = preflight.verify_custody_metadata(manifest)

        self.assertEqual(set(verified), set(materialized))
        self.assertEqual(custody["notary"]["historyProbe"], "passed")
        self.assertEqual(
            preflight.signing_certificate_digests(manifest),
            (CERTIFICATE_SHA1, CERTIFICATE_SHA256),
        )
        for role, path in materialized.items():
            self.assertEqual(
                verified[role]["fileSha256"],
                hashlib.sha256(path.read_bytes()).hexdigest(),
            )

    def test_materialized_profile_drift_and_role_swap_are_rejected(self) -> None:
        result = self.run_preflight()
        manifest, materialized = self._materialized_profiles(result)
        materialized["host"].write_bytes(b"X" * materialized["host"].stat().st_size)
        with self.assertRaisesRegex(
            preflight.SigningPreflightError, "differs from preflight"
        ):
            preflight.verify_materialized_profiles(manifest, materialized)

        materialized["host"].write_bytes(self.fixture.host.read_bytes())
        materialized["host"], materialized["proxy-agent"] = (
            materialized["proxy-agent"],
            materialized["host"],
        )
        with self.assertRaisesRegex(
            preflight.SigningPreflightError, "differs from preflight"
        ):
            preflight.verify_materialized_profiles(manifest, materialized)

    def test_materialized_profile_symlink_and_manifest_drift_are_rejected(self) -> None:
        result = self.run_preflight()
        manifest, materialized = self._materialized_profiles(result)
        proxy = materialized["proxy-agent"]
        real_proxy = self.fixture.repository / "real-proxy.provisionprofile"
        proxy.rename(real_proxy)
        proxy.symlink_to(real_proxy)
        with self.assertRaises(preflight.SigningPreflightError):
            preflight.verify_materialized_profiles(manifest, materialized)

        proxy.unlink()
        real_proxy.rename(proxy)
        manifest.write_bytes(manifest.read_bytes() + b" ")
        with self.assertRaisesRegex(
            preflight.SigningPreflightError, "canonical JSON"
        ):
            preflight.verify_materialized_profiles(manifest, materialized)

    def test_custody_metadata_drift_and_forged_notary_proof_are_rejected(self) -> None:
        result = self.run_preflight()
        manifest, _materialized = self._materialized_profiles(result)
        self.fixture.updater_key.chmod(0o400)
        with self.assertRaisesRegex(
            preflight.SigningPreflightError, "custody metadata differs"
        ):
            preflight.verify_custody_metadata(manifest)

        self.fixture.updater_key.chmod(0o600)
        value = json.loads(manifest.read_bytes())
        value["notary"]["historyProbe"] = "failed"
        manifest.write_bytes(preflight.canonical_manifest(value))
        with self.assertRaisesRegex(
            preflight.SigningPreflightError, "notary proof"
        ):
            preflight.load_preflight_manifest(manifest)

    def test_commands_are_fixed_bounded_and_never_request_secrets(self) -> None:
        real_open = preflight.os.open

        def guarded_open(path: object, *args: object, **kwargs: object):
            if Path(path) == self.fixture.updater_key:
                self.fail("updater private key was opened")
            return real_open(path, *args, **kwargs)

        with mock.patch.object(preflight.os, "open", side_effect=guarded_open):
            self.run_preflight()

        commands = [call[0] for call in self.runner.calls]
        self.assertTrue(commands)
        self.assertTrue(
            all(
                command[0] in {preflight.SECURITY, preflight.XCRUN, preflight.LS}
                for command in commands
            )
        )
        flattened = [argument for command in commands for argument in command]
        self.assertNotIn("-w", flattened)
        self.assertNotIn("-g", flattened)
        self.assertNotIn(str(self.fixture.updater_key), [
            command[-1]
            for command in commands
            if command[0] == preflight.SECURITY and command[1] != "find-generic-password"
        ])
        notary = next(command for command in commands if command[0] == preflight.XCRUN)
        self.assertEqual(
            notary,
            [
                preflight.XCRUN,
                "notarytool",
                "history",
                "--keychain-profile",
                preflight.NOTARY_PROFILE,
                "--output-format",
                "json",
                "--no-progress",
            ],
        )
        for _arguments, kwargs in self.runner.calls:
            self.assertEqual(kwargs["cwd"], self.fixture.repository)
            self.assertGreater(kwargs["timeout"], 0)
            self.assertGreater(kwargs["output_limit"], 0)

    def test_proxy_and_packet_profiles_resolve_only_from_fixed_cache(self) -> None:
        self.run_preflight()
        cms_paths = [
            Path(arguments[-1])
            for arguments, _kwargs in self.runner.calls
            if arguments[:3] == [preflight.SECURITY, "cms", "-D"]
        ]
        cache = self.fixture.home / "Library/Developer/Xcode/UserData/Provisioning Profiles"
        self.assertEqual(
            cms_paths,
            [
                self.fixture.host,
                cache / f"{PACKET_UUID}.provisionprofile",
                cache / f"{PROXY_UUID}.provisionprofile",
            ],
        )

    def test_wrong_identity_team_is_rejected_before_commands(self) -> None:
        self.fixture.environment["MACOS_SIGN_IDENTITY"] = (
            "Developer ID Application: Release Owner (WRONGTEAM1)"
        )
        with self.assertRaisesRegex(preflight.SigningPreflightError, "Developer ID"):
            self.run_preflight()
        self.assertEqual(self.runner.calls, [])

    def test_any_nonzero_or_stderr_fails_closed(self) -> None:
        for tag, kind in (("identity", "nonzero"), ("cms", "stderr")):
            with self.subTest(tag=tag, kind=kind):
                runner = FakeRunner(self.fixture)
                setattr(runner, f"{kind}_for", tag)
                with self.assertRaises(preflight.SigningPreflightError):
                    preflight._run_preflight_with_runtime(
                        source_environment=self.fixture.environment,
                        home=self.fixture.home,
                        repository=self.fixture.repository,
                        runner=runner,
                        now=NOW,
                    )

    def test_strict_profile_schema_rejects_unknown_field(self) -> None:
        self.fixture.profiles[self.fixture.host]["Unexpected"] = "not allowed"
        with self.assertRaisesRegex(preflight.SigningPreflightError, "schema"):
            self.run_preflight()

    def test_expired_profile_is_rejected(self) -> None:
        self.fixture.profiles[self.fixture.packet]["ExpirationDate"] = NOW.replace(
            tzinfo=None
        )
        with self.assertRaisesRegex(preflight.SigningPreflightError, "expired"):
            self.run_preflight()

    def test_wrong_developer_certificate_is_rejected(self) -> None:
        self.fixture.profiles[self.fixture.proxy]["DeveloperCertificates"] = [
            b"different certificate"
        ]
        with self.assertRaisesRegex(
            preflight.SigningPreflightError, "selected Developer ID certificate"
        ):
            self.run_preflight()

    def test_wrong_team_bundle_or_app_group_is_rejected(self) -> None:
        mutations = {
            "team": lambda profile: profile.__setitem__(
                "TeamIdentifier", ["WRONGTEAM1"]
            ),
            "bundle": lambda profile: profile["Entitlements"].__setitem__(
                "com.apple.application-identifier",
                f"{preflight.TEAM_ID}.com.example.wrong",
            ),
            "group": lambda profile: profile["Entitlements"].__setitem__(
                "com.apple.security.application-groups", ["group.example.wrong"]
            ),
        }
        for name, mutate in mutations.items():
            with self.subTest(name=name):
                profile = _profile("host", HOST_UUID)
                mutate(profile)
                self.fixture.profiles[self.fixture.host] = profile
                with self.assertRaises(preflight.SigningPreflightError):
                    self.run_preflight()
                self.fixture.profiles[self.fixture.host] = _profile("host", HOST_UUID)

    def test_relative_profile_and_noncanonical_uuid_are_rejected(self) -> None:
        for name, value in (
            ("HOST_PROVISIONING_PROFILE_PATH", "relative.provisionprofile"),
            (
                "PACKET_TUNNEL_PROVISIONING_PROFILE_SPECIFIER",
                "22222222-2222-4222-8222-22222222222A",
            ),
        ):
            with self.subTest(name=name):
                original = self.fixture.environment[name]
                self.fixture.environment[name] = value
                with self.assertRaises(preflight.SigningPreflightError):
                    self.run_preflight()
                self.fixture.environment[name] = original

    def test_profile_symlink_and_hardlink_are_rejected(self) -> None:
        original = self.fixture.host
        target = self.fixture.root / "real-host.provisionprofile"
        target.write_bytes(b"real profile")
        original.unlink()
        original.symlink_to(target)
        with self.assertRaises(preflight.SigningPreflightError):
            self.run_preflight()

        original.unlink()
        original.write_bytes(b"host profile")
        original.chmod(0o644)
        alias = self.fixture.root / "host-alias.provisionprofile"
        os.link(original, alias)
        with self.assertRaisesRegex(preflight.SigningPreflightError, "hard link"):
            self.run_preflight()

    def test_profile_uuid_must_match_fixed_cache_name(self) -> None:
        self.fixture.profiles[self.fixture.packet]["UUID"] = HOST_UUID
        with self.assertRaisesRegex(preflight.SigningPreflightError, "cache path"):
            self.run_preflight()

    def test_notary_failure_or_malformed_response_is_rejected(self) -> None:
        self.runner.nonzero_for = "notary"
        with self.assertRaises(preflight.SigningPreflightError):
            self.run_preflight()
        self.runner.nonzero_for = None
        self.runner.notary_payload = {"history": [], "message": "wrong"}
        with self.assertRaisesRegex(preflight.SigningPreflightError, "schema"):
            self.run_preflight()

    def test_updater_key_mode_hardlink_and_acl_grant_are_rejected(self) -> None:
        self.fixture.updater_key.chmod(0o644)
        with self.assertRaisesRegex(preflight.SigningPreflightError, "mode"):
            self.run_preflight()
        self.fixture.updater_key.chmod(0o600)

        alias = self.fixture.root / "updater-key-alias"
        os.link(self.fixture.updater_key, alias)
        with self.assertRaisesRegex(preflight.SigningPreflightError, "hard link"):
            self.run_preflight()
        alias.unlink()

        self.runner.acl_grant = True
        with self.assertRaisesRegex(preflight.SigningPreflightError, "ACL grants"):
            self.run_preflight()

    def test_updater_key_symlink_is_rejected(self) -> None:
        real = self.fixture.root / "updater-real.key"
        real.write_bytes(b"real private key")
        real.chmod(0o600)
        self.fixture.updater_key.unlink()
        self.fixture.updater_key.symlink_to(real)
        with self.assertRaises(preflight.SigningPreflightError):
            self.run_preflight()

    def test_keychain_sync_metadata_and_diagnostics_are_rejected(self) -> None:
        self.runner.synchronizable = True
        with self.assertRaisesRegex(preflight.SigningPreflightError, "synchronizable"):
            self.run_preflight()
        self.runner.synchronizable = False
        self.runner.stderr_for = "keychain"
        with self.assertRaisesRegex(preflight.SigningPreflightError, "diagnostics"):
            self.run_preflight()

    def test_result_validation_does_not_copy_profiles_or_create_xcent(self) -> None:
        before = sorted(
            str(path.relative_to(self.fixture.root))
            for path in self.fixture.root.rglob("*")
        )
        self.run_preflight()
        after = sorted(
            str(path.relative_to(self.fixture.root))
            for path in self.fixture.root.rglob("*")
        )
        self.assertEqual(after, before)
        self.assertFalse(any(path.endswith(".xcent") for path in after))


if __name__ == "__main__":
    unittest.main()
