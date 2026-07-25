from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from scripts.verify_pinned_build_inputs import (
    MANIFEST_RELATIVE_PATH,
    PinnedInputError,
    verify,
)

REPO_ROOT = Path(__file__).resolve().parents[2]


def _sha(body: bytes) -> str:
    return hashlib.sha256(body).hexdigest()


# Synthetic, self-consistent patch bodies. Their real SHA-256 digests drive the
# generated manifest, env, and lock so the verifier logic can be exercised without
# needing SHA-256 preimages of the shipped design pins.
PATCH_BODIES = {
    "security": b"synthetic security dependencies patch body\n",
    "raw": b"synthetic raw packet tun patch body\n",
    "dns": b"synthetic dns failover patch body\n",
}
LEGACY_BODY = b"synthetic legacy partial digest body\n"

SECURITY_SHA = _sha(PATCH_BODIES["security"])
RAW_SHA = _sha(PATCH_BODIES["raw"])
DNS_SHA = _sha(PATCH_BODIES["dns"])
COMBINED_SHA = _sha(b"synthetic combined diff body\n")
LEGACY_SHA = _sha(LEGACY_BODY)
COMMIT = "25a600db24f7680ad9806ce5427bd0ab8afe1114"

PATCH_PATHS = {
    "security": "native/macos/patches/security.patch",
    "raw": "native/macos/patches/raw-packet.patch",
    "dns": "native/macos/patches/dns-failover.patch",
}

BUILD_LIBBOX = """\
#!/usr/bin/env bash
set -euo pipefail
echo "$GO_VERSION $GOMOBILE_VERSION $SING_BOX_VERSION $SING_BOX_COMMIT"
python3 hash_artifact.py "$out" \\
  --metadata "sourceCommit=$SING_BOX_COMMIT" \\
  --metadata "securityPatchSha256=$SING_BOX_SECURITY_PATCH_SHA256" \\
  --metadata "rawPacketPatchSha256=$SING_BOX_RAW_PACKET_PATCH_SHA256" \\
  --metadata "dnsFailoverPatchSha256=$SING_BOX_DNS_FAILOVER_PATCH_SHA256" \\
  --metadata "combinedDiffSha256=$SING_BOX_COMBINED_DIFF_SHA256"
"""
BUILD_NATIVE = '#!/usr/bin/env bash\necho "--metadata singBoxCommit=$SING_BOX_COMMIT"\n'
BUILD_TAGS = "with_quic,with_clash_api,grpcnotrace"
CONTROLLER_RELATIVE_PATH = "crates/cfw-singbox-config/src/controller.rs"
CONTROLLER_TRIGGER = '"clash_api": {'
CONTROLLER_SOURCE = (
    "fn experimental_value(&self) -> Value {\n"
    "    json!({\n"
    f"        {CONTROLLER_TRIGGER}\n"
    '            "external_controller": self.external_controller(),\n'
    "    })\n"
    "}\n"
)
BUILD_UNSIGNED = (
    "#!/usr/bin/env bash\n"
    'echo "sourceCommit=$SING_BOX_COMMIT"\n'
    'echo "combinedDiffSha256=$SING_BOX_COMBINED_DIFF_SHA256"\n'
)


class Fixture:
    """A self-consistent, mutable pinned-input repository fixture."""

    def __init__(self) -> None:
        self.env: dict[str, str] = {
            "RUST_VERSION": "1.97.1",
            "NODE_VERSION": "24.18.0",
            "GO_VERSION": "1.26.5",
            "GOMOBILE_VERSION": "v0.1.12",
            "GOMOBILE_MODULE_SUM": "h1:XwzjZaclFF96deLqwAgK8gU3w0M2A8qxgDmhV+A0wjg=",
            "GOVULNCHECK_VERSION": "v1.6.0",
            "GOVULNCHECK_MODULE_SUM": "h1:FeMO9Rm/HwyduOztbvKcOw+zvDEPr4I4aQNSfevFcKY=",
            "SING_BOX_VERSION": "v1.13.14",
            "SING_BOX_COMMIT": COMMIT,
            "SING_BOX_UPSTREAM_GO_MOD_SHA256": _sha(b"upstream go.mod"),
            "SING_BOX_UPSTREAM_GO_SUM_SHA256": _sha(b"upstream go.sum"),
            "SING_BOX_SECURITY_PATCH_PATH": PATCH_PATHS["security"],
            "SING_BOX_SECURITY_PATCH_SHA256": SECURITY_SHA,
            "SING_BOX_RAW_PACKET_PATCH_PATH": PATCH_PATHS["raw"],
            "SING_BOX_RAW_PACKET_PATCH_SHA256": RAW_SHA,
            "SING_BOX_DNS_FAILOVER_PATCH_PATH": PATCH_PATHS["dns"],
            "SING_BOX_DNS_FAILOVER_PATCH_SHA256": DNS_SHA,
            "SING_BOX_PATCHED_DIFF_SHA256": SECURITY_SHA,
            "SING_BOX_COMBINED_DIFF_SHA256": COMBINED_SHA,
            "SING_BOX_PATCHED_GO_MOD_SHA256": _sha(b"patched go.mod"),
            "SING_BOX_PATCHED_GO_SUM_SHA256": _sha(b"patched go.sum"),
            "LIBBOX_BUILD_TAGS": BUILD_TAGS,
        }
        self.patch_bodies = dict(PATCH_BODIES)
        self.controller_source = CONTROLLER_SOURCE
        self.manifest = {
            "schema": "cfw-pinned-build-inputs-v1",
            "dependencyPinsPath": "scripts/dependency_pins.env",
            "nativeLockPath": "native/macos/Dependencies.lock.json",
            "tools": {
                "RUST_VERSION": "1.97.1",
                "NODE_VERSION": "24.18.0",
                "GO_VERSION": "1.26.5",
                "GOMOBILE_VERSION": "v0.1.12",
                "GOVULNCHECK_VERSION": "v1.6.0",
                "SING_BOX_VERSION": "v1.13.14",
            },
            "singBoxCommitKey": "SING_BOX_COMMIT",
            "singBoxCommit": COMMIT,
            "patches": [
                {
                    "name": "security",
                    "pathKey": "SING_BOX_SECURITY_PATCH_PATH",
                    "sha256Key": "SING_BOX_SECURITY_PATCH_SHA256",
                    "sha256": SECURITY_SHA,
                },
                {
                    "name": "raw packet",
                    "pathKey": "SING_BOX_RAW_PACKET_PATCH_PATH",
                    "sha256Key": "SING_BOX_RAW_PACKET_PATCH_SHA256",
                    "sha256": RAW_SHA,
                },
                {
                    "name": "DNS failover",
                    "pathKey": "SING_BOX_DNS_FAILOVER_PATCH_PATH",
                    "sha256Key": "SING_BOX_DNS_FAILOVER_PATCH_SHA256",
                    "sha256": DNS_SHA,
                },
            ],
            "combinedDiffSha256Key": "SING_BOX_COMBINED_DIFF_SHA256",
            "combinedDiffSha256": COMBINED_SHA,
            "verifiedGoModuleInputKeys": [
                "GOMOBILE_MODULE_SUM",
                "GOVULNCHECK_MODULE_SUM",
                "SING_BOX_UPSTREAM_GO_MOD_SHA256",
                "SING_BOX_UPSTREAM_GO_SUM_SHA256",
                "SING_BOX_PATCHED_GO_MOD_SHA256",
                "SING_BOX_PATCHED_GO_SUM_SHA256",
            ],
            "rejectedPatchDigests": [LEGACY_SHA],
            "libboxBuildTags": {
                "pinKey": "LIBBOX_BUILD_TAGS",
                "value": BUILD_TAGS,
                "required": [
                    {"tag": "with_quic", "reason": "QUIC outbounds"},
                    {"tag": "with_clash_api", "reason": "engine start path needs the server"},
                    {"tag": "grpcnotrace", "reason": "no gRPC trace surface"},
                ],
                "engineStartPathBindings": [
                    {
                        "tag": "with_clash_api",
                        "path": CONTROLLER_RELATIVE_PATH,
                        "requiredWhenContains": CONTROLLER_TRIGGER,
                        "triggerRequired": True,
                        "reason": "the projected controller block needs the real server",
                    }
                ],
            },
            "buildScripts": {
                "scripts/build_libbox.sh": {
                    "requirePinReferences": [
                        "$GO_VERSION",
                        "$GOMOBILE_VERSION",
                        "$SING_BOX_VERSION",
                        "$SING_BOX_COMMIT",
                        "$SING_BOX_COMBINED_DIFF_SHA256",
                        "$SING_BOX_SECURITY_PATCH_SHA256",
                        "$SING_BOX_RAW_PACKET_PATCH_SHA256",
                        "$SING_BOX_DNS_FAILOVER_PATCH_SHA256",
                    ],
                    "forbidNetworkRecursion": True,
                }
            },
            "artifactBindings": {
                "scripts/build_libbox.sh": [
                    "sourceCommit=$SING_BOX_COMMIT",
                    "combinedDiffSha256=$SING_BOX_COMBINED_DIFF_SHA256",
                ],
                "scripts/build_native_products.sh": ["singBoxCommit=$SING_BOX_COMMIT"],
                "scripts/build_unsigned_candidate.sh": [
                    "sourceCommit=$SING_BOX_COMMIT",
                    "combinedDiffSha256=$SING_BOX_COMBINED_DIFF_SHA256",
                ],
            },
        }
        self.lock = {
            "go": "1.26.5",
            "gomobile": "v0.1.12",
            "singBox": {
                "commit": COMMIT,
                "tag": "v1.13.14",
                "securityPatch": {"path": PATCH_PATHS["security"], "sha256": SECURITY_SHA},
                "rawPacketPatch": {"path": PATCH_PATHS["raw"], "sha256": RAW_SHA},
                "dnsFailoverPatch": {"path": PATCH_PATHS["dns"], "sha256": DNS_SHA},
                "combinedDiffSha256": COMBINED_SHA,
            },
        }
        self.build_libbox = BUILD_LIBBOX
        self.build_native = BUILD_NATIVE
        self.build_unsigned = BUILD_UNSIGNED
        self._extra_env_text = ""

    def env_text(self) -> str:
        lines = ["# generated test pins"]
        lines += [f"{key}={value}" for key, value in self.env.items()]
        return "\n".join(lines) + "\n" + self._extra_env_text

    def append_env_text(self, text: str) -> None:
        self._extra_env_text += text

    def write(self, root: Path) -> Path:
        (root / "scripts").mkdir(parents=True, exist_ok=True)
        (root / "native/macos/patches").mkdir(parents=True, exist_ok=True)
        controller = root / CONTROLLER_RELATIVE_PATH
        controller.parent.mkdir(parents=True, exist_ok=True)
        controller.write_text(self.controller_source, encoding="utf-8")
        (root / MANIFEST_RELATIVE_PATH).write_text(json.dumps(self.manifest), encoding="utf-8")
        (root / "scripts/dependency_pins.env").write_text(self.env_text(), encoding="utf-8")
        for key, body in self.patch_bodies.items():
            (root / PATCH_PATHS[key]).write_bytes(body)
        (root / "native/macos/Dependencies.lock.json").write_text(
            json.dumps(self.lock), encoding="utf-8"
        )
        (root / "scripts/build_libbox.sh").write_text(self.build_libbox, encoding="utf-8")
        (root / "scripts/build_native_products.sh").write_text(self.build_native, encoding="utf-8")
        (root / "scripts/build_unsigned_candidate.sh").write_text(
            self.build_unsigned, encoding="utf-8"
        )
        return root


class PinnedBuildInputsTests(unittest.TestCase):
    def _verify_fixture(self, fixture: Fixture) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            verify(fixture.write(Path(temporary)))

    def _assert_fails(self, fixture: Fixture, pattern: str) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = fixture.write(Path(temporary))
            with self.assertRaisesRegex(PinnedInputError, pattern):
                verify(root)

    # --- success ------------------------------------------------------------

    def test_correct_pins_pass(self) -> None:
        self._verify_fixture(Fixture())

    def test_real_repository_passes(self) -> None:
        # Binds the shipped manifest, dependency_pins.env, patch files, native lock,
        # and offline build scripts together.
        verify(REPO_ROOT)

    # --- wrong / missing pins -----------------------------------------------

    def test_wrong_tool_version_fails(self) -> None:
        fixture = Fixture()
        fixture.env["GO_VERSION"] = "1.26.4"
        self._assert_fails(fixture, "GO_VERSION")

    def test_missing_pin_fails(self) -> None:
        fixture = Fixture()
        del fixture.env["GOVULNCHECK_VERSION"]
        self._assert_fails(fixture, "GOVULNCHECK_VERSION")

    def test_wrong_commit_fails(self) -> None:
        fixture = Fixture()
        fixture.env["SING_BOX_COMMIT"] = "0" * 40
        self._assert_fails(fixture, "commit")

    def test_missing_go_module_input_fails(self) -> None:
        fixture = Fixture()
        del fixture.env["GOMOBILE_MODULE_SUM"]
        self._assert_fails(fixture, "GOMOBILE_MODULE_SUM")

    # --- patch digest failures ----------------------------------------------

    def test_wrong_patch_env_digest_fails(self) -> None:
        fixture = Fixture()
        fixture.env["SING_BOX_DNS_FAILOVER_PATCH_SHA256"] = "a" * 64
        self._assert_fails(fixture, "DNS failover")

    def test_patch_file_content_drift_fails(self) -> None:
        fixture = Fixture()
        fixture.patch_bodies["security"] = b"tampered body\n"
        self._assert_fails(fixture, "file digest")

    def test_missing_patch_file_fails_closed(self) -> None:
        fixture = Fixture()
        del fixture.patch_bodies["raw"]
        self._assert_fails(fixture, "missing or not regular")

    def test_legacy_partial_digest_rejected(self) -> None:
        # Point the raw-packet patch entirely at the rejected legacy digest.
        fixture = Fixture()
        fixture.patch_bodies["raw"] = LEGACY_BODY
        fixture.env["SING_BOX_RAW_PACKET_PATCH_SHA256"] = LEGACY_SHA
        fixture.manifest["patches"][1]["sha256"] = LEGACY_SHA
        fixture.lock["singBox"]["rawPacketPatch"]["sha256"] = LEGACY_SHA
        self._assert_fails(fixture, "rejected/legacy digest")

    def test_combined_diff_equal_to_patch_rejected(self) -> None:
        fixture = Fixture()
        fixture.env["SING_BOX_COMBINED_DIFF_SHA256"] = SECURITY_SHA
        fixture.manifest["combinedDiffSha256"] = SECURITY_SHA
        fixture.lock["singBox"]["combinedDiffSha256"] = SECURITY_SHA
        self._assert_fails(fixture, "partial")

    # --- libbox build tags --------------------------------------------------

    def test_missing_engine_start_path_tag_fails(self) -> None:
        # The exact defect this check exists for: dropping with_clash_api while the
        # projection still injects experimental.clash_api, which makes box.New fail
        # on every engine start.
        fixture = Fixture()
        reduced = "with_quic,grpcnotrace"
        fixture.env["LIBBOX_BUILD_TAGS"] = reduced
        fixture.manifest["libboxBuildTags"]["value"] = reduced
        self._assert_fails(fixture, "required tag 'with_clash_api'")

    def test_tag_list_drift_from_manifest_fails(self) -> None:
        fixture = Fixture()
        fixture.env["LIBBOX_BUILD_TAGS"] = "with_quic,grpcnotrace"
        self._assert_fails(fixture, "pinned libbox build tags LIBBOX_BUILD_TAGS")

    def test_missing_tag_pin_fails_closed(self) -> None:
        fixture = Fixture()
        del fixture.env["LIBBOX_BUILD_TAGS"]
        self._assert_fails(fixture, "LIBBOX_BUILD_TAGS")

    def test_malformed_tag_fails(self) -> None:
        fixture = Fixture()
        malformed = "with_quic, with_clash_api,grpcnotrace"
        fixture.env["LIBBOX_BUILD_TAGS"] = malformed
        fixture.manifest["libboxBuildTags"]["value"] = malformed
        self._assert_fails(fixture, "malformed")

    def test_repeated_tag_fails(self) -> None:
        fixture = Fixture()
        repeated = "with_quic,with_clash_api,grpcnotrace,with_quic"
        fixture.env["LIBBOX_BUILD_TAGS"] = repeated
        fixture.manifest["libboxBuildTags"]["value"] = repeated
        self._assert_fails(fixture, "repeat")

    def test_source_binding_without_required_tag_fails(self) -> None:
        # A source trigger may not be satisfied by the required-tag table alone:
        # removing the tag from both the pin and the required table still fails
        # because the tracked source still needs it.
        fixture = Fixture()
        reduced = "with_quic,grpcnotrace"
        fixture.env["LIBBOX_BUILD_TAGS"] = reduced
        fixture.manifest["libboxBuildTags"]["value"] = reduced
        fixture.manifest["libboxBuildTags"]["required"] = [
            entry
            for entry in fixture.manifest["libboxBuildTags"]["required"]
            if entry["tag"] != "with_clash_api"
        ]
        self._assert_fails(fixture, "requires libbox build tag 'with_clash_api'")

    def test_vanished_source_trigger_fails(self) -> None:
        fixture = Fixture()
        fixture.controller_source = "fn experimental_value() {}\n"
        self._assert_fails(fixture, "no longer contains the pinned tag trigger")

    def test_missing_tag_binding_section_fails_closed(self) -> None:
        fixture = Fixture()
        del fixture.manifest["libboxBuildTags"]
        self._assert_fails(fixture, "no libbox build tag binding")

    def test_required_tag_without_reason_fails(self) -> None:
        fixture = Fixture()
        del fixture.manifest["libboxBuildTags"]["required"][1]["reason"]
        self._assert_fails(fixture, "no recorded reason")

    # --- malformed / unavailable inputs -------------------------------------

    def test_malformed_env_line_fails(self) -> None:
        fixture = Fixture()
        fixture.append_env_text("this is not a valid pin line\n")
        self._assert_fails(fixture, "malformed")

    def test_missing_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            (root / MANIFEST_RELATIVE_PATH).unlink()
            with self.assertRaisesRegex(PinnedInputError, "manifest is missing"):
                verify(root)

    def test_malformed_manifest_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Fixture().write(Path(temporary))
            (root / MANIFEST_RELATIVE_PATH).write_text("{not json", encoding="utf-8")
            with self.assertRaisesRegex(PinnedInputError, "malformed"):
                verify(root)

    # --- native lock and build-script bindings ------------------------------

    def test_native_lock_mismatch_fails(self) -> None:
        fixture = Fixture()
        fixture.lock["singBox"]["rawPacketPatch"]["sha256"] = "b" * 64
        self._assert_fails(fixture, "rawPacketPatch")

    def test_build_script_missing_pin_reference_fails(self) -> None:
        fixture = Fixture()
        fixture.build_libbox = fixture.build_libbox.replace("$SING_BOX_COMMIT", "25a600db")
        self._assert_fails(fixture, "floating version|artifact-hash")

    def test_build_script_network_action_fails(self) -> None:
        fixture = Fixture()
        fixture.build_libbox += "git clone https://example.com/sing-box\n"
        self._assert_fails(fixture, "network or recursive")

    def test_missing_artifact_binding_fails(self) -> None:
        fixture = Fixture()
        fixture.build_native = '#!/usr/bin/env bash\necho "no binding"\n'
        self._assert_fails(fixture, "artifact-hash binding")


if __name__ == "__main__":
    unittest.main()
