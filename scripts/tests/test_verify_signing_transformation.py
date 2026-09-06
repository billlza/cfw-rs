from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import plistlib
import shutil
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from scripts.candidate_freeze import FrozenCandidate
from scripts.hash_artifact import build_manifest
from scripts.publication import durable_file
from scripts.publication.common import PublicationError
from scripts import verify_signing_transformation as transformation


ADHOC_SIGNATURE_SIZE = 0x1000
DEVELOPER_ID_SIGNATURE_SIZE = 0x5000
FIXTURE_LINKEDIT_FILEOFF = 0x4000
FIXTURE_SIGNATURE_DATAOFF = 0x4400


def fixture_signed_macho(
    signature_size: int,
    signature_byte: bytes,
    *,
    linkedit_count: int = 1,
    code_signature_count: int = 1,
) -> bytes:
    if (
        signature_size < 16
        or signature_size % 16
        or len(signature_byte) != 1
        or linkedit_count not in {0, 1, 2}
        or code_signature_count not in {0, 1, 2}
    ):
        raise ValueError("fixture signature contract is invalid")
    file_size = FIXTURE_SIGNATURE_DATAOFF + signature_size
    linkedit_filesize = file_size - FIXTURE_LINKEDIT_FILEOFF
    linkedit_vmsize = transformation._align_up(
        linkedit_filesize, transformation.ARM64_SEGMENT_ALIGNMENT
    )
    segment = struct.pack(
        "<II16sQQQQIIII",
        transformation.LC_SEGMENT_64,
        transformation.SEGMENT_COMMAND_64_SIZE,
        transformation.LINKEDIT_SEGMENT_NAME,
        0x100004000,
        linkedit_vmsize,
        FIXTURE_LINKEDIT_FILEOFF,
        linkedit_filesize,
        7,
        5,
        0,
        0,
    )
    signature = struct.pack(
        "<IIII",
        transformation.LC_CODE_SIGNATURE,
        transformation.LINKEDIT_DATA_COMMAND_SIZE,
        FIXTURE_SIGNATURE_DATAOFF,
        signature_size,
    )
    commands = segment * linkedit_count + signature * code_signature_count
    header = struct.pack(
        "<8I",
        transformation.MH_MAGIC_64,
        transformation.CPU_TYPE_ARM64,
        0,
        transformation.MH_EXECUTE,
        linkedit_count + code_signature_count,
        len(commands),
        0,
        0,
    )
    prefix = header + commands
    if len(prefix) > FIXTURE_LINKEDIT_FILEOFF:
        raise AssertionError("fixture Mach-O load commands escaped __LINKEDIT")
    return (
        prefix
        + (b"\0" * (FIXTURE_LINKEDIT_FILEOFF - len(prefix)))
        + (b"L" * (FIXTURE_SIGNATURE_DATAOFF - FIXTURE_LINKEDIT_FILEOFF))
        + (signature_byte * signature_size)
    )


def remove_fixture_signature(data: bytes, *, alignment_padding: int = 0) -> bytes:
    layout = transformation._parse_macho(data, "fixture signed Mach-O")
    command_offset = layout.code_signature_command_offset
    dataoff = layout.code_signature_dataoff
    if command_offset is None or dataoff is None:
        raise AssertionError("fixture signed Mach-O has no signature command")
    if alignment_padding < 0 or alignment_padding >= 16:
        raise ValueError("fixture signature alignment padding is invalid")
    result = bytearray(data[: dataoff - alignment_padding])
    struct.pack_into("<I", result, 16, layout.ncmds - 1)
    struct.pack_into(
        "<I",
        result,
        20,
        layout.sizeofcmds - transformation.LINKEDIT_DATA_COMMAND_SIZE,
    )
    result[
        command_offset : command_offset + transformation.LINKEDIT_DATA_COMMAND_SIZE
    ] = b"\0" * transformation.LINKEDIT_DATA_COMMAND_SIZE
    struct.pack_into(
        "<Q",
        result,
        layout.linkedit_command_offset + 48,
        len(result) - layout.linkedit_fileoff,
    )
    return bytes(result)


class SigningTransformationFixture:
    def __init__(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.repository = Path(self.temporary.name).resolve()
        self.root = (
            self.repository / "target/candidates/0.4.0/ga/40044"
        )
        self.pre_sign_app = self.root / transformation.PRE_SIGN_APP_RELATIVE
        self.signing_output = (
            self.root / "transactions/signing-attempts/00000001/work"
        )
        self.signing_output.mkdir(parents=True, mode=0o700)
        for private in (
            self.signing_output.parent.parent.parent,
            self.signing_output.parent.parent,
            self.signing_output.parent,
            self.signing_output,
        ):
            private.chmod(0o700)
        self.signed_app = (
            self.signing_output / transformation.SIGNED_APP_WITHIN_OUTPUT
        )
        self.intent_path = self.root / "candidate-freeze/intent.json"
        self.calls: list[tuple[str, ...]] = []
        self._create_profiles()
        self._create_app(self.pre_sign_app)
        self._sign_fixture_app(ADHOC_SIGNATURE_SIZE, b"A", "adhoc")
        self._write_pre_sign_manifest()
        shutil.copytree(self.pre_sign_app, self.signed_app, symlinks=True)
        self._sign_fixture_app(
            DEVELOPER_ID_SIGNATURE_SIZE, b"D", "developer-id"
        )
        self._embed_profiles()
        self._write_intent()

    def cleanup(self) -> None:
        self.temporary.cleanup()

    def _create_profiles(self) -> None:
        profiles = self.root / "profiles"
        profiles.mkdir(parents=True)
        for role, (relative, _embedded) in transformation.PROFILE_BINDINGS.items():
            path = self.root / relative
            path.write_bytes(f"{role}-profile\n".encode("ascii"))
            path.chmod(0o644)

    def _create_app(self, app: Path) -> None:
        (app / "Contents/Resources").mkdir(parents=True)
        (app / "Contents/Resources/config.json").write_bytes(b'{"fixed":true}\n')
        for relative in transformation.CODE_OBJECTS:
            path = app if relative == "." else app.joinpath(*Path(relative).parts)
            if relative in transformation.DIRECTORY_CODE_OBJECTS:
                path.mkdir(parents=True, exist_ok=True)
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
        for relative in transformation.MACHO_EXECUTABLES:
            executable = app.joinpath(*Path(relative).parts)
            executable.parent.mkdir(parents=True, exist_ok=True)
            executable.write_bytes(fixture_signed_macho(ADHOC_SIGNATURE_SIZE, b"A"))
            executable.chmod(0o755)

    def _write_pre_sign_manifest(self) -> None:
        metadata = {
            "artifactKind": "pre-sign-application-v1",
            "buildNumber": "40044",
            "version": "0.4.0",
        }
        value = build_manifest(
            self.pre_sign_app,
            metadata=metadata,
            algorithm="sha256-tree-v1",
        )
        path = self.root / transformation.PRE_SIGN_MANIFEST_RELATIVE
        path.write_text(
            json.dumps(value, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        path.chmod(0o600)

    def _sign_fixture_app(
        self, signature_size: int, signature_byte: bytes, label: str
    ) -> None:
        app = self.pre_sign_app if label == "adhoc" else self.signed_app
        for code_relative, executable_relative in zip(
            transformation.CODE_OBJECTS,
            transformation.MACHO_EXECUTABLES,
            strict=True,
        ):
            executable = app.joinpath(*Path(executable_relative).parts)
            executable.write_bytes(
                fixture_signed_macho(signature_size, signature_byte)
            )
            if code_relative in transformation.DIRECTORY_CODE_OBJECTS and label == "developer-id":
                signature = app.joinpath(
                    *Path(
                        transformation.SIGNATURE_DIRECTORY_BY_CODE_OBJECT[
                            code_relative
                        ]
                    ).parts
                )
                signature.mkdir(exist_ok=True)
                (signature / "CodeResources").write_bytes(
                    f"{label}:{code_relative}\n".encode("ascii")
                )

    def _embed_profiles(self) -> None:
        for source_relative, embedded_relative in transformation.PROFILE_BINDINGS.values():
            source = self.root / source_relative
            embedded = self.signed_app.joinpath(*Path(embedded_relative).parts)
            embedded.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, embedded)

    def _write_intent(self) -> None:
        value = {
            "build_number": "40044",
            "consumption_state": "candidate_frozen_consumed",
            "document": "cfm-candidate-freeze-intent-v3",
            "pre_sign_app_tree_sha256": "a" * 64,
            "product_version": "0.4.0",
            "schema_version": 3,
        }
        self.intent_path.parent.mkdir(mode=0o700)
        self.intent_path.write_bytes(transformation.canonical_json(value))
        self.intent_path.chmod(0o600)

    def freeze_verifier(self, repository: Path) -> FrozenCandidate:
        if repository != self.repository:
            raise AssertionError(f"unexpected repository: {repository}")
        return FrozenCandidate(
            root=self.root,
            intent_path=self.intent_path,
            intent_sha256=hashlib.sha256(self.intent_path.read_bytes()).hexdigest(),
            product_version="0.4.0",
            build_number="40044",
            recovered=False,
        )

    def codesign_runner(self, command: tuple[str, ...], repository: Path) -> None:
        if repository != self.repository:
            raise AssertionError(f"unexpected repository: {repository}")
        if command[:2] != ("/usr/bin/codesign", "--remove-signature"):
            raise AssertionError(f"unexpected command: {command}")
        path = Path(command[2])
        self.calls.append(command)
        app = path if path.name == "Clash for Mac.app" else next(
            parent for parent in path.parents if parent.name == "Clash for Mac.app"
        )
        relative = "." if path == app else path.relative_to(app).as_posix()
        index = transformation.CODE_OBJECTS.index(relative)
        executable = app.joinpath(*Path(transformation.MACHO_EXECUTABLES[index]).parts)
        executable.write_bytes(remove_fixture_signature(executable.read_bytes()))
        signature = path / "_CodeSignature" if path.is_dir() else None
        if signature is not None and signature.exists():
            shutil.rmtree(signature)

    def create(self) -> dict[str, object]:
        return transformation.create_attempt_receipt(
            self.repository,
            self.signing_output,
            codesign_runner=self.codesign_runner,
            freeze_verifier=self.freeze_verifier,
        )

    def verify(self) -> dict[str, object]:
        return transformation.verify_attempt_receipt(
            self.repository,
            self.signing_output,
            codesign_runner=self.codesign_runner,
            freeze_verifier=self.freeze_verifier,
        )

    def retain_published_signed_input(self) -> dict[str, object]:
        receipt = self.create()
        canonical = self.root / transformation.SIGNING_OUTPUT_RELATIVE
        self.signing_output.rename(canonical)
        self.signing_output = canonical
        retained = self.root / "transactions/app-notary/recovery-source"
        retained.parent.mkdir(mode=0o700)
        (canonical / transformation.SIGNED_APP_WITHIN_OUTPUT.parent).rename(retained)
        self.signed_app = retained / transformation.SIGNED_APP_WITHIN_OUTPUT.name
        return receipt


class MachONormalizationTests(unittest.TestCase):
    def test_signature_capacity_is_the_only_normalized_load_command_field(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            pre = root / "pre-sign"
            signed = root / "developer-id"
            pre.write_bytes(fixture_signed_macho(ADHOC_SIGNATURE_SIZE, b"A"))
            signed.write_bytes(
                fixture_signed_macho(DEVELOPER_ID_SIGNATURE_SIZE, b"D")
            )
            pre.chmod(0o755)
            signed.chmod(0o755)
            pre_layout = transformation._inspect_signed_macho(pre, "pre-sign fixture")
            signed_layout = transformation._inspect_signed_macho(
                signed, "Developer ID fixture"
            )
            self.assertNotEqual(
                pre_layout.linkedit_vmsize, signed_layout.linkedit_vmsize
            )

            pre.write_bytes(remove_fixture_signature(pre.read_bytes()))
            signed.write_bytes(remove_fixture_signature(signed.read_bytes()))
            transformation._normalize_removed_signature_macho(
                pre, "pre-sign fixture", pre_layout
            )
            transformation._normalize_removed_signature_macho(
                signed, "Developer ID fixture", signed_layout
            )
            self.assertEqual(pre.read_bytes(), signed.read_bytes())

    def test_malformed_signed_macho_variants_fail_closed(self) -> None:
        valid = fixture_signed_macho(ADHOC_SIGNATURE_SIZE, b"A")

        def patch_u32(data: bytes, offset: int, value: int) -> bytes:
            mutated = bytearray(data)
            struct.pack_into("<I", mutated, offset, value)
            return bytes(mutated)

        def patch_u64(data: bytes, offset: int, value: int) -> bytes:
            mutated = bytearray(data)
            struct.pack_into("<Q", mutated, offset, value)
            return bytes(mutated)

        signature_command = (
            transformation.MACH_HEADER_64_SIZE
            + transformation.SEGMENT_COMMAND_64_SIZE
        )
        cases = {
            "truncated-header": valid[:20],
            "fat-magic": patch_u32(valid, 0, 0xCAFEBABE),
            "wrong-cpu": patch_u32(valid, 4, 0x01000007),
            "load-command-out-of-bounds": patch_u32(
                valid, transformation.MACH_HEADER_64_SIZE + 4, 0xFFFFFFF8
            ),
            "missing-linkedit": fixture_signed_macho(
                ADHOC_SIGNATURE_SIZE, b"A", linkedit_count=0
            ),
            "duplicate-linkedit": fixture_signed_macho(
                ADHOC_SIGNATURE_SIZE, b"A", linkedit_count=2
            ),
            "missing-signature": fixture_signed_macho(
                ADHOC_SIGNATURE_SIZE, b"A", code_signature_count=0
            ),
            "duplicate-signature": fixture_signed_macho(
                ADHOC_SIGNATURE_SIZE, b"A", code_signature_count=2
            ),
            "bad-signature-dataoff": patch_u32(
                valid,
                signature_command + 8,
                FIXTURE_SIGNATURE_DATAOFF - 16,
            ),
            "bad-linkedit-vmsize": patch_u64(
                valid,
                transformation.MACH_HEADER_64_SIZE + 32,
                0x1234,
            ),
            "trailing-bytes": valid + b"unexpected-tail",
        }
        for name, data in cases.items():
            with self.subTest(name=name), self.assertRaises(
                transformation.SigningTransformationError
            ):
                transformation._validate_signed_macho(data, name)

    def test_removed_signature_cannot_hide_other_load_command_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "tampered"
            path.write_bytes(
                fixture_signed_macho(DEVELOPER_ID_SIGNATURE_SIZE, b"D")
            )
            path.chmod(0o755)
            signed = transformation._inspect_signed_macho(path, "signed fixture")
            removed = bytearray(remove_fixture_signature(path.read_bytes()))
            struct.pack_into(
                "<Q",
                removed,
                signed.linkedit_command_offset + 24,
                signed.linkedit_vmaddr + transformation.ARM64_SEGMENT_ALIGNMENT,
            )
            path.write_bytes(removed)
            with self.assertRaisesRegex(
                transformation.SigningTransformationError,
                "outside the removable Mach-O signature envelope",
            ):
                transformation._normalize_removed_signature_macho(
                    path, "signed fixture", signed
                )

    def test_only_zero_signature_alignment_padding_may_be_trimmed(self) -> None:
        for padding_byte, accepted in ((b"\0", True), (b"P", False)):
            with self.subTest(accepted=accepted), tempfile.TemporaryDirectory() as temporary:
                path = Path(temporary) / "padding-fixture"
                data = bytearray(
                    fixture_signed_macho(DEVELOPER_ID_SIGNATURE_SIZE, b"D")
                )
                data[
                    FIXTURE_SIGNATURE_DATAOFF - 8 : FIXTURE_SIGNATURE_DATAOFF
                ] = padding_byte * 8
                path.write_bytes(data)
                path.chmod(0o755)
                signed = transformation._inspect_signed_macho(
                    path, "padding fixture"
                )
                path.write_bytes(
                    remove_fixture_signature(path.read_bytes(), alignment_padding=8)
                )
                if accepted:
                    transformation._normalize_removed_signature_macho(
                        path, "padding fixture", signed
                    )
                else:
                    with self.assertRaisesRegex(
                        transformation.SigningTransformationError,
                        "outside the removable Mach-O signature envelope",
                    ):
                        transformation._normalize_removed_signature_macho(
                            path, "padding fixture", signed
                        )

    def test_real_codesign_signature_capacity_normalizes_on_darwin(self) -> None:
        self.assertEqual(sys.platform, "darwin")
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "main.c"
            base = root / "base"
            pre = root / "pre-sign"
            signed = root / "developer-id"
            source.write_text("int main(void) { return 0; }\n", encoding="utf-8")
            clang = subprocess.run(
                ("/usr/bin/xcrun", "--find", "clang"),
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout.strip()
            sdk = subprocess.run(
                ("/usr/bin/xcrun", "--sdk", "macosx", "--show-sdk-path"),
                cwd=root,
                check=True,
                capture_output=True,
                text=True,
                timeout=30,
            ).stdout.strip()
            compiled = subprocess.run(
                (
                    clang,
                    "-arch",
                    "arm64",
                    "-isysroot",
                    sdk,
                    "-mmacosx-version-min=15.0",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    str(source),
                    "-o",
                    str(base),
                ),
                cwd=root,
                capture_output=True,
                timeout=60,
            )
            self.assertEqual(
                compiled.returncode,
                0,
                compiled.stderr.decode("utf-8", errors="replace"),
            )
            shutil.copy2(base, pre)
            shutil.copy2(base, signed)
            small_entitlements = root / "small.plist"
            large_entitlements = root / "large.plist"
            with small_entitlements.open("wb") as handle:
                plistlib.dump({"com.bill.cfw.fixture": "small"}, handle)
            with large_entitlements.open("wb") as handle:
                plistlib.dump({"com.bill.cfw.fixture": "L" * (128 * 1024)}, handle)
            for executable, entitlements in (
                (pre, small_entitlements),
                (signed, large_entitlements),
            ):
                signed_result = subprocess.run(
                    (
                        "/usr/bin/codesign",
                        "--force",
                        "--sign",
                        "-",
                        "--timestamp=none",
                        "--identifier",
                        "com.bill.cfw.fixture",
                        "--entitlements",
                        str(entitlements),
                        str(executable),
                    ),
                    cwd=root,
                    capture_output=True,
                    timeout=60,
                )
                self.assertEqual(
                    signed_result.returncode,
                    0,
                    signed_result.stderr.decode("utf-8", errors="replace"),
                )
            pre_layout = transformation._inspect_signed_macho(pre, "real pre-sign")
            signed_layout = transformation._inspect_signed_macho(
                signed, "real alternate signature"
            )
            self.assertNotEqual(
                pre_layout.linkedit_vmsize, signed_layout.linkedit_vmsize
            )
            for executable, layout, label in (
                (pre, pre_layout, "real pre-sign"),
                (signed, signed_layout, "real alternate signature"),
            ):
                transformation.production_codesign_runner(
                    ("/usr/bin/codesign", "--remove-signature", str(executable)),
                    root,
                )
                transformation._normalize_removed_signature_macho(
                    executable, label, layout
                )
            self.assertEqual(pre.read_bytes(), signed.read_bytes())


class SigningTransformationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fixture = SigningTransformationFixture()
        self.addCleanup(self.fixture.cleanup)
        durability = patch.object(durable_file, "full_fsync", side_effect=os.fsync)
        durability.start()
        self.addCleanup(durability.stop)

    def test_retained_notary_input_recomputes_receipt_without_restoring_consumed_path(self) -> None:
        expected = self.fixture.retain_published_signed_input()
        consumed = self.fixture.signing_output / transformation.SIGNED_APP_WITHIN_OUTPUT
        before = build_manifest(self.fixture.root, algorithm="sha256-tree-v2")
        with self.assertRaises(transformation.SigningTransformationError):
            transformation.verify_receipt(
                self.fixture.repository,
                codesign_runner=self.fixture.codesign_runner,
                freeze_verifier=self.fixture.freeze_verifier,
            )
        actual = transformation.verify_retained_receipt(
            self.fixture.repository,
            self.fixture.signed_app,
            codesign_runner=self.fixture.codesign_runner,
            freeze_verifier=self.fixture.freeze_verifier,
        )
        self.assertEqual(actual, expected)
        self.assertFalse(consumed.exists())
        self.assertEqual(
            build_manifest(self.fixture.root, algorithm="sha256-tree-v2"), before
        )

    def test_retained_input_tampering_does_not_rewrite_original_receipt(self) -> None:
        self.fixture.retain_published_signed_input()
        receipt = self.fixture.signing_output / transformation.RECEIPT_NAME
        original_receipt = receipt.read_bytes()
        (self.fixture.signed_app / "Contents/Resources/config.json").write_bytes(
            b'{"fixed":false}\n'
        )
        with self.assertRaisesRegex(
            transformation.SigningTransformationError, "outside signatures and profiles"
        ):
            transformation.verify_retained_receipt(
                self.fixture.repository,
                self.fixture.signed_app,
                codesign_runner=self.fixture.codesign_runner,
                freeze_verifier=self.fixture.freeze_verifier,
            )
        self.assertEqual(receipt.read_bytes(), original_receipt)

    def test_retained_receipt_is_recomputed_not_only_loaded(self) -> None:
        document = self.fixture.retain_published_signed_input()
        document["normalized_app_tree_sha256"] = "0" * 64
        receipt = self.fixture.signing_output / transformation.RECEIPT_NAME
        changed = transformation.canonical_json(document)
        receipt.write_bytes(changed)
        with self.assertRaisesRegex(
            transformation.SigningTransformationError, "differs from the current exact GA apps"
        ):
            transformation.verify_retained_receipt(
                self.fixture.repository,
                self.fixture.signed_app,
                codesign_runner=self.fixture.codesign_runner,
                freeze_verifier=self.fixture.freeze_verifier,
            )
        self.assertEqual(receipt.read_bytes(), changed)

    def test_retained_app_path_boundary_prevents_any_normalization(self) -> None:
        self.fixture.retain_published_signed_input()
        linked = self.fixture.root / "linked/Clash for Mac.app"
        linked.parent.mkdir()
        linked.symlink_to(self.fixture.signed_app, target_is_directory=True)
        foreign = self.fixture.repository / "Clash for Mac.app"
        foreign.mkdir()
        paths = (
            linked,
            foreign,
            self.fixture.signed_app / "missing",
            Path("relative/Clash for Mac.app"),
        )
        for path in paths:
            with (
                self.subTest(path=path),
                patch.object(transformation, "_compose_receipt_for_app") as compose,
                self.assertRaises(transformation.SigningTransformationError),
            ):
                transformation.verify_retained_receipt(
                    self.fixture.repository, path,
                    codesign_runner=self.fixture.codesign_runner,
                    freeze_verifier=self.fixture.freeze_verifier,
                )
            compose.assert_not_called()

    def test_retained_input_change_during_normalization_fails(self) -> None:
        self.fixture.retain_published_signed_input()
        mutated = False

        def mutate_after_copy(command: tuple[str, ...], repository: Path) -> None:
            nonlocal mutated
            self.fixture.codesign_runner(command, repository)
            if not mutated:
                mutated = True
                (self.fixture.signed_app / "Contents/Resources/config.json").write_bytes(
                    b'{"fixed":false}\n'
                )

        with self.assertRaisesRegex(
            transformation.SigningTransformationError, "changed during normalization"
        ):
            transformation.verify_retained_receipt(
                self.fixture.repository,
                self.fixture.signed_app,
                codesign_runner=mutate_after_copy,
                freeze_verifier=self.fixture.freeze_verifier,
            )
        self.assertTrue(mutated)

    def test_signature_only_macho_seam_publishes_and_reopens_fixed_receipt(self) -> None:
        receipt = self.fixture.create()
        receipt_path = self.fixture.signing_output / transformation.RECEIPT_NAME
        self.assertEqual(receipt["document"], transformation.DOCUMENT)
        self.assertEqual(tuple(receipt["code_objects"]), transformation.CODE_OBJECTS)
        self.assertEqual(
            tuple(receipt["removed_signed_profiles"]),
            transformation.EMBEDDED_PROFILE_PATHS,
        )
        self.assertEqual(receipt["pre_sign_app_tree_sha256"], "a" * 64)
        self.assertRegex(receipt["signed_app_tree_sha256"], r"^[0-9a-f]{64}$")
        self.assertRegex(receipt["normalized_app_tree_sha256"], r"^[0-9a-f]{64}$")
        self.assertNotEqual(
            receipt["normalized_app_tree_sha256"],
            build_manifest(self.fixture.pre_sign_app, algorithm="sha256-tree-v2")[
                "sha256"
            ],
        )
        expected_profiles = {
            role: hashlib.sha256((self.fixture.root / source).read_bytes()).hexdigest()
            for role, (source, _embedded) in transformation.PROFILE_BINDINGS.items()
        }
        self.assertEqual(receipt["profiles"], expected_profiles)
        self.assertEqual(receipt_path.read_bytes(), transformation.canonical_json(receipt))
        self.assertEqual(receipt_path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(receipt_path.parent.stat().st_mode & 0o777, 0o700)
        self.assertEqual(len(self.fixture.calls), 24)
        for offset in range(0, 24, 6):
            observed = self.fixture.calls[offset : offset + 6]
            self.assertEqual(
                tuple(
                    "."
                    if Path(command[2]).name == "Clash for Mac.app"
                    else next(
                        relative
                        for relative in transformation.CODE_OBJECTS
                        if relative != "." and command[2].endswith(relative)
                    )
                    for command in observed
                ),
                transformation.CODE_OBJECTS,
            )
        self.assertEqual(self.fixture.verify(), receipt)

    def test_resource_tampering_is_not_a_signing_transformation(self) -> None:
        (self.fixture.signed_app / "Contents/Resources/config.json").write_bytes(
            b'{"fixed":false}\n'
        )
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "outside signatures and profiles",
        ):
            self.fixture.create()

    def test_executable_tampering_is_not_hidden_by_signature_removal(self) -> None:
        authority = self.fixture.signed_app.joinpath(
            *Path(transformation.MACHO_EXECUTABLES[1]).parts
        )
        data = bytearray(authority.read_bytes())
        data[0x200] ^= 0x01
        authority.write_bytes(data)
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "outside signatures and profiles",
        ):
            self.fixture.create()

    def test_extra_missing_and_wrong_profiles_fail_closed(self) -> None:
        cases = ("extra", "missing", "wrong")
        for case in cases:
            with self.subTest(case=case):
                fixture = SigningTransformationFixture()
                try:
                    if case == "extra":
                        extra = (
                            fixture.signed_app
                            / "Contents/Resources/embedded.provisionprofile"
                        )
                        extra.write_bytes(b"extra-profile")
                    elif case == "missing":
                        missing = fixture.signed_app.joinpath(
                            *Path(transformation.EMBEDDED_PROFILE_PATHS[0]).parts
                        )
                        missing.unlink()
                    else:
                        wrong = fixture.signed_app.joinpath(
                            *Path(transformation.EMBEDDED_PROFILE_PATHS[1]).parts
                        )
                        wrong.write_bytes(b"wrong-profile")
                    with self.assertRaisesRegex(
                        transformation.SigningTransformationError,
                        "profiles|profile differs",
                    ):
                        transformation.create_attempt_receipt(
                            fixture.repository,
                            fixture.signing_output,
                            codesign_runner=fixture.codesign_runner,
                            freeze_verifier=fixture.freeze_verifier,
                        )
                finally:
                    fixture.cleanup()

    def test_fixed_code_object_symlink_is_rejected(self) -> None:
        authority = self.fixture.signed_app.joinpath(
            *Path(transformation.CODE_OBJECTS[1]).parts
        )
        target = authority.with_name("authority-target")
        authority.rename(target)
        authority.symlink_to(target.name)
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "code object is unsafe",
        ):
            self.fixture.create()

    def test_unexpected_code_signature_container_is_rejected(self) -> None:
        unexpected = (
            self.fixture.signed_app
            / "Contents/Resources/unexpected/_CodeSignature"
        )
        unexpected.mkdir(parents=True)
        (unexpected / "CodeResources").write_bytes(b"unexpected")
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "code-signature container inventory is invalid",
        ):
            self.fixture.create()

    def test_pre_sign_manifest_drift_is_rejected(self) -> None:
        manifest_path = self.fixture.root / transformation.PRE_SIGN_MANIFEST_RELATIVE
        original_manifest = manifest_path.read_bytes()
        for build_number in (
            "40030",
            "40031",
            "40032",
            "40033",
            "40034",
            "40035",
            "40036",
            "40037",
            "40038",
        ):
            manifest = json.loads(original_manifest)
            manifest["metadata"]["buildNumber"] = build_number
            manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
            try:
                with self.subTest(
                    build_number=build_number
                ), self.assertRaisesRegex(
                    transformation.SigningTransformationError,
                    "manifest identity is invalid",
                ):
                    self.fixture.create()
            finally:
                manifest_path.write_bytes(original_manifest)

    def test_receipt_tamper_is_rejected_on_reopen(self) -> None:
        receipt = self.fixture.create()
        receipt["normalized_app_tree_sha256"] = "f" * 64
        path = self.fixture.signing_output / transformation.RECEIPT_NAME
        path.write_bytes(transformation.canonical_json(receipt))
        path.chmod(0o600)
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "differs from the current exact GA apps",
        ):
            self.fixture.verify()

    def test_legacy_receipt_schema_is_rejected(self) -> None:
        receipt = self.fixture.create()
        receipt["document"] = "cfm-ga-signing-transformation-v1"
        receipt["schema_version"] = 1
        path = self.fixture.signing_output / transformation.RECEIPT_NAME
        path.write_bytes(transformation.canonical_json(receipt))
        path.chmod(0o600)
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "receipt identity is invalid",
        ):
            self.fixture.verify()

    def test_receipt_symlink_is_rejected(self) -> None:
        self.fixture.create()
        receipt = self.fixture.signing_output / transformation.RECEIPT_NAME
        target = receipt.with_name("receipt-target.json")
        receipt.rename(target)
        receipt.symlink_to(target.name)
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "cannot durably reopen",
        ):
            self.fixture.verify()

    def test_duplicate_publication_never_replaces_receipt(self) -> None:
        first = self.fixture.create()
        path = self.fixture.signing_output / transformation.RECEIPT_NAME
        original = path.read_bytes()
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "already exists",
        ):
            self.fixture.create()
        self.assertEqual(path.read_bytes(), original)
        self.assertEqual(first, json.loads(original))

    def test_input_drift_after_publication_never_returns_success(self) -> None:
        original_write = transformation._write_receipt

        def write_then_mutate(
            repository: Path, signing_output: Path, data: bytes
        ) -> None:
            original_write(repository, signing_output, data)
            resource = self.fixture.signed_app / "Contents/Resources/config.json"
            resource.write_bytes(b'{"changed-after-compose":true}\n')

        with (
            patch.object(
                transformation,
                "_write_receipt",
                side_effect=write_then_mutate,
            ),
            self.assertRaisesRegex(
                transformation.SigningTransformationError,
                "outside signatures and profiles",
            ),
        ):
            self.fixture.create()

        receipt = self.fixture.signing_output / transformation.RECEIPT_NAME
        self.assertTrue(receipt.is_file())
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "outside signatures and profiles",
        ):
            self.fixture.verify()

    def test_parent_fsync_reply_loss_is_outcome_unknown_and_recoverable(self) -> None:
        with (
            patch.object(
                durable_file,
                "fsync_locked_directory",
                side_effect=PublicationError("simulated parent fsync loss"),
            ),
            self.assertRaisesRegex(
                transformation.SigningTransformationOutcomeUnknown,
                "outcome is unknown",
            ),
        ):
            self.fixture.create()
        receipt = self.fixture.signing_output / transformation.RECEIPT_NAME
        self.assertTrue(receipt.is_file())
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "already exists",
        ):
            self.fixture.create()
        self.assertEqual(self.fixture.verify()["document"], transformation.DOCUMENT)

    def test_partial_crash_receipt_is_quarantined_and_never_replaced(self) -> None:
        receipt = self.fixture.signing_output / transformation.RECEIPT_NAME
        receipt.write_bytes(b'{"document":')
        receipt.chmod(0o600)
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "strict JSON",
        ):
            self.fixture.verify()
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "already exists",
        ):
            self.fixture.create()
        self.assertEqual(receipt.read_bytes(), b'{"document":')

    def test_codesign_failure_blocks_receipt_creation(self) -> None:
        def reject(_command: tuple[str, ...], _repository: Path) -> None:
            raise transformation.SigningTransformationError("codesign failed")

        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "codesign failed",
        ):
            transformation.create_attempt_receipt(
                self.fixture.repository,
                self.fixture.signing_output,
                codesign_runner=reject,
                freeze_verifier=self.fixture.freeze_verifier,
            )
        self.assertFalse(
            (self.fixture.signing_output / transformation.RECEIPT_NAME).exists()
        )

    def test_zero_attempt_identifier_is_rejected_by_the_shared_contract(self) -> None:
        attempt = self.fixture.signing_output.parent
        invalid_attempt = attempt.parent / "00000000"
        attempt.rename(invalid_attempt)
        invalid_output = invalid_attempt / "work"
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "positive eight-digit ASCII decimal",
        ):
            transformation._signing_output_path(
                self.fixture.repository, invalid_output
            )

    def test_canonical_receipt_verifies_after_atomic_container_publication(self) -> None:
        receipt = self.fixture.create()
        canonical = self.fixture.root / transformation.SIGNING_OUTPUT_RELATIVE
        self.fixture.signing_output.rename(canonical)
        self.fixture.signing_output = canonical
        self.fixture.signed_app = canonical / transformation.SIGNED_APP_WITHIN_OUTPUT
        self.assertEqual(
            transformation.verify_receipt(
                self.fixture.repository,
                codesign_runner=self.fixture.codesign_runner,
                freeze_verifier=self.fixture.freeze_verifier,
            ),
            receipt,
        )

    def test_private_receipt_can_be_loaded_without_claiming_verification(self) -> None:
        receipt = self.fixture.create()
        self.assertEqual(
            transformation.load_attempt_receipt(
                self.fixture.repository,
                self.fixture.signing_output,
            ),
            receipt,
        )

        canonical = self.fixture.root / transformation.SIGNING_OUTPUT_RELATIVE
        self.fixture.signing_output.rename(canonical)
        with self.assertRaisesRegex(
            transformation.SigningTransformationError,
            "fixed private attempt workspace",
        ):
            transformation.load_attempt_receipt(
                self.fixture.repository,
                canonical,
            )

    def test_signing_transformation_error_codes_are_closed(self) -> None:
        generic = transformation.SigningTransformationError("fixture")
        self.assertEqual(generic.code, transformation.GENERIC_ERROR_CODE)
        outcome = transformation.SigningTransformationOutcomeUnknown("fixture")
        self.assertEqual(
            outcome.code,
            transformation.OUTCOME_UNKNOWN_ERROR_CODE,
        )
        with self.assertRaisesRegex(ValueError, "not allowlisted"):
            transformation.SigningTransformationError(
                "fixture",
                code="attacker_controlled_code",
            )

    def test_operational_candidate_freeze_code_maps_to_recoverable_enum(self) -> None:
        def unavailable(_repository: Path) -> FrozenCandidate:
            raise transformation.CandidateFreezeError(
                "updater_verifier_unavailable",
                "typed operational verifier failure",
                consumed=True,
            )

        with self.assertRaises(
            transformation.SigningTransformationError
        ) as caught:
            transformation._freeze_inputs(
                self.fixture.repository,
                unavailable,
            )
        self.assertEqual(
            caught.exception.code,
            "candidate_freeze_updater_verifier_unavailable",
        )
        self.assertIn(
            caught.exception.code,
            transformation.RECOVERABLE_VERIFICATION_ERROR_CODES,
        )

    def test_quarantined_candidate_freeze_code_maps_to_terminal_generic(self) -> None:
        def quarantined(_repository: Path) -> FrozenCandidate:
            raise transformation.CandidateFreezeError(
                "candidate_freeze_quarantined",
                "semantic or operational cause is ambiguous",
                consumed=True,
            )

        with self.assertRaises(
            transformation.SigningTransformationError
        ) as caught:
            transformation._freeze_inputs(
                self.fixture.repository,
                quarantined,
            )
        self.assertEqual(caught.exception.code, transformation.GENERIC_ERROR_CODE)
        self.assertNotIn(
            caught.exception.code,
            transformation.RECOVERABLE_VERIFICATION_ERROR_CODES,
        )

    def test_build_wires_signing_transaction_before_notary_submission(self) -> None:
        script = (
            Path(__file__).resolve().parents[2] / "scripts/build_signed_candidate.sh"
        ).read_text(encoding="utf-8")
        transaction = script.index('signing_attempt_transaction.py"')
        verify = script.index('verify_signing_transformation.py" verify')
        notary = script.index('"$repo_root/scripts/notarization_transaction.py"')
        helper = (
            Path(__file__).resolve().parents[2]
            / "scripts/run_ga_signing_attempt.sh"
        ).read_text(encoding="utf-8")
        context_bound_commands = (
            (
                '  --signed-manifest "$signed_native_products/'
                'CFWLegacyTombstone.manifest.json" \\\n'
                '  --embedded-app "$staged_app" \\\n'
                "  --context signing-attempt-work"
            ),
            (
                '"$repo_root/scripts/verify_candidate_bundle.sh" \\\n'
                '  "$staged_app" "$signed_native_products" \\\n'
                "  --context signing-attempt-work"
            ),
            (
                '"$repo_root/scripts/verify_release_app.sh" \\\n'
                '  --pre-notary "$staged_app" "$signed_native_products" \\\n'
                "  --context signing-attempt-work"
            ),
        )
        for command in context_bound_commands:
            with self.subTest(command=command):
                self.assertEqual(helper.count(command), 1)
        self.assertEqual(
            helper.count("--context signing-attempt-work"),
            len(context_bound_commands),
        )
        self.assertLess(transaction, verify)
        self.assertLess(verify, notary)


if __name__ == "__main__":
    unittest.main()
