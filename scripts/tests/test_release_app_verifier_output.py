from __future__ import annotations

import unittest

from scripts.release_app_verifier_output import (
    RELEASE_APP_VERIFIER_OUTPUT_LIMIT,
    NotarizationCheck,
    ReleaseAppVerifierOutputError,
    parse_release_app_verifier_output,
)
from scripts.tests.release_app_verifier_fixture import (
    SEALED_NOTARIZATION_LINE,
    complete_verifier_stderr,
    complete_verifier_stdout,
    pre_notary_verifier_stdout,
    sealed_verifier_stdout,
)
from scripts.release_build_identity import ACTIVE_RELEASE_IDENTITY, PRODUCT_VERSION


GA_BUILD = ACTIVE_RELEASE_IDENTITY.ga_build


APP = f"/private/tmp/release/target/candidates/{PRODUCT_VERSION}/ga/{GA_BUILD}/signed/Clash for Mac.app"
APP_SUFFIX = f"/target/candidates/{PRODUCT_VERSION}/ga/{GA_BUILD}/signed/Clash for Mac.app"
FRAMEWORK_CURRENT = (
    APP + "/Contents/Frameworks/CFWNativeBridge.framework/Versions/Current/."
)
PROXY_BUNDLE = APP + "/Contents/Library/LoginItems/CFWProxyAgent.app"
AUTHORITY = APP + "/Contents/Library/HelperTools/CFWGlobalAuthority"
HOST = APP + "/Contents/MacOS/clash-for-mac"


class ReleaseAppVerifierOutputTests(unittest.TestCase):
    def parse(
        self,
        stdout: bytes | None = None,
        stderr: bytes | None = None,
        *,
        notarization: NotarizationCheck = NotarizationCheck.LIVE,
    ) -> None:
        parse_release_app_verifier_output(
            complete_verifier_stdout(APP) if stdout is None else stdout,
            complete_verifier_stderr(APP) if stderr is None else stderr,
            notarization=notarization,
            expected_app_suffix=APP_SUFFIX,
            expected_build_number=GA_BUILD,
        )

    def test_complete_observed_transcript_shape_is_accepted(self) -> None:
        stdout = complete_verifier_stdout(APP)
        stderr = complete_verifier_stderr(APP)
        self.assertEqual(len(stdout.splitlines()), 15)
        self.assertEqual(len(stderr.splitlines()), 44)
        self.parse(stdout=stdout, stderr=stderr)

    def test_swiftui_library_lines_are_required_exactly(self) -> None:
        stdout = complete_verifier_stdout(APP)
        stderr = complete_verifier_stderr(APP)
        library = (APP + "/Contents/Frameworks/libCFMNativeDashboard.dylib").encode()
        lines = stderr.splitlines(keepends=True)
        library_lines = [line for line in lines if library in line]
        self.assertEqual(len(library_lines), 10)
        for index, line in enumerate(library_lines):
            with self.subTest(dropped=index), self.assertRaises(ReleaseAppVerifierOutputError):
                self.parse(stderr=b"".join(item for item in lines if item is not line))
        with self.assertRaises(ReleaseAppVerifierOutputError):
            self.parse(stdout=stdout.replace(b"Mach-O objects: 7", b"Mach-O objects: 6", 1))
        with self.assertRaises(ReleaseAppVerifierOutputError):
            self.parse(stderr=stderr + library_lines[0])

    def test_exact_app_mode_is_accepted(self) -> None:
        parsed = parse_release_app_verifier_output(
            complete_verifier_stdout(APP),
            complete_verifier_stderr(APP),
            notarization=NotarizationCheck.LIVE,
            expected_app=APP,
            expected_build_number=GA_BUILD,
        )
        self.assertEqual(parsed.app, APP)

    def test_sealed_transcript_is_accepted_only_in_sealed_mode(self) -> None:
        stdout = sealed_verifier_stdout(APP)
        self.assertEqual(len(stdout.splitlines()), 13)
        self.parse(stdout=stdout, notarization=NotarizationCheck.SEALED)
        parsed = parse_release_app_verifier_output(
            stdout,
            complete_verifier_stderr(APP),
            notarization=NotarizationCheck.SEALED,
            expected_app=APP,
            expected_build_number=GA_BUILD,
        )
        self.assertEqual(parsed.app, APP)
        with self.assertRaisesRegex(ReleaseAppVerifierOutputError, "15-line live"):
            self.parse(stdout=stdout, notarization=NotarizationCheck.LIVE)

    def test_sealed_mode_rejects_the_live_and_pre_notary_transcripts(self) -> None:
        with self.assertRaisesRegex(ReleaseAppVerifierOutputError, "13-line sealed"):
            self.parse(
                stdout=complete_verifier_stdout(APP),
                notarization=NotarizationCheck.SEALED,
            )
        # Same length as the sealed shape; only its final line differs.
        pre_notary = pre_notary_verifier_stdout(APP)
        with self.assertRaisesRegex(ReleaseAppVerifierOutputError, "altered success"):
            self.parse(stdout=pre_notary, notarization=NotarizationCheck.SEALED)
        with self.assertRaisesRegex(ReleaseAppVerifierOutputError, "15-line live"):
            self.parse(stdout=pre_notary, notarization=NotarizationCheck.LIVE)

    def test_sealed_transcript_is_one_fixed_success_grammar(self) -> None:
        stdout = sealed_verifier_stdout(APP)
        sealed_line = SEALED_NOTARIZATION_LINE.encode("utf-8") + b"\n"
        closing = f"release app verified: {APP}\n".encode("utf-8")
        mutations = (
            stdout + b"fatal: signature invalid\n",
            stdout.replace(sealed_line, b"", 1),
            stdout.replace(
                sealed_line, b"notarization: sealed ticket bytes reopened offline\n", 1
            ),
            stdout.replace(sealed_line, b"", 1).replace(closing, sealed_line + closing, 1),
            stdout.replace(
                f"build number: {GA_BUILD}\n".encode("utf-8"), b"build number: 1\n", 1
            ),
            stdout.replace(b"a" * 64, b"A" * 64, 1),
            stdout.replace(closing, b"release app verified: /private/tmp/foreign.app\n", 1),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(
                ReleaseAppVerifierOutputError
            ):
                self.parse(stdout=mutation, notarization=NotarizationCheck.SEALED)

    def test_stderr_contract_is_the_same_in_both_modes(self) -> None:
        stderr = complete_verifier_stderr(APP)
        authority_pair = (
            f"{AUTHORITY}: valid on disk\n"
            f"{AUTHORITY}: satisfies its Designated Requirement\n"
        ).encode("utf-8")
        mutations = (
            b"",
            stderr + b"unknown diagnostic\n",
            stderr.replace(authority_pair, b"", 1),
            stderr.replace(
                FRAMEWORK_CURRENT.encode("utf-8"), b"/private/tmp/foreign.app", 1
            ),
            stderr.replace(
                f"--validated:{FRAMEWORK_CURRENT}".encode("utf-8"),
                f"--validated:{PROXY_BUNDLE}".encode("utf-8"),
                1,
            ),
        )
        transcripts = {
            NotarizationCheck.LIVE: complete_verifier_stdout(APP),
            NotarizationCheck.SEALED: sealed_verifier_stdout(APP),
        }
        for notarization, stdout in transcripts.items():
            with self.subTest(notarization=notarization):
                self.parse(stdout=stdout, stderr=stderr, notarization=notarization)
        for mutation in mutations:
            diagnostics = []
            for notarization, stdout in transcripts.items():
                with self.subTest(notarization=notarization, mutation=mutation):
                    with self.assertRaises(ReleaseAppVerifierOutputError) as rejected:
                        self.parse(stdout=stdout, stderr=mutation, notarization=notarization)
                    diagnostics.append(str(rejected.exception))
            self.assertEqual(len(set(diagnostics)), 1, diagnostics)

    def test_notarization_check_is_a_required_typed_keyword(self) -> None:
        with self.assertRaises(TypeError):
            parse_release_app_verifier_output(
                complete_verifier_stdout(APP),
                complete_verifier_stderr(APP),
                expected_app=APP,
                expected_build_number=GA_BUILD,
            )
        for value in ("live", "sealed", None, True):
            with self.subTest(value=value), self.assertRaisesRegex(
                ReleaseAppVerifierOutputError, "notarization check"
            ):
                parse_release_app_verifier_output(
                    complete_verifier_stdout(APP),
                    complete_verifier_stderr(APP),
                    notarization=value,
                    expected_app=APP,
                    expected_build_number=GA_BUILD,
                )

    def test_reported_gatekeeper_origin_pair_is_accepted(self) -> None:
        stdout = complete_verifier_stdout(APP).replace(
            (
                b"origin-status=not-reported-by-spctl, "
                b"identity-source=codesign-leaf-authority"
            ),
            b"origin-status=reported-by-spctl, identity-source=spctl-origin",
            1,
        )
        self.parse(stdout=stdout)

    def test_stdout_is_one_fixed_success_grammar(self) -> None:
        stdout = complete_verifier_stdout(APP)
        mutations = (
            stdout + b"fatal: signature invalid\n",
            stdout.replace(b"The validate action worked!", b"FAILED", 1),
            stdout.replace(
                b"identity-source=codesign-leaf-authority",
                b"identity-source=spctl-origin",
                1,
            ),
            stdout.replace(b"a" * 64, b"A" * 64, 1),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(
                ReleaseAppVerifierOutputError
            ):
                self.parse(stdout=mutation)

    def test_control_characters_and_unicode_line_separators_are_rejected(self) -> None:
        stdout = complete_verifier_stdout(APP)
        for marker in (b"\x00", b"\x1b[2J", b"\r", "\u2028".encode("utf-8")):
            mutation = stdout.replace(b"Clash for Mac.app", b"Clash" + marker + b".app", 1)
            with self.subTest(marker=marker), self.assertRaises(
                ReleaseAppVerifierOutputError
            ):
                self.parse(stdout=mutation)

    def test_non_utf8_missing_newline_and_combined_overflow_are_rejected(self) -> None:
        with self.assertRaises(ReleaseAppVerifierOutputError):
            self.parse(stderr=b"\xff")
        with self.assertRaises(ReleaseAppVerifierOutputError):
            self.parse(stderr=complete_verifier_stderr(APP).rstrip(b"\n"))
        half_plus_one = RELEASE_APP_VERIFIER_OUTPUT_LIMIT // 2 + 1
        with self.assertRaisesRegex(ReleaseAppVerifierOutputError, "combined"):
            parse_release_app_verifier_output(
                b"A" * half_plus_one,
                b"B" * half_plus_one,
                notarization=NotarizationCheck.LIVE,
                expected_app=APP,
                expected_build_number=GA_BUILD,
            )

    def test_prepared_and_validated_use_the_exact_subject_multiset(self) -> None:
        stderr = complete_verifier_stderr(APP)
        drifted = stderr.replace(
            f"--validated:{FRAMEWORK_CURRENT}".encode("utf-8"),
            f"--validated:{PROXY_BUNDLE}".encode("utf-8"),
            1,
        )
        with self.assertRaisesRegex(ReleaseAppVerifierOutputError, "prepared/validated"):
            self.parse(stderr=drifted)

    def test_result_pairs_use_the_exact_subject_multiset(self) -> None:
        stderr = complete_verifier_stderr(APP)
        drifted = stderr.replace(
            f"{AUTHORITY}: satisfies its Designated Requirement".encode("utf-8"),
            f"{HOST}: satisfies its Designated Requirement".encode("utf-8"),
            1,
        )
        with self.assertRaisesRegex(ReleaseAppVerifierOutputError, "result set"):
            self.parse(stderr=drifted)

    def test_missing_authority_and_unknown_contained_code_are_rejected(self) -> None:
        stderr = complete_verifier_stderr(APP)
        authority_pair = (
            f"{AUTHORITY}: valid on disk\n"
            f"{AUTHORITY}: satisfies its Designated Requirement\n"
        ).encode("utf-8")
        with self.assertRaises(ReleaseAppVerifierOutputError):
            self.parse(stderr=stderr.replace(authority_pair, b"", 1))

        unknown = APP + "/Contents/MacOS/UNREVIEWED"
        unknown_pair = (
            f"{unknown}: valid on disk\n"
            f"{unknown}: satisfies its Designated Requirement\n"
        ).encode("utf-8")
        with self.assertRaisesRegex(ReleaseAppVerifierOutputError, "result set"):
            self.parse(stderr=stderr.replace(authority_pair, unknown_pair, 1))

    def test_terminal_dot_is_allowed_only_for_exact_preparation_subject(self) -> None:
        stderr = complete_verifier_stderr(APP)
        mutations = (
            stderr.replace(
                f"{AUTHORITY}: valid on disk".encode("utf-8"),
                f"{AUTHORITY}/.: valid on disk".encode("utf-8"),
                1,
            ),
            stderr.replace(
                FRAMEWORK_CURRENT.encode("utf-8"),
                FRAMEWORK_CURRENT[:-2].encode("utf-8"),
                1,
            ),
            stderr.replace(
                f"--prepared:{PROXY_BUNDLE}".encode("utf-8"),
                f"--prepared:{PROXY_BUNDLE}/.".encode("utf-8"),
                1,
            ),
        )
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(
                ReleaseAppVerifierOutputError
            ):
                self.parse(stderr=mutation)

    def test_noncanonical_or_outside_subjects_are_rejected(self) -> None:
        original = FRAMEWORK_CURRENT.encode("utf-8")
        replacements = (
            b"relative/path",
            (APP + "/Contents/../outside").encode("utf-8"),
            b"/private/tmp/foreign.app",
            (APP + "/Contents//MacOS").encode("utf-8"),
            (FRAMEWORK_CURRENT + "\x1b[2J").encode("utf-8"),
        )
        for replacement in replacements:
            with self.subTest(replacement=replacement), self.assertRaises(
                ReleaseAppVerifierOutputError
            ):
                self.parse(
                    stderr=complete_verifier_stderr(APP).replace(
                        original, replacement, 1
                    )
                )


if __name__ == "__main__":
    unittest.main()
