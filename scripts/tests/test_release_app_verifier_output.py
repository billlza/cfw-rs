from __future__ import annotations

import unittest

from scripts.release_app_verifier_output import (
    RELEASE_APP_VERIFIER_OUTPUT_LIMIT,
    ReleaseAppVerifierOutputError,
    parse_release_app_verifier_output,
)
from scripts.tests.release_app_verifier_fixture import (
    complete_verifier_stderr,
    complete_verifier_stdout,
)


APP = "/private/tmp/release/target/candidates/0.4.0/ga/40037/signed/Clash for Mac.app"
APP_SUFFIX = "/target/candidates/0.4.0/ga/40037/signed/Clash for Mac.app"
FRAMEWORK_CURRENT = (
    APP + "/Contents/Frameworks/CFWNativeBridge.framework/Versions/Current/."
)
PROXY_BUNDLE = APP + "/Contents/Library/LoginItems/CFWProxyAgent.app"
AUTHORITY = APP + "/Contents/Library/HelperTools/CFWGlobalAuthority"
HOST = APP + "/Contents/MacOS/clash-for-mac"


class ReleaseAppVerifierOutputTests(unittest.TestCase):
    def parse(self, stdout: bytes | None = None, stderr: bytes | None = None) -> None:
        parse_release_app_verifier_output(
            complete_verifier_stdout(APP) if stdout is None else stdout,
            complete_verifier_stderr(APP) if stderr is None else stderr,
            expected_app_suffix=APP_SUFFIX,
            expected_build_number="40037",
        )

    def test_complete_observed_transcript_shape_is_accepted(self) -> None:
        stdout = complete_verifier_stdout(APP)
        stderr = complete_verifier_stderr(APP)
        self.assertEqual(len(stdout.splitlines()), 15)
        self.assertEqual(len(stderr.splitlines()), 34)
        self.parse(stdout=stdout, stderr=stderr)

    def test_exact_app_mode_is_accepted(self) -> None:
        parsed = parse_release_app_verifier_output(
            complete_verifier_stdout(APP),
            complete_verifier_stderr(APP),
            expected_app=APP,
            expected_build_number="40037",
        )
        self.assertEqual(parsed.app, APP)

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
                expected_app=APP,
                expected_build_number="40037",
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
