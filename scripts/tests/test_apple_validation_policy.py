from __future__ import annotations

import unittest

from scripts.apple_validation_policy import (
    AppleValidationPolicyError,
    BUILD_KEY,
    VERSION_KEY,
    selected_apple_identity,
)


class AppleValidationPolicyTests(unittest.TestCase):
    pins = {"XCODE_VERSION": "27.0", "XCODE_BUILD_VERSION": "27A266a"}

    def selection(self, version="27.0", build="27A5252f"):
        return {VERSION_KEY: version, BUILD_KEY: build, "CFW_UNSIGNED_VALIDATION_PYTHON": "/hosted/Python/bin/python3"}

    def test_production_still_uses_exact_pins(self):
        self.assertEqual(selected_apple_identity(self.pins, {}, role="production"), ("27.0", "27A266a"))

    def test_explicit_unsigned_selection_can_use_hosted_beta(self):
        self.assertEqual(selected_apple_identity(self.pins, self.selection(), role="unsigned-validation"), ("27.0", "27A5252f"))
        self.assertEqual(self.pins["XCODE_BUILD_VERSION"], "27A266a")

    def test_newer_available_version_is_allowed_for_validation(self):
        self.assertEqual(selected_apple_identity(self.pins, self.selection("27.1", "27B5032a")), ("27.1", "27B5032a"))

    def test_production_rejects_validation_even_when_same_version(self):
        for build in ("27A5252f", "27A266a"):
            with self.subTest(build=build), self.assertRaisesRegex(AppleValidationPolicyError, "production refuses"):
                selected_apple_identity(self.pins, self.selection(build=build), role="production")

    def test_partial_or_empty_selection_is_an_error(self):
        for key in (VERSION_KEY, BUILD_KEY):
            for value in (None, ""):
                selected = self.selection()
                if value is None:
                    del selected[key]
                else:
                    selected[key] = value
                with self.subTest(key=key, value=value), self.assertRaises(AppleValidationPolicyError):
                    selected_apple_identity(self.pins, selected)

    def test_validation_selection_needs_explicit_validation_role(self):
        for python in (None, "python3", ""):
            selected = self.selection()
            if python is None:
                del selected["CFW_UNSIGNED_VALIDATION_PYTHON"]
            else:
                selected["CFW_UNSIGNED_VALIDATION_PYTHON"] = python
            with self.subTest(python=python), self.assertRaisesRegex(AppleValidationPolicyError, "explicit validation role"):
                selected_apple_identity(self.pins, selected)

    def test_older_hosted_toolchain_is_recorded_without_changing_release_pin(self):
        self.assertEqual(selected_apple_identity(self.pins, self.selection("26.6", "17F113")), ("26.6", "17F113"))
        self.assertEqual(self.pins["XCODE_VERSION"], "27.0")

    def test_invalid_identity_is_rejected(self):
        for version, build in (("27", "27A5252f"), ("27.0\n", "27A5252f"), ("27.0", "27A5252f\n"), ("27.0", "$(command)")):
            with self.subTest(version=version, build=build), self.assertRaises(AppleValidationPolicyError):
                selected_apple_identity(self.pins, self.selection(version, build))


if __name__ == "__main__":
    unittest.main()
