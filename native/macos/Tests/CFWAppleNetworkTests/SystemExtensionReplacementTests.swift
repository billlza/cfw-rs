import CFWSharedProtocol
import Foundation
@preconcurrency import NetworkExtension
import Testing

@testable import CFWAppleNetwork

// Replacing the System Extension: only a newer bundle version replaces it, and
// a malformed or non-canonical version cancels the replacement.
@Test func systemExtensionReplacementCancelsEqualBundleVersion() {
  #expect(
    OSSystemExtensionInstaller.replacementAction(
      existingBundleVersion: "40002",
      candidateBundleVersion: "40002"
    ) == .cancel
  )
}

@Test func systemExtensionReplacementCancelsOlderBundleVersion() {
  #expect(
    OSSystemExtensionInstaller.replacementAction(
      existingBundleVersion: "40002",
      candidateBundleVersion: "40001"
    ) == .cancel
  )
}

@Test func systemExtensionReplacementAcceptsOnlyNewerBundleVersion() {
  for (existing, candidate) in [
    ("40001", "40002"),
    ("9223372036854775806", "9223372036854775807"),
  ] {
    #expect(
      OSSystemExtensionInstaller.replacementAction(
        existingBundleVersion: existing,
        candidateBundleVersion: candidate
      ) == .replace
    )
  }
}

@Test func systemExtensionReplacementCancelsMalformedOrNonCanonicalVersions() {
  for (existing, candidate) in [
    ("abc", "40002"),
    ("40001", "abc"),
    ("40001", "040002"),
    ("40001", "0"),
    ("40001", "40002.0"),
    ("40001", "40002b1"),
    ("40001", "9223372036854775808"),
    ("40001", "10000000000000000000"),
    ("40001", ""),
  ] {
    #expect(
      OSSystemExtensionInstaller.replacementAction(
        existingBundleVersion: existing,
        candidateBundleVersion: candidate
      ) == .cancel
    )
  }
}
