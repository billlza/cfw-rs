import CFWSharedProtocol
import Darwin
import Foundation
import Security
import Testing

@testable import CFWProxyAgentCore

private final class CapturingCodeSigningConnection: XPCCodeSigningRequirementApplying {
  let effectiveUserIdentifier: uid_t
  private(set) var requirements: [String] = []

  init(effectiveUserIdentifier: uid_t) {
    self.effectiveUserIdentifier = effectiveUserIdentifier
  }

  func setCodeSigningRequirement(_ requirement: String) {
    requirements.append(requirement)
  }
}

private final class CapturingCodeSigningListener:
  XPCListenerCodeSigningRequirementApplying
{
  private(set) var requirements: [String] = []

  func setConnectionCodeSigningRequirement(_ requirement: String) {
    requirements.append(requirement)
  }
}

@Test func codeIdentityConfiguresExactConnectionCodeSigningRequirement() throws {
  let policy = try CodeIdentityRequirement(
    expectedTeamIdentifier: "YKUPL7Z869",
    expectedBundleIdentifier: "com.bill.clashformac"
  )
  let connection = CapturingCodeSigningConnection(
    effectiveUserIdentifier: geteuid()
  )

  try policy.configure(connection, requiredUserIdentifier: geteuid())

  #expect(
    connection.requirements == [
      "anchor apple generic "
        + "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
        + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
        + "and certificate leaf[subject.OU] = \"YKUPL7Z869\" "
        + "and (identifier \"com.bill.clashformac\")"
    ]
  )
}

@Test func codeIdentityRequirementParsesAndRequiresDeveloperIDApplication() throws {
  let policy = try CodeIdentityRequirement(
    expectedTeamIdentifier: "YKUPL7Z869",
    expectedBundleIdentifiers: [
      "com.bill.clashformac.proxy-agent",
      "com.bill.clashformac",
    ]
  )

  var requirement: SecRequirement?
  #expect(
    SecRequirementCreateWithString(
      policy.requirementText as CFString, [], &requirement) == errSecSuccess)
  #expect(requirement != nil)
  #expect(
    policy.requirementText.contains(
      "certificate leaf[field.1.2.840.113635.100.6.1.13] exists"))
  #expect(
    policy.requirementText.contains(
      "certificate 1[field.1.2.840.113635.100.6.2.6] exists"))
}

@Test func codeIdentityConfiguresListenerLevelCodeSigningGate() throws {
  let policy = try CodeIdentityRequirement(
    expectedTeamIdentifier: "YKUPL7Z869",
    expectedBundleIdentifier: "com.bill.clashformac"
  )
  let listener = CapturingCodeSigningListener()

  policy.configure(listener)

  #expect(listener.requirements == [policy.requirementText])
}

@Test func codeIdentityRejectsUserMismatchBeforeSettingRequirement() throws {
  let policy = try CodeIdentityRequirement(
    expectedTeamIdentifier: "YKUPL7Z869",
    expectedBundleIdentifier: "com.bill.clashformac"
  )
  let actualUserIdentifier = geteuid() &+ 1
  let connection = CapturingCodeSigningConnection(
    effectiveUserIdentifier: actualUserIdentifier
  )

  #expect(
    throws: CodeIdentityError.userIdentifierMismatch(
      expected: geteuid(),
      actual: actualUserIdentifier
    )
  ) {
    try policy.configure(connection, requiredUserIdentifier: geteuid())
  }
  #expect(connection.requirements.isEmpty)
}
