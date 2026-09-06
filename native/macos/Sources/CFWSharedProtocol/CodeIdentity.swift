import Foundation

public enum CodeIdentityError: Error, Equatable, Sendable {
  case missingBundleSetting(String)
  case invalidTeamIdentifier
  case invalidBundleIdentifier
  case emptyBundleIdentifierSet
  case userIdentifierMismatch(expected: uid_t, actual: uid_t)
}

extension CodeIdentityError: LocalizedError {
  public var errorDescription: String? {
    switch self {
    case .missingBundleSetting(let key):
      return "Required bundle setting \(key) is missing."
    case .invalidTeamIdentifier:
      return "The configured signing Team ID is invalid."
    case .invalidBundleIdentifier:
      return "A configured signing bundle identifier is invalid."
    case .emptyBundleIdentifierSet:
      return "At least one signing bundle identifier is required."
    case .userIdentifierMismatch(let expected, let actual):
      return "XPC peer uid \(actual) does not match required uid \(expected)."
    }
  }
}

public protocol XPCCodeSigningRequirementApplying: AnyObject {
  var effectiveUserIdentifier: uid_t { get }
  func setCodeSigningRequirement(_ requirement: String)
}

extension NSXPCConnection: XPCCodeSigningRequirementApplying {}

public protocol XPCListenerCodeSigningRequirementApplying: AnyObject {
  func setConnectionCodeSigningRequirement(_ requirement: String)
}

extension NSXPCListener: XPCListenerCodeSigningRequirementApplying {}

/// A public-API-only identity policy for an XPC connection. Foundation binds
/// the requirement to the connection audit token; callers never authorize a
/// process by looking up its PID.
public struct CodeIdentityRequirement: Sendable {
  public let expectedTeamIdentifier: String
  public let expectedBundleIdentifiers: [String]

  public init(
    expectedTeamIdentifier: String,
    expectedBundleIdentifiers: [String]
  ) throws {
    let teamPattern = /^[A-Z0-9]{10}$/
    guard expectedTeamIdentifier.wholeMatch(of: teamPattern) != nil else {
      throw CodeIdentityError.invalidTeamIdentifier
    }
    guard !expectedBundleIdentifiers.isEmpty else {
      throw CodeIdentityError.emptyBundleIdentifierSet
    }
    let bundlePattern = /^[A-Za-z0-9][A-Za-z0-9.-]{2,254}$/
    guard
      expectedBundleIdentifiers.allSatisfy({
        $0.wholeMatch(of: bundlePattern) != nil
      })
    else {
      throw CodeIdentityError.invalidBundleIdentifier
    }
    self.expectedTeamIdentifier = expectedTeamIdentifier
    self.expectedBundleIdentifiers = Array(Set(expectedBundleIdentifiers)).sorted()
  }

  public init(
    expectedTeamIdentifier: String,
    expectedBundleIdentifier: String
  ) throws {
    try self.init(
      expectedTeamIdentifier: expectedTeamIdentifier,
      expectedBundleIdentifiers: [expectedBundleIdentifier]
    )
  }

  public var requirementText: String {
    let identifiers =
      expectedBundleIdentifiers
      .map { "identifier \"\($0)\"" }
      .joined(separator: " or ")
    return "anchor apple generic "
      + "and certificate 1[field.1.2.840.113635.100.6.2.6] exists "
      + "and certificate leaf[field.1.2.840.113635.100.6.1.13] exists "
      + "and certificate leaf[subject.OU] = \"\(expectedTeamIdentifier)\" "
      + "and (\(identifiers))"
  }

  public func configure(
    _ connection: any XPCCodeSigningRequirementApplying,
    requiredUserIdentifier: uid_t? = nil
  ) throws {
    if let requiredUserIdentifier,
      connection.effectiveUserIdentifier != requiredUserIdentifier
    {
      throw CodeIdentityError.userIdentifierMismatch(
        expected: requiredUserIdentifier,
        actual: connection.effectiveUserIdentifier
      )
    }
    connection.setCodeSigningRequirement(requirementText)
  }

  public func configure(_ listener: any XPCListenerCodeSigningRequirementApplying) {
    listener.setConnectionCodeSigningRequirement(requirementText)
  }
}
