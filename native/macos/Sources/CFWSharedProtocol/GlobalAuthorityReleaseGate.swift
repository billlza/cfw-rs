import Foundation

public enum GlobalAuthorityProofStatus: String, CaseIterable, Sendable {
  case registrationUnproven = "registration_unproven"
  case approvalUnproven = "approval_unproven"
  case identityUnproven = "identity_unproven"
  case availabilityUnproven = "availability_unproven"
  case compatibilityUnproven = "compatibility_unproven"
  case proven
}

public enum GlobalAuthorityGateError: Error, Equatable, Sendable {
  case proofMissing(GlobalAuthorityProofStatus)

  public static let stableCode = "global-authority-unavailable"
  public static let stableMessage =
    "Global Authority registration, approval, identity, availability, and protocol compatibility are not proven."
}

extension GlobalAuthorityGateError: LocalizedError {
  public var errorDescription: String? { Self.stableMessage }
}

public enum GlobalAuthorityReleaseGate {
  static func validate(_ status: GlobalAuthorityProofStatus) throws {
    guard status == .proven else {
      throw GlobalAuthorityGateError.proofMissing(status)
    }
  }
}
