import Foundation

/// A read-only observation of the machine's enrollment, available only to a
/// current-console Host while the Authority is Off. It grants no engine lease
/// and never resets the durable replay cursor. The Host authenticates its user
/// separately before replacing that user's local Keychain lineage.
public struct InstallationRecoveryIdentity: Codable, Equatable, Sendable {
  public let installationID: AuthorityIdentifier
  public let acceptedEpoch: UInt64
  public let revision: UInt64
  public let consoleUID: UInt32

  public init(
    installationID: AuthorityIdentifier, acceptedEpoch: UInt64,
    revision: UInt64, consoleUID: UInt32
  ) throws {
    guard consoleUID > 0, consoleUID != UInt32.max, revision > 0,
      installationID.rawValue.uuidString != "00000000-0000-0000-0000-000000000000",
      acceptedEpoch < UInt64.max
    else { throw AuthorityV1ValidationError.invalidContext }
    self.installationID = installationID
    self.acceptedEpoch = acceptedEpoch
    self.revision = revision
    self.consoleUID = consoleUID
  }

  enum CodingKeys: String, CodingKey {
    case installationID = "installation_id"
    case acceptedEpoch = "accepted_epoch"
    case revision
    case consoleUID = "console_uid"
  }
}

extension InstallationRecoveryIdentity: AuthorityV1WireModel {
  public func validateAuthorityV1() throws {
    _ = try InstallationRecoveryIdentity(
      installationID: installationID, acceptedEpoch: acceptedEpoch,
      revision: revision, consoleUID: consoleUID)
  }
}

/// `nil` means the Authority has never enrolled an installation. It does not
/// stand for an unavailable service, an unreadable journal, or unproven Off.
public struct InstallationRecoveryState: Codable, Equatable, Sendable, AuthorityV1WireModel {
  public let identity: InstallationRecoveryIdentity?

  public init(identity: InstallationRecoveryIdentity?) { self.identity = identity }

  public func validateAuthorityV1() throws {
    try identity?.validateAuthorityV1()
  }
}
