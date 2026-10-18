import Foundation

public struct CredentialRebindRequest: Codable, Equatable, Sendable {
  public let previousAudience: CredentialAudience
  public let audience: CredentialAudience
  public let slots: [CredentialSlot]

  public init(
    previousAudience: CredentialAudience, audience: CredentialAudience, slots: [CredentialSlot]
  ) throws {
    guard previousAudience.profileID == audience.profileID,
      slots.count <= NativeBridgeProtocolConstants.maximumCredentialSlots,
      Set(slots.map(\.jsonPointer)).count == slots.count
    else { throw NativeBridgeProtocolError.invalidCredentialSlot }
    self.previousAudience = previousAudience
    self.audience = audience
    self.slots = slots
  }

  private enum CodingKeys: String, CodingKey {
    case previousAudience = "previous_audience"
    case audience
    case slots
  }

  public init(from decoder: Decoder) throws {
    let container = try decoder.container(keyedBy: CodingKeys.self)
    try self.init(
      previousAudience: container.decode(CredentialAudience.self, forKey: .previousAudience),
      audience: container.decode(CredentialAudience.self, forKey: .audience),
      slots: container.decode([CredentialSlot].self, forKey: .slots))
  }
}
