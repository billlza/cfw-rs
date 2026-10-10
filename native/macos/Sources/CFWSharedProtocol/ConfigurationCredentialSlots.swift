import Foundation

enum ConfigurationCredentialSlots {
  static func validate(
    _ slots: [CredentialSlot],
    root: [String: Any]
  ) throws {
    guard slots.count <= NativeBridgeProtocolConstants.maximumCredentialSlots else {
      throw NativeBridgeProtocolError.invalidCredentialSlot
    }
    var pointers = Set<String>()
    var referenceKinds: [UUID: CredentialKind] = [:]
    for slot in slots {
      guard pointers.insert(slot.jsonPointer).inserted else {
        throw NativeBridgeProtocolError.duplicateCredentialPointer
      }
      if let prior = referenceKinds.updateValue(slot.reference.kind, forKey: slot.reference.id),
        prior != slot.reference.kind
      {
        throw NativeBridgeProtocolError.conflictingCredentialKind
      }
      guard let outbounds = root[slot.target.configurationContainer] as? [Any],
        Int(slot.outboundIndex) < outbounds.count,
        let outbound = outbounds[Int(slot.outboundIndex)] as? [String: Any],
        Self.placeholder(in: outbound, target: slot.target) == ""
      else {
        throw NativeBridgeProtocolError.nonEmptyCredentialPlaceholder
      }
    }
  }

  private static func placeholder(
    in outbound: [String: Any],
    target: CredentialTarget
  ) -> String? {
    switch target {
    case .wireguardPrivateKey:
      outbound["type"] as? String == "wireguard" ? outbound["private_key"] as? String : nil
    case .wireguardPreSharedKey:
      if outbound["type"] as? String == "wireguard",
        let peers = outbound["peers"] as? [[String: Any]], peers.count == 1
      {
        peers[0]["pre_shared_key"] as? String
      } else {
        nil
      }
    case .socks5Username:
      outbound["username"] as? String
    case .httpProxyUsername:
      outbound["type"] as? String == "http" ? outbound["username"] as? String : nil
    case .httpProxyPassword:
      outbound["type"] as? String == "http" ? outbound["password"] as? String : nil
    case .shadowsocksPassword, .trojanPassword, .hysteria2Password, .anytlsPassword,
      .tuicPassword, .socks5Password:
      outbound["password"] as? String
    case .vmessUUID, .vlessUUID, .tuicUUID:
      outbound["uuid"] as? String
    case .hysteria2ObfsPassword:
      (outbound["obfs"] as? [String: Any])?["password"] as? String
    }
  }

}
