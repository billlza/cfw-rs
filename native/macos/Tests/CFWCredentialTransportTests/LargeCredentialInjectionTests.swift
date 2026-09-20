import CFWCredentialTransport
import CFWSharedProtocol
import Foundation
import Testing

@Test func largeCredentialInjectionPreservesEveryProtocolSlotWithoutTemplateMutation() throws {
  var slots: [CredentialSlot] = []
  var entries: [CredentialMaterialEntry] = []
  var outbounds: [[String: Any]] = []
  for index in UInt16(0)..<1_024 {
    let http = index % 2 == 0
    outbounds.append([
      "type": http ? "http" : "socks", "tag": "node-\(index)", "username": "", "password": "",
    ])
    for password in [false, true] {
      let kind: CredentialKind =
        http
        ? (password ? .httpProxyPassword : .httpProxyUsername)
        : (password ? .socks5Password : .socks5Username)
      let target: CredentialTarget =
        http
        ? (password ? .httpProxyPassword : .httpProxyUsername)
        : (password ? .socks5Password : .socks5Username)
      let reference = CredentialReference(id: UUID(), kind: kind)
      slots.append(
        try CredentialSlot(
          reference: reference, target: target, outboundIndex: index,
          jsonPointer: "/outbounds/\(index)/\(password ? "password" : "username")"))
      entries.append(
        try CredentialMaterialEntry(
          reference: reference, secret: Data("fixture-\(index)-\(password)".utf8)))
    }
  }
  let template = try JSONSerialization.data(withJSONObject: ["outbounds": outbounds])
  var material = try CredentialMaterial(entries: entries)
  defer { material.erase() }
  let started = ContinuousClock.now
  let injected = try CredentialInjector.inject(template: template, slots: slots, material: material)
  print("capacity native: 1024 nodes / 2048 slots injected in \(started.duration(to: .now))")
  let root = try #require(JSONSerialization.jsonObject(with: injected) as? [String: Any])
  let filled = try #require(root["outbounds"] as? [[String: Any]])
  #expect(filled.count == 1_024)
  for index in 0..<1_024 {
    #expect(filled[index]["username"] as? String == "fixture-\(index)-false")
    #expect(filled[index]["password"] as? String == "fixture-\(index)-true")
  }
  #expect(
    outbounds.allSatisfy { $0["username"] as? String == "" && $0["password"] as? String == "" })
}
