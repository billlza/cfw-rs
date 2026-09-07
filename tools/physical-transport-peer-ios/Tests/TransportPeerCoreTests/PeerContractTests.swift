import CryptoKit
import Foundation
import Security
import Testing

@testable import TransportPeerCore

@Suite("iOS transport peer contract")
struct PeerContractTests {
  private let now = Date(timeIntervalSince1970: 1_777_777_777.123456)

  @Test("canonical session is accepted")
  func canonicalSession() throws {
    let created = now.addingTimeInterval(-1)
    let expires = now.addingTimeInterval(600)
    let body: [String: Any] = [
      "certificate_sha256": String(repeating: "2", count: 64),
      "created_at": PeerSession.timestamp(created),
      "document": PeerContract.sessionDocument,
      "expires_at": PeerSession.timestamp(expires),
      "private_key_sha256": String(repeating: "3", count: 64),
      "schema_version": PeerContract.schemaVersion,
      "session_id": String(repeating: "1", count: 64),
    ]
    var data = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
    data.append(0x0A)
    let session = try ExactJSON.decodeSession(data)
    _ = try session.validate(now: now)
    #expect(session.document == PeerContract.sessionDocument)
  }

  @Test("unknown fields and noncanonical bytes are rejected")
  func strictSessionShape() throws {
    let body: [String: Any] = [
      "certificate_sha256": String(repeating: "2", count: 64),
      "created_at": PeerSession.timestamp(now.addingTimeInterval(-1)),
      "document": PeerContract.sessionDocument,
      "expires_at": PeerSession.timestamp(now.addingTimeInterval(600)),
      "fallback": true,
      "private_key_sha256": String(repeating: "3", count: 64),
      "schema_version": PeerContract.schemaVersion,
      "session_id": String(repeating: "1", count: 64),
    ]
    var data = try JSONSerialization.data(withJSONObject: body, options: [.sortedKeys])
    data.append(0x0A)
    #expect(throws: PeerContractError.self) {
      try ExactJSON.decodeSession(data)
    }
  }

  @Test("receipts preserve explicit null ALPN and canonical order")
  func canonicalReceipt() throws {
    let receipt = ReadyReceipt(
      schemaVersion: 1,
      document: PeerContract.readyDocument,
      sessionID: String(repeating: "1", count: 64),
      bundleIdentifier: PeerContract.bundleIdentifier,
      processID: 42,
      startedAt: PeerSession.timestamp(now),
      expiresAt: PeerSession.timestamp(now.addingTimeInterval(600)),
      certificateSHA256: String(repeating: "2", count: 64),
      network: try PeerNetworkReceipt(interfaceName: "en0", ipv4: "192.168.1.20"),
      listeners: .fixed
    )
    let data = try ExactJSON.encode(receipt)
    #expect(data.last == 0x0A)
    let object = try #require(
      JSONSerialization.jsonObject(with: data.dropLast()) as? [String: Any]
    )
    let listeners = try #require(object["listeners"] as? [String: Any])
    let tcp = try #require(listeners["tcp_sink"] as? [String: Any])
    #expect(tcp["alpn"] is NSNull)
  }

  @Test("network identity accepts only RFC1918 en0 IPv4 addresses")
  func closedNetworkIdentity() {
    #expect(
      PeerNetworkIdentity.isControlledWiFiIPv4(
        interfaceName: "en0", address: "10.0.0.4"))
    #expect(
      PeerNetworkIdentity.isControlledWiFiIPv4(
        interfaceName: "en0", address: "172.20.10.2"))
    #expect(
      PeerNetworkIdentity.isControlledWiFiIPv4(
        interfaceName: "en0", address: "192.168.1.20"))
    #expect(
      !PeerNetworkIdentity.isControlledWiFiIPv4(
        interfaceName: "pdp_ip0", address: "10.0.0.4"))
    #expect(
      !PeerNetworkIdentity.isControlledWiFiIPv4(
        interfaceName: "en0", address: "169.254.1.1"))
    #expect(
      !PeerNetworkIdentity.isControlledWiFiIPv4(
        interfaceName: "en0", address: "203.0.113.1"))
    #expect(
      !PeerNetworkIdentity.isControlledWiFiIPv4(
        interfaceName: "en0", address: "not-an-ip"))
  }

  @Test("session lifetime is bounded")
  func boundedLifetime() {
    let session = PeerSession(
      schemaVersion: 1,
      document: PeerContract.sessionDocument,
      sessionID: String(repeating: "1", count: 64),
      createdAt: PeerSession.timestamp(now.addingTimeInterval(-1)),
      expiresAt: PeerSession.timestamp(
        now.addingTimeInterval(PeerContract.maximumSessionSeconds + 1)
      ),
      certificateSHA256: String(repeating: "2", count: 64),
      privateKeySHA256: String(repeating: "3", count: 64)
    )
    #expect(throws: PeerContractError.self) {
      try session.validate(now: now)
    }
  }

  @Test("TCP sink accepts EOF at the bound and rejects overflow")
  func tcpSinkBounds() {
    let payload = Data(repeating: 0x41, count: PeerContract.maximumPayloadBytes)
    #expect(
      PeerStreamProtocol.evaluate(
        service: .tcpSink,
        buffer: payload,
        streamComplete: false
      ) == .readMore
    )
    #expect(
      PeerStreamProtocol.evaluate(
        service: .tcpSink,
        buffer: payload,
        streamComplete: true
      ) == .complete(payload: payload, response: nil)
    )
    #expect(
      PeerStreamProtocol.evaluate(
        service: .tcpSink,
        buffer: payload + Data([0x42]),
        streamComplete: true
      ) == .reject
    )
  }

  @Test("framed echo handles partial reads and exact response")
  func framedEcho() {
    let payload = Data("hello".utf8)
    let frame = Data([0, UInt8(payload.count)]) + payload
    #expect(
      PeerStreamProtocol.evaluate(
        service: .tls13Echo,
        buffer: Data(frame.prefix(1)),
        streamComplete: false
      ) == .readMore
    )
    #expect(
      PeerStreamProtocol.evaluate(
        service: .quicEcho,
        buffer: Data(frame.dropLast()),
        streamComplete: false
      ) == .readMore
    )
    #expect(
      PeerStreamProtocol.evaluate(
        service: .quicEcho,
        buffer: frame,
        streamComplete: false
      ) == .complete(payload: payload, response: frame)
    )
  }

  @Test("framed echo rejects zero, truncation, overflow, and trailing bytes")
  func framedEchoFailures() {
    for frame in [
      Data([0, 0]),
      Data([0, 65]),
      Data([0, 1]),
      Data([0, 1, 0x41, 0x42]),
    ] {
      #expect(
        PeerStreamProtocol.evaluate(
          service: .tls13Echo,
          buffer: frame,
          streamComplete: true
        ) == .reject
      )
    }
  }

  @Test("Security accepts the fresh P-256 X9.63 private-key representation")
  func securityAcceptsX963PrivateKey() throws {
    let generated = P256.Signing.PrivateKey()
    let bytes = generated.x963Representation
    #expect(bytes.count == 97)
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecAttrKeySizeInBits: 256,
    ]
    var error: Unmanaged<CFError>?
    let key = SecKeyCreateWithData(bytes as CFData, attributes as CFDictionary, &error)
    if let error {
      Issue.record(error.takeRetainedValue() as Error)
    }
    #expect(key != nil)
  }
}
