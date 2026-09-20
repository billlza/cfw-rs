import Darwin
import Foundation
import Testing

@testable import TransportPeerCore

@Suite("iOS packet LAN peer contract")
struct PacketLanPeerContractTests {
  private let now = Date(timeIntervalSince1970: 1_777_777_777.123456)

  private var payloads: [PacketLanStage: Data] {
    [
      .start: Data("s0123456789abcdef012".utf8),
      .target: Data("t0123456789abcdef012".utf8),
      .end: Data("e0123456789abcdef012".utf8),
    ]
  }

  private func session() -> PacketLanPeerSession {
    let payloads = payloads
    return PacketLanPeerSession(
      schemaVersion: PacketLanPeerContract.schemaVersion,
      document: PacketLanPeerContract.sessionDocument,
      sessionID: String(repeating: "1", count: 64),
      caseID: PacketLanPeerContract.caseID,
      createdAt: PeerSession.timestamp(now.addingTimeInterval(-1)),
      expiresAt: PeerSession.timestamp(now.addingTimeInterval(600)),
      listenerPort: PacketLanPeerContract.listenerPort,
      stageTokenSHA256: PacketLanTokenDigests(
        start: PeerDigest.sha256(payloads[.start]!),
        target: PeerDigest.sha256(payloads[.target]!),
        end: PeerDigest.sha256(payloads[.end]!)
      )
    )
  }

  private func ready(for session: PacketLanPeerSession) -> PacketLanReadyReceipt {
    PacketLanReadyReceipt(
      schemaVersion: PacketLanPeerContract.schemaVersion,
      document: PacketLanPeerContract.readyDocument,
      evidenceRole: PacketLanPeerContract.evidenceRole,
      claimEligible: false,
      sessionID: session.sessionID,
      bundleIdentifier: PeerContract.bundleIdentifier,
      processID: 42,
      startedAt: PeerSession.timestamp(now),
      expiresAt: session.expiresAt,
      network: try! PeerNetworkReceipt(interfaceName: "en0", ipv4: "192.168.1.20"),
      listener: .fixed,
      sessionFileRemoved: true
    )
  }

  @Test("canonical packet session is strict and bounded")
  func canonicalSession() throws {
    let expected = session()
    let data = try ExactJSON.encode(expected)
    let decoded = try ExactJSON.decodePacketLanSession(data)
    try decoded.validate(now: now)
    #expect(decoded == expected)

    var object = try #require(
      JSONSerialization.jsonObject(with: data.dropLast()) as? [String: Any]
    )
    object["fallback"] = true
    var unknown = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    unknown.append(0x0A)
    #expect(throws: PeerContractError.self) {
      try ExactJSON.decodePacketLanSession(unknown)
    }
  }

  @Test("launch modes remain disjoint")
  func launchModes() throws {
    #expect(
      try PeerLaunchMode.parse(arguments: [PacketLanPeerContract.launchArgument])
        == .packetLan
    )
    #expect(
      try PeerLaunchMode.parse(arguments: [PeerContract.transportRunLaunchArgument])
        == .session
    )
    #expect(throws: PeerContractError.self) {
      try PeerLaunchMode.parse(arguments: [PacketLanPeerContract.launchArgument, "extra"])
    }
  }

  @Test("three exact ordered connections close the packet session")
  func exactThreeStageCompletion() throws {
    let session = session()
    var tracker = try PacketLanCompletionTracker(
      session: session,
      localIPv4: "192.168.1.20"
    )
    #expect(
      tracker.record(
        payload: payloads[.start]!,
        eofObserved: true,
        peerIPv4: "192.168.1.10",
        peerPort: 50_001
      ) == .continueRunning
    )
    #expect(
      tracker.record(
        payload: payloads[.target]!,
        eofObserved: true,
        peerIPv4: "192.168.1.10",
        peerPort: 50_002
      ) == .continueRunning
    )
    #expect(
      tracker.record(
        payload: payloads[.end]!,
        eofObserved: true,
        peerIPv4: "192.168.1.10",
        peerPort: 50_003
      ) == .close
    )
    #expect(
      tracker.record(
        payload: payloads[.end]!,
        eofObserved: true,
        peerIPv4: "192.168.1.10",
        peerPort: 50_004
      ) == .fail(.extraConnection)
    )
  }

  @Test("wrong order truncation no EOF and endpoint drift fail closed")
  func rejectedConnections() throws {
    for (payload, eof, peerIPv4, peerPort, expected) in [
      (payloads[.target]!, true, "192.168.1.10", UInt16(50_001), .payloadInvalid),
      (Data(payloads[.start]!.dropLast()), true, "192.168.1.10", 50_001, .payloadInvalid),
      (payloads[.start]!, false, "192.168.1.10", 50_001, .payloadInvalid),
      (payloads[.start]!, true, "203.0.113.10", 50_001, .clientEndpointInvalid),
      (payloads[.start]!, true, "192.168.1.20", 50_001, .clientEndpointInvalid),
      (payloads[.start]!, true, "192.168.1.10", 4_433, .clientEndpointInvalid),
    ] as [(Data, Bool, String, UInt16, PacketLanFailureReason)] {
      var tracker = try PacketLanCompletionTracker(
        session: session(),
        localIPv4: "192.168.1.20"
      )
      #expect(
        tracker.record(
          payload: payload,
          eofObserved: eof,
          peerIPv4: peerIPv4,
          peerPort: peerPort
        ) == .fail(expected)
      )
    }
  }

  @Test("closed result binds ready digest and all server observations")
  func closedResult() throws {
    let session = session()
    let ready = ready(for: session)
    try ready.validate(session: session)
    var tracker = try PacketLanCompletionTracker(
      session: session,
      localIPv4: ready.network.ipv4
    )
    for (index, stage) in PacketLanStage.allCases.enumerated() {
      _ = tracker.record(
        payload: payloads[stage]!,
        eofObserved: true,
        peerIPv4: "192.168.1.10",
        peerPort: UInt16(50_001 + index)
      )
    }
    let result = PacketLanResultReceipt(
      schemaVersion: PacketLanPeerContract.schemaVersion,
      document: PacketLanPeerContract.resultDocument,
      evidenceRole: PacketLanPeerContract.evidenceRole,
      claimEligible: false,
      sessionID: session.sessionID,
      readySHA256: PeerDigest.sha256(try ExactJSON.encode(ready)),
      bundleIdentifier: PeerContract.bundleIdentifier,
      processID: ready.processID,
      completedAt: PeerSession.timestamp(now.addingTimeInterval(1)),
      status: .closed,
      failurePhase: .none,
      failureReason: .none,
      network: ready.network,
      listener: .fixed,
      listenerClosed: true,
      sessionFileRemoved: true,
      connections: tracker.connections
    )
    try result.validate(session: session, ready: ready)
    let decoded = try ExactJSON.decodePacketLanResult(ExactJSON.encode(result))
    #expect(decoded == result)

    let stale = PacketLanResultReceipt(
      schemaVersion: result.schemaVersion,
      document: result.document,
      evidenceRole: result.evidenceRole,
      claimEligible: result.claimEligible,
      sessionID: result.sessionID,
      readySHA256: String(repeating: "f", count: 64),
      bundleIdentifier: result.bundleIdentifier,
      processID: result.processID,
      completedAt: result.completedAt,
      status: result.status,
      failurePhase: result.failurePhase,
      failureReason: result.failureReason,
      network: result.network,
      listener: result.listener,
      listenerClosed: result.listenerClosed,
      sessionFileRemoved: result.sessionFileRemoved,
      connections: result.connections
    )
    #expect(throws: PeerContractError.self) {
      try stale.validate(session: session, ready: ready)
    }
  }

  @Test("packet session file is consumed before readiness")
  func sessionFileConsumption() throws {
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(
      "cfm-packet-lan-tests-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: temporary,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: temporary) }
    let paths = try PacketLanPeerPaths(documentsDirectory: temporary)
    try FileManager.default.createDirectory(
      at: paths.directory,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o755]
    )
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o755],
      ofItemAtPath: paths.directory.path
    )
    let data = try ExactJSON.encode(session())
    #expect(
      FileManager.default.createFile(
        atPath: paths.session.path,
        contents: data,
        attributes: [.posixPermissions: 0o600]
      )
    )
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o600],
      ofItemAtPath: paths.session.path
    )

    try paths.prepareCopiedInputs()
    let tightened = try FileManager.default.attributesOfItem(
      atPath: paths.directory.path
    )
    #expect((tightened[.posixPermissions] as? NSNumber)?.intValue == 0o700)
    let loaded = try paths.loadSessionAndRemove(now: now)
    #expect(loaded == session())
    #expect(!FileManager.default.fileExists(atPath: paths.session.path))
  }

  @Test("packet copied directory accepts only the pinned CoreDevice mode")
  func copiedDirectoryModeIsExact() throws {
    let temporary = FileManager.default.temporaryDirectory.appendingPathComponent(
      "cfm-packet-lan-mode-tests-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(
      at: temporary,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )
    defer { try? FileManager.default.removeItem(at: temporary) }
    let paths = try PacketLanPeerPaths(documentsDirectory: temporary)
    try FileManager.default.createDirectory(
      at: paths.directory,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o700],
      ofItemAtPath: paths.directory.path
    )
    #expect(
      FileManager.default.createFile(
        atPath: paths.session.path,
        contents: try ExactJSON.encode(session()),
        attributes: [.posixPermissions: 0o600]
      )
    )
    try FileManager.default.setAttributes(
      [.posixPermissions: 0o600],
      ofItemAtPath: paths.session.path
    )

    #expect(throws: PeerContractError.self) {
      try paths.prepareCopiedInputs()
    }
  }
}
