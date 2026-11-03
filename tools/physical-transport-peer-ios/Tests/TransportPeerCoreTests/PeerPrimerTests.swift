import Darwin
import Foundation
import Testing

@testable import TransportPeerCore
@testable import TransportPeerMacProbeSupport

// The local network primer: its lifecycle evidence, canonical receipt,
// freshness checks and retry directory.
extension PeerLifecycleAndMacProbeTests {
  @Test("primer proof requires registration, ready, then observed cancellation")
  func primerLifecycleEvidence() throws {
    var incomplete = LocalNetworkPrimerEvidenceTracker(startedAt: now)
    #expect(throws: PeerContractError.self) {
      try incomplete.observeListenerCancelled(at: now.addingTimeInterval(1))
    }

    var tracker = LocalNetworkPrimerEvidenceTracker(startedAt: now)
    let registrationCompleted = try tracker.observeServiceRegistered(
      at: now.addingTimeInterval(1)
    )
    let readyCompleted = try tracker.observeListenerReady(at: now.addingTimeInterval(2))
    #expect(!registrationCompleted)
    #expect(readyCompleted)
    #expect(tracker.canCancel)
    try tracker.observeListenerCancelled(at: now.addingTimeInterval(3))
    #expect(tracker.isProven)
  }

  @Test("primer receipt and private path are canonical and write-once")
  func canonicalPrimerReceipt() throws {
    let receipt = try makePrimerReceipt()
    let canonical = try ExactJSON.encode(receipt)
    #expect(try ExactJSON.decodePrimerResult(canonical) == receipt)

    var object = try #require(
      JSONSerialization.jsonObject(with: canonical.dropLast()) as? [String: Any]
    )
    var listener = try #require(object["listener"] as? [String: Any])
    listener["fallback"] = true
    object["listener"] = listener
    var altered = try JSONSerialization.data(withJSONObject: object, options: [.sortedKeys])
    altered.append(0x0A)
    #expect(throws: PeerContractError.self) {
      try ExactJSON.decodePrimerResult(altered)
    }

    try withPrivateTemporaryDirectory { documents in
      let paths = try LocalNetworkPrimerPaths(documentsDirectory: documents)
      try paths.prepareEmptyDirectory()
      // The system permission sheet exits this foreground-only app. A bounded
      // host retry must be able to reuse the still-empty owned directory
      // without weakening its metadata or accepting stale receipts.
      try paths.prepareEmptyDirectory()
      try paths.writeResult(receipt)
      #expect(throws: PeerContractError.self) {
        try paths.prepareEmptyDirectory()
      }
      #expect(try ExactJSON.decodePrimerResult(Data(contentsOf: paths.result)) == receipt)
      #expect(try paths.loadFreshResult(now: now) == receipt)
      let directoryMode = try #require(
        FileManager.default.attributesOfItem(atPath: paths.directory.path)[.posixPermissions]
          as? NSNumber
      )
      let resultMode = try #require(
        FileManager.default.attributesOfItem(atPath: paths.result.path)[.posixPermissions]
          as? NSNumber
      )
      #expect(directoryMode.intValue == 0o700)
      #expect(resultMode.intValue == 0o600)
      #expect(throws: PeerContractError.self) {
        try paths.writeResult(receipt)
      }
    }
  }

  @Test("primer receipt freshness and file metadata fail closed")
  func freshPrimerReceipt() throws {
    try withPrivateTemporaryDirectory { documents in
      let paths = try LocalNetworkPrimerPaths(documentsDirectory: documents)
      try paths.prepareEmptyDirectory()
      try paths.writeResult(try makePrimerReceipt())
      #expect(throws: PeerContractError.stalePrimer) {
        try paths.loadFreshResult(
          now: now.addingTimeInterval(PeerContract.maximumSessionSeconds + 1)
        )
      }
    }

    try withPrivateTemporaryDirectory { documents in
      let paths = try LocalNetworkPrimerPaths(documentsDirectory: documents)
      try paths.prepareEmptyDirectory()
      try paths.writeResult(try makePrimerReceipt())
      try setMode(0o644, for: paths.result)
      #expect(throws: PeerContractError.self) {
        try paths.loadFreshResult(now: now)
      }
    }
  }

  @Test("primer retry rejects mode drift and symbolic-link directories")
  func unsafePrimerRetryDirectory() throws {
    try withPrivateTemporaryDirectory { documents in
      let paths = try LocalNetworkPrimerPaths(documentsDirectory: documents)
      try FileManager.default.createDirectory(
        at: paths.directory,
        withIntermediateDirectories: false
      )
      try setMode(0o755, for: paths.directory)
      #expect(throws: PeerContractError.self) {
        try paths.prepareEmptyDirectory()
      }
    }

    try withPrivateTemporaryDirectory { documents in
      let paths = try LocalNetworkPrimerPaths(documentsDirectory: documents)
      let target = documents.appendingPathComponent("primer-target", isDirectory: true)
      try FileManager.default.createDirectory(
        at: target,
        withIntermediateDirectories: false
      )
      try FileManager.default.createSymbolicLink(
        at: paths.directory,
        withDestinationURL: target
      )
      #expect(throws: PeerContractError.self) {
        try paths.prepareEmptyDirectory()
      }
    }

    try withPrivateTemporaryDirectory { documents in
      let paths = try LocalNetworkPrimerPaths(documentsDirectory: documents)
      try FileManager.default.createDirectory(
        at: paths.transportDirectory,
        withIntermediateDirectories: false
      )
      try setMode(0o700, for: paths.transportDirectory)
      #expect(throws: PeerContractError.self) {
        try paths.prepareEmptyDirectory()
      }
    }
  }

  private func makePrimerReceipt() throws -> LocalNetworkPrimerReceipt {
    LocalNetworkPrimerReceipt(
      schemaVersion: PeerContract.schemaVersion,
      document: PeerContract.primerResultDocument,
      mode: PeerContract.primerMode,
      claimEligible: false,
      bundleIdentifier: PeerContract.bundleIdentifier,
      processID: 42,
      startedAt: PeerSession.timestamp(now.addingTimeInterval(-3)),
      serviceRegisteredAt: PeerSession.timestamp(now.addingTimeInterval(-2)),
      listenerReadyAt: PeerSession.timestamp(now.addingTimeInterval(-1)),
      listenerCancelledAt: PeerSession.timestamp(now),
      serviceRegistered: true,
      listenerReady: true,
      listenerCancelled: true,
      network: try PeerNetworkReceipt(interfaceName: "en0", ipv4: "192.168.1.20"),
      listener: .fixed
    )
  }
}
