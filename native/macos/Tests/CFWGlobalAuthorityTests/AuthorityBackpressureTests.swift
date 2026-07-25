import CFWSharedProtocol
import CryptoKit
import Foundation
import Testing

@testable import CFWGlobalAuthority

// Focused coverage for task 3.6 behaviors that the pure security state machine
// relies on: explicit busy/resource-exhausted backpressure and a bounded event
// queue that never silently drops revocation/stop directives under saturation.

private func backpressureDigest(_ data: Data) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: data).map {
      String(format: "%02x", $0)
    }.joined())
}

private func backpressureOperation() throws -> OperationContext {
  try OperationContext(
    operationID: AuthorityIdentifier(UUID()),
    root: RootContext(
      installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1),
    mode: .tunnel,
    configSHA256: try backpressureDigest(Data("config".utf8)),
    identitySHA256: try backpressureDigest(Data("identity".utf8)),
    ownerUID: 501, authorityRevision: 1)
}

private func backpressureStop() throws -> AuthorityEvent {
  let operation = try backpressureOperation()
  return .stop(
    try StopDirective(
      operation: operation, leaseID: AuthorityIdentifier(UUID()),
      deadlineMonotonic: 5_000, revision: operation.authorityRevision))
}

private func backpressureRevoke() throws -> AuthorityEvent {
  let operation = try backpressureOperation()
  return .revoke(
    try StopDirective(
      operation: operation, leaseID: AuthorityIdentifier(UUID()),
      deadlineMonotonic: 5_000, revision: operation.authorityRevision))
}

private func backpressureSnapshot() throws -> AuthorityEvent {
  .snapshot(
    try AuthoritySnapshot(
      protocolVersion: AuthorityProtocolVersion(),
      state: .off, revision: 1,
      replayCursor: try ReplayCursor(
        installationID: AuthorityIdentifier(UUID()),
        acceptedEpoch: 1, acceptedGeneration: 1, revision: 1,
        previousRecordSHA256: try backpressureDigest(Data("cursor".utf8))),
      leaseView: nil, lastFailure: nil, consoleUID: 501))
}

private func code(_ error: Error) -> AuthorityErrorCode? {
  (error as? AuthorityDomainError)?.code
}

@Test func mutationContentionReturnsBusyBackpressure() throws {
  let gate = AuthorityConcurrencyGate()
  var innerCode: AuthorityErrorCode?
  try gate.withMutation {
    do {
      try gate.withMutation {}
    } catch {
      innerCode = code(error)
    }
  }
  #expect(innerCode == .busy)
}

@Test func readOnlySaturationReturnsResourceExhausted() throws {
  let gate = AuthorityConcurrencyGate()

  func hold(_ remaining: Int) throws {
    guard remaining > 0 else { return }
    try gate.withRead { try hold(remaining - 1) }
  }

  // Exactly the maximum number of concurrent read-only requests is admitted.
  try hold(AuthorityV1Limits.maximumReadOnlyRequests)

  // One more concurrent read-only request beyond the bound is rejected with
  // explicit resource-exhausted backpressure rather than blocking.
  var overflowCode: AuthorityErrorCode?
  func holdThenOverflow(_ remaining: Int) throws {
    if remaining > 0 {
      try gate.withRead { try holdThenOverflow(remaining - 1) }
      return
    }
    do {
      try gate.withRead {}
    } catch {
      overflowCode = code(error)
    }
  }
  try holdThenOverflow(AuthorityV1Limits.maximumReadOnlyRequests)
  #expect(overflowCode == .resourceExhausted)
}

@Test func eventQueueNeverDropsStopUnderSaturation() throws {
  let queue = BoundedAuthorityEventQueue()
  let limit = AuthorityV1Limits.maximumQueuedEventsPerPeer

  for _ in 0..<limit {
    #expect(try queue.enqueue(backpressureStop()) == .queued)
  }
  #expect(queue.count == limit)

  // A saturated queue of control directives forces the peer to disconnect
  // instead of silently discarding a revoke/stop command.
  #expect(try queue.enqueue(backpressureStop()) == .peerMustDisconnect)
  #expect(try queue.enqueue(backpressureRevoke()) == .peerMustDisconnect)
  #expect(queue.count == limit)

  var controlEvents = 0
  while let event = queue.dequeue() {
    switch event {
    case .stop, .revoke: controlEvents += 1
    case .snapshot: Issue.record("Unexpected snapshot retained under saturation")
    }
  }
  #expect(controlEvents == limit)
}

@Test func eventQueueEvictsSnapshotToAdmitStop() throws {
  let queue = BoundedAuthorityEventQueue()
  let limit = AuthorityV1Limits.maximumQueuedEventsPerPeer

  #expect(try queue.enqueue(backpressureSnapshot()) == .queued)
  for _ in 0..<(limit - 1) {
    #expect(try queue.enqueue(backpressureStop()) == .queued)
  }
  #expect(queue.count == limit)

  // The queue is full but holds a coalescible snapshot; a stop directive
  // evicts the snapshot rather than being dropped.
  #expect(try queue.enqueue(backpressureStop()) == .queued)
  #expect(queue.count == limit)

  var controlEvents = 0
  var snapshots = 0
  while let event = queue.dequeue() {
    switch event {
    case .stop, .revoke: controlEvents += 1
    case .snapshot: snapshots += 1
    }
  }
  #expect(controlEvents == limit)
  #expect(snapshots == 0)
}
