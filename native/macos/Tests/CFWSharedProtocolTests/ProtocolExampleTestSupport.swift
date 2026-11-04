import Foundation
import Testing

@testable import CFWSharedProtocol

// Shared by the task 2.6 example tests: in-memory digests, operations and
// events.
// MARK: - Shared in-memory factories

func exampleDigest(_ byte: Character) throws -> SHA256Digest {
  try SHA256Digest(hex: String(repeating: byte, count: 64))
}

func exampleTunnelOperation() throws -> OperationContext {
  let root = try RootContext(
    installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1)
  return try OperationContext(
    operationID: AuthorityIdentifier(UUID()), root: root, mode: .tunnel,
    configSHA256: try exampleDigest("a"), identitySHA256: try exampleDigest("b"),
    ownerUID: 501, authorityRevision: 1)
}

func exampleProxyOperation() throws -> OperationContext {
  let root = try RootContext(
    installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1)
  return try OperationContext(
    operationID: AuthorityIdentifier(UUID()), root: root, mode: .systemProxy,
    configSHA256: try exampleDigest("a"), identitySHA256: try exampleDigest("b"),
    ownerUID: 501, authorityRevision: 1)
}

func exampleStopEvent() throws -> AuthorityEvent {
  let operation = try exampleTunnelOperation()
  let directive = try StopDirective(
    operation: operation, leaseID: AuthorityIdentifier(UUID()),
    deadlineMonotonic: 1_000, revision: operation.authorityRevision)
  return .stop(directive)
}

func exampleSnapshotEvent() throws -> AuthorityEvent {
  let cursor = try ReplayCursor(
    installationID: AuthorityIdentifier(UUID()), acceptedEpoch: 1,
    acceptedGeneration: 1, revision: 1, previousRecordSHA256: try exampleDigest("c"))
  let snapshot = try AuthoritySnapshot(
    protocolVersion: try AuthorityProtocolVersion(), state: .off, revision: 1,
    replayCursor: cursor, leaseView: nil, lastFailure: nil, consoleUID: nil)
  return .snapshot(snapshot)
}
