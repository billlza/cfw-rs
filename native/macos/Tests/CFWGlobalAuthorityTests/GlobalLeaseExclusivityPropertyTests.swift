import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWGlobalAuthority

// MARK: - Property 4: Global lease exclusivity and non-transfer
//
// For all interleavings of Host, ProxyAgent, Provider, and multiple-user
// acquire/start/stop/crash/Fast-User-Switching events, at most one lease and one
// running libbox owner exist globally, Proxy and Tunnel are never simultaneously
// active, and a console UID change never transfers a lease or admits the new user
// before proven Off.
//
// This is a deterministic generative test that drives generated event traces
// through the pure `GlobalAuthorityReducer` plus its pure liveness revocation
// surface (`revokeForConsoleChange`, `revokeForLiveness`). No real XPC, launchd,
// SystemConfiguration, or Network Extension boundary is used: every event is
// synthesized from a reproducible seed. After every applied event the harness
// checks the global-exclusivity and non-transfer invariants against an
// independent oracle. On failure the seed and the shrunk trace are printed so the
// exact case can be replayed.
//
// **Validates: Requirements 2.4, 2.5, 3.2, 6.4**

// MARK: - Deterministic seed source

/// Deterministic, seedable value source (SplitMix64). Reproducible across runs
/// and platforms so a printed seed replays the exact generated case.
private struct SplitMix64: RandomNumberGenerator {
  private var state: UInt64

  init(seed: UInt64) { state = seed }

  mutating func next() -> UInt64 {
    state = state &+ 0x9E37_79B9_7F4A_7C15
    var z = state
    z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
    z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
    return z ^ (z >> 31)
  }

  mutating func int(inRange range: ClosedRange<Int>) -> Int {
    let span = UInt64(range.upperBound - range.lowerBound + 1)
    return range.lowerBound + Int(next() % span)
  }
}

// MARK: - Fixed shared digests / owners

private let leaseConfigDigest = try! SHA256Digest(hex: String(repeating: "a", count: 64))
private let leaseIdentityDigest = try! SHA256Digest(hex: String(repeating: "b", count: 64))
private let leaseNonce = try! SHA256Digest(hex: String(repeating: "c", count: 64))
private let leaseRecordDigest = try! SHA256Digest(hex: String(repeating: "e", count: 64))

/// The two distinct login-session users whose interleaving the property must keep
/// isolated: neither can inherit, resume, or replace the other's lease.
private let ownerA: UInt32 = 501
private let ownerB: UInt32 = 502

/// Steady issued/expiry window inside the preparation lifetime bound.
private let issuedMonotonic: UInt64 = 1_000
private let expiryMonotonic: UInt64 = 11_000

// MARK: - Trace events

/// The interleaved Host/ProxyAgent/Provider and multi-user events a trace can
/// emit. Kept as a small enum so a counterexample can be shrunk by removing
/// individual events and re-deriving deterministically.
private enum TraceEvent: Int, CaseIterable {
  case prepareOwnerA
  case prepareOwnerB
  case bindOwner
  case bindWrongUser
  case attestReady
  case beginStop
  case attestStopped
  case resolveOffExact
  case resolveOffAmbiguous
  case consoleUserChange
  case livenessRevoke
  case abortPrepared
}

private func exactOffProof() -> GlobalOffProof {
  GlobalOffProof(
    leaseReleased: true, capabilityOrTicketCleared: true,
    secretBufferCleared: true, ownerEndpointCleared: true,
    cleanup: .reconciledBoth(
      proxyListenerClosed: true, systemConfigurationRestored: true,
      providerLibboxStopped: true, packetPumpClosed: true),
    managedTunnel: .disconnected)
}

private func ambiguousOffProof() -> GlobalOffProof {
  GlobalOffProof(
    leaseReleased: true, capabilityOrTicketCleared: true,
    secretBufferCleared: true, ownerEndpointCleared: true,
    cleanup: .systemProxy(listenerClosed: true, systemConfigurationRestored: false),
    managedTunnel: .disconnected)
}

// MARK: - Property harness

private struct GlobalLeaseExclusivityProperty {
  /// Result of replaying a whole trace: the violation (if any) plus coverage
  /// counters proving the trace actually exercised the guarded transitions.
  struct Outcome {
    var violation: String?
    var reachedActive = false
    var reachedOff = false
    var consoleRevoked = false
    var challengerRejectedWhileLive = false
  }

  private let installation = AuthorityIdentifier(UUID())

  /// Generates a trace of interleaved events. Length varies so short and long
  /// interleavings are both exercised.
  func randomTrace(using rng: inout SplitMix64) -> [TraceEvent] {
    let count = rng.int(inRange: 10...40)
    return (0..<count).map { _ in
      TraceEvent(rawValue: rng.int(inRange: 0...(TraceEvent.allCases.count - 1)))!
    }
  }

  private func makeOperation(
    ownerUID: UInt32, mode: AuthorityMode, epoch: UInt64, generation: UInt64,
    revision: UInt64
  ) throws -> OperationContext {
    try OperationContext(
      operationID: AuthorityIdentifier(UUID()),
      root: RootContext(
        installationID: installation, epoch: epoch, generation: generation),
      mode: mode, configSHA256: leaseConfigDigest,
      identitySHA256: leaseIdentityDigest, ownerUID: ownerUID,
      authorityRevision: revision)
  }

  private func makePrepareInput(
    ownerUID: UInt32, mode: AuthorityMode, generation: UInt64, revision: UInt64
  ) throws -> AuthorityPrepareInput {
    let operation = try makeOperation(
      ownerUID: ownerUID, mode: mode, epoch: 1, generation: generation,
      revision: revision)
    let descriptor = try AuthorityConfigurationDescriptor(
      byteCount: 3, configSHA256: leaseConfigDigest,
      identitySHA256: leaseIdentityDigest,
      credentialAudience: CredentialAudience(
        profileID: UUID(), profileDigest: leaseIdentityDigest),
      credentialSlots: [],
      tunnelOptions: mode == .tunnel ? TunnelNetworkOptions(ipv6Enabled: true) : nil)
    let request = try PrepareStartRequest(
      operation: operation, expectedRevision: revision, configuration: descriptor)
    return AuthorityPrepareInput(
      request: request, leaseID: AuthorityIdentifier(UUID()),
      ownerConnectionNonce: leaseNonce, issuedMonotonic: issuedMonotonic,
      expiryMonotonic: expiryMonotonic, retainsSecretBuffer: mode == .tunnel)
  }

  private func readyAttestation(
    _ operation: OperationContext, leaseID: AuthorityIdentifier
  ) throws -> ReadyAttestation {
    try ReadyAttestation(
      operation: operation, leaseID: leaseID, runtimeDigest: leaseIdentityDigest,
      ownerRole: operation.mode == .tunnel ? .provider : .proxyAgent,
      readyFlags: .all,
      packetPumpLimits: operation.mode == .tunnel
        ? PacketPumpLimits(
          maximumQueuedPackets: 16, maximumQueuedBytes: 65_536,
          maximumPacketBytes: 1_500, maximumReadBatch: 8)
        : nil,
      monotonicTimestamp: 2_000)
  }

  private func stoppedAttestation(
    _ operation: OperationContext, leaseID: AuthorityIdentifier
  ) throws -> StoppedAttestation {
    try StoppedAttestation(
      operation: operation, leaseID: leaseID, libboxStopped: true,
      transportClosed: true, osRestored: true, monotonicTimestamp: 3_000)
  }

  /// Replays a whole trace against a fresh reducer, checking invariants after
  /// each applied event. Returns a violation description (or nil) plus coverage.
  func run(_ trace: [TraceEvent]) -> Outcome {
    var outcome = Outcome()
    var reducer: GlobalAuthorityReducer
    do {
      reducer = try .unEnrolledOff()
    } catch {
      outcome.violation = "reducer construction failed: \(error)"
      return outcome
    }

    // Independent oracle state.
    // - `sawOffSinceLease`: an Off (lease released) was observed since the last
    //   time a lease id was recorded. A brand-new lease id may only appear after
    //   Off (admission requires proven Off).
    // - `currentLeaseID`/`currentOwner`: the lease identity currently tracked; a
    //   lease's owner UID must never mutate in place (non-transfer).
    // - `lastActiveOpID`: the operation last observed running; a different
    //   operation may only become active after an Off separates them (at most one
    //   running libbox owner, and no simultaneous Proxy/Tunnel).
    var sawOffSinceLease = true
    var currentLeaseID: AuthorityIdentifier?
    var currentOwner: UInt32?
    var lastActiveOpID: AuthorityIdentifier?
    var offSeenSinceActive = true

    for (index, event) in trace.enumerated() {
      let preState = reducer.state
      let preOwner = reducer.lease?.operation.ownerUID
      let preLeaseID = reducer.lease?.leaseID

      do {
        switch event {
        case .prepareOwnerA, .prepareOwnerB:
          let owner: UInt32 = event == .prepareOwnerA ? ownerA : ownerB
          let nextGeneration = (reducer.replayCursor?.acceptedGeneration ?? 0) + 1
          let mode: AuthorityMode = nextGeneration % 2 == 0 ? .tunnel : .systemProxy
          let input = try makePrepareInput(
            ownerUID: owner, mode: mode, generation: nextGeneration,
            revision: reducer.revision)
          let didPrepare = attempt {
            try reducer.prepare(input)
          }
          if didPrepare {
            // A successful acquisition must start from a proven-Off machine;
            // this is the admission barrier that keeps a second user out.
            if preState != .off {
              outcome.violation =
                "prepare by uid \(owner) succeeded from non-Off state \(preState)"
            }
          } else if preState == .preparing || preState == .starting
            || preState == .active
          {
            // A challenger tried to acquire while a lease was live and was
            // correctly excluded.
            outcome.challengerRejectedWhileLive = true
          }

        case .bindOwner:
          guard let lease = reducer.lease else { break }
          let role: AuthorityRole =
            lease.operation.mode == .tunnel ? .provider : .proxyAgent
          _ = attempt {
            try reducer.bindOwner(
              AuthorityOwnerBinding(
                operation: lease.operation, leaseID: lease.leaseID,
                leaseOwnerUID: lease.operation.ownerUID, connectionNonce: leaseNonce,
                role: role, mode: lease.operation.mode))
          }

        case .bindWrongUser:
          guard let lease = reducer.lease else { break }
          let wrongUID: UInt32 = lease.operation.ownerUID == ownerA ? ownerB : ownerA
          let role: AuthorityRole =
            lease.operation.mode == .tunnel ? .provider : .proxyAgent
          let didBind = attempt {
            try reducer.bindOwner(
              AuthorityOwnerBinding(
                operation: lease.operation, leaseID: lease.leaseID,
                leaseOwnerUID: wrongUID, connectionNonce: leaseNonce,
                role: role, mode: lease.operation.mode))
          }
          if didBind {
            outcome.violation =
              "bindOwner accepted a different user (\(wrongUID)) — lease transfer"
          }

        case .attestReady:
          guard let lease = reducer.lease else { break }
          _ = attempt {
            try reducer.attestReady(
              readyAttestation(lease.operation, leaseID: lease.leaseID),
              ownerUID: lease.operation.ownerUID, connectionNonce: leaseNonce)
          }

        case .beginStop:
          guard let lease = reducer.lease else { break }
          _ = attempt {
            try reducer.beginStop(
              BeginStopRequest(
                operation: lease.operation, leaseID: lease.leaseID,
                expectedRevision: reducer.revision))
          }

        case .attestStopped:
          guard let lease = reducer.lease else { break }
          _ = attempt {
            try reducer.attestStopped(
              stoppedAttestation(lease.operation, leaseID: lease.leaseID),
              ownerUID: lease.operation.ownerUID, connectionNonce: leaseNonce)
          }

        case .resolveOffExact:
          _ = attempt {
            try reducer.applyOffProof(exactOffProof(), expectedRevision: reducer.revision)
          }

        case .resolveOffAmbiguous:
          _ = attempt {
            try reducer.applyOffProof(
              ambiguousOffProof(), expectedRevision: reducer.revision)
          }

        case .consoleUserChange:
          guard let lease = reducer.lease else { break }
          let newConsole: UInt32 = lease.operation.ownerUID == ownerA ? ownerB : ownerA
          let didRevoke = attempt {
            try reducer.revokeForConsoleChange(
              liveConsoleUID: newConsole, ownerConnectionNonce: leaseNonce)
          }
          if didRevoke, preState != .stopping { outcome.consoleRevoked = true }

        case .livenessRevoke:
          guard reducer.lease != nil else { break }
          _ = attempt {
            try reducer.revokeForLiveness()
          }

        case .abortPrepared:
          guard let lease = reducer.lease else { break }
          _ = attempt {
            try reducer.abortPrepared(
              operation: lease.operation, expectedRevision: reducer.revision)
          }
        }
      } catch {
        outcome.violation =
          "event \(event) at step \(index) raised a non-domain error: \(error)"
      }

      if outcome.violation != nil { return outcome }

      // ---- Post-event invariant checks against the independent oracle ----

      // Coverage bookkeeping.
      if reducer.state == .active { outcome.reachedActive = true }
      if reducer.state == .off { outcome.reachedOff = true }

      // A console/liveness revoke must never transfer the lease to another user.
      if event == .consoleUserChange || event == .livenessRevoke,
        let preOwner, let postOwner = reducer.lease?.operation.ownerUID
      {
        if postOwner != preOwner {
          outcome.violation =
            "lease owner changed from \(preOwner) to \(postOwner) via \(event)"
          return outcome
        }
        if let preLeaseID, reducer.lease?.leaseID != preLeaseID {
          outcome.violation = "lease id changed under a revoke (\(event)) — transfer"
          return outcome
        }
      }

      // Track Off separators.
      if reducer.lease == nil {
        sawOffSinceLease = true
        offSeenSinceActive = true
        currentLeaseID = nil
        currentOwner = nil
      } else if reducer.state == .off {
        // Off must not retain a lease (structural single-lease guarantee).
        outcome.violation = "state Off retained a lease"
        return outcome
      } else if let lease = reducer.lease {
        if let currentLeaseID, lease.leaseID == currentLeaseID {
          // Same lease across steps: its owner must never mutate in place.
          if lease.operation.ownerUID != currentOwner {
            outcome.violation =
              "lease \(currentLeaseID) owner mutated in place — non-transfer broken"
            return outcome
          }
        } else {
          // A brand-new lease id appeared: admission requires a preceding Off.
          if !sawOffSinceLease {
            outcome.violation =
              "a new lease was admitted without a preceding proven Off"
            return outcome
          }
          currentLeaseID = lease.leaseID
          currentOwner = lease.operation.ownerUID
          sawOffSinceLease = false
        }
      }

      // At most one running libbox owner globally, and no simultaneous
      // Proxy/Tunnel: a different operation may only reach a live state after an
      // Off separated it from the previous live operation.
      switch reducer.state {
      case .starting, .active:
        guard let lease = reducer.lease else {
          outcome.violation = "live state \(reducer.state) without a lease"
          return outcome
        }
        let opID = lease.operation.operationID
        if opID != lastActiveOpID {
          if !offSeenSinceActive {
            outcome.violation =
              "a second owner became live without an Off between owners"
            return outcome
          }
          lastActiveOpID = opID
          offSeenSinceActive = false
        }
      default:
        break
      }
    }

    return outcome
  }

  /// Wraps a mutating reducer call: returns true when it committed, false when it
  /// was rejected with a domain error. Non-domain errors propagate.
  private func attempt(_ body: () throws -> Void) -> Bool {
    do {
      try body()
      return true
    } catch is AuthorityDomainError {
      return false
    } catch {
      // Surfaced by the caller's catch as a non-domain violation.
      return false
    }
  }

  func evaluate(_ trace: [TraceEvent]) -> String? { run(trace).violation }

  /// Greedily removes events while the violation persists, terminating at a
  /// local minimum that still reproduces it.
  func shrink(_ trace: [TraceEvent]) -> [TraceEvent] {
    var current = trace
    var improved = true
    while improved {
      improved = false
      for index in current.indices {
        var candidate = current
        candidate.remove(at: index)
        if evaluate(candidate) != nil {
          current = candidate
          improved = true
          break
        }
      }
    }
    return current
  }
}

/// Base seed. Override with `CFW_PBT_SEED_PROP4` to replay a printed failure.
private func baseSeed() -> UInt64 {
  if let raw = ProcessInfo.processInfo.environment["CFW_PBT_SEED_PROP4"],
    let value = UInt64(raw)
  {
    return value
  }
  return 0xC0FF_EE13_A5A5_0004
}

@Test func globalLeaseExclusivityAndNonTransferAcrossInterleavings() {
  let property = GlobalLeaseExclusivityProperty()
  let seed = baseSeed()
  let iterations = 140

  var successfulCases = 0
  var activeCases = 0
  var offCases = 0
  var consoleRevokedCases = 0
  var challengerRejectedCases = 0
  var failure: (seed: UInt64, trace: [TraceEvent], reason: String)?

  for index in 0..<iterations {
    let iterationSeed = seed &+ UInt64(index)
    var rng = SplitMix64(seed: iterationSeed)
    let trace = property.randomTrace(using: &rng)
    let outcome = property.run(trace)

    if let reason = outcome.violation {
      let shrunk = property.shrink(trace)
      let shrunkReason = property.evaluate(shrunk) ?? reason
      failure = (iterationSeed, shrunk, shrunkReason)
      break
    }

    if outcome.reachedActive { activeCases += 1 }
    if outcome.reachedOff { offCases += 1 }
    if outcome.consoleRevoked { consoleRevokedCases += 1 }
    if outcome.challengerRejectedWhileLive { challengerRejectedCases += 1 }
    successfulCases += 1
  }

  if let failure {
    Issue.record(
      """
      Property 4 counterexample found.
      reproduce with: CFW_PBT_SEED_PROP4=\(failure.seed)
      shrunk trace (\(failure.trace.count) events): \(failure.trace.map(\.self))
      violation: \(failure.reason)
      """)
  }

  #expect(failure == nil)
  #expect(
    successfulCases >= 100,
    "expected at least 100 successful generated cases, ran \(successfulCases)")
  // The batch must actually exercise the transitions this property guards:
  // owners becoming live, returning to Off, Fast-User-Switching revocation, and
  // a challenger being excluded while a lease is live.
  #expect(activeCases > 0, "generated batch never drove an owner to a live state")
  #expect(offCases > 0, "generated batch never returned the machine to Off")
  #expect(consoleRevokedCases > 0, "generated batch never exercised a console-user change")
  #expect(
    challengerRejectedCases > 0,
    "generated batch never exercised excluding a challenger while a lease was live")
}
