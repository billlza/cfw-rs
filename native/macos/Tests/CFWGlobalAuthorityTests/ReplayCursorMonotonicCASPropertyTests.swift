import CFWSharedProtocol
import Foundation
import Testing

@testable import CFWGlobalAuthority

// MARK: - Property 5: Replay cursor is monotonic CAS
//
// For all Authority revisions, installation IDs, epochs, generations, duplicate
// requests, and commit reorderings, exactly one request can commit against an
// expected revision; a commit requires the immutable installation ID and a
// lexicographically newer (epoch, generation); the durable high-water cursor
// never decreases or accepts a consumed tuple again.
//
// This is a deterministic generative test that drives generated prepare/CAS
// attempts through the pure `GlobalAuthorityReducer` prepare path (with an
// abort + proven-Off reset between successful acquisitions so the durable
// high-water cursor persists across returns to Off). No real XPC, launchd,
// journal, or Network Extension boundary is used: every attempt is synthesized
// from a reproducible seed. After each applied attempt the harness checks the
// monotonic-CAS invariants against an independent oracle. On failure the seed
// and the shrunk attempt list are printed so the exact case can be replayed.
//
// **Validates: Requirements 2.6, 6.4**

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

// MARK: - Fixed shared digests / installations

private let cursorConfigDigest = try! SHA256Digest(hex: String(repeating: "a", count: 64))
private let cursorIdentityDigest = try! SHA256Digest(hex: String(repeating: "b", count: 64))
private let cursorNonce = try! SHA256Digest(hex: String(repeating: "c", count: 64))

/// The immutable installation the machine enrolls first, plus foreign lineages a
/// second, non-enrolled installation might present. Identity equality (not the
/// concrete UUID value) is what the CAS path arbitrates, so fixed deterministic
/// UUIDs keep a printed seed fully replayable.
private let canonicalInstallation = AuthorityIdentifier(
  UUID(uuidString: "0a000000-0000-0000-0000-0000000000a1")!)
private let foreignInstallations = [
  AuthorityIdentifier(UUID(uuidString: "0a000000-0000-0000-0000-0000000000a2")!),
  AuthorityIdentifier(UUID(uuidString: "0a000000-0000-0000-0000-0000000000a3")!),
  AuthorityIdentifier(UUID(uuidString: "0a000000-0000-0000-0000-0000000000a4")!),
]

/// Steady issued/expiry window inside the preparation lifetime bound.
private let cursorIssuedMonotonic: UInt64 = 1_000
private let cursorExpiryMonotonic: UInt64 = 11_000

private func exactOffProof() -> GlobalOffProof {
  GlobalOffProof(
    leaseReleased: true, capabilityOrTicketCleared: true,
    secretBufferCleared: true, ownerEndpointCleared: true,
    cleanup: .reconciledBoth(
      proxyListenerClosed: true, systemConfigurationRestored: true,
      providerLibboxStopped: true, packetPumpClosed: true),
    managedTunnel: .disconnected)
}

// MARK: - Generated attempt

/// One generated prepare/CAS attempt. Kept as small value data so a counterexample
/// can be shrunk by removing individual attempts and re-derived deterministically.
private struct CASAttempt {
  /// 0 selects the canonical installation; 1...n select a foreign installation.
  var installationIndex: Int
  var epoch: UInt64
  var generation: UInt64
  /// When true the attempt presents a wrong expected revision (stale CAS token).
  var staleRevision: Bool
  var mode: AuthorityMode
}

// MARK: - Property harness

private struct ReplayCursorMonotonicCASProperty {
  /// Result of replaying a whole attempt list: the violation (if any) plus
  /// coverage counters proving the batch actually exercised each guarded path.
  struct Outcome {
    var violation: String?
    var enrollments = 0
    var subsequentCommits = 0
    var staleRevisionRejected = 0
    var foreignInstallationRejected = 0
    var staleTupleRejected = 0
    var duplicateRevisionRejected = 0
  }

  private func installationID(for attempt: CASAttempt) -> AuthorityIdentifier {
    attempt.installationIndex == 0
      ? canonicalInstallation
      : foreignInstallations[attempt.installationIndex - 1]
  }

  /// Deterministic UUID from a namespace tag and index so operation/lease IDs are
  /// stable across generation and shrink replays of the same attempt list.
  private func deterministicUUID(tag: UInt32, index: Int) -> UUID {
    UUID(
      uuidString:
        String(format: "%08x-0000-0000-0000-%012x", tag, index))!
  }

  /// Generates an attempt list. Length varies so short and long CAS sequences are
  /// both exercised.
  func randomTrace(using rng: inout SplitMix64) -> [CASAttempt] {
    let count = rng.int(inRange: 12...36)
    return (0..<count).map { _ in
      let foreign = rng.int(inRange: 0...9) >= 8
      let installationIndex =
        foreign ? rng.int(inRange: 1...foreignInstallations.count) : 0
      return CASAttempt(
        installationIndex: installationIndex,
        epoch: UInt64(rng.int(inRange: 1...3)),
        generation: UInt64(rng.int(inRange: 1...12)),
        staleRevision: rng.int(inRange: 0...9) < 2,
        mode: rng.int(inRange: 0...1) == 0 ? .systemProxy : .tunnel)
    }
  }

  private func makeOperation(
    installation: AuthorityIdentifier, mode: AuthorityMode, epoch: UInt64,
    generation: UInt64, revision: UInt64, index: Int
  ) throws -> OperationContext {
    try OperationContext(
      operationID: AuthorityIdentifier(deterministicUUID(tag: 1, index: index)),
      root: RootContext(installationID: installation, epoch: epoch, generation: generation),
      mode: mode, configSHA256: cursorConfigDigest,
      identitySHA256: cursorIdentityDigest, ownerUID: 501,
      authorityRevision: revision)
  }

  private func makePrepareInput(
    installation: AuthorityIdentifier, mode: AuthorityMode, epoch: UInt64,
    generation: UInt64, expectedRevision: UInt64, index: Int
  ) throws -> AuthorityPrepareInput {
    let operation = try makeOperation(
      installation: installation, mode: mode, epoch: epoch, generation: generation,
      revision: expectedRevision, index: index)
    let descriptor = try AuthorityConfigurationDescriptor(
      byteCount: 3, configSHA256: cursorConfigDigest,
      identitySHA256: cursorIdentityDigest, credentialSlots: [],
      tunnelOptions: mode == .tunnel ? TunnelNetworkOptions(ipv6Enabled: true) : nil)
    let request = try PrepareStartRequest(
      operation: operation, expectedRevision: expectedRevision, configuration: descriptor)
    return AuthorityPrepareInput(
      request: request,
      leaseID: AuthorityIdentifier(deterministicUUID(tag: 2, index: index)),
      ownerConnectionNonce: cursorNonce, issuedMonotonic: cursorIssuedMonotonic,
      expiryMonotonic: cursorExpiryMonotonic, retainsSecretBuffer: mode == .tunnel)
  }

  /// Aborts the just-prepared operation and proves Global Off so the durable
  /// high-water cursor persists into the next attempt. Returns a violation string
  /// if the reset itself misbehaves.
  private func resetToOff(
    _ reducer: inout GlobalAuthorityReducer, operation: OperationContext
  ) -> String? {
    do {
      try reducer.abortPrepared(operation: operation, expectedRevision: reducer.revision)
      _ = try reducer.applyOffProof(exactOffProof(), expectedRevision: reducer.revision)
    } catch {
      return "reset to Off failed: \(error)"
    }
    guard reducer.state == .off else {
      return "reset did not reach Off: \(reducer.state)"
    }
    return nil
  }

  private func tuplesEqual(
    _ lhs: (UInt64, UInt64)?, _ rhs: (UInt64, UInt64)?
  ) -> Bool {
    switch (lhs, rhs) {
    case (nil, nil): return true
    case (let l?, let r?): return l == r
    default: return false
    }
  }

  /// Replays a whole attempt list against a fresh reducer, checking the
  /// monotonic-CAS invariants after each attempt. Returns a violation description
  /// (or nil) plus coverage counts.
  func run(_ attempts: [CASAttempt]) -> Outcome {
    var outcome = Outcome()
    var reducer: GlobalAuthorityReducer
    do {
      reducer = try .unEnrolledOff()
    } catch {
      outcome.violation = "reducer construction failed: \(error)"
      return outcome
    }

    // Independent oracle:
    // - `enrolled`: the immutable installation admitted by the first commit; every
    //   later commit must present this exact installation.
    // - `highWater`: the highest committed (epoch, generation); a commit requires a
    //   strictly greater tuple, so consumed tuples can never be accepted again.
    var enrolled: AuthorityIdentifier?
    var highWater: (UInt64, UInt64)?

    for (index, attempt) in attempts.enumerated() {
      guard reducer.state == .off else {
        outcome.violation = "reducer not Off before attempt \(index): \(reducer.state)"
        return outcome
      }

      let preRevision = reducer.revision
      let preCursorRevision = reducer.replayCursor?.revision
      let preCursorTuple = reducer.replayCursor.map {
        ($0.acceptedEpoch, $0.acceptedGeneration)
      }

      let installation = installationID(for: attempt)
      let expectedRevision = attempt.staleRevision ? (preRevision &+ 1) : preRevision

      // Oracle prediction. Order mirrors the reducer: expected-revision CAS first,
      // then immutable-installation equality, then strict tuple monotonicity.
      let revisionOK = !attempt.staleRevision
      let installationOK = enrolled == nil ? true : (installation == enrolled)
      let tupleOK: Bool
      if let highWater {
        tupleOK = (attempt.epoch, attempt.generation) > highWater
      } else {
        tupleOK = true
      }
      let shouldCommit = revisionOK && installationOK && tupleOK

      let input: AuthorityPrepareInput
      do {
        input = try makePrepareInput(
          installation: installation, mode: attempt.mode, epoch: attempt.epoch,
          generation: attempt.generation, expectedRevision: expectedRevision, index: index)
      } catch {
        outcome.violation = "attempt \(index) input construction threw: \(error)"
        return outcome
      }

      var committed = false
      do {
        _ = try reducer.prepare(input)
        committed = true
      } catch is AuthorityDomainError {
        committed = false
      } catch {
        outcome.violation = "attempt \(index) prepare raised a non-domain error: \(error)"
        return outcome
      }

      if committed != shouldCommit {
        outcome.violation =
          "attempt \(index) commit=\(committed) but oracle predicted \(shouldCommit) "
          + "(revisionOK=\(revisionOK), installationOK=\(installationOK), tupleOK=\(tupleOK))"
        return outcome
      }

      if committed {
        guard let cursor = reducer.replayCursor else {
          outcome.violation = "attempt \(index) committed without a replay cursor"
          return outcome
        }
        if cursor.installationID != installation {
          outcome.violation = "attempt \(index) cursor installation mutated on commit"
          return outcome
        }
        if cursor.acceptedEpoch != attempt.epoch
          || cursor.acceptedGeneration != attempt.generation
        {
          outcome.violation = "attempt \(index) cursor tuple not advanced to committed tuple"
          return outcome
        }
        if let preCursorRevision, cursor.revision <= preCursorRevision {
          outcome.violation =
            "attempt \(index) durable cursor revision did not increase "
            + "(\(preCursorRevision) -> \(cursor.revision))"
          return outcome
        }
        if reducer.revision <= preRevision {
          outcome.violation = "attempt \(index) authority revision did not increase on commit"
          return outcome
        }
        if let preCursorTuple, !((attempt.epoch, attempt.generation) > preCursorTuple) {
          outcome.violation = "attempt \(index) committed a non-newer tuple over high-water"
          return outcome
        }

        if enrolled == nil { outcome.enrollments += 1 } else { outcome.subsequentCommits += 1 }

        // Single-winner CAS: a second request presenting the pre-commit revision
        // (even with a strictly-newer tuple) must now be rejected, because exactly
        // one request may commit against a given expected revision.
        let duplicate = duplicateExpectedRevisionRejected(
          &reducer, preRevision: preRevision, installation: installation,
          over: (attempt.epoch, attempt.generation), index: index)
        if let reason = duplicate.violation {
          outcome.violation = reason
          return outcome
        }
        if duplicate.rejected { outcome.duplicateRevisionRejected += 1 }

        if enrolled == nil { enrolled = installation }
        highWater = (attempt.epoch, attempt.generation)

        if let reason = resetToOff(&reducer, operation: input.request.operation) {
          outcome.violation = reason
          return outcome
        }
      } else {
        // A rejected attempt must leave the durable cursor, revision, and state
        // untouched: the high-water mark never decreases and Off is preserved.
        if reducer.revision != preRevision {
          outcome.violation = "attempt \(index) was rejected but the authority revision changed"
          return outcome
        }
        let nowTuple = reducer.replayCursor.map {
          ($0.acceptedEpoch, $0.acceptedGeneration)
        }
        if !tuplesEqual(nowTuple, preCursorTuple) {
          outcome.violation = "attempt \(index) was rejected but the durable cursor tuple changed"
          return outcome
        }
        if reducer.replayCursor?.revision != preCursorRevision {
          outcome.violation =
            "attempt \(index) was rejected but the durable cursor revision changed"
          return outcome
        }
        if reducer.state != .off {
          outcome.violation = "attempt \(index) was rejected but left Off: \(reducer.state)"
          return outcome
        }

        if !revisionOK {
          outcome.staleRevisionRejected += 1
        } else if !installationOK {
          outcome.foreignInstallationRejected += 1
        } else if !tupleOK {
          outcome.staleTupleRejected += 1
        }
      }
    }

    return outcome
  }

  /// After a commit advanced the revision from `preRevision`, attempts a fresh
  /// prepare that still presents `preRevision` with a strictly-newer tuple. The
  /// reducer must reject it (the expected revision is consumed) without mutating
  /// the durable cursor. Returns whether it was correctly rejected, plus any
  /// violation.
  private func duplicateExpectedRevisionRejected(
    _ reducer: inout GlobalAuthorityReducer, preRevision: UInt64,
    installation: AuthorityIdentifier, over tuple: (UInt64, UInt64), index: Int
  ) -> (rejected: Bool, violation: String?) {
    let preCursorTuple = reducer.replayCursor.map {
      ($0.acceptedEpoch, $0.acceptedGeneration)
    }
    let input: AuthorityPrepareInput
    do {
      input = try makePrepareInput(
        installation: installation, mode: .systemProxy, epoch: tuple.0,
        generation: tuple.1 &+ 1, expectedRevision: preRevision, index: 100_000 + index)
    } catch {
      return (false, "attempt \(index) duplicate-CAS input construction threw: \(error)")
    }
    do {
      _ = try reducer.prepare(input)
      let reason = "attempt \(index) a second request committed against a consumed revision"
      return (false, reason)
    } catch is AuthorityDomainError {
      let nowTuple = reducer.replayCursor.map {
        ($0.acceptedEpoch, $0.acceptedGeneration)
      }
      if !tuplesEqual(nowTuple, preCursorTuple) {
        return (false, "attempt \(index) duplicate-CAS rejection still mutated the durable cursor")
      }
      return (true, nil)
    } catch {
      return (false, "attempt \(index) duplicate-CAS raised a non-domain error: \(error)")
    }
  }

  func evaluate(_ attempts: [CASAttempt]) -> String? { run(attempts).violation }

  /// Greedily removes attempts while the violation persists, terminating at a
  /// local minimum that still reproduces it.
  func shrink(_ attempts: [CASAttempt]) -> [CASAttempt] {
    var current = attempts
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

/// Base seed. Override with `CFW_PBT_SEED_PROP5` to replay a printed failure.
private func baseSeed() -> UInt64 {
  if let raw = ProcessInfo.processInfo.environment["CFW_PBT_SEED_PROP5"],
    let value = UInt64(raw)
  {
    return value
  }
  return 0xC0FF_EE13_A5A5_0005
}

@Test func replayCursorIsMonotonicCASAcrossRevisionsAndReorderings() {
  let property = ReplayCursorMonotonicCASProperty()
  let seed = baseSeed()
  let iterations = 160

  var successfulCases = 0
  var enrollmentCases = 0
  var subsequentCommitCases = 0
  var staleRevisionCases = 0
  var foreignInstallationCases = 0
  var staleTupleCases = 0
  var duplicateRevisionCases = 0
  var failure: (seed: UInt64, attempts: [CASAttempt], reason: String)?

  for index in 0..<iterations {
    let iterationSeed = seed &+ UInt64(index)
    var rng = SplitMix64(seed: iterationSeed)
    let attempts = property.randomTrace(using: &rng)
    let outcome = property.run(attempts)

    if let reason = outcome.violation {
      let shrunk = property.shrink(attempts)
      let shrunkReason = property.evaluate(shrunk) ?? reason
      failure = (iterationSeed, shrunk, shrunkReason)
      break
    }

    if outcome.enrollments > 0 { enrollmentCases += 1 }
    if outcome.subsequentCommits > 0 { subsequentCommitCases += 1 }
    if outcome.staleRevisionRejected > 0 { staleRevisionCases += 1 }
    if outcome.foreignInstallationRejected > 0 { foreignInstallationCases += 1 }
    if outcome.staleTupleRejected > 0 { staleTupleCases += 1 }
    if outcome.duplicateRevisionRejected > 0 { duplicateRevisionCases += 1 }
    successfulCases += 1
  }

  if let failure {
    Issue.record(
      """
      Property 5 counterexample found.
      reproduce with: CFW_PBT_SEED_PROP5=\(failure.seed)
      shrunk attempts (\(failure.attempts.count)): \(failure.attempts)
      violation: \(failure.reason)
      """)
  }

  #expect(failure == nil)
  #expect(
    successfulCases >= 100,
    "expected at least 100 successful generated cases, ran \(successfulCases)")
  // The batch must actually exercise the transitions this property guards:
  // enrollment, subsequent monotonic commits, and every rejection reason
  // (stale expected revision, foreign installation, non-newer tuple), plus the
  // single-winner expected-revision CAS.
  #expect(enrollmentCases > 0, "generated batch never enrolled an installation")
  #expect(subsequentCommitCases > 0, "generated batch never committed a newer generation")
  #expect(staleRevisionCases > 0, "generated batch never rejected a stale expected revision")
  #expect(
    foreignInstallationCases > 0,
    "generated batch never rejected a foreign installation ID")
  #expect(staleTupleCases > 0, "generated batch never rejected a non-newer (epoch, generation)")
  #expect(
    duplicateRevisionCases > 0,
    "generated batch never exercised single-winner expected-revision CAS")
}
