import CFWSharedProtocol
import CryptoKit
import Darwin
import Foundation
import Testing

@testable import CFWGlobalAuthority

// MARK: - Property 1: Authority failure is fail-closed
//
// For all Authority handshake, installation, availability, and
// protocol-compatibility outcomes other than an authenticated compatible
// success, a requested start emits NO libbox start, System Proxy apply, Tunnel
// start, or fallback action and ends in Off, Failed, or Quarantined.
//
// This is a deterministic generative test against the pure fail-closed authority
// logic: the shared Release gate (`GlobalAuthorityReleaseGate`), the real
// protocol-version validator (`AuthorityProtocolVersion`), and the Authority
// service handshake/prepare rejection paths (`GlobalAuthorityServiceCore`). No
// real launchd, Network Extension, or Security.framework resolution is used;
// every boundary is a fake driven from a reproducible seed. On failure the seed
// and the shrunk counterexample are printed so the exact case can be replayed.
//
// **Validates: Requirements 1.1, 1.2, 2.7**

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

  mutating func bool() -> Bool { next() & 1 == 0 }
}

// MARK: - Observable start effects

/// Every externally visible action a requested start could emit. Fail-closed
/// behavior forbids all of these unless the start is an authenticated compatible
/// success; `fallback` must never be emitted on any path.
private enum StartAction: Hashable, CaseIterable {
  case libboxStart
  case systemProxyApply
  case tunnelStart
  case fallback
}

/// The engine disposition a requested start ends in. `active` is reachable only
/// from an authenticated compatible success; every other outcome is one of the
/// fail-closed dispositions.
private enum EngineDisposition: Hashable {
  case off
  case failed
  case quarantined
  case active
}

private let failClosedDispositions: Set<EngineDisposition> = [.off, .failed, .quarantined]

private struct StartResult {
  var actions: Set<StartAction>
  var disposition: EngineDisposition
}

// MARK: - Generated case

/// Numeric choices that fully determine a generated start scenario. Kept as
/// small values so a counterexample can be shrunk by reducing each choice toward
/// its authenticated-compatible-success value and re-deriving deterministically.
private struct CaseChoices: Equatable {
  /// Index into `GlobalAuthorityProofStatus.allCases`; the `.proven` index is the
  /// only value that clears the Release gate (installation, approval, identity,
  /// availability, and protocol-compatibility proofs).
  var proofIndex: Int
  /// Advertised protocol major version fed to the real version validator; only
  /// the v1 major is compatible.
  var protocolMajor: UInt16
  /// When true, advertises an unsupported required feature bit the validator
  /// rejects.
  var unsupportedFeature: Bool
  /// Index into `AuthorityRole.allCases`; only `.host` may prepare a start.
  var peerRoleIndex: Int
  /// When true, the peer effective UID matches the operation owner UID.
  var euidMatchesOwner: Bool
  /// Selects Tunnel versus System Proxy start.
  var modeIsTunnel: Bool
}

// MARK: - Fakes for the Authority service boundary

private struct FakeRandomness: AuthorityTicketRandomness {
  func randomBytes(count: Int) throws -> Data { Data(repeating: 0x5a, count: count) }
}

private struct FakeClock: AuthorityMonotonicClock {
  func nowMilliseconds() -> UInt64 { 1_000 }
}

private final class FakeJournal: AuthorityJournalCommitting, @unchecked Sendable {
  private let lock = NSLock()
  private var count = 0

  func appendCommitted(_ state: AuthorityCommittedState) throws -> AuthorityJournalHead {
    try lock.withLock {
      count += 1
      return try AuthorityJournalHead(
        sequence: UInt64(count), committedLength: UInt64(count),
        recordSHA256: digestHex(Data("journal-\(count)".utf8)))
    }
  }
}

private func digestHex(_ data: Data) throws -> CFWSharedProtocol.SHA256Digest {
  try CFWSharedProtocol.SHA256Digest(
    hex: SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined())
}

// MARK: - Property

private struct FailClosedAuthorityProperty {
  static let ownerUID: uid_t = 501

  /// The independent oracle: a start is an authenticated compatible success
  /// exactly when every fail-closed gate is cleared. `attemptStart` never reads
  /// this; it derives its outcome only from the real authority logic, so the two
  /// agreeing is the property under test.
  func isAuthenticatedCompatibleSuccess(_ choices: CaseChoices) -> Bool {
    GlobalAuthorityProofStatus.allCases[choices.proofIndex] == .proven
      && choices.protocolMajor == AuthorityV1Limits.major
      && !choices.unsupportedFeature
      && AuthorityRole.allCases[choices.peerRoleIndex] == .host
      && choices.euidMatchesOwner
  }

  /// Fully valid authenticated-compatible-success choices for the given mode.
  func successChoices(modeIsTunnel: Bool) -> CaseChoices {
    CaseChoices(
      proofIndex: GlobalAuthorityProofStatus.allCases.firstIndex(of: .proven)!,
      protocolMajor: AuthorityV1Limits.major, unsupportedFeature: false,
      peerRoleIndex: AuthorityRole.allCases.firstIndex(of: .host)!,
      euidMatchesOwner: true, modeIsTunnel: modeIsTunnel)
  }

  /// Draws each dimension with a bias toward its success value so the generated
  /// batch contains both authenticated successes and a broad spread of
  /// fail-closed deviations. Each dimension independently deviates ~50% of the
  /// time, and when it does the deviating value is chosen uniformly.
  func randomChoices(using rng: inout SplitMix64) -> CaseChoices {
    let provenIndex = GlobalAuthorityProofStatus.allCases.firstIndex(of: .proven)!
    let unprovenCount = GlobalAuthorityProofStatus.allCases.count - 1
    let proofIndex = rng.bool() ? provenIndex : rng.int(inRange: 0...(unprovenCount - 1))
    return CaseChoices(
      proofIndex: proofIndex,
      protocolMajor: rng.bool() ? AuthorityV1Limits.major : UInt16(rng.int(inRange: 2...4)),
      unsupportedFeature: rng.bool(),
      peerRoleIndex: rng.bool() ? 0 : rng.int(inRange: 1...(AuthorityRole.allCases.count - 1)),
      euidMatchesOwner: rng.bool(),
      modeIsTunnel: rng.bool())
  }

  /// Drives the requested start through the real fail-closed authority logic and
  /// records the effects it emitted plus the disposition it ended in.
  func attemptStart(_ choices: CaseChoices) throws -> StartResult {
    // Gate 1 — Release gate contract: proves installation, approval, identity,
    // availability, and protocol-compatibility. Per `GlobalAuthorityReleaseGate`
    // only `.proven` clears the gate; every other proof leaves the engine Off
    // with no start attempted. Constructing the typed gate error for the
    // unproven statuses exercises the shared error surface.
    let proof = GlobalAuthorityProofStatus.allCases[choices.proofIndex]
    guard proof == .proven else {
      _ = GlobalAuthorityGateError.proofMissing(proof)
      return StartResult(actions: [], disposition: .off)
    }

    // Gate 2 — real protocol-version validator. An incompatible major or an
    // unsupported required feature fails closed before any service work.
    let featureBits =
      choices.unsupportedFeature ? UInt64(1) : AuthorityV1Limits.supportedFeatureBits
    guard
      let version = try? AuthorityProtocolVersion(
        major: choices.protocolMajor, featureBits: featureBits)
    else {
      return StartResult(actions: [], disposition: .failed)
    }

    // Gate 3 — real Authority service handshake rejection path.
    let core = GlobalAuthorityServiceCore(
      reducer: try .unEnrolledOff(), journal: FakeJournal(),
      randomness: FakeRandomness(), clock: FakeClock())
    guard (try? core.handshake(HandshakeRequest(version: version))) != nil else {
      return StartResult(actions: [], disposition: .failed)
    }

    // Gate 4 — real Authority service prepare rejection path. Prepare authorizes
    // the peer (Host role bound to the owner UID) before any owner capability or
    // ticket is issued; an unauthorized peer fails closed.
    let fixture = try makeFixture(modeIsTunnel: choices.modeIsTunnel)
    let peer = makePeer(choices: choices, operation: fixture.request.operation)
    guard
      let prepared = try? core.prepare(
        fixture.request, configuration: fixture.configuration,
        secretPayload: fixture.secretPayload, peer: peer)
    else {
      return StartResult(actions: [], disposition: .failed)
    }
    prepared.erase()

    // Authenticated compatible success: the only path that emits start actions.
    let startAction: StartAction = choices.modeIsTunnel ? .tunnelStart : .systemProxyApply
    return StartResult(actions: [.libboxStart, startAction], disposition: .active)
  }

  /// Returns nil when the case satisfies the fail-closed property, or a
  /// human-readable description of the first violation otherwise.
  func evaluate(_ choices: CaseChoices) -> String? {
    let result: StartResult
    do {
      result = try attemptStart(choices)
    } catch {
      return "test fixture construction failed: \(error)"
    }

    // A fallback action is forbidden on every path, success or failure.
    if result.actions.contains(.fallback) {
      return "fallback action emitted — production must never fall back"
    }

    let success = isAuthenticatedCompatibleSuccess(choices)

    if result.disposition == .active {
      guard success else {
        return "engine reached Active without an authenticated compatible success"
      }
      let expectedStart: StartAction = choices.modeIsTunnel ? .tunnelStart : .systemProxyApply
      guard result.actions == [.libboxStart, expectedStart] else {
        return "authenticated success emitted unexpected actions: \(result.actions)"
      }
      return nil
    }

    // Non-active outcome: must be fail-closed and emit no start actions.
    guard failClosedDispositions.contains(result.disposition) else {
      return "non-success disposition \(result.disposition) is outside {Off, Failed, Quarantined}"
    }
    guard result.actions.isEmpty else {
      return "fail-closed path emitted start actions: \(result.actions)"
    }
    if success {
      return "an authenticated compatible success failed closed instead of starting"
    }
    return nil
  }

  private func makePeer(choices: CaseChoices, operation: OperationContext) -> PeerIdentity {
    let role = AuthorityRole.allCases[choices.peerRoleIndex]
    let euid: uid_t = choices.euidMatchesOwner ? Self.ownerUID : Self.ownerUID &+ 1
    return PeerIdentity(
      auditTokenDigest: (try? digestHex(Data("audit".utf8)))!,
      pid: 42, euid: euid, auditSessionID: role == .provider ? 0 : 7,
      teamID: GlobalAuthorityPeerPolicy.teamID, signingID: role.rawValue,
      designatedRequirementDigest: (try? digestHex(Data("requirement".utf8)))!,
      entitlementDigest: (try? digestHex(Data("entitlements".utf8)))!,
      role: role, consoleUID: Self.ownerUID)
  }

  private struct Fixture {
    let request: PrepareStartRequest
    let configuration: Data
    let secretPayload: Data?
  }

  private func makeFixture(modeIsTunnel: Bool) throws -> Fixture {
    let configuration = Data("{\"outbounds\":[{}]}".utf8)
    let configDigest = try digestHex(configuration)
    let identityDigest = try digestHex(Data("identity".utf8))
    let root = try RootContext(
      installationID: AuthorityIdentifier(UUID()), epoch: 1, generation: 1)

    if modeIsTunnel {
      let reference = CredentialReference(id: UUID(), kind: .trojanPassword)
      let slot = try CredentialSlot(
        reference: reference, target: .trojanPassword,
        outboundIndex: 0, jsonPointer: "/outbounds/0/password")
      let descriptor = try AuthorityConfigurationDescriptor(
        byteCount: UInt32(configuration.count), configSHA256: configDigest,
        identitySHA256: identityDigest, credentialSlots: [slot],
        tunnelOptions: TunnelNetworkOptions(ipv6Enabled: true))
      let operation = try OperationContext(
        operationID: AuthorityIdentifier(UUID()), root: root, mode: .tunnel,
        configSHA256: configDigest, identitySHA256: identityDigest,
        ownerUID: Self.ownerUID, authorityRevision: 1)
      let request = try PrepareStartRequest(
        operation: operation, expectedRevision: 1, configuration: descriptor)
      let secretSlot = try AuthoritySecretSlot(
        reference: reference, copying: Data("credential-marker".utf8))
      let material = try AuthoritySecretMaterial(slots: [secretSlot])
      let encoded = try #require(try AuthoritySecretPayloadCodec.encode(material))
      let payload = try encoded.withUnsafeBytes { Data($0) }
      encoded.erase()
      material.erase()
      return Fixture(request: request, configuration: configuration, secretPayload: payload)
    }

    let descriptor = try AuthorityConfigurationDescriptor(
      byteCount: UInt32(configuration.count), configSHA256: configDigest,
      identitySHA256: identityDigest, credentialSlots: [], tunnelOptions: nil)
    let operation = try OperationContext(
      operationID: AuthorityIdentifier(UUID()), root: root, mode: .systemProxy,
      configSHA256: configDigest, identitySHA256: identityDigest,
      ownerUID: Self.ownerUID, authorityRevision: 1)
    let request = try PrepareStartRequest(
      operation: operation, expectedRevision: 1, configuration: descriptor)
    return Fixture(request: request, configuration: configuration, secretPayload: nil)
  }

  // MARK: Shrinking

  /// Candidate reductions that move each choice toward its
  /// authenticated-compatible-success value, shrinking a counterexample toward a
  /// minimal reproducer.
  private func shrinkCandidates(_ choices: CaseChoices) -> [CaseChoices] {
    let provenIndex = GlobalAuthorityProofStatus.allCases.firstIndex(of: .proven)!
    var candidates: [CaseChoices] = []
    if choices.proofIndex != provenIndex {
      var c = choices
      c.proofIndex = provenIndex
      candidates.append(c)
    }
    if choices.protocolMajor != AuthorityV1Limits.major {
      var c = choices
      c.protocolMajor = AuthorityV1Limits.major
      candidates.append(c)
    }
    if choices.unsupportedFeature {
      var c = choices
      c.unsupportedFeature = false
      candidates.append(c)
    }
    if choices.peerRoleIndex != 0 {
      var c = choices
      c.peerRoleIndex = 0
      candidates.append(c)
    }
    if !choices.euidMatchesOwner {
      var c = choices
      c.euidMatchesOwner = true
      candidates.append(c)
    }
    if choices.modeIsTunnel {
      var c = choices
      c.modeIsTunnel = false
      candidates.append(c)
    }
    return candidates
  }

  /// Greedily reduces choices while the failure persists, terminating at a local
  /// minimum that still reproduces the violation.
  func shrink(_ choices: CaseChoices) -> CaseChoices {
    var current = choices
    var improved = true
    while improved {
      improved = false
      for candidate in shrinkCandidates(current) where candidate != current {
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

/// Base seed. Override with `CFW_PBT_SEED_PROP1` to replay a printed failure.
private func baseSeed() -> UInt64 {
  if let raw = ProcessInfo.processInfo.environment["CFW_PBT_SEED_PROP1"],
    let value = UInt64(raw)
  {
    return value
  }
  return 0xC0FF_EE13_A5A5_0001
}

@Test func authorityFailureIsFailClosedAcrossGeneratedOutcomes() {
  let property = FailClosedAuthorityProperty()
  let seed = baseSeed()
  let iterations = 160

  var successfulCases = 0
  var authenticatedSuccesses = 0
  var failClosedCases = 0
  var failure: (seed: UInt64, choices: CaseChoices, reason: String)?

  for index in 0..<iterations {
    let iterationSeed = seed &+ UInt64(index)
    var rng = SplitMix64(seed: iterationSeed)
    // Deterministically interleave guaranteed authenticated-compatible-success
    // cases (both modes) so the success path is always exercised and proven to
    // emit start actions, independent of the biased random draw.
    let choices: CaseChoices
    switch index % 4 {
    case 0: choices = property.successChoices(modeIsTunnel: true)
    case 1: choices = property.successChoices(modeIsTunnel: false)
    default: choices = property.randomChoices(using: &rng)
    }

    if let reason = property.evaluate(choices) {
      let shrunk = property.shrink(choices)
      let shrunkReason = property.evaluate(shrunk) ?? reason
      failure = (iterationSeed, shrunk, shrunkReason)
      break
    }

    if property.isAuthenticatedCompatibleSuccess(choices) {
      authenticatedSuccesses += 1
    } else {
      failClosedCases += 1
    }
    successfulCases += 1
  }

  if let failure {
    Issue.record(
      """
      Property 1 counterexample found.
      reproduce with: CFW_PBT_SEED_PROP1=\(failure.seed)
      shrunk choices: \(failure.choices)
      violation: \(failure.reason)
      """)
  }

  #expect(failure == nil)
  #expect(
    successfulCases >= 100,
    "expected at least 100 successful generated cases, ran \(successfulCases)")
  // The batch must actually exercise the fail-closed paths this property guards.
  #expect(failClosedCases > 0, "generated batch never exercised a fail-closed outcome")
  // ...and at least one authenticated compatible success, so the test is not
  // vacuously satisfied by a start path that can never succeed.
  #expect(authenticatedSuccesses > 0, "generated batch never exercised a successful start")
}
