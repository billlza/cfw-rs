import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWGlobalAuthority

// MARK: - Property 3: Authorization is exact conjunction
//
// For all generated peer evidence and live console-user states, a role is
// authorized if and only if audit-token resolution succeeds and every exact
// role predicate (Team ID, signing identifier, designated requirement,
// entitlements, effective UID, audit session, and console UID) holds; changing
// any single required predicate to a non-matching value denies the request.
//
// This is a deterministic generative test against the pure
// `GlobalAuthorityPeerPolicy`. No real Security.framework or SystemConfiguration
// resolution is used: every input is synthesized from a reproducible seed. On
// failure the seed and the shrunk counterexample are printed so the exact case
// can be replayed.
//
// **Validates: Requirements 2.3, 6.4**

private let goodDigest = try! SHA256Digest(hex: String(repeating: "1", count: 64))
private let badDigest = try! SHA256Digest(hex: String(repeating: "f", count: 64))

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

  mutating func uInt(inRange range: ClosedRange<UInt64>) -> UInt64 {
    let span = range.upperBound - range.lowerBound + 1
    return range.lowerBound + next() % span
  }
}

/// Numeric choices that fully determine a generated case for a role. Kept
/// separate from the built case so a counterexample can be shrunk by reducing
/// individual choices and re-deriving deterministically.
private struct CaseChoices: Equatable {
  var uid: uid_t
  var session: UInt32
  var pid: pid_t
  var providerConsolePresent: Bool
  var providerConsoleUID: uid_t
}

private struct GeneratedCase {
  var role: AuthorityRole
  var evidence: PeerAuthorizationEvidence
  var consoleUID: uid_t?
  var context: TrustedPeerSessionContext
}

extension PeerAuthorizationEvidence {
  /// Single-field override used to build minimal single-predicate mutations.
  fileprivate func with(
    pid: pid_t? = nil, euid: uid_t? = nil, auditSessionID: UInt32? = nil,
    teamID: String? = nil, signingID: String? = nil,
    designatedRequirementDigest: SHA256Digest? = nil,
    entitlementDigest: SHA256Digest? = nil,
    requirementValidated: Bool? = nil, auditTokenBound: Bool? = nil,
    adHocSigned: Bool? = nil, debugSigned: Bool? = nil,
    systemExtensionContext: Bool? = nil
  ) -> PeerAuthorizationEvidence {
    PeerAuthorizationEvidence(
      auditTokenDigest: auditTokenDigest, pid: pid ?? self.pid,
      euid: euid ?? self.euid, auditSessionID: auditSessionID ?? self.auditSessionID,
      teamID: teamID ?? self.teamID, signingID: signingID ?? self.signingID,
      designatedRequirementDigest: designatedRequirementDigest
        ?? self.designatedRequirementDigest,
      entitlementDigest: entitlementDigest ?? self.entitlementDigest,
      requirementValidated: requirementValidated ?? self.requirementValidated,
      auditTokenBound: auditTokenBound ?? self.auditTokenBound,
      adHocSigned: adHocSigned ?? self.adHocSigned,
      debugSigned: debugSigned ?? self.debugSigned,
      systemExtensionContext: systemExtensionContext ?? self.systemExtensionContext)
  }
}

private struct SinglePredicateMutation {
  let name: String
  let apply: (GeneratedCase) -> GeneratedCase
}

private struct PeerAuthorizationProperty {
  let policy = GlobalAuthorityPeerPolicy()

  func randomChoices(role: AuthorityRole, using rng: inout SplitMix64) -> CaseChoices {
    CaseChoices(
      uid: uid_t(rng.uInt(inRange: 501...900)),
      session: UInt32(rng.uInt(inRange: 1...4_000_000)),
      pid: pid_t(rng.uInt(inRange: 1...90_000)),
      providerConsolePresent: rng.next() & 1 == 0,
      providerConsoleUID: uid_t(rng.uInt(inRange: 501...900)))
  }

  /// Builds a fully valid case (all predicates hold) for the role from choices.
  func buildCase(role: AuthorityRole, choices: CaseChoices) -> GeneratedCase {
    let rolePolicy = GlobalAuthorityPeerPolicy.policy(for: role)
    switch role {
    case .host:
      let evidence = PeerAuthorizationEvidence(
        auditTokenDigest: goodDigest, pid: choices.pid, euid: choices.uid,
        auditSessionID: choices.session, teamID: GlobalAuthorityPeerPolicy.teamID,
        signingID: rolePolicy.signingID,
        designatedRequirementDigest: rolePolicy.designatedRequirementDigest,
        entitlementDigest: rolePolicy.entitlementDigest, requirementValidated: true,
        auditTokenBound: true, adHocSigned: false, debugSigned: false,
        systemExtensionContext: false)
      return GeneratedCase(
        role: role, evidence: evidence, consoleUID: choices.uid,
        context: .user(auditSessionID: choices.session, leaseOwnerUID: nil))
    case .proxyAgent:
      let evidence = PeerAuthorizationEvidence(
        auditTokenDigest: goodDigest, pid: choices.pid, euid: choices.uid,
        auditSessionID: choices.session, teamID: GlobalAuthorityPeerPolicy.teamID,
        signingID: rolePolicy.signingID,
        designatedRequirementDigest: rolePolicy.designatedRequirementDigest,
        entitlementDigest: rolePolicy.entitlementDigest, requirementValidated: true,
        auditTokenBound: true, adHocSigned: false, debugSigned: false,
        systemExtensionContext: false)
      return GeneratedCase(
        role: role, evidence: evidence, consoleUID: choices.uid,
        context: .user(auditSessionID: choices.session, leaseOwnerUID: choices.uid))
    case .provider:
      let evidence = PeerAuthorizationEvidence(
        auditTokenDigest: goodDigest, pid: choices.pid, euid: 0, auditSessionID: 0,
        teamID: GlobalAuthorityPeerPolicy.teamID, signingID: rolePolicy.signingID,
        designatedRequirementDigest: rolePolicy.designatedRequirementDigest,
        entitlementDigest: rolePolicy.entitlementDigest, requirementValidated: true,
        auditTokenBound: true, adHocSigned: false, debugSigned: false,
        systemExtensionContext: true)
      return GeneratedCase(
        role: role, evidence: evidence,
        consoleUID: choices.providerConsolePresent ? choices.providerConsoleUID : nil,
        context: .providerSystemExtension)
    }
  }

  /// Common single-predicate mutations that must deny every role.
  private func commonMutations() -> [SinglePredicateMutation] {
    [
      SinglePredicateMutation(name: "auditTokenBound=false") {
        var c = $0
        c.evidence = c.evidence.with(auditTokenBound: false)
        return c
      },
      SinglePredicateMutation(name: "pid=0") {
        var c = $0
        c.evidence = c.evidence.with(pid: 0)
        return c
      },
      SinglePredicateMutation(name: "teamID mismatch") {
        var c = $0
        c.evidence = c.evidence.with(teamID: "AAAAAAAAAA")
        return c
      },
      SinglePredicateMutation(name: "signingID unknown") {
        var c = $0
        c.evidence = c.evidence.with(signingID: "com.bill.clashformac.unknown")
        return c
      },
      SinglePredicateMutation(name: "requirementValidated=false") {
        var c = $0
        c.evidence = c.evidence.with(requirementValidated: false)
        return c
      },
      SinglePredicateMutation(name: "designatedRequirementDigest mismatch") {
        var c = $0
        c.evidence = c.evidence.with(designatedRequirementDigest: badDigest)
        return c
      },
      SinglePredicateMutation(name: "entitlementDigest mismatch") {
        var c = $0
        c.evidence = c.evidence.with(entitlementDigest: badDigest)
        return c
      },
      SinglePredicateMutation(name: "adHocSigned=true") {
        var c = $0
        c.evidence = c.evidence.with(adHocSigned: true)
        return c
      },
      SinglePredicateMutation(name: "debugSigned=true") {
        var c = $0
        c.evidence = c.evidence.with(debugSigned: true)
        return c
      },
    ]
  }

  /// Role-specific single-predicate mutations. Each changes exactly one required
  /// predicate to a non-matching value while leaving all others valid.
  private func roleMutations(for role: AuthorityRole) -> [SinglePredicateMutation] {
    switch role {
    case .host:
      return [
        SinglePredicateMutation(name: "console UID absent") {
          var c = $0
          c.consoleUID = nil
          return c
        },
        SinglePredicateMutation(name: "euid != console UID") {
          var c = $0
          c.consoleUID = c.evidence.euid &+ 1
          return c
        },
        SinglePredicateMutation(name: "audit session mismatch") {
          var c = $0
          c.evidence = c.evidence.with(auditSessionID: c.evidence.auditSessionID ^ 1)
          return c
        },
        SinglePredicateMutation(name: "audit session zero") {
          var c = $0
          c.evidence = c.evidence.with(auditSessionID: 0)
          c.context = .user(auditSessionID: 0, leaseOwnerUID: nil)
          return c
        },
        SinglePredicateMutation(name: "audit session sentinel") {
          var c = $0
          c.evidence = c.evidence.with(auditSessionID: UInt32.max)
          c.context = .user(auditSessionID: UInt32.max, leaseOwnerUID: nil)
          return c
        },
      ]
    case .proxyAgent:
      return [
        SinglePredicateMutation(name: "console UID absent") {
          var c = $0
          c.consoleUID = nil
          return c
        },
        SinglePredicateMutation(name: "fast user switch (console != euid)") {
          var c = $0
          c.consoleUID = c.evidence.euid &+ 1
          return c
        },
        SinglePredicateMutation(name: "lease owner absent") {
          var c = $0
          c.context = .user(auditSessionID: c.evidence.auditSessionID, leaseOwnerUID: nil)
          return c
        },
        SinglePredicateMutation(name: "lease owner mismatch") {
          var c = $0
          c.context = .user(
            auditSessionID: c.evidence.auditSessionID, leaseOwnerUID: c.evidence.euid &+ 1)
          return c
        },
        SinglePredicateMutation(name: "audit session mismatch") {
          var c = $0
          c.evidence = c.evidence.with(auditSessionID: c.evidence.auditSessionID ^ 1)
          return c
        },
      ]
    case .provider:
      return [
        SinglePredicateMutation(name: "euid != root") {
          var c = $0
          c.evidence = c.evidence.with(euid: 501)
          return c
        },
        SinglePredicateMutation(name: "audit session != 0") {
          var c = $0
          c.evidence = c.evidence.with(auditSessionID: 7)
          return c
        },
        SinglePredicateMutation(name: "systemExtensionContext=false") {
          var c = $0
          c.evidence = c.evidence.with(systemExtensionContext: false)
          return c
        },
        SinglePredicateMutation(name: "wrong session context") {
          var c = $0
          c.context = .user(auditSessionID: 7, leaseOwnerUID: nil)
          return c
        },
      ]
    }
  }

  private func mutations(for role: AuthorityRole) -> [SinglePredicateMutation] {
    commonMutations() + roleMutations(for: role)
  }

  /// Returns nil when the case satisfies the exact-conjunction property, or a
  /// human-readable description of the first violation otherwise.
  func evaluate(_ generated: GeneratedCase) -> String? {
    do {
      let identity = try policy.authorize(
        generated.evidence, liveConsoleUID: generated.consoleUID, context: generated.context)
      guard identity.role == generated.role else {
        return "valid case authorized wrong role: got \(identity.role), expected \(generated.role)"
      }
    } catch {
      return "valid case denied (\(error)) — every predicate held but authorization failed"
    }

    for mutation in mutations(for: generated.role) {
      let mutated = mutation.apply(generated)
      do {
        _ = try policy.authorize(
          mutated.evidence, liveConsoleUID: mutated.consoleUID, context: mutated.context)
        return "single-predicate mutation '\(mutation.name)' was authorized but must deny"
      } catch let error as GlobalAuthorityAuthorizationError where error == .identityRejected {
        continue
      } catch {
        return "mutation '\(mutation.name)' threw unexpected error: \(error)"
      }
    }
    return nil
  }

  private func shrinkCandidates(_ choices: CaseChoices) -> [CaseChoices] {
    var candidates: [CaseChoices] = []
    if choices.uid != 501 {
      var c = choices
      c.uid = 501
      candidates.append(c)
    }
    if choices.session != 1 {
      var c = choices
      c.session = 1
      candidates.append(c)
    }
    if choices.pid != 1 {
      var c = choices
      c.pid = 1
      candidates.append(c)
    }
    if choices.providerConsolePresent {
      var c = choices
      c.providerConsolePresent = false
      candidates.append(c)
    }
    if choices.providerConsoleUID != 501 {
      var c = choices
      c.providerConsoleUID = 501
      candidates.append(c)
    }
    return candidates
  }

  /// Greedily reduces choices while the failure persists, terminating at a
  /// local minimum that still reproduces the violation.
  func shrink(role: AuthorityRole, choices: CaseChoices) -> CaseChoices {
    var current = choices
    var improved = true
    while improved {
      improved = false
      for candidate in shrinkCandidates(current) where candidate != current {
        if evaluate(buildCase(role: role, choices: candidate)) != nil {
          current = candidate
          improved = true
          break
        }
      }
    }
    return current
  }
}

/// Base seed. Override with `CFW_PBT_SEED_PROP3` to replay a printed failure.
private func baseSeed() -> UInt64 {
  if let raw = ProcessInfo.processInfo.environment["CFW_PBT_SEED_PROP3"],
    let value = UInt64(raw)
  {
    return value
  }
  return 0xC0FF_EE13_A5A5_0003
}

@Test func authorizationIsExactConjunctionAcrossGeneratedPeers() {
  let property = PeerAuthorizationProperty()
  let roles = AuthorityRole.allCases
  let seed = baseSeed()
  let iterations = 150

  var successfulCases = 0
  var failure: (seed: UInt64, role: AuthorityRole, choices: CaseChoices, reason: String)?

  for index in 0..<iterations {
    let iterationSeed = seed &+ UInt64(index)
    var rng = SplitMix64(seed: iterationSeed)
    let role = roles[index % roles.count]
    let choices = property.randomChoices(role: role, using: &rng)

    if let reason = property.evaluate(property.buildCase(role: role, choices: choices)) {
      let shrunk = property.shrink(role: role, choices: choices)
      let shrunkReason =
        property.evaluate(property.buildCase(role: role, choices: shrunk)) ?? reason
      failure = (iterationSeed, role, shrunk, shrunkReason)
      break
    }
    successfulCases += 1
  }

  if let failure {
    Issue.record(
      """
      Property 3 counterexample found.
      reproduce with: CFW_PBT_SEED_PROP3=\(failure.seed)
      role: \(failure.role)
      shrunk choices: \(failure.choices)
      violation: \(failure.reason)
      """)
  }

  #expect(failure == nil)
  #expect(
    successfulCases >= 100,
    "expected at least 100 successful generated cases, ran \(successfulCases)")
  // Every role must be exercised by the generated batch.
  #expect(iterations / roles.count >= 34)
}
