import CFWSharedProtocol
import Darwin
import Foundation
import Testing

@testable import CFWGlobalAuthority

// The role-specific listener proves the immutable code-signing conjunction.
// This property test covers the remaining public, kernel-populated connection
// attributes for every role and verifies that changing one required value never
// authorizes a peer.

private struct SplitMix64: RandomNumberGenerator {
  private var state: UInt64

  init(seed: UInt64) { state = seed }

  mutating func next() -> UInt64 {
    state = state &+ 0x9E37_79B9_7F4A_7C15
    var value = state
    value = (value ^ (value >> 30)) &* 0xBF58_476D_1CE4_E5B9
    value = (value ^ (value >> 27)) &* 0x94D0_49BB_1331_11EB
    return value ^ (value >> 31)
  }

  mutating func value(in range: ClosedRange<UInt64>) -> UInt64 {
    range.lowerBound + next() % (range.upperBound - range.lowerBound + 1)
  }
}

private struct GeneratedConnection: Equatable {
  var role: AuthorityRole
  var pid: pid_t
  var euid: uid_t
  var auditSessionID: UInt32
  var liveConsoleUID: uid_t?
  var leaseOwnerUID: uid_t?
}

private struct ConnectionChoices: Equatable, CustomStringConvertible {
  var uid: uid_t
  var session: UInt32
  var pid: pid_t
  var providerConsoleUID: uid_t?

  var description: String {
    "uid=\(uid), session=\(session), pid=\(pid), providerConsole=\(String(describing: providerConsoleUID))"
  }
}

private struct ConnectionMutation {
  let name: String
  let apply: (GeneratedConnection) -> GeneratedConnection
}

private struct RoleScopedConnectionProperty {
  let policy = GlobalAuthorityPeerPolicy()

  func randomChoices(using rng: inout SplitMix64) -> ConnectionChoices {
    ConnectionChoices(
      uid: uid_t(rng.value(in: 501...900)),
      session: UInt32(rng.value(in: 1...4_000_000)),
      pid: pid_t(rng.value(in: 1...90_000)),
      providerConsoleUID: rng.next() & 1 == 0
        ? nil : uid_t(rng.value(in: 501...900)))
  }

  func build(role: AuthorityRole, choices: ConnectionChoices) -> GeneratedConnection {
    switch role {
    case .host:
      GeneratedConnection(
        role: role, pid: choices.pid, euid: choices.uid,
        auditSessionID: choices.session, liveConsoleUID: choices.uid,
        leaseOwnerUID: nil)
    case .proxyAgent:
      GeneratedConnection(
        role: role, pid: choices.pid, euid: choices.uid,
        auditSessionID: choices.session, liveConsoleUID: choices.uid,
        leaseOwnerUID: choices.uid)
    case .provider:
      GeneratedConnection(
        role: role, pid: choices.pid, euid: 0,
        auditSessionID: 0, liveConsoleUID: choices.providerConsoleUID,
        leaseOwnerUID: choices.uid)
    }
  }

  func mutations(for role: AuthorityRole) -> [ConnectionMutation] {
    var values = [
      ConnectionMutation(name: "pid is not a live process") {
        var value = $0
        value.pid = 0
        return value
      }
    ]
    switch role {
    case .host:
      values += userMutations(includeLeaseOwner: false)
    case .proxyAgent:
      values += userMutations(includeLeaseOwner: true)
    case .provider:
      values += [
        ConnectionMutation(name: "provider is not root") {
          var value = $0
          value.euid = 501
          return value
        },
        ConnectionMutation(name: "provider has a user audit session") {
          var value = $0
          value.auditSessionID = 7
          return value
        },
      ]
    }
    return values
  }

  private func userMutations(includeLeaseOwner: Bool) -> [ConnectionMutation] {
    var values = [
      ConnectionMutation(name: "console user absent") {
        var value = $0
        value.liveConsoleUID = nil
        return value
      },
      ConnectionMutation(name: "effective user is not console user") {
        var value = $0
        value.liveConsoleUID = value.euid &+ 1
        return value
      },
      ConnectionMutation(name: "audit session is zero") {
        var value = $0
        value.auditSessionID = 0
        return value
      },
      ConnectionMutation(name: "audit session is invalid sentinel") {
        var value = $0
        value.auditSessionID = UInt32.max
        return value
      },
    ]
    if includeLeaseOwner {
      values += [
        ConnectionMutation(name: "lease owner absent") {
          var value = $0
          value.leaseOwnerUID = nil
          return value
        },
        ConnectionMutation(name: "lease owner differs") {
          var value = $0
          value.leaseOwnerUID = value.euid &+ 1
          return value
        },
      ]
    }
    return values
  }

  func evaluate(_ connection: GeneratedConnection) -> String? {
    do {
      let identity = try authorize(connection)
      guard identity.role == connection.role,
        identity.pid == connection.pid,
        identity.euid == connection.euid,
        identity.auditSessionID == connection.auditSessionID
      else { return "valid public connection attributes were projected incorrectly" }
    } catch {
      return "valid role-scoped connection was denied: \(error)"
    }

    for mutation in mutations(for: connection.role) {
      do {
        _ = try authorize(mutation.apply(connection))
        return "single-attribute mutation '\(mutation.name)' was authorized"
      } catch let error as GlobalAuthorityAuthorizationError
        where error == .identityRejected
      {
        continue
      } catch {
        return "mutation '\(mutation.name)' produced unexpected error: \(error)"
      }
    }
    return nil
  }

  private func authorize(_ value: GeneratedConnection) throws -> PeerIdentity {
    try policy.authorizeRoleScopedConnection(
      role: value.role, pid: value.pid, euid: value.euid,
      auditSessionID: value.auditSessionID,
      liveConsoleUID: value.liveConsoleUID,
      leaseOwnerUID: value.leaseOwnerUID)
  }
}

private func baseSeed() -> UInt64 {
  if let raw = ProcessInfo.processInfo.environment["CFW_PBT_SEED_PROP3"],
    let value = UInt64(raw)
  {
    return value
  }
  return 0xC0FF_EE13_A5A5_0003
}

@Test func authorizationIsExactConjunctionAcrossGeneratedPeers() {
  let property = RoleScopedConnectionProperty()
  let roles = AuthorityRole.allCases
  let seed = baseSeed()
  let iterations = 150
  var completed = 0
  var failure: String?

  for index in 0..<iterations {
    let iterationSeed = seed &+ UInt64(index)
    var rng = SplitMix64(seed: iterationSeed)
    let role = roles[index % roles.count]
    let choices = property.randomChoices(using: &rng)
    if let reason = property.evaluate(property.build(role: role, choices: choices)) {
      failure =
        "seed=\(iterationSeed), role=\(role), choices=\(choices), violation=\(reason)"
      break
    }
    completed += 1
  }

  if let failure { Issue.record("Role-scoped authorization counterexample: \(failure)") }
  #expect(failure == nil)
  #expect(completed == iterations)
}
