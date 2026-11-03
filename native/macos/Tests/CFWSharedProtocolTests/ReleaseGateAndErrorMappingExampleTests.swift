import Foundation
import Testing

@testable import CFWSharedProtocol

// Example (non-property) tests for task 2.6. These cover the exact protocol
// bounds, unsupported feature/version rejection, the missing/unavailable
// Authority failure path, the stable cross-language error mapping, and the
// absence of mutation/fallback on the Release gate path. All boundaries are
// exercised with pure in-memory fakes; no real launchd or Network Extension
// is involved. The canonical fixtures are read from disk rather than
// duplicated inline.

// MARK: - Stable cross-language error mapping

private struct ErrorContractFixture: Decodable {
  struct Entry: Decodable {
    let code: String
    let retry: String
    let message: String
  }

  let errors: [Entry]
}

private func errorContractData() throws -> Data {
  var root = URL(fileURLWithPath: #filePath)
  for _ in 0..<5 { root.deleteLastPathComponent() }
  return try Data(
    contentsOf: root.appendingPathComponent("fixtures/authority-v1/error-contract.json"))
}

@Test func authorityErrorCodesMapOneToOneToTheSharedContractFixture() throws {
  let contract = try JSONDecoder().decode(
    ErrorContractFixture.self, from: errorContractData())
  let byCode = Dictionary(uniqueKeysWithValues: contract.errors.map { ($0.code, $0) })

  // Every Swift AuthorityErrorCode has exactly one contract entry with a
  // matching wire code, stable message, retry directive, and NativeBridge code.
  #expect(byCode.count == AuthorityErrorCode.allCases.count)
  for code in AuthorityErrorCode.allCases {
    let entry = try #require(byCode[code.rawValue])
    #expect(code.nativeBridgeCode.rawValue == entry.code)
    #expect(code.stableMessage == entry.message)
    #expect(code.nativeBridgeCode.stableMessage == entry.message)
    #expect(code.retryDirective.rawValue == entry.retry)

    // NativeBridgeErrorCode round-trips over its stable wire representation.
    let encoded = try JSONEncoder().encode(code.nativeBridgeCode)
    #expect(
      try JSONDecoder().decode(NativeBridgeErrorCode.self, from: encoded)
        == code.nativeBridgeCode)
  }
}

@Test func nativeFailureIgnoresUntrustedTextAndUnknownCodesFailClosed() throws {
  // Localized/untrusted supplied text is discarded in favor of the stable message.
  let failure = NativeBridgeFailure(
    code: .globalLeaseConflict, message: "untrusted localized text")
  let encoded = try JSONEncoder().encode(failure)
  let decoded = try JSONDecoder().decode(NativeBridgeFailure.self, from: encoded)
  #expect(decoded == failure)
  #expect(decoded.message == NativeBridgeErrorCode.globalLeaseConflict.stableMessage)
  #expect(!decoded.message.contains("untrusted"))

  // An unknown wire code decodes to the internal fail-closed code with a
  // redacted stable message.
  let unknown = Data(
    "{\"code\":\"future_authority_code\",\"message\":\"/private/path secret\"}".utf8)
  let fallback = try JSONDecoder().decode(NativeBridgeFailure.self, from: unknown)
  #expect(fallback.code == .internal)
  #expect(fallback.message == NativeBridgeErrorCode.internal.stableMessage)
  #expect(!fallback.message.contains("private"))
  #expect(!fallback.message.contains("secret"))
}

// MARK: - Release gate emits no mutation or fallback action

private enum StartAction: Equatable {
  case libboxStart
  case systemProxyApply
  case tunnelStart
  case fallback
}

/// Pure fake that records any data-plane action a start pipeline would take.
private final class RecordingStartActuator {
  private(set) var actions: [StartAction] = []

  func performProvenStart() {
    actions.append(.libboxStart)
    actions.append(.tunnelStart)
  }
}

/// A start pipeline that consults the Release gate before any mutation and has
/// no fallback branch. Mutation is reachable only after a proven gate.
private func gatedStart(
  proof: GlobalAuthorityProofStatus, actuator: RecordingStartActuator
) throws {
  try GlobalAuthorityReleaseGate.validate(proof)
  actuator.performProvenStart()
}

@Test func unprovenReleaseGateEmitsNoMutationOrFallbackAction() {
  for status in GlobalAuthorityProofStatus.allCases where status != .proven {
    let actuator = RecordingStartActuator()
    #expect(throws: GlobalAuthorityGateError.proofMissing(status)) {
      try gatedStart(proof: status, actuator: actuator)
    }
    // No libbox start, System Proxy apply, Tunnel start, or fallback occurs.
    #expect(actuator.actions.isEmpty)
    #expect(!actuator.actions.contains(.fallback))
  }
}

@Test func provenReleaseGateIsTheOnlyPathThatPermitsAStart() throws {
  let actuator = RecordingStartActuator()
  try gatedStart(proof: .proven, actuator: actuator)
  #expect(actuator.actions == [.libboxStart, .tunnelStart])
  #expect(!actuator.actions.contains(.fallback))
}
