import Foundation
import Testing

@testable import CFWSharedProtocol

@Test func everyUnprovenAuthorityConditionFailsWithStableTypedError() {
  for status in GlobalAuthorityProofStatus.allCases where status != .proven {
    #expect(throws: GlobalAuthorityGateError.proofMissing(status)) {
      try GlobalAuthorityReleaseGate.validate(status)
    }
  }
}

@Test func completeAuthorityProofIsTheOnlyAcceptedProofState() throws {
  try GlobalAuthorityReleaseGate.validate(.proven)
}

@Test func buildConfigurationEnforcesTheReleaseAuthorityGate() throws {
  #if CFW_GLOBAL_AUTHORITY_REQUIRED
    #expect(throws: GlobalAuthorityGateError.proofMissing(.availabilityUnproven)) {
      try GlobalAuthorityReleaseGate.requireStartAuthorization()
    }
  #else
    try GlobalAuthorityReleaseGate.requireStartAuthorization()
  #endif
}

@Test func authorityFailureCodeHasStableWireRepresentation() throws {
  let failure = NativeBridgeFailure(
    code: .globalAuthorityUnavailable,
    message: GlobalAuthorityGateError.stableMessage
  )
  let encoded = try JSONEncoder().encode(failure)
  #expect(String(decoding: encoded, as: UTF8.self).contains("global_authority_unavailable"))
  #expect(try JSONDecoder().decode(NativeBridgeFailure.self, from: encoded) == failure)
}

@Test func authorityFailureMessageIsStableAndRedacted() {
  #expect(GlobalAuthorityGateError.stableCode == "global-authority-unavailable")
  #expect(
    GlobalAuthorityGateError.stableMessage
      == "Global Authority registration, approval, identity, availability, and protocol compatibility are not proven."
  )
}

private struct AuthorityErrorContract: Decodable {
  let errors: [AuthorityErrorFixture]
}

private struct AuthorityErrorFixture: Decodable {
  let code: String
  let retry: String
  let message: String
}

private func authorityErrorFixture() throws -> Data {
  var root = URL(fileURLWithPath: #filePath)
  for _ in 0..<5 { root.deleteLastPathComponent() }
  return try Data(
    contentsOf: root.appendingPathComponent("fixtures/authority-v1/error-contract.json")
  )
}

@Test func authorityErrorMatrixIsUniqueCompleteAndOneToOne() throws {
  let contract = try JSONDecoder().decode(
    AuthorityErrorContract.self, from: authorityErrorFixture()
  )
  let entries = contract.errors
  #expect(entries.count == AuthorityErrorCode.allCases.count)
  #expect(Set(entries.map(\.code)).count == entries.count)
  #expect(
    Set(NativeBridgeErrorCode.allCases.map(\.rawValue)).count
      == NativeBridgeErrorCode.allCases.count
  )

  for entry in entries {
    let code = try #require(AuthorityErrorCode(rawValue: entry.code))
    #expect(code.nativeBridgeCode.rawValue == entry.code)
    #expect(code.stableMessage == entry.message)
    #expect(code.nativeBridgeCode.stableMessage == entry.message)
    #expect(code.retryDirective.rawValue == entry.retry)
    let encodedCode = try JSONEncoder().encode(code.nativeBridgeCode)
    #expect(
      try JSONDecoder().decode(NativeBridgeErrorCode.self, from: encodedCode)
        == code.nativeBridgeCode
    )
    let failure = NativeBridgeFailure(
      code: code.nativeBridgeCode,
      message: "untrusted localized text"
    )
    let encodedFailure = try JSONEncoder().encode(failure)
    #expect(try JSONDecoder().decode(NativeBridgeFailure.self, from: encodedFailure) == failure)
    #expect(failure.message == entry.message)
    #expect(!failure.message.contains("untrusted"))
    #expect(!code.allowsAutomaticRetry(for: .mutation))
    #expect(
      code.allowsAutomaticRetry(for: .idempotentReadOnly)
        == (code.retryDirective == .idempotentReadOnly)
    )
  }
}

@Test func authorityDiagnosticsAreStableAndRedacted() throws {
  let digest = String(repeating: "ab", count: 32)
  let context = AuthorityDiagnosticContext(
    operationID: AuthorityIdentifier(
      try #require(UUID(uuidString: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"))
    ),
    generation: 7,
    role: .host,
    digest: try SHA256Digest(hex: digest)
  )
  let error = AuthorityDomainError(code: .globalLeaseConflict, context: context)
  let diagnostic = error.description
  #expect(diagnostic.contains("code=global_lease_conflict"))
  #expect(diagnostic.contains("generation=7"))
  #expect(diagnostic.contains("role=host"))
  #expect(diagnostic.contains("digest_prefix=abababababab"))
  #expect(!diagnostic.contains(digest))
  #expect(error.nativeBridgeFailure.code == .globalLeaseConflict)
  #expect(error.nativeBridgeFailure.message == AuthorityErrorCode.globalLeaseConflict.stableMessage)
  #expect(!error.nativeBridgeFailure.message.contains("aaaaaaaa"))
  #expect(!error.nativeBridgeFailure.message.contains(digest))
}

@Test func unknownNativeErrorCodeFailsClosedAsInternal() throws {
  let data = Data(
    "{\"code\":\"future_authority_code\",\"message\":\"/private/path secret identity\"}".utf8
  )
  let failure = try JSONDecoder().decode(NativeBridgeFailure.self, from: data)
  #expect(failure.code == .internal)
  #expect(failure.message == NativeBridgeErrorCode.internal.stableMessage)
  #expect(!failure.message.contains("private"))
  #expect(!failure.message.contains("secret"))
}
