import Foundation
import Testing

@testable import CFWCredentialTransport

private enum SensitiveBufferTestError: Error {
  case requested
}

@Test func sensitiveBufferErasesAfterSuccessfulAndThrowingConsumers() throws {
  let success = SensitiveDataBuffer(copying: Data("top-secret".utf8))
  let count = try success.withErasingData { $0.count }
  #expect(count == 10)
  #expect(success.isErasedForTesting)
  #expect(throws: SensitiveDataBufferError.unavailable) {
    try success.withErasingData { _ in () }
  }

  let failure = SensitiveDataBuffer(copying: Data("other-secret".utf8))
  #expect(throws: SensitiveBufferTestError.requested) {
    try failure.withErasingData { _ in throw SensitiveBufferTestError.requested }
  }
  #expect(failure.isErasedForTesting)
}

@Test func sensitiveBufferExplicitEraseIsIdempotent() {
  let buffer = SensitiveDataBuffer(copying: Data("secret".utf8))
  buffer.erase()
  buffer.erase()
  #expect(buffer.isErasedForTesting)
}
