import Foundation
import Testing

@testable import CFWSharedProtocol

@Test func crossProcessLeaseExcludesBothAddressFamiliesAndReleasesIdempotently() throws {
  let first = try CrossProcessEngineLeaseStore(testingPort: 0).acquire()
  let competingStore = CrossProcessEngineLeaseStore(testingPort: first.port)

  #expect(throws: CrossProcessEngineLeaseError.alreadyHeld) {
    try competingStore.acquire()
  }

  first.release()
  first.release()
  let replacement = try competingStore.acquire()
  #expect(replacement.port == first.port)
  replacement.release()
}

@Test func crossProcessLeaseReleasesOnDeinitialization() throws {
  var lease: CrossProcessEngineLease? = try CrossProcessEngineLeaseStore(
    testingPort: 0
  ).acquire()
  let port = try #require(lease?.port)
  lease = nil

  let replacement = try CrossProcessEngineLeaseStore(testingPort: port).acquire()
  #expect(replacement.port == port)
  replacement.release()
}
