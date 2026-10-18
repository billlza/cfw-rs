import CFWSharedProtocol
import Darwin
import Foundation

private struct ReadAttempt: Sendable {
  let request: Data
  let errorCode: AuthorityErrorCode?
}

struct RequestFloodObservation: Sendable {
  let requestSHA256: String
  let before: SnapshotObservation
  let after: SnapshotObservation
}

func exerciseBoundedRequestFlood() async throws -> RequestFloodObservation {
  let before = try await directSnapshot()
  guard before.snapshot.state == .off else { throw FixtureError.cleanupContaminated }
  let requestCount = AuthorityV1Limits.maximumReadOnlyRequests + 32
  var sessions: [AuthorityWireSession] = []
  var requests: [Data] = []
  sessions.reserveCapacity(requestCount)
  requests.reserveCapacity(requestCount)
  do {
    for _ in 0..<requestCount {
      let session = AuthorityWireSession(timeout: .seconds(5))
      try await session.handshake()
      sessions.append(session)
      requests.append(try session.makeSnapshotRequest())
    }
    let attempts = try await withThrowingTaskGroup(
      of: ReadAttempt.self, returning: [ReadAttempt].self
    ) {
      group in
      for index in sessions.indices {
        let session = sessions[index]
        let request = requests[index]
        group.addTask {
          do {
            try await Task.sleep(for: .milliseconds(50))
            _ = try await session.performSnapshotRequest(request)
            return ReadAttempt(request: request, errorCode: nil)
          } catch let error as AuthorityDomainError {
            return ReadAttempt(request: request, errorCode: error.code)
          } catch {
            throw error
          }
        }
      }
      var values: [ReadAttempt] = []
      values.reserveCapacity(requestCount)
      for try await value in group { values.append(value) }
      return values
    }
    for session in sessions { await session.invalidate() }
    guard let rejected = attempts.first(where: { $0.errorCode == .resourceExhausted }) else {
      throw FixtureError.physicalPreconditionUnavailable
    }
    let after = try await directSnapshot()
    guard after.snapshot.state == .off,
      try before.stateSHA256 == after.stateSHA256
    else { throw FixtureError.cleanupContaminated }
    return RequestFloodObservation(
      requestSHA256: sha256(rejected.request), before: before, after: after)
  } catch {
    for session in sessions { await session.invalidate() }
    throw error
  }
}
