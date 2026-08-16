import Darwin
import Foundation

struct PIDReuseObservation: Sendable {
  let evidence: IdentityFreshnessEvidence
  let requestSHA256: String
  let process: ProcessObservation
  let effectiveUserIdentifier: UInt32
  let auditSessionIdentifier: UInt32
}

func exerciseBoundedPIDReuse(maximumSpawns: Int = 512) throws -> PIDReuseObservation {
  guard 1...4_096 ~= maximumSpawns else {
    throw FixtureError.physicalPreconditionUnavailable
  }
  let captured = try withHeldSpawnedChild { $0.process }
  for _ in 0..<maximumSpawns {
    let candidate = try withHeldSpawnedChild { $0 }
    guard candidate.process.pid == captured.pid else { continue }
    guard candidate.process.startUnixMilliseconds != captured.startUnixMilliseconds else {
      throw FixtureError.authorityResponseInvalid
    }
    let evidence = IdentityFreshnessEvidence(
      capturedPID: captured.pid,
      capturedStartUnixMilliseconds: captured.startUnixMilliseconds,
      currentPID: candidate.process.pid,
      currentStartUnixMilliseconds: candidate.process.startUnixMilliseconds,
      capturedAuditSessionID: candidate.auditSessionIdentifier,
      currentAuditSessionID: candidate.auditSessionIdentifier)
    return PIDReuseObservation(
      evidence: evidence,
      requestSHA256: sha256(try canonicalJSON(evidence)),
      process: candidate.process,
      effectiveUserIdentifier: candidate.effectiveUserIdentifier,
      auditSessionIdentifier: candidate.auditSessionIdentifier)
  }
  throw FixtureError.physicalPreconditionUnavailable
}

private func withHeldSpawnedChild<Result>(
  _ body: (RuntimeIdentityObservation) throws -> Result
) throws -> Result {
  let input = Pipe()
  let output = Pipe()
  let errors = Pipe()
  let process = Process()
  process.executableURL = URL(fileURLWithPath: try installedExecutablePath())
  process.arguments = ["internal-hold-identity"]
  process.environment = [
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LANG": "C",
    "LC_ALL": "C",
  ]
  process.standardInput = input.fileHandleForReading
  process.standardOutput = output.fileHandleForWriting
  process.standardError = errors.fileHandleForWriting
  let finished = DispatchSemaphore(value: 0)
  process.terminationHandler = { _ in finished.signal() }
  try process.run()
  try input.fileHandleForReading.close()
  try output.fileHandleForWriting.close()
  try errors.fileHandleForWriting.close()
  defer {
    var release: UInt8 = 1
    while write(input.fileHandleForWriting.fileDescriptor, &release, 1) < 0, errno == EINTR {}
    input.fileHandleForWriting.closeFile()
    if finished.wait(timeout: .now() + .seconds(2)) != .success {
      process.terminate()
      if finished.wait(timeout: .now() + .seconds(1)) != .success {
        _ = kill(process.processIdentifier, SIGKILL)
        _ = finished.wait(timeout: .now() + .seconds(1))
      }
    }
    output.fileHandleForReading.closeFile()
    errors.fileHandleForReading.closeFile()
  }

  var descriptor = pollfd(
    fd: output.fileHandleForReading.fileDescriptor,
    events: Int16(POLLIN),
    revents: 0)
  guard poll(&descriptor, 1, 5_000) > 0, descriptor.revents & Int16(POLLIN) != 0 else {
    throw FixtureError.physicalPreconditionUnavailable
  }
  var payload = Data()
  while payload.count <= 4_096 {
    var byte: UInt8 = 0
    let count = read(output.fileHandleForReading.fileDescriptor, &byte, 1)
    if count == 1 {
      if byte == 0x0A { break }
      payload.append(byte)
      continue
    }
    if count < 0, errno == EINTR { continue }
    throw FixtureError.physicalPreconditionUnavailable
  }
  guard !payload.isEmpty, payload.count <= 4_096 else {
    throw FixtureError.physicalPreconditionUnavailable
  }
  let observation = try JSONDecoder().decode(RuntimeIdentityObservation.self, from: payload)
  guard try canonicalJSON(observation) == payload,
    observation.process.pid == UInt32(bitPattern: process.processIdentifier)
  else { throw FixtureError.authorityResponseInvalid }
  return try body(observation)
}
