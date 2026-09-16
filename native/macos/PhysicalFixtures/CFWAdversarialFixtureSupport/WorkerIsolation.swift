import CFWSharedProtocol
import Darwin
import Foundation
import SystemConfiguration

private let maximumWorkerOutputBytes = 64 * 1_024

struct BoundedCommandOutput: Sendable {
  let stdout: Data
  let stderr: Data
  let exitCode: Int32
}

func runBoundedCommand(
  executable: String,
  arguments: [String],
  standardInput: Data = Data(),
  timeoutSeconds: Int = 15,
  maximumOutputBytes: Int = maximumWorkerOutputBytes
) throws -> BoundedCommandOutput {
  guard executable.hasPrefix("/"), timeoutSeconds > 0, timeoutSeconds <= 60,
    maximumOutputBytes >= 0, maximumOutputBytes <= 64 * 1_024 * 1_024
  else { throw FixtureError.boundedCommandFailed }
  let temporaryDirectory = URL(
    fileURLWithPath: "/private/var/tmp", isDirectory: true
  ).appendingPathComponent("cfw-adversarial-command-\(UUID().uuidString.lowercased())")
  try FileManager.default.createDirectory(
    at: temporaryDirectory,
    withIntermediateDirectories: false,
    attributes: [.posixPermissions: 0o700])
  do {
    let result = try runBoundedCommand(
      executable: executable,
      arguments: arguments,
      standardInput: standardInput,
      timeoutSeconds: timeoutSeconds,
      maximumOutputBytes: maximumOutputBytes,
      temporaryDirectory: temporaryDirectory)
    do {
      try FileManager.default.removeItem(at: temporaryDirectory)
    } catch {
      throw FixtureError.cleanupContaminated
    }
    return result
  } catch let operationError {
    do {
      try FileManager.default.removeItem(at: temporaryDirectory)
    } catch {
      throw FixtureError.cleanupContaminated
    }
    throw operationError
  }
}

private func runBoundedCommand(
  executable: String,
  arguments: [String],
  standardInput: Data,
  timeoutSeconds: Int,
  maximumOutputBytes: Int,
  temporaryDirectory: URL
) throws -> BoundedCommandOutput {
  let stdoutURL = temporaryDirectory.appendingPathComponent("stdout")
  let stderrURL = temporaryDirectory.appendingPathComponent("stderr")
  guard
    FileManager.default.createFile(
      atPath: stdoutURL.path, contents: nil, attributes: [.posixPermissions: 0o600]),
    FileManager.default.createFile(
      atPath: stderrURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
  else { throw FixtureError.boundedCommandFailed }
  let stdoutHandle = try FileHandle(forWritingTo: stdoutURL)
  let stderrHandle = try FileHandle(forWritingTo: stderrURL)
  let input = Pipe()

  let process = Process()
  process.executableURL = URL(fileURLWithPath: executable)
  process.arguments = arguments
  process.environment = [
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
    "LANG": "C",
    "LC_ALL": "C",
  ]
  process.standardInput = input.fileHandleForReading
  process.standardOutput = stdoutHandle
  process.standardError = stderrHandle
  let finished = DispatchSemaphore(value: 0)
  process.terminationHandler = { _ in finished.signal() }
  try process.run()
  try input.fileHandleForReading.close()
  if !standardInput.isEmpty { input.fileHandleForWriting.write(standardInput) }
  try input.fileHandleForWriting.close()

  guard finished.wait(timeout: .now() + .seconds(timeoutSeconds)) == .success else {
    process.terminate()
    if finished.wait(timeout: .now() + .seconds(1)) != .success {
      guard kill(process.processIdentifier, SIGKILL) == 0,
        finished.wait(timeout: .now() + .seconds(1)) == .success
      else { throw FixtureError.boundedCommandFailed }
    }
    throw FixtureError.physicalPreconditionUnavailable
  }
  try stdoutHandle.close()
  try stderrHandle.close()

  let stdout = try readBoundedRegularFile(stdoutURL, maximum: maximumOutputBytes)
  let stderr = try readBoundedRegularFile(stderrURL, maximum: maximumOutputBytes)
  return BoundedCommandOutput(
    stdout: stdout, stderr: stderr, exitCode: process.terminationStatus)
}

private func readBoundedRegularFile(_ url: URL, maximum: Int) throws -> Data {
  var metadata = stat()
  guard lstat(url.path, &metadata) == 0,
    (metadata.st_mode & S_IFMT) == S_IFREG,
    metadata.st_nlink == 1,
    metadata.st_size >= 0,
    metadata.st_size <= maximum
  else { throw FixtureError.boundedCommandFailed }
  return try Data(contentsOf: url, options: [.mappedIfSafe])
}

struct ConsoleIdentity: Sendable {
  let uid: uid_t
  let gid: gid_t
}

struct RuntimeIdentityObservation: Codable, Sendable {
  let process: ProcessObservation
  let effectiveUserIdentifier: UInt32
  let auditSessionIdentifier: UInt32
}

func currentConsoleIdentity() throws -> ConsoleIdentity {
  var uid: uid_t = 0
  var gid: gid_t = 0
  guard let name = SCDynamicStoreCopyConsoleUser(nil, &uid, &gid) else {
    throw FixtureError.physicalPreconditionUnavailable
  }
  let value = name as String
  guard value != "loginwindow", uid > 0, uid != uid_t.max, gid != gid_t.max else {
    throw FixtureError.physicalPreconditionUnavailable
  }
  return ConsoleIdentity(uid: uid, gid: gid)
}

private func dropPrivileges(to identity: ConsoleIdentity) throws {
  guard geteuid() == 0, let account = getpwuid(identity.uid),
    account.pointee.pw_uid == identity.uid,
    account.pointee.pw_gid == identity.gid,
    let name = account.pointee.pw_name
  else { throw FixtureError.physicalPreconditionUnavailable }
  guard initgroups(name, Int32(identity.gid)) == 0,
    setgid(identity.gid) == 0,
    setuid(identity.uid) == 0,
    getuid() == identity.uid,
    geteuid() == identity.uid,
    getgid() == identity.gid,
    getegid() == identity.gid
  else { throw FixtureError.physicalPreconditionUnavailable }
}

func installedExecutablePath() throws -> String {
  guard let path = Bundle.main.executableURL?.path, path.hasPrefix("/") else {
    throw FixtureError.physicalPreconditionUnavailable
  }
  var metadata = stat()
  guard lstat(path, &metadata) == 0,
    (metadata.st_mode & S_IFMT) == S_IFREG,
    metadata.st_uid == 0,
    metadata.st_mode & 0o022 == 0,
    metadata.st_mode & 0o111 != 0,
    metadata.st_mode & (S_ISUID | S_ISGID) == 0
  else { throw FixtureError.physicalPreconditionUnavailable }
  return path
}

private func decodeWorkerResult<Result: Codable>(
  _ type: Result.Type, output: BoundedCommandOutput
) throws -> Result {
  guard output.exitCode == 0, output.stderr.isEmpty,
    output.stdout.last == 0x0A
  else { throw FixtureError.physicalPreconditionUnavailable }
  let payload = output.stdout.dropLast()
  let value = try JSONDecoder().decode(type, from: payload)
  guard try canonicalJSON(value) == Data(payload) else {
    throw FixtureError.authorityResponseInvalid
  }
  return value
}

func consoleSnapshotWorker() throws -> SnapshotObservation {
  let identity = try currentConsoleIdentity()
  let path = try installedExecutablePath()
  let output = try runBoundedCommand(
    executable: "/bin/launchctl",
    arguments: [
      "asuser", String(identity.uid), path, "internal-snapshot", String(identity.uid),
      String(identity.gid),
    ])
  return try decodeWorkerResult(SnapshotObservation.self, output: output)
}

func isolatedRejectedWorker() throws -> RejectedPeerObservation {
  let identity = try currentConsoleIdentity()
  let path = try installedExecutablePath()
  let output = try runBoundedCommand(
    executable: path,
    arguments: ["internal-reject", String(identity.uid), String(identity.gid)])
  return try decodeWorkerResult(RejectedPeerObservation.self, output: output)
}

func isolatedIdentityWorker() throws -> RuntimeIdentityObservation {
  let identity = try currentConsoleIdentity()
  let path = try installedExecutablePath()
  let output = try runBoundedCommand(
    executable: path,
    arguments: ["internal-identity", String(identity.uid), String(identity.gid)])
  return try decodeWorkerResult(RuntimeIdentityObservation.self, output: output)
}

func consoleCanaryCycleWorker(_ canary: Data) throws -> CanaryCycleObservation {
  let identity = try currentConsoleIdentity()
  let path = try installedExecutablePath()
  let output = try runBoundedCommand(
    executable: "/bin/launchctl",
    arguments: [
      "asuser", String(identity.uid), path, "internal-canary-cycle", String(identity.uid),
      String(identity.gid),
    ],
    standardInput: canary)
  return try decodeWorkerResult(CanaryCycleObservation.self, output: output)
}

func runInternalWorker(arguments: [String]) async throws -> Bool {
  guard arguments.count >= 2, arguments[1].hasPrefix("internal-") else { return false }
  if arguments.count == 2, arguments[1] == "internal-hold-identity" {
    try writeCanonical(
      RuntimeIdentityObservation(
        process: try currentProcessObservation(),
        effectiveUserIdentifier: UInt32(geteuid()),
        auditSessionIdentifier: audit_session_self()))
    var release: UInt8 = 0
    while read(STDIN_FILENO, &release, 1) < 0, errno == EINTR {}
    return true
  }
  guard arguments.count == 4,
    let uid = uid_t(arguments[2]),
    let gid = gid_t(arguments[3])
  else { throw FixtureError.invalidArguments }
  try dropPrivileges(to: ConsoleIdentity(uid: uid, gid: gid))
  switch arguments[1] {
  case "internal-snapshot":
    try await writeCanonical(directSnapshot())
  case "internal-reject":
    try await writeCanonical(rejectedHostHandshake())
  case "internal-identity":
    try writeCanonical(
      RuntimeIdentityObservation(
        process: try currentProcessObservation(),
        effectiveUserIdentifier: UInt32(geteuid()),
        auditSessionIdentifier: audit_session_self()))
  case "internal-canary-cycle":
    let input = try FileHandle.standardInput.readToEnd() ?? Data()
    try await writeCanonical(exerciseCanaryCycle(input))
  default:
    throw FixtureError.invalidArguments
  }
  return true
}
