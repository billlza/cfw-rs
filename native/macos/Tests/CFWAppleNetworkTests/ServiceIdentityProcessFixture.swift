import Darwin
import Foundation
@preconcurrency import Security

@testable import CFWAppleNetwork

/// An ad-hoc-signed, unprivileged child used only by signature boundary tests.
/// It has no CFM service name, registration, network listener or shared storage.
struct ServiceIdentityProcessFixture {
  static let identifier = "org.cfm.tests.service-identity"
  let directory: URL
  let executable: URL
  let replacement: URL
  let requirement: SecRequirement
  let original: ServiceCodeMetadata
  let newer: ServiceCodeMetadata
  let child: Process
  let completion: DispatchSemaphore

  struct Failure: Error, CustomStringConvertible {
    let description: String
  }

  static func start() throws -> Self {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent(
      "CFMServiceIdentity-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(
      at: directory, withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700])
    let source = directory.appendingPathComponent("fixture.c")
    try Data(
      """
      #include <unistd.h>
      int main(void) {
        alarm(60);
        if (write(STDOUT_FILENO, "R", 1) != 1) return 2;
        for (;;) pause();
      }
      """.utf8
    ).write(to: source)
    let requirement = try makeRequirement(identifier)
    let executable = directory.appendingPathComponent("cfm-service-build-fixture")
    let replacement = directory.appendingPathComponent("replacement")
    let original = try compile(
      build: 50030, output: executable, source: source, requirement: requirement)
    let newer = try compile(
      build: 51004, output: replacement, source: source, requirement: requirement)
    let child = Process()
    let ready = Pipe()
    let completion = DispatchSemaphore(value: 0)
    let errors = directory.appendingPathComponent("child.stderr.log")
    guard FileManager.default.createFile(atPath: errors.path, contents: Data()) else {
      throw Failure(description: "Could not create fixture child log")
    }
    let errorHandle = try FileHandle(forWritingTo: errors)
    child.executableURL = executable
    child.standardOutput = ready
    child.standardError = errorHandle
    child.terminationHandler = { _ in completion.signal() }
    try child.run()
    do {
      try errorHandle.close()
      var descriptor = pollfd(
        fd: ready.fileHandleForReading.fileDescriptor, events: Int16(POLLIN), revents: 0)
      guard poll(&descriptor, 1, 5_000) == 1,
        descriptor.revents & Int16(POLLIN) != 0,
        try ready.fileHandleForReading.read(upToCount: 1) == Data("R".utf8)
      else { throw Failure(description: "Fixture did not become ready: \(directory.path)") }
      try ready.fileHandleForReading.close()
      try ready.fileHandleForWriting.close()
    } catch {
      try stop(child, completion: completion)
      throw error
    }
    return Self(
      directory: directory, executable: executable, replacement: replacement,
      requirement: requirement, original: original, newer: newer,
      child: child, completion: completion)
  }

  func replaceOnDisk() throws {
    guard rename(replacement.path, executable.path) == 0 else {
      throw Failure(description: "Fixture replacement failed: errno \(errno)")
    }
  }

  func close() throws {
    try Self.stop(child, completion: completion)
    try FileManager.default.removeItem(at: directory)
  }

  static func makeRequirement(_ identifier: String) throws -> SecRequirement {
    var requirement: SecRequirement?
    guard
      SecRequirementCreateWithString(
        "identifier \"\(identifier)\"" as CFString, [], &requirement) == errSecSuccess,
      let requirement
    else { throw Failure(description: "Fixture requirement could not be constructed") }
    return requirement
  }

  private static func compile(
    build: Int64, output: URL, source: URL, requirement: SecRequirement
  ) throws -> ServiceCodeMetadata {
    let info = Data(
      """
      <?xml version="1.0" encoding="UTF-8"?>
      <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
      <plist version="1.0"><dict>
      <key>CFBundleIdentifier</key><string>\(identifier)</string>
      <key>CFBundleExecutable</key><string>cfm-service-build-fixture</string>
      <key>CFBundleVersion</key><string>\(build)</string>
      </dict></plist>
      """.utf8)
    let plist = output.deletingLastPathComponent().appendingPathComponent("\(build).plist")
    try info.write(to: plist)
    try runTool(
      "/usr/bin/clang",
      [
        "-Wall", "-Wextra", "-Werror", "-mmacosx-version-min=15.0", source.path,
        "-Wl,-sectcreate,__TEXT,__info_plist,\(plist.path)", "-o", output.path,
      ], in: output.deletingLastPathComponent())
    try runTool(
      "/usr/bin/codesign",
      ["--force", "--sign", "-", "--timestamp=none", "--identifier", identifier, output.path],
      in: output.deletingLastPathComponent())
    return try ServiceCodeMetadata(
      identity: ServiceCodeIdentityReader.staticCode(output, requirement: requirement),
      infoPlist: info)
  }

  private static func runTool(_ path: String, _ arguments: [String], in directory: URL) throws {
    let output = directory.appendingPathComponent("command-\(UUID().uuidString).log")
    guard FileManager.default.createFile(atPath: output.path, contents: Data()) else {
      throw Failure(description: "Could not create fixture command log")
    }
    let handle = try FileHandle(forWritingTo: output)
    let process = Process()
    let completion = DispatchSemaphore(value: 0)
    process.executableURL = URL(fileURLWithPath: path)
    process.arguments = arguments
    process.standardOutput = handle
    process.standardError = handle
    process.terminationHandler = { _ in completion.signal() }
    try process.run()
    guard completion.wait(timeout: .now() + 30) == .success else {
      try stop(process, completion: completion)
      try handle.close()
      throw Failure(description: "Fixture command timed out; evidence: \(directory.path)")
    }
    try handle.close()
    guard process.terminationReason == .exit, process.terminationStatus == 0 else {
      let details = String(decoding: try Data(contentsOf: output).prefix(32_768), as: UTF8.self)
      throw Failure(description: "Fixture command failed: \(path); \(details); \(directory.path)")
    }
  }

  private static func stop(_ process: Process, completion: DispatchSemaphore) throws {
    if process.isRunning { process.terminate() }
    if completion.wait(timeout: .now() + 2) == .success { return }
    if process.isRunning {
      guard kill(process.processIdentifier, SIGKILL) == 0 || errno == ESRCH else {
        throw Failure(description: "Could not stop owned fixture child")
      }
    }
    guard completion.wait(timeout: .now() + 2) == .success else {
      throw Failure(description: "Owned fixture child did not exit within its cleanup bound")
    }
  }
}
