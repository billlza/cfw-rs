import CryptoKit
import Darwin
import Foundation
import Security

private let maximumCoverageEntries = 4_096
private let maximumCoverageEntryBytes = 64 * 1_024 * 1_024
private let maximumCoverageTotalBytes = 512 * 1_024 * 1_024

struct SecretCanary: Sendable {
  let bytes: Data

  static func generate() throws -> SecretCanary {
    var random = Data(count: 32)
    let status = random.withUnsafeMutableBytes { buffer in
      SecRandomCopyBytes(kSecRandomDefault, buffer.count, buffer.baseAddress!)
    }
    guard status == errSecSuccess else {
      random.resetBytes(in: random.startIndex..<random.endIndex)
      throw FixtureError.physicalPreconditionUnavailable
    }
    let suffix = random.map { String(format: "%02x", $0) }.joined()
    random.resetBytes(in: random.startIndex..<random.endIndex)
    return SecretCanary(bytes: Data("CFW_SECRET_CANARY_\(suffix)".utf8))
  }
}

private struct ScanInput: Sendable {
  let location: String
  let content: Data
}

func scanSecretSurface(
  caseID: ExternalCaseID,
  canary: SecretCanary,
  authoritySnapshot: SnapshotObservation
) throws -> SecretCoverage {
  guard let surface = caseID.secretSurface else { throw FixtureError.fixtureCaseMismatch }
  let started = Date()
  let inputs: [ScanInput]
  switch caseID {
  case .secretExtractionLogs:
    let output = try runBoundedCommand(
      executable: "/usr/bin/log",
      arguments: [
        "show", "--last", "10m", "--style", "ndjson", "--info", "--debug",
        "--predicate", "subsystem == \"com.bill.clashformac\"",
      ],
      timeoutSeconds: 30,
      maximumOutputBytes: maximumCoverageEntryBytes)
    guard output.exitCode == 0, output.stderr.isEmpty else {
      throw FixtureError.physicalPreconditionUnavailable
    }
    inputs = [
      ScanInput(location: "unified-log:com.bill.clashformac:last-10m", content: output.stdout)
    ]
  case .secretExtractionPreferences:
    inputs = try scanInputs(for: preferenceRoots()) { url in
      let name = url.lastPathComponent.lowercased()
      return name.contains("com.bill.clashformac") || name.contains("clash for mac")
    }
  case .secretExtractionJournal:
    inputs = try scanInputs(for: [
      URL(
        fileURLWithPath: "/Library/Application Support/com.bill.clashformac.global-authority",
        isDirectory: true)
    ])
  case .secretExtractionCrashRecords:
    inputs = try scanInputs(for: crashReportRoots()) { url in
      let name = url.lastPathComponent.lowercased()
      return name.hasPrefix("cfw") || name.contains("clash for mac")
        || name.contains("com.bill.clashformac")
    }
  case .secretExtractionSnapshots:
    inputs = [
      ScanInput(
        location: "authority-xpc:snapshot",
        content: try canonicalJSON(authoritySnapshot.snapshot))
    ]
  case .secretExtractionEvidence:
    inputs = try scanInputs(for: [
      URL(
        fileURLWithPath:
          "/Library/Application Support/Clash for Mac/ReleaseVerification",
        isDirectory: true),
      URL(
        fileURLWithPath: "/Users/bill/cfw-rs/target/physical-capture",
        isDirectory: true),
    ])
  default:
    throw FixtureError.fixtureCaseMismatch
  }
  guard !inputs.isEmpty, inputs.count <= maximumCoverageEntries else {
    throw FixtureError.physicalPreconditionUnavailable
  }

  var entries: [SecretCoverageEntry] = []
  var totalBytes: UInt64 = 0
  var totalMatches: UInt64 = 0
  for input in inputs {
    guard input.content.count <= maximumCoverageEntryBytes else {
      throw FixtureError.physicalPreconditionUnavailable
    }
    let (nextBytes, bytesOverflow) = totalBytes.addingReportingOverflow(
      UInt64(input.content.count))
    guard !bytesOverflow, nextBytes <= UInt64(maximumCoverageTotalBytes) else {
      throw FixtureError.physicalPreconditionUnavailable
    }
    let matches = countOccurrences(of: canary.bytes, in: input.content)
    let (nextMatches, matchOverflow) = totalMatches.addingReportingOverflow(matches)
    guard !matchOverflow else { throw FixtureError.secretCanaryObserved }
    totalBytes = nextBytes
    totalMatches = nextMatches
    entries.append(
      SecretCoverageEntry(
        locationSHA256: sha256(Data(input.location.utf8)),
        contentSHA256: sha256(input.content),
        scannedBytes: UInt64(input.content.count),
        matchCount: matches))
  }
  entries.sort { $0.locationSHA256 < $1.locationSHA256 }
  guard Set(entries.map(\.locationSHA256)).count == entries.count else {
    throw FixtureError.unsafeFilesystemEntry
  }
  guard totalMatches == 0 else { throw FixtureError.secretCanaryObserved }
  usleep(2_000)
  let finished = Date()
  return SecretCoverage(
    schemaVersion: 1,
    document: "cfw-adversarial-secret-coverage-v1",
    caseID: caseID.rawValue,
    surface: surface,
    canarySHA256: sha256(canary.bytes),
    startedAt: iso8601Milliseconds(started),
    finishedAt: iso8601Milliseconds(finished),
    enumerationComplete: true,
    unreadableCount: 0,
    excludedCount: 0,
    entryCount: UInt32(entries.count),
    totalScannedBytes: totalBytes,
    totalMatchCount: totalMatches,
    entries: entries)
}

func countOccurrences(of needle: Data, in haystack: Data) -> UInt64 {
  guard !needle.isEmpty, haystack.count >= needle.count else { return 0 }
  var count: UInt64 = 0
  var search = haystack.startIndex..<haystack.endIndex
  while let range = haystack.range(of: needle, options: [], in: search) {
    count += 1
    search = range.upperBound..<haystack.endIndex
  }
  return count
}

private func preferenceRoots() throws -> [URL] {
  let identity = try currentConsoleIdentity()
  guard let account = getpwuid(identity.uid), let home = account.pointee.pw_dir else {
    throw FixtureError.physicalPreconditionUnavailable
  }
  let homePath = String(cString: home)
  guard homePath.hasPrefix("/Users/"), !homePath.contains("..") else {
    throw FixtureError.physicalPreconditionUnavailable
  }
  return [
    URL(fileURLWithPath: homePath, isDirectory: true)
      .appendingPathComponent("Library/Preferences", isDirectory: true),
    URL(fileURLWithPath: homePath, isDirectory: true)
      .appendingPathComponent(
        "Library/Group Containers/YKUPL7Z869.group.com.bill.clashformac/Library/Preferences",
        isDirectory: true),
  ]
}

private func crashReportRoots() throws -> [URL] {
  let identity = try currentConsoleIdentity()
  guard let account = getpwuid(identity.uid), let home = account.pointee.pw_dir else {
    throw FixtureError.physicalPreconditionUnavailable
  }
  let homePath = String(cString: home)
  guard homePath.hasPrefix("/Users/"), !homePath.contains("..") else {
    throw FixtureError.physicalPreconditionUnavailable
  }
  return [
    URL(fileURLWithPath: "/Library/Logs/DiagnosticReports", isDirectory: true),
    URL(fileURLWithPath: homePath, isDirectory: true)
      .appendingPathComponent("Library/Logs/DiagnosticReports", isDirectory: true),
  ]
}

private func scanInputs(
  for roots: [URL],
  include: (URL) -> Bool = { _ in true }
) throws -> [ScanInput] {
  var inputs: [ScanInput] = []
  var locations = Set<String>()
  for root in roots {
    var metadata = stat()
    if lstat(root.path, &metadata) != 0 {
      guard errno == ENOENT else { throw FixtureError.physicalPreconditionUnavailable }
      try appendInput(
        ScanInput(location: root.path, content: Data()),
        to: &inputs,
        locations: &locations)
      continue
    }
    guard (metadata.st_mode & S_IFMT) == S_IFDIR,
      metadata.st_mode & S_IFMT != S_IFLNK
    else { throw FixtureError.unsafeFilesystemEntry }
    var enumerationError: Error?
    guard
      let enumerator = FileManager.default.enumerator(
        at: root,
        includingPropertiesForKeys: nil,
        options: [],
        errorHandler: { _, error in
          enumerationError = error
          return false
        })
    else { throw FixtureError.physicalPreconditionUnavailable }
    let initialCount = inputs.count
    while let value = enumerator.nextObject() as? URL {
      guard inputs.count < maximumCoverageEntries else {
        throw FixtureError.physicalPreconditionUnavailable
      }
      var child = stat()
      guard lstat(value.path, &child) == 0 else {
        throw FixtureError.physicalPreconditionUnavailable
      }
      let type = child.st_mode & S_IFMT
      if type == S_IFDIR { continue }
      if !include(value) { continue }
      guard type == S_IFREG,
        child.st_nlink == 1,
        child.st_size >= 0,
        child.st_size <= maximumCoverageEntryBytes
      else { throw FixtureError.unsafeFilesystemEntry }
      let content = try Data(contentsOf: value, options: [.mappedIfSafe])
      try appendInput(
        ScanInput(location: value.path, content: content),
        to: &inputs,
        locations: &locations)
    }
    if enumerationError != nil { throw FixtureError.physicalPreconditionUnavailable }
    if inputs.count == initialCount {
      try appendInput(
        ScanInput(location: root.path, content: Data()),
        to: &inputs,
        locations: &locations)
    }
  }
  return inputs
}

private func appendInput(
  _ input: ScanInput,
  to inputs: inout [ScanInput],
  locations: inout Set<String>
) throws {
  guard locations.insert(input.location).inserted else {
    throw FixtureError.unsafeFilesystemEntry
  }
  inputs.append(input)
}
