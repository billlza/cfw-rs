import Darwin
import Foundation
import Security
import TransportPeerCore

public enum MacProbeContract {
  public static let planSchemaVersion = 1
  public static let resultSchemaVersion = 3
  public static let planDocument = "cfm-ios-transport-peer-mac-probe-plan-v1"
  public static let resultDocument = "cfm-ios-transport-peer-mac-probe-result-v3"
  public static let resultMode = "lab_smoke_only"
  public static let planFileName = "probe.json"
  public static let readyFileName = PeerContract.readyFileName
  public static let certificateFileName = PeerContract.certificateFileName
  public static let serverName = "cfm-transport-peer.invalid"
  public static let mismatchedALPN = "cfm-transport-peer-no-overlap/1"
  public static let attemptCount = 7
  public static let connectionDeadlineSeconds: TimeInterval = 8
}

public enum MacProbeError: Error, Equatable, LocalizedError {
  case invalidInput(String)
  case connectionFailed(String)
  case deadline(String)
  case protocolMismatch(String)

  public var errorDescription: String? {
    switch self {
    case .invalidInput(let label):
      "Invalid Mac transport probe input: \(label)"
    case .connectionFailed(let label):
      "Mac transport probe connection failed: \(label)"
    case .deadline(let label):
      "Mac transport probe deadline expired: \(label)"
    case .protocolMismatch(let label):
      "Mac transport probe protocol mismatch: \(label)"
    }
  }
}

public struct MacProbePlan: Codable, Equatable, Sendable {
  public let schemaVersion: Int
  public let document: String
  public let sessionID: String
  public let createdAt: String
  public let expiresAt: String
  public let peerIPv4: String
  public let certificateSHA256: String

  enum CodingKeys: String, CodingKey {
    case schemaVersion = "schema_version"
    case document
    case sessionID = "session_id"
    case createdAt = "created_at"
    case expiresAt = "expires_at"
    case peerIPv4 = "peer_ipv4"
    case certificateSHA256 = "certificate_sha256"
  }

  static let exactFields: Set<String> = [
    "schema_version",
    "document",
    "session_id",
    "created_at",
    "expires_at",
    "peer_ipv4",
    "certificate_sha256",
  ]

  public init(
    schemaVersion: Int,
    document: String,
    sessionID: String,
    createdAt: String,
    expiresAt: String,
    peerIPv4: String,
    certificateSHA256: String
  ) {
    self.schemaVersion = schemaVersion
    self.document = document
    self.sessionID = sessionID
    self.createdAt = createdAt
    self.expiresAt = expiresAt
    self.peerIPv4 = peerIPv4
    self.certificateSHA256 = certificateSHA256
  }

  public static func decodeCanonical(_ data: Data, now: Date) throws -> MacProbePlan {
    guard data.count > 1, data.count <= PeerContract.maximumJSONBytes, data.last == 0x0A else {
      throw MacProbeError.invalidInput("probe plan size or terminator")
    }
    let object = try JSONSerialization.jsonObject(with: Data(data.dropLast()), options: [])
    guard let dictionary = object as? [String: Any], Set(dictionary.keys) == exactFields else {
      throw MacProbeError.invalidInput("probe plan fields")
    }
    let plan = try JSONDecoder().decode(MacProbePlan.self, from: data)
    guard try ExactJSON.encode(plan) == data else {
      throw MacProbeError.invalidInput("probe plan canonical JSON")
    }
    try plan.validate(now: now)
    return plan
  }

  public func validate(now: Date) throws {
    guard schemaVersion == MacProbeContract.planSchemaVersion,
      document == MacProbeContract.planDocument,
      PeerSession.isDigest(sessionID),
      PeerSession.isDigest(certificateSHA256),
      PeerNetworkIdentity.isControlledWiFiIPv4(interfaceName: "en0", address: peerIPv4),
      let created = PeerSession.parseTimestamp(createdAt),
      let expires = PeerSession.parseTimestamp(expiresAt),
      created <= now,
      now < expires,
      expires.timeIntervalSince(created) <= PeerContract.maximumSessionSeconds
    else {
      throw MacProbeError.invalidInput("probe plan identity or lifetime")
    }
  }
}

public struct MacProbeInputs: Sendable {
  public let plan: MacProbePlan
  public let ready: ReadyReceipt
  public let certificateDER: Data
}

public enum MacProbeRunDirectory {
  public static func load(path: String, now: Date = Date()) throws -> MacProbeInputs {
    guard path.hasPrefix("/") else {
      throw MacProbeError.invalidInput("run directory is not absolute")
    }
    let directory = URL(fileURLWithPath: path, isDirectory: true).standardizedFileURL
    guard directory.path == directory.resolvingSymlinksInPath().standardizedFileURL.path else {
      throw MacProbeError.invalidInput("run directory contains a symbolic link")
    }
    try requirePrivateDirectory(directory)
    let expected = Set([
      MacProbeContract.planFileName,
      MacProbeContract.readyFileName,
      MacProbeContract.certificateFileName,
    ])
    try requireExactEntries(directory, expected: expected)

    let planData = try readStableFile(
      directory.appendingPathComponent(MacProbeContract.planFileName),
      maximumBytes: PeerContract.maximumJSONBytes
    )
    let readyData = try readStableFile(
      directory.appendingPathComponent(MacProbeContract.readyFileName),
      maximumBytes: PeerContract.maximumJSONBytes
    )
    let certificateDER = try readStableFile(
      directory.appendingPathComponent(MacProbeContract.certificateFileName),
      maximumBytes: 16 * 1_024
    )
    try requireExactEntries(directory, expected: expected)

    let plan = try MacProbePlan.decodeCanonical(planData, now: now)
    let ready: ReadyReceipt
    do {
      ready = try ExactJSON.decodeReady(readyData)
    } catch {
      throw MacProbeError.invalidInput("ready canonical JSON")
    }
    try validate(ready: ready, against: plan, now: now)
    guard PeerDigest.sha256(certificateDER) == plan.certificateSHA256,
      SecCertificateCreateWithData(nil, certificateDER as CFData) != nil
    else {
      throw MacProbeError.invalidInput("certificate bytes")
    }
    return MacProbeInputs(plan: plan, ready: ready, certificateDER: certificateDER)
  }

  private static func validate(ready: ReadyReceipt, against plan: MacProbePlan, now: Date) throws {
    guard ready.schemaVersion == PeerContract.schemaVersion,
      ready.document == PeerContract.readyDocument,
      ready.sessionID == plan.sessionID,
      ready.bundleIdentifier == PeerContract.bundleIdentifier,
      ready.processID > 0,
      ready.certificateSHA256 == plan.certificateSHA256,
      ready.network.interfaceName == "en0",
      ready.network.ipv4 == plan.peerIPv4,
      ready.listeners == .fixed,
      ready.expiresAt == plan.expiresAt,
      let planCreated = PeerSession.parseTimestamp(plan.createdAt),
      let started = PeerSession.parseTimestamp(ready.startedAt),
      let expires = PeerSession.parseTimestamp(ready.expiresAt),
      started <= planCreated,
      started <= now,
      now < expires
    else {
      throw MacProbeError.invalidInput("ready receipt binding")
    }
  }

  private static func requirePrivateDirectory(_ url: URL) throws {
    var metadata = stat()
    guard url.path.withCString({ lstat($0, &metadata) }) == 0,
      metadata.st_mode & S_IFMT == S_IFDIR,
      metadata.st_uid == geteuid(),
      metadata.st_mode & 0o777 == 0o700
    else {
      throw MacProbeError.invalidInput("run directory ownership or mode")
    }
  }

  private static func requireExactEntries(_ directory: URL, expected: Set<String>) throws {
    let entries: [URL]
    do {
      entries = try FileManager.default.contentsOfDirectory(
        at: directory,
        includingPropertiesForKeys: nil,
        options: []
      )
    } catch {
      throw MacProbeError.invalidInput("run directory inventory")
    }
    guard entries.count == expected.count, Set(entries.map(\.lastPathComponent)) == expected else {
      throw MacProbeError.invalidInput("run directory entries")
    }
  }

  private static func readStableFile(_ url: URL, maximumBytes: Int) throws -> Data {
    var before = stat()
    guard url.path.withCString({ lstat($0, &before) }) == 0,
      before.st_mode & S_IFMT == S_IFREG,
      before.st_uid == geteuid(),
      before.st_nlink == 1,
      before.st_mode & 0o022 == 0,
      before.st_size > 0,
      before.st_size <= maximumBytes
    else {
      throw MacProbeError.invalidInput("run input metadata")
    }
    let data: Data
    do {
      data = try Data(contentsOf: url, options: [.uncached])
    } catch {
      throw MacProbeError.invalidInput("run input read")
    }
    var after = stat()
    guard url.path.withCString({ lstat($0, &after) }) == 0,
      before.st_dev == after.st_dev,
      before.st_ino == after.st_ino,
      before.st_size == after.st_size,
      before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
      before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec,
      data.count == Int(before.st_size)
    else {
      throw MacProbeError.invalidInput("run input changed while reading")
    }
    return data
  }
}
