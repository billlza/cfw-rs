import Darwin
import Foundation
import Security

public struct PeerPaths: Sendable {
  public let directory: URL
  public let session: URL
  public let certificate: URL
  public let privateKey: URL
  public let ready: URL
  public let result: URL

  public init(documentsDirectory: URL) throws {
    guard documentsDirectory.isFileURL else {
      throw PeerContractError.unsafeFile("documents directory")
    }
    directory = documentsDirectory.appendingPathComponent(
      PeerContract.sessionDirectoryName,
      isDirectory: true
    )
    session = directory.appendingPathComponent(PeerContract.sessionFileName, isDirectory: false)
    certificate = directory.appendingPathComponent(
      PeerContract.certificateFileName,
      isDirectory: false
    )
    privateKey = directory.appendingPathComponent(
      PeerContract.privateKeyFileName,
      isDirectory: false
    )
    ready = directory.appendingPathComponent(PeerContract.readyFileName, isDirectory: false)
    result = directory.appendingPathComponent(PeerContract.resultFileName, isDirectory: false)
  }

  public static func applicationDocuments() throws -> PeerPaths {
    guard
      let documents = FileManager.default.urls(
        for: .documentDirectory,
        in: .userDomainMask
      ).first
    else {
      throw PeerContractError.unsafeFile("application documents directory")
    }
    return try PeerPaths(documentsDirectory: documents)
  }

  public func validateCleanInputs() throws {
    try requireDirectory(directory)
    let entries: [URL]
    do {
      entries = try FileManager.default.contentsOfDirectory(
        at: directory,
        includingPropertiesForKeys: nil,
        options: []
      )
    } catch {
      throw PeerContractError.unsafeFile("peer input inventory")
    }
    let expected = Set([
      PeerContract.sessionFileName,
      PeerContract.certificateFileName,
      PeerContract.privateKeyFileName,
    ])
    guard entries.count == expected.count,
      Set(entries.map(\.lastPathComponent)) == expected
    else {
      throw PeerContractError.unsafeFile("peer input entries")
    }
    try requireRegularFile(session, maximumBytes: PeerContract.maximumJSONBytes)
    try requireRegularFile(certificate, maximumBytes: 16 * 1_024)
    try requireRegularFile(privateKey, maximumBytes: 1_024)
  }

  public func loadSession(now: Date) throws -> PeerSession {
    try requireRegularFile(session, maximumBytes: PeerContract.maximumJSONBytes)
    let data = try Data(contentsOf: session, options: [.uncached])
    let value = try ExactJSON.decodeSession(data)
    _ = try value.validate(now: now)
    return value
  }

  public func writeReady(_ receipt: ReadyReceipt) throws {
    try writeOnce(try ExactJSON.encode(receipt), to: ready, label: "ready receipt")
  }

  public func writeResult(_ receipt: ResultReceipt) throws {
    try receipt.validate()
    try writeOnce(try ExactJSON.encode(receipt), to: result, label: "result receipt")
  }

  private func writeOnce(_ data: Data, to url: URL, label: String) throws {
    try writeExclusiveReceipt(data, to: url, label: label)
  }

  private func requireDirectory(_ url: URL) throws {
    let values = try url.resourceValues(forKeys: [
      .isDirectoryKey,
      .isSymbolicLinkKey,
    ])
    guard values.isDirectory == true, values.isSymbolicLink != true else {
      throw PeerContractError.unsafeFile(url.lastPathComponent)
    }
  }

  private func requireRegularFile(_ url: URL, maximumBytes: Int) throws {
    let values = try url.resourceValues(forKeys: [
      .isRegularFileKey,
      .isSymbolicLinkKey,
      .fileSizeKey,
    ])
    guard values.isRegularFile == true,
      values.isSymbolicLink != true,
      let size = values.fileSize,
      size > 0,
      size <= maximumBytes
    else {
      throw PeerContractError.unsafeFile(url.lastPathComponent)
    }
  }
}

public struct LocalNetworkPrimerPaths: Sendable {
  public let directory: URL
  public let result: URL
  public let transportDirectory: URL
  public let packetLanDirectory: URL

  public init(documentsDirectory: URL) throws {
    guard documentsDirectory.isFileURL else {
      throw PeerContractError.unsafeFile("documents directory")
    }
    directory = documentsDirectory.appendingPathComponent(
      PeerContract.primerDirectoryName,
      isDirectory: true
    )
    result = directory.appendingPathComponent(
      PeerContract.primerResultFileName,
      isDirectory: false
    )
    transportDirectory = documentsDirectory.appendingPathComponent(
      PeerContract.sessionDirectoryName,
      isDirectory: true
    )
    packetLanDirectory = documentsDirectory.appendingPathComponent(
      PacketLanPeerContract.directoryName,
      isDirectory: true
    )
  }

  public static func applicationDocuments() throws -> LocalNetworkPrimerPaths {
    guard
      let documents = FileManager.default.urls(
        for: .documentDirectory,
        in: .userDomainMask
      ).first
    else {
      throw PeerContractError.unsafeFile("application documents directory")
    }
    return try LocalNetworkPrimerPaths(documentsDirectory: documents)
  }

  public func prepareEmptyDirectory() throws {
    do {
      var transportMetadata = stat()
      errno = 0
      if lstat(transportDirectory.path, &transportMetadata) == 0 || errno != ENOENT {
        throw PeerContractError.unsafeFile("transport inputs exist during primer")
      }
      var packetLanMetadata = stat()
      errno = 0
      if lstat(packetLanDirectory.path, &packetLanMetadata) == 0 || errno != ENOENT {
        throw PeerContractError.unsafeFile("packet LAN inputs exist during primer")
      }
      if !FileManager.default.fileExists(atPath: directory.path) {
        try FileManager.default.createDirectory(
          at: directory,
          withIntermediateDirectories: false,
          attributes: [.posixPermissions: 0o700]
        )
        try FileManager.default.setAttributes(
          [.posixPermissions: 0o700],
          ofItemAtPath: directory.path
        )
      }
      var metadata = stat()
      guard lstat(directory.path, &metadata) == 0 else {
        throw PeerContractError.unsafeFile("primer directory metadata")
      }
      let entries = try FileManager.default.contentsOfDirectory(
        at: directory,
        includingPropertiesForKeys: nil,
        options: []
      )
      guard metadata.st_mode & S_IFMT == S_IFDIR,
        metadata.st_uid == geteuid(),
        metadata.st_mode & 0o777 == 0o700,
        entries.isEmpty
      else {
        throw PeerContractError.unsafeFile("primer directory metadata")
      }
    } catch let error as PeerContractError {
      throw error
    } catch {
      throw PeerContractError.unsafeFile("primer directory creation")
    }
  }

  public func writeResult(_ receipt: LocalNetworkPrimerReceipt) throws {
    let data = try ExactJSON.encode(receipt)
    try writeExclusiveReceipt(data, to: result, label: "primer result receipt")
  }

  public func loadFreshResult(now: Date) throws -> LocalNetworkPrimerReceipt {
    var directoryMetadata = stat()
    guard lstat(directory.path, &directoryMetadata) == 0,
      directoryMetadata.st_mode & S_IFMT == S_IFDIR,
      directoryMetadata.st_uid == geteuid(),
      directoryMetadata.st_mode & 0o777 == 0o700
    else {
      throw PeerContractError.unsafeFile("primer directory metadata")
    }
    let entries: [URL]
    do {
      entries = try FileManager.default.contentsOfDirectory(
        at: directory,
        includingPropertiesForKeys: nil,
        options: []
      )
    } catch {
      throw PeerContractError.unsafeFile("primer result inventory")
    }
    guard entries.count == 1,
      entries[0].lastPathComponent == PeerContract.primerResultFileName
    else {
      throw PeerContractError.unsafeFile("primer result inventory")
    }
    let data = try readPinnedReceipt(
      from: result,
      maximumBytes: PeerContract.maximumJSONBytes,
      label: "primer result receipt"
    )
    let receipt = try ExactJSON.decodePrimerResult(data)
    try receipt.validateFresh(now: now)
    return receipt
  }
}

func readPinnedReceipt(from url: URL, maximumBytes: Int, label: String) throws -> Data {
  guard url.isFileURL, maximumBytes > 0 else {
    throw PeerContractError.unsafeFile(label)
  }
  let descriptor = url.path.withCString { path in
    open(path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
  }
  guard descriptor >= 0 else {
    throw PeerContractError.unsafeFile(label)
  }

  var shouldClose = true
  defer {
    if shouldClose {
      _ = close(descriptor)
    }
  }
  var metadata = stat()
  guard fstat(descriptor, &metadata) == 0,
    metadata.st_mode & S_IFMT == S_IFREG,
    metadata.st_nlink == 1,
    metadata.st_uid == geteuid(),
    metadata.st_mode & 0o777 == 0o600,
    metadata.st_size > 0,
    metadata.st_size <= maximumBytes
  else {
    throw PeerContractError.unsafeFile(label)
  }

  let byteCount = Int(metadata.st_size)
  var data = Data(count: byteCount)
  var offset = 0
  let readSucceeded = data.withUnsafeMutableBytes { buffer -> Bool in
    guard let baseAddress = buffer.baseAddress else { return false }
    while offset < byteCount {
      let count = Darwin.read(
        descriptor,
        baseAddress.advanced(by: offset),
        byteCount - offset
      )
      if count > 0 {
        offset += count
      } else if count < 0, errno == EINTR {
        continue
      } else {
        return false
      }
    }
    return true
  }
  var trailingByte: UInt8 = 0
  let trailingCount = Darwin.read(descriptor, &trailingByte, 1)
  guard readSucceeded, offset == byteCount, trailingCount == 0 else {
    throw PeerContractError.unsafeFile(label)
  }
  let closeResult = close(descriptor)
  shouldClose = false
  guard closeResult == 0 else {
    throw PeerContractError.unsafeFile(label)
  }
  return data
}

func writeExclusiveReceipt(_ data: Data, to url: URL, label: String) throws {
  guard url.isFileURL,
    !data.isEmpty,
    data.count <= PeerContract.maximumJSONBytes
  else {
    throw PeerContractError.writeFailed(label)
  }
  let descriptor = url.path.withCString { path in
    open(path, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, mode_t(0o600))
  }
  guard descriptor >= 0 else {
    throw PeerContractError.writeFailed(label)
  }

  var succeeded = true
  data.withUnsafeBytes { buffer in
    var offset = 0
    while succeeded, offset < buffer.count {
      let count = Darwin.write(
        descriptor,
        buffer.baseAddress!.advanced(by: offset),
        buffer.count - offset
      )
      if count > 0 {
        offset += count
      } else if count < 0, errno == EINTR {
        continue
      } else {
        succeeded = false
      }
    }
  }
  if succeeded, fsync(descriptor) != 0 {
    succeeded = false
  }

  var metadata = stat()
  if succeeded,
    fstat(descriptor, &metadata) != 0
      || metadata.st_mode & S_IFMT != S_IFREG
      || metadata.st_uid != geteuid()
      || metadata.st_nlink != 1
      || metadata.st_mode & 0o777 != 0o600
      || metadata.st_size != data.count
  {
    succeeded = false
  }

  var reopened = Data(count: data.count)
  reopened.withUnsafeMutableBytes { buffer in
    var offset = 0
    while succeeded, offset < buffer.count {
      let count = pread(
        descriptor,
        buffer.baseAddress!.advanced(by: offset),
        buffer.count - offset,
        off_t(offset)
      )
      if count > 0 {
        offset += count
      } else if count < 0, errno == EINTR {
        continue
      } else {
        succeeded = false
      }
    }
  }
  if reopened != data {
    succeeded = false
  }
  if close(descriptor) != 0 {
    succeeded = false
  }

  let parent = url.deletingLastPathComponent()
  let directoryDescriptor = parent.path.withCString { path in
    open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  if directoryDescriptor < 0 {
    succeeded = false
  } else {
    if fsync(directoryDescriptor) != 0 {
      succeeded = false
    }
    if close(directoryDescriptor) != 0 {
      succeeded = false
    }
  }
  guard succeeded else {
    throw PeerContractError.writeFailed(label)
  }
}

public final class PeerIdentity: @unchecked Sendable {
  public let protocolIdentity: sec_identity_t
  public let certificateSHA256: String
  public let sourceFilesRemoved: Bool

  public init(paths: PeerPaths, session: PeerSession) throws {
    let certificateData = try Data(contentsOf: paths.certificate, options: [.uncached])
    let privateKeyData = try Data(contentsOf: paths.privateKey, options: [.uncached])
    guard PeerDigest.sha256(certificateData) == session.certificateSHA256,
      PeerDigest.sha256(privateKeyData) == session.privateKeySHA256
    else {
      throw PeerContractError.identityMismatch("input digests")
    }
    guard let certificate = SecCertificateCreateWithData(nil, certificateData as CFData) else {
      throw PeerContractError.identityMismatch("certificate DER")
    }
    let attributes: [CFString: Any] = [
      kSecAttrKeyType: kSecAttrKeyTypeECSECPrimeRandom,
      kSecAttrKeyClass: kSecAttrKeyClassPrivate,
      kSecAttrKeySizeInBits: 256,
    ]
    var keyError: Unmanaged<CFError>?
    guard
      let privateKey = SecKeyCreateWithData(
        privateKeyData as CFData,
        attributes as CFDictionary,
        &keyError
      )
    else {
      _ = keyError?.takeRetainedValue()
      throw PeerContractError.identityMismatch("private key")
    }
    guard let identity = SecIdentityCreate(nil, certificate, privateKey),
      let protocolIdentity = sec_identity_create(identity)
    else {
      throw PeerContractError.identityMismatch("certificate and private key")
    }
    do {
      try FileManager.default.removeItem(at: paths.privateKey)
      try FileManager.default.removeItem(at: paths.certificate)
    } catch {
      throw PeerContractError.unsafeFile("identity input cleanup")
    }
    guard !FileManager.default.fileExists(atPath: paths.privateKey.path),
      !FileManager.default.fileExists(atPath: paths.certificate.path)
    else {
      throw PeerContractError.unsafeFile("identity input cleanup proof")
    }
    self.protocolIdentity = protocolIdentity
    certificateSHA256 = session.certificateSHA256
    sourceFilesRemoved = true
  }
}
