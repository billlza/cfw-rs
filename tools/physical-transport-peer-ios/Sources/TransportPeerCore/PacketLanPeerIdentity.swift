import Darwin
import Foundation

public struct PacketLanPeerPaths: Sendable {
  public let directory: URL
  public let session: URL
  public let ready: URL
  public let result: URL

  public init(documentsDirectory: URL) throws {
    guard documentsDirectory.isFileURL else {
      throw PeerContractError.unsafeFile("documents directory")
    }
    directory = documentsDirectory.appendingPathComponent(
      PacketLanPeerContract.directoryName,
      isDirectory: true
    )
    session = directory.appendingPathComponent(
      PacketLanPeerContract.sessionFileName,
      isDirectory: false
    )
    ready = directory.appendingPathComponent(
      PacketLanPeerContract.readyFileName,
      isDirectory: false
    )
    result = directory.appendingPathComponent(
      PacketLanPeerContract.resultFileName,
      isDirectory: false
    )
  }

  public static func applicationDocuments() throws -> PacketLanPeerPaths {
    guard
      let documents = FileManager.default.urls(
        for: .documentDirectory,
        in: .userDomainMask
      ).first
    else {
      throw PeerContractError.unsafeFile("application documents directory")
    }
    return try PacketLanPeerPaths(documentsDirectory: documents)
  }

  public func prepareCopiedInputs() throws {
    let descriptor = directory.path.withCString { path in
      open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    }
    guard descriptor >= 0 else {
      throw PeerContractError.unsafeFile("packet LAN input directory")
    }
    var shouldClose = true
    defer {
      if shouldClose {
        _ = close(descriptor)
      }
    }

    var copiedMetadata = stat()
    guard fstat(descriptor, &copiedMetadata) == 0,
      copiedMetadata.st_mode & S_IFMT == S_IFDIR,
      copiedMetadata.st_uid == geteuid(),
      copiedMetadata.st_mode & 0o777 == 0o755
    else {
      throw PeerContractError.unsafeFile("packet LAN copied directory metadata")
    }
    let beforeEntries = try inputEntries()
    let beforeSession = try readPinnedReceipt(
      from: session,
      maximumBytes: PeerContract.maximumJSONBytes,
      label: "packet LAN session"
    )

    guard fchmod(descriptor, 0o700) == 0,
      fsync(descriptor) == 0
    else {
      throw PeerContractError.unsafeFile("packet LAN directory permission tightening")
    }
    var tightenedMetadata = stat()
    guard fstat(descriptor, &tightenedMetadata) == 0,
      tightenedMetadata.st_dev == copiedMetadata.st_dev,
      tightenedMetadata.st_ino == copiedMetadata.st_ino,
      tightenedMetadata.st_mode & S_IFMT == S_IFDIR,
      tightenedMetadata.st_uid == geteuid(),
      tightenedMetadata.st_mode & 0o777 == 0o700,
      close(descriptor) == 0
    else {
      throw PeerContractError.unsafeFile("packet LAN tightened directory metadata")
    }
    shouldClose = false

    var pathMetadata = stat()
    guard lstat(directory.path, &pathMetadata) == 0,
      pathMetadata.st_dev == tightenedMetadata.st_dev,
      pathMetadata.st_ino == tightenedMetadata.st_ino,
      pathMetadata.st_mode & S_IFMT == S_IFDIR,
      pathMetadata.st_uid == geteuid(),
      pathMetadata.st_mode & 0o777 == 0o700,
      try inputEntries() == beforeEntries,
      try readPinnedReceipt(
        from: session,
        maximumBytes: PeerContract.maximumJSONBytes,
        label: "packet LAN session"
      ) == beforeSession
    else {
      throw PeerContractError.unsafeFile("packet LAN tightened input proof")
    }
  }

  private func inputEntries() throws -> Set<String> {
    let entries: [URL]
    do {
      entries = try FileManager.default.contentsOfDirectory(
        at: directory,
        includingPropertiesForKeys: nil,
        options: []
      )
    } catch {
      throw PeerContractError.unsafeFile("packet LAN input inventory")
    }
    let names = Set(entries.map(\.lastPathComponent))
    guard entries.count == 1,
      names == [PacketLanPeerContract.sessionFileName]
    else {
      throw PeerContractError.unsafeFile("packet LAN input inventory")
    }
    return names
  }

  public func loadSessionAndRemove(now: Date) throws -> PacketLanPeerSession {
    let data = try readPinnedReceipt(
      from: session,
      maximumBytes: PeerContract.maximumJSONBytes,
      label: "packet LAN session"
    )
    let value = try ExactJSON.decodePacketLanSession(data)
    try value.validate(now: now)
    do {
      try FileManager.default.removeItem(at: session)
      try synchronizeDirectory()
    } catch {
      throw PeerContractError.unsafeFile("packet LAN session cleanup")
    }
    var metadata = stat()
    errno = 0
    guard lstat(session.path, &metadata) != 0, errno == ENOENT else {
      throw PeerContractError.unsafeFile("packet LAN session cleanup proof")
    }
    return value
  }

  @discardableResult
  public func writeReady(
    _ receipt: PacketLanReadyReceipt,
    session: PacketLanPeerSession
  ) throws -> String {
    try receipt.validate(session: session)
    let data = try ExactJSON.encode(receipt)
    try writeExclusiveReceipt(data, to: ready, label: "packet LAN ready receipt")
    return PeerDigest.sha256(data)
  }

  public func writeResult(
    _ receipt: PacketLanResultReceipt,
    session: PacketLanPeerSession,
    ready: PacketLanReadyReceipt
  ) throws {
    try receipt.validate(session: session, ready: ready)
    let data = try ExactJSON.encode(receipt)
    try writeExclusiveReceipt(data, to: result, label: "packet LAN result receipt")
  }

  private func synchronizeDirectory() throws {
    let descriptor = directory.path.withCString { path in
      open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    }
    guard descriptor >= 0 else {
      throw PeerContractError.unsafeFile("packet LAN directory sync")
    }
    let syncResult = fsync(descriptor)
    let closeResult = close(descriptor)
    guard syncResult == 0, closeResult == 0 else {
      throw PeerContractError.unsafeFile("packet LAN directory sync")
    }
  }
}
