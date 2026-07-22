import CFWLibboxRuntime
import Darwin
import Foundation
import Testing

private func withTemporaryDirectory(
  _ body: (URL) throws -> Void
) throws {
  let root = FileManager.default.temporaryDirectory.appendingPathComponent(
    "cfw-libbox-runtime-tests-\(UUID().uuidString)",
    isDirectory: true
  )
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: root) }
  try body(root)
}

private func permissions(at url: URL) throws -> mode_t {
  var metadata = stat()
  guard lstat(url.path, &metadata) == 0 else {
    throw CocoaError(.fileReadUnknown)
  }
  return metadata.st_mode & mode_t(0o7777)
}

@Test func runtimeDirectoriesArePrivateAndRoleSeparated() throws {
  try withTemporaryDirectory { root in
    let proxy = try LibboxRuntimeDirectories.prepare(
      container: root,
      role: .systemProxy
    )
    let tunnel = try LibboxRuntimeDirectories.prepare(
      container: root,
      role: .packetTunnel
    )

    #expect(proxy.base != tunnel.base)
    for directory in [
      proxy.base, proxy.working, proxy.temporary,
      tunnel.base, tunnel.working, tunnel.temporary,
    ] {
      #expect(try permissions(at: directory) == mode_t(0o700))
    }
    try proxy.validate()
    try tunnel.validate()
  }
}

@Test func runtimeDirectoryRejectsSymlinkedChild() throws {
  try withTemporaryDirectory { root in
    let base = root.appendingPathComponent("LibboxProxy", isDirectory: true)
    try FileManager.default.createDirectory(at: base, withIntermediateDirectories: false)
    let outside = root.appendingPathComponent("Outside", isDirectory: true)
    try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
    try FileManager.default.createSymbolicLink(
      at: base.appendingPathComponent("Working"),
      withDestinationURL: outside
    )

    #expect(throws: LibboxRuntimeError.self) {
      _ = try LibboxRuntimeDirectories.prepare(container: root, role: .systemProxy)
    }
  }
}
