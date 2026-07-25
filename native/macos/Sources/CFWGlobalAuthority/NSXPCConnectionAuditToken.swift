import Darwin
import Foundation

/// The kernel-supplied audit token of an `NSXPCConnection` peer.
///
/// `NSXPCConnection` exposes the peer audit token only through the private
/// `auditToken` accessor. The value is filled in by the kernel when the
/// connection is created and therefore cannot be forged by the peer, which is
/// exactly why the authority derives identity from it rather than from any
/// caller-supplied wire field. Because the accessor is not part of the public
/// Swift interface it is reached through the Objective-C selector; the call is
/// gated on `responds(to:)` so a future SDK change fails closed (no token,
/// connection rejected) instead of trapping.
@objc private protocol CFWXPCAuditTokenProviding {
  var auditToken: audit_token_t { get }
}

enum CFWXPCConnectionAuditToken {
  static func read(_ connection: NSXPCConnection) -> audit_token_t? {
    let selector = NSSelectorFromString("auditToken")
    guard connection.responds(to: selector) else { return nil }
    let accessor = unsafeBitCast(connection, to: CFWXPCAuditTokenProviding.self)
    return accessor.auditToken
  }
}
