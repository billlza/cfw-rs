# Service identity after a bundle replacement

Finder can replace `/Applications/Clash for Mac.app` while its registered
background services continue running the previous executable. A default
`SecCode` process view then resolves the replacement's disk signature. Strict
validation correctly rejects the discrepancy with `errSecCSStaticCodeChanged`.
The service upgrader must identify the old running code before it can prove Off
and perform the existing ordered handoff.

`ServiceCodeIdentityReader` first uses the ordinary strict, network-disabled
validation path. Only `errSecCSStaticCodeChanged` admits the alternate observation:
the public `kSecGuestAttributeDynamicCode` and
`kSecGuestAttributeDynamicCodeInfoPlist` attributes ask Security to authenticate
the running code using original signed metadata. The same Team ID and bundle
requirement and the same strict validation flags still apply. A successful result
must also match the retained build number and CDHash exactly. The original version
ordering, complete process inventory, UID checks and XPC audit-token policies
remain in their existing owners; this reader does not authorize XPC operations.

Missing metadata, another signer or identifier, an unknown code hash, or another
validation failure remains an identity rejection. Only an Info.plist signature
mismatch can advance to another retained candidate. There are at most eight
candidates per component and at most 64 KiB of metadata per candidate. Nothing is
downloaded, cached in user storage, inferred from a filename or accepted from an
unverified version claim.

## Retained inputs and maintenance

`ServiceBuildMetadataCatalog.swift` contains exact original Info.plist bytes from
the retained signed 50030 and 51004 applications. The first is the published
predecessor; the second is the installed, retired 0.5.1 candidate. Each entry names
its build, original CDHash and the SHA-256 of its metadata. Metadata remains a
candidate until Security checks it against the live process; the catalog alone
never grants trust.

For a future supported predecessor, obtain the retained signed bundle bound to
its release receipt. Verify its expected Developer ID Team ID and component
identifier with strict signature checks. Copy the ProxyAgent's original
`Contents/Info.plist` bytes and the GlobalAuthority's original
`__TEXT,__info_plist` section bytes without parsing and reserializing them. Bind
each to the verified CDHash and build number, record the raw-byte SHA-256, and
encode those bytes in the catalog. The source change goes through the normal
review, CI and release-source closure. Do not derive historical metadata from the
new executable, synthesize a version field or accept a re-signed equal build.

The 51004 private acceptance directory retains extraction inputs, raw checks,
hashes, the independent Mac report and the isolated process-replacement records.
The committed native regression creates two ad-hoc-signed test executables,
keeps the first running while atomically replacing its pathname, observes the
old API failure, and exercises the corrected reader. It also rejects tampered
metadata, the replacement's metadata, an incorrect CDHash, another identifier,
and an oversized candidate set. It never registers a service or changes network
settings. Developer ID / XPC handoff and consumer upgrade acceptance still require
the actual signed candidate on a real Mac.

Apple documents the [disk-code mismatch](https://developer.apple.com/documentation/security/errseccsstaticcodechanged)
and the public [guest attribute keys](https://developer.apple.com/documentation/security/guest-attribute-dictionary-keys).
The distinction between disk-derived signing information and process-backed
metadata is visible in Apple's [SecCode implementation](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/SecCode.cpp)
and [process-backed metadata reader](https://github.com/apple-oss-distributions/Security/blob/main/OSX/libsecurity_codesigning/lib/piddiskrep.cpp).
