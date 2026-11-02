//! A minisign public key, an archive and the key's signature of it, made for
//! the verifier's tests. The key's secret half was discarded after signing.

pub const PUBLIC_KEY: &str = concat!(
    "dW50cnVzdGVkIGNvbW1lbnQ6IG1pbmlzaWduIHB1YmxpYyBrZXk6IDI2NzkxOURDRjBGNzVFRjMK",
    "UldUelh2ZnczQmw1Sm1yNVZnTVpsMVNybEU4RWQvQ01ucEp2QmRuVytIYkdVZDB6YnVHNStTZDIK"
);

/// The signature of `ARCHIVE` under the name `ARCHIVE_NAME`.
pub const SIGNATURE: &str = concat!(
    "dW50cnVzdGVkIGNvbW1lbnQ6IHNpZ25hdHVyZSBmcm9tIHRhdXJpIHNlY3JldCBrZXkKUlVUelh2",
    "ZnczQmw1SnRKNGFxMlVTVEd6K0FKdXgwaWlCUnBHYmZ2NUd6YU11aWdqSFNBdzlXVlo1Yjc5b3BE",
    "b2JNemgvaDlsLzhYek0xM21DQnYyeTJMUEtaRXNDaU9LaXdnPQp0cnVzdGVkIGNvbW1lbnQ6IHRp",
    "bWVzdGFtcDoxNzkzNjU1MjY0CWZpbGU6Q2xhc2guZm9yLk1hY185LjkuOV9hYXJjaDY0LmFwcC50",
    "YXIuZ3oKb2JDRkxhNjRUY3hTUnpnSjJ6ajFxNk9xYUVCa1ZVbXVWNEZrbFdmdm5jaDllTXNteHNF",
    "eWVtWGN0aytoMXJIaUthM0hFWE5WMnhoeVR0S3dSRFVDQ0E9PQo="
);

pub const ARCHIVE_NAME: &str = "Clash.for.Mac_9.9.9_aarch64.app.tar.gz";

pub const ARCHIVE: &[u8] = b"cfw-release-verifier fixture archive\n";
