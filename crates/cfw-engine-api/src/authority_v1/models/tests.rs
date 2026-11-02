use super::*;
use crate::authority_v1::test_support::{digest, operation, rejects};

#[test]
fn protocol_version_accepts_only_v1_without_features() {
    assert_eq!(ProtocolVersion::v1().validate(), Ok(()));
    let rejected = |change: fn(&mut ProtocolVersion)| {
        let mut version = ProtocolVersion::v1();
        change(&mut version);
        version.validate()
    };
    assert_eq!(
        rejected(|version| version.major = 2),
        Err(CodecError::UnsupportedMajor(2))
    );
    assert_eq!(
        rejected(|version| version.minor = 2),
        Err(CodecError::UnsupportedMinor(2))
    );
    assert_eq!(
        rejected(|version| version.minimum_minor = 0),
        Err(CodecError::UnsupportedMinor(MINOR))
    );
    assert_eq!(
        rejected(|version| version.feature_bits = 0b100),
        Err(CodecError::UnsupportedRequiredFeatures(0b100))
    );
    assert_eq!(
        rejected(|version| version.max_message_bytes = 0),
        Err(CodecError::BoundViolation)
    );
    assert_eq!(
        rejected(|version| version.max_message_bytes = MAX_ENVELOPE_BYTES as u32 + 1),
        Err(CodecError::BoundViolation)
    );
}

#[test]
fn operations_need_live_roots_a_revision_and_lowercase_digests() {
    for mode in [
        AuthorityMode::LocalProxy,
        AuthorityMode::SystemProxy,
        AuthorityMode::Tunnel,
    ] {
        rejects(
            &operation(mode),
            &[
                |operation| operation.root.epoch = 0,
                |operation| operation.root.generation = 0,
                |operation| operation.authority_revision = 0,
                |operation| operation.config_sha256 = digest('A'),
                |operation| operation.config_sha256 = digest('g'),
                |operation| operation.identity_sha256.truncate(63),
                |operation| operation.identity_sha256.push('0'),
            ],
        );
    }
}
