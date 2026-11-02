use serde_json::json;

use super::*;

mod platform;

const VERSION: &str = "1.2.3-beta.4+build.5";
const SIGNATURE: &str = "encoded-minisign-envelope";

fn manifest(url: &str) -> Value {
    json!({
        "version": VERSION,
        "notes": "Release notes",
        "pub_date": "2026-07-22T00:00:00Z",
        "platforms": {
            "darwin-aarch64": { "url": url, "signature": SIGNATURE },
            "darwin-arm64": { "url": url, "signature": SIGNATURE }
        }
    })
}

fn validate_url(url: &str) -> Result<UpdateAuthorization, UpdateContractError> {
    let parsed = Url::parse(url).expect("test URL must parse");
    validate_update(
        ReleaseTarget::MacArm64,
        VERSION,
        &parsed,
        SIGNATURE,
        &manifest(url),
    )
}

#[test]
fn accepts_only_the_canonical_github_release_asset() {
    let expected = ReleaseTarget::MacArm64
        .download_url(VERSION, &ReleaseTarget::MacArm64.archive_name(VERSION));
    let authorization = validate_url(&expected).expect("canonical update must validate");
    assert_eq!(authorization.version, VERSION);
    assert_eq!(
        authorization.archive_name,
        ReleaseTarget::MacArm64.archive_name(VERSION)
    );
    assert_eq!(authorization.download_url, expected);
    assert_eq!(authorization.signature, SIGNATURE);
}

#[test]
fn rejects_alternate_origins_and_url_components() {
    let expected = ReleaseTarget::MacArm64
        .download_url(VERSION, &ReleaseTarget::MacArm64.archive_name(VERSION));
    let cases = [
        expected.replacen("https://", "http://", 1),
        expected.replacen("github.com", "example.com", 1),
        expected.replacen("github.com", "user@github.com", 1),
        expected.replacen("github.com", "github.com:8443", 1),
        format!("{expected}?download=1"),
        format!("{expected}#archive"),
    ];
    for candidate in cases {
        assert!(
            validate_url(&candidate).is_err(),
            "alternate URL was accepted: {candidate}"
        );
    }
}

#[test]
fn rejects_encodings_and_lexical_traversal_even_after_url_normalization() {
    let expected = ReleaseTarget::MacArm64
        .download_url(VERSION, &ReleaseTarget::MacArm64.archive_name(VERSION));
    let encoded = expected.replace("Clash.for.Mac", "Clash%2Efor%2EMac");
    assert!(validate_url(&encoded).is_err());

    let asset = expected.rsplit('/').next().expect("asset name");
    let traversal = expected.replace(asset, &format!("ignored/../{asset}"));
    let normalized = Url::parse(&traversal).expect("traversal URL must parse");
    assert_eq!(normalized.as_str(), expected);
    assert_eq!(
        validate_update(
            ReleaseTarget::MacArm64,
            VERSION,
            &normalized,
            SIGNATURE,
            &manifest(&traversal)
        ),
        Err(UpdateContractError::ManifestUrlMismatch)
    );
}

#[test]
fn rejects_noncanonical_versions_and_wrong_asset_names() {
    let expected = ReleaseTarget::MacArm64
        .download_url(VERSION, &ReleaseTarget::MacArm64.archive_name(VERSION));
    let parsed = Url::parse(&expected).expect("expected URL");
    assert!(matches!(
        validate_update(
            ReleaseTarget::MacArm64,
            "01.2.3",
            &parsed,
            SIGNATURE,
            &manifest(&expected)
        ),
        Err(UpdateContractError::InvalidVersion)
    ));

    let wrong_arch = expected.replace("_aarch64", "_arm64");
    assert!(validate_url(&wrong_arch).is_err());
}

#[test]
fn rejects_manifest_alias_or_signature_drift() {
    let expected = ReleaseTarget::MacArm64
        .download_url(VERSION, &ReleaseTarget::MacArm64.archive_name(VERSION));
    let parsed = Url::parse(&expected).expect("expected URL");
    let mut wrong_alias = manifest(&expected);
    wrong_alias["platforms"]["darwin-arm64"]["url"] =
        Value::String("https://example.com/update".into());
    assert_eq!(
        validate_update(
            ReleaseTarget::MacArm64,
            VERSION,
            &parsed,
            SIGNATURE,
            &wrong_alias
        ),
        Err(UpdateContractError::ManifestUrlMismatch)
    );

    let mut wrong_signature = manifest(&expected);
    wrong_signature["platforms"]["darwin-aarch64"]["signature"] = Value::String("different".into());
    assert_eq!(
        validate_update(
            ReleaseTarget::MacArm64,
            VERSION,
            &parsed,
            SIGNATURE,
            &wrong_signature
        ),
        Err(UpdateContractError::ManifestSignatureMismatch)
    );
}

#[test]
fn rejects_dynamic_or_multi_platform_manifests() {
    let expected = ReleaseTarget::MacArm64
        .download_url(VERSION, &ReleaseTarget::MacArm64.archive_name(VERSION));
    let parsed = Url::parse(&expected).expect("expected URL");
    let dynamic = json!({ "version": VERSION, "url": expected, "signature": SIGNATURE });
    assert_eq!(
        validate_update(
            ReleaseTarget::MacArm64,
            VERSION,
            &parsed,
            SIGNATURE,
            &dynamic
        ),
        Err(UpdateContractError::UnexpectedManifestFields)
    );

    let mut extra = manifest(parsed.as_str());
    extra["platforms"]["linux-aarch64"] = json!({
        "url": parsed.as_str(),
        "signature": SIGNATURE
    });
    assert_eq!(
        validate_update(ReleaseTarget::MacArm64, VERSION, &parsed, SIGNATURE, &extra),
        Err(UpdateContractError::UnexpectedPlatforms)
    );
}

fn canonical_url() -> String {
    ReleaseTarget::MacArm64.download_url(VERSION, &ReleaseTarget::MacArm64.archive_name(VERSION))
}

fn admit(raw_manifest: &Value) -> Result<UpdateAuthorization, UpdateContractError> {
    let url = canonical_url();
    validate_update(
        ReleaseTarget::MacArm64,
        VERSION,
        &Url::parse(&url).expect("canonical URL"),
        SIGNATURE,
        raw_manifest,
    )
}

#[test]
fn the_debug_form_never_shows_the_signature() {
    let authorization = validate_url(&canonical_url()).expect("canonical update");
    let rendered = format!("{authorization:?}");
    assert!(rendered.contains("<minisign signature>"), "{rendered}");
    assert!(!rendered.contains(SIGNATURE), "{rendered}");
    assert!(rendered.contains(VERSION), "{rendered}");
}

#[test]
fn an_overlong_download_url_is_refused_before_it_is_compared() {
    let overlong = format!("{}?{}", canonical_url(), "a".repeat(MAX_DOWNLOAD_URL_BYTES));
    assert_eq!(
        validate_url(&overlong),
        Err(UpdateContractError::DownloadUrlTooLong)
    );
}

#[test]
fn the_manifest_must_name_this_version_and_valid_presentation_metadata() {
    let mut other_version = manifest(&canonical_url());
    other_version["version"] = Value::String("1.2.4".into());
    assert_eq!(
        admit(&other_version),
        Err(UpdateContractError::ManifestVersionMismatch)
    );

    let edits: [fn(&mut Value); 4] = [
        |manifest| manifest["notes"] = Value::Null,
        |manifest| manifest["pub_date"] = Value::Bool(true),
        |manifest| manifest["notes"] = Value::String("n".repeat(MAX_NOTES_BYTES + 1)),
        |manifest| manifest["pub_date"] = Value::String("yesterday".into()),
    ];
    for edit in edits {
        let mut invalid = manifest(&canonical_url());
        edit(&mut invalid);
        assert_eq!(
            admit(&invalid),
            Err(UpdateContractError::InvalidPresentationMetadata)
        );
    }
    let mut longest_notes = manifest(&canonical_url());
    longest_notes["notes"] = Value::String("n".repeat(MAX_NOTES_BYTES));
    admit(&longest_notes).expect("the longest notes are accepted");
}
