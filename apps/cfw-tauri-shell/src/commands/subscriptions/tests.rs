use cfw_singbox_config::MAX_PROFILE_BYTES;
use std::collections::{BTreeSet, VecDeque};
use std::sync::{Arc, Mutex};

use cfw_engine_api::{
    CredentialGarbageCollectionCommitFuture, CredentialGarbageCollectionCommitRequest,
    CredentialGarbageCollectionPreviewFuture, CredentialGarbageCollectionRequest,
    CredentialPresenceFuture, CredentialPresenceRequest, CredentialProvisionRequest, CredentialRef,
    CredentialVaultError, CredentialVaultFuture, CredentialVaultReceipt,
};
use sha2::{Digest as _, Sha256};

use super::fetch::*;
use super::*;
use reqwest::Client;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use reqwest::header::{CONTENT_ENCODING, HeaderMap, HeaderValue};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

#[test]
fn subscription_transport_bound_accepts_legacy_yaml_but_not_unbounded_profiles() {
    let observed_legacy_document = vec![b'x'; 494_575];
    assert!(observed_legacy_document.len() > 384 * 1024);
    assert!(observed_legacy_document.len() < MAX_PROFILE_BYTES);
    assert!(observed_legacy_document.len() < MAX_SUBSCRIPTION_DOCUMENT_BYTES);
    const { assert!(MAX_PROFILE_BYTES < MAX_SUBSCRIPTION_DOCUMENT_BYTES) };
}

const PROFILE_JSON: &str = r#"{"outbounds":[{"type":"trojan","tag":"proxy","server":"proxy.example.com","server_port":443,"credential_ref":{"id":"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb","kind":"trojan_password"},"tls":{"enabled":true,"server_name":"proxy.example.com"}}]}"#;
const DIRECT_PROFILE_JSON: &str =
    r#"{"route":{"final":"direct"},"outbounds":[{"tag":"direct","type":"direct"}]}"#;
const TRANSACTION_PROFILE_ID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TRANSACTION_SOURCE_URL: &str = "https://subscription.example/current";
const IMPORT_SECRET: &str = "subscription-secret-must-not-leak";

#[test]
fn subscription_update_result_flattens_profile_and_exposes_cleanup_state() {
    let value = serde_json::to_value(UiSubscriptionUpdateResult {
        profile: ProfileImportResult {
            id: TRANSACTION_PROFILE_ID.into(),
            name: "Work".into(),
            bytes: 123,
            digest: "ab".repeat(32),
        },
        credential_cleanup_removed: 2,
        credential_cleanup_pending: false,
        credential_cleanup_error: None,
        reset_proxy_groups: Vec::new(),
    })
    .expect("serialize update result");
    assert_eq!(value["name"], "Work");
    assert_eq!(value["credential_cleanup_removed"], 2);
    assert_eq!(value["credential_cleanup_pending"], false);
    assert!(value.get("credential_cleanup_error").is_none());
}

#[test]
fn only_a_direct_immutable_conflict_authorizes_reference_rotation() {
    let immutable =
        SubscriptionUpdateCommitError::Credential(ImportedCredentialProvisionError::Rejected(
            ImportedCredentialProvisionAttemptError::Vault(CredentialVaultError::ImmutableConflict),
        ));
    assert!(immutable.is_immutable_conflict());

    let unknown =
        SubscriptionUpdateCommitError::Credential(ImportedCredentialProvisionError::Rejected(
            ImportedCredentialProvisionAttemptError::Vault(CredentialVaultError::OutcomeUnknown),
        ));
    assert!(!unknown.is_immutable_conflict());
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ProvisionRequestSnapshot {
    profile_id: String,
    profile_digest: String,
    required_references: Vec<CredentialRef>,
    entries: Vec<(CredentialRef, [u8; 32])>,
    repository_profile_visible: bool,
}

fn provision_request_snapshot(
    profiles_dir: &Path,
    request: &CredentialProvisionRequest<'_>,
) -> ProvisionRequestSnapshot {
    let entries = request
        .entries()
        .iter()
        .map(|entry| {
            let digest = Sha256::digest(entry.secret().expose_to_vault().as_bytes());
            (entry.reference().clone(), digest.into())
        })
        .collect();
    let profile_path = profiles_dir.join(format!("{}.profile.json", request.profile_id()));
    let repository_profile_visible = match std::fs::symlink_metadata(profile_path) {
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => panic!("observe repository before vault response: {error}"),
    };
    ProvisionRequestSnapshot {
        profile_id: request.audience().profile_id().to_owned(),
        profile_digest: request.audience().profile_digest().to_owned(),
        required_references: request.required_references().to_vec(),
        entries,
        repository_profile_visible,
    }
}

#[derive(Debug)]
struct ScriptedCredentialVault {
    profiles_dir: PathBuf,
    responses: Mutex<VecDeque<Result<CredentialVaultReceipt, CredentialVaultError>>>,
    requests: Mutex<Vec<ProvisionRequestSnapshot>>,
    garbage_collection_requests: Mutex<usize>,
    provision_entered: Mutex<Option<std::sync::mpsc::Sender<()>>>,
    provision_release: Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
}

impl ScriptedCredentialVault {
    fn new(
        profiles_dir: PathBuf,
        responses: Vec<Result<CredentialVaultReceipt, CredentialVaultError>>,
    ) -> Self {
        Self {
            profiles_dir,
            responses: Mutex::new(responses.into()),
            requests: Mutex::new(Vec::new()),
            garbage_collection_requests: Mutex::new(0),
            provision_entered: Mutex::new(None),
            provision_release: Mutex::new(None),
        }
    }

    fn new_paused(
        profiles_dir: PathBuf,
        response: Result<CredentialVaultReceipt, CredentialVaultError>,
    ) -> (
        Self,
        std::sync::mpsc::Receiver<()>,
        tokio::sync::oneshot::Sender<()>,
    ) {
        let (entered_sender, entered_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = tokio::sync::oneshot::channel();
        (
            Self {
                profiles_dir,
                responses: Mutex::new(VecDeque::from([response])),
                requests: Mutex::new(Vec::new()),
                garbage_collection_requests: Mutex::new(0),
                provision_entered: Mutex::new(Some(entered_sender)),
                provision_release: Mutex::new(Some(release_receiver)),
            },
            entered_receiver,
            release_sender,
        )
    }

    fn requests(&self) -> Vec<ProvisionRequestSnapshot> {
        self.requests.lock().expect("request lock").clone()
    }

    fn garbage_collection_requests(&self) -> usize {
        *self
            .garbage_collection_requests
            .lock()
            .expect("garbage collection request lock")
    }
}

impl CredentialVaultProvisioner for ScriptedCredentialVault {
    fn provision_profile_credentials<'a>(
        &'a self,
        request: CredentialProvisionRequest<'a>,
    ) -> CredentialVaultFuture<'a> {
        let request_snapshot = provision_request_snapshot(&self.profiles_dir, &request);
        self.requests
            .lock()
            .expect("request lock")
            .push(request_snapshot);
        let response = self
            .responses
            .lock()
            .expect("response lock")
            .pop_front()
            .unwrap_or(Err(CredentialVaultError::Internal));
        if let Some(sender) = self
            .provision_entered
            .lock()
            .expect("provision entered lock")
            .take()
        {
            sender.send(()).expect("signal paused provision");
        }
        let release = self
            .provision_release
            .lock()
            .expect("provision release lock")
            .take();
        Box::pin(async move {
            if let Some(release) = release {
                release.await.map_err(|_| CredentialVaultError::Internal)?;
            }
            response
        })
    }

    fn query_profile_credentials(
        &self,
        _request: CredentialPresenceRequest,
    ) -> CredentialPresenceFuture<'_> {
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }

    fn preview_credential_garbage_collection(
        &self,
        _request: CredentialGarbageCollectionRequest,
    ) -> CredentialGarbageCollectionPreviewFuture<'_> {
        *self
            .garbage_collection_requests
            .lock()
            .expect("garbage collection request lock") += 1;
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }

    fn commit_credential_garbage_collection(
        &self,
        _request: CredentialGarbageCollectionCommitRequest,
    ) -> CredentialGarbageCollectionCommitFuture<'_> {
        *self
            .garbage_collection_requests
            .lock()
            .expect("garbage collection request lock") += 1;
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }
}

#[derive(Debug, Clone, Copy)]
enum RotationVaultMode {
    ImmutableThenEcho,
    AlwaysOutcomeUnknown,
}

#[derive(Debug)]
struct RotationCredentialVault {
    profiles_dir: PathBuf,
    mode: RotationVaultMode,
    requests: Mutex<Vec<ProvisionRequestSnapshot>>,
}

impl RotationCredentialVault {
    fn new(profiles_dir: PathBuf, mode: RotationVaultMode) -> Self {
        Self {
            profiles_dir,
            mode,
            requests: Mutex::new(Vec::new()),
        }
    }

    fn requests(&self) -> Vec<ProvisionRequestSnapshot> {
        self.requests.lock().expect("request lock").clone()
    }
}

impl CredentialVaultProvisioner for RotationCredentialVault {
    fn provision_profile_credentials<'a>(
        &'a self,
        request: CredentialProvisionRequest<'a>,
    ) -> CredentialVaultFuture<'a> {
        let request_snapshot = provision_request_snapshot(&self.profiles_dir, &request);
        let receipt = CredentialVaultReceipt {
            profile_id: request_snapshot.profile_id.clone(),
            profile_digest: request_snapshot.profile_digest.clone(),
        };
        let call = {
            let mut requests = self.requests.lock().expect("request lock");
            let call = requests.len();
            requests.push(request_snapshot);
            call
        };
        let response = match (self.mode, call) {
            (RotationVaultMode::ImmutableThenEcho, 0) => {
                Err(CredentialVaultError::ImmutableConflict)
            }
            (RotationVaultMode::ImmutableThenEcho, 1) => Ok(receipt),
            (RotationVaultMode::ImmutableThenEcho, _) => Err(CredentialVaultError::Internal),
            (RotationVaultMode::AlwaysOutcomeUnknown, _) => {
                Err(CredentialVaultError::OutcomeUnknown)
            }
        };
        Box::pin(async move { response })
    }

    fn query_profile_credentials(
        &self,
        _request: CredentialPresenceRequest,
    ) -> CredentialPresenceFuture<'_> {
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }

    fn preview_credential_garbage_collection(
        &self,
        _request: CredentialGarbageCollectionRequest,
    ) -> CredentialGarbageCollectionPreviewFuture<'_> {
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }

    fn commit_credential_garbage_collection(
        &self,
        _request: CredentialGarbageCollectionCommitRequest,
    ) -> CredentialGarbageCollectionCommitFuture<'_> {
        Box::pin(async { Err(CredentialVaultError::Internal) })
    }
}

fn credential_subscription(namespace: &str) -> crate::subscription_import::ImportedSubscription {
    validated_subscription_import_with_namespace(
        &format!("trojan://{IMPORT_SECRET}@proxy.example.com:443?sni=proxy.example.com#Work"),
        &EngineSettings::default(),
        Uuid::parse_str(namespace).expect("credential namespace"),
    )
    .expect("credential subscription")
}

fn successful_receipt(
    profile_id: &str,
    imported: &crate::subscription_import::ImportedSubscription,
) -> CredentialVaultReceipt {
    CredentialVaultReceipt {
        profile_id: profile_id.into(),
        profile_digest: imported.profile.digest().to_owned(),
    }
}

fn selected_direct_profile(repository: &ProfileRepository) -> StoredProfile {
    let profile = ValidatedSingBoxProfile::parse(DIRECT_PROFILE_JSON).expect("direct profile");
    repository
        .import_with_id_and_source(
            TRANSACTION_PROFILE_ID,
            Some("Original"),
            &profile,
            Some(TRANSACTION_SOURCE_URL),
        )
        .expect("import original profile");
    repository
        .select(TRANSACTION_PROFILE_ID)
        .expect("select original profile");
    repository
        .load(TRANSACTION_PROFILE_ID)
        .expect("load original profile")
        .expect("stored original profile")
}

#[derive(Debug)]
struct FixedDnsResolver {
    addresses: Vec<SocketAddr>,
}

impl Resolve for FixedDnsResolver {
    fn resolve(&self, _name: Name) -> Resolving {
        let addresses = self.addresses.clone();
        Box::pin(async move { Ok(Box::new(addresses.into_iter()) as Addrs) })
    }
}

#[test]
fn subscription_urls_must_be_public_https_endpoints() {
    assert_eq!(
        validate_subscription_url(" https://example.com/sub?token=t ")
            .expect("public https URL")
            .as_str(),
        "https://example.com/sub?token=t"
    );
    for rejected in [
        "http://example.com/sub",
        "https://127.0.0.1:9090/configs",
        "https://localhost/sub",
        "https://[::1]/sub",
        "https://10.0.0.5/sub",
        "https://192.168.1.1/sub",
        "https://169.254.1.1/sub",
        "https://100.64.0.1/sub",
        "https://[fc00::1]/sub",
        "https://[::ffff:127.0.0.1]/sub",
        "file:///etc/passwd",
        "clash://install-config?url=x",
        "https://example.com/ sub",
        "example.com/sub",
    ] {
        assert!(
            validate_subscription_url(rejected).is_err(),
            "accepted unsafe subscription URL: {rejected}"
        );
    }
    assert!(
        validate_subscription_url(&format!("https://example.com/{}", "a".repeat(4096))).is_err()
    );
}

#[test]
fn subscription_redirects_never_forward_referer_credentials() {
    const { assert!(!FORWARD_SUBSCRIPTION_REFERER) };
}

#[test]
fn subscription_client_keeps_the_closed_transport_policy_wired() {
    let source = include_str!("fetch.rs");
    let builder = source
        .split("fn subscription_client_with_resolver<")
        .nth(1)
        .expect("subscription client function")
        .split("/// Transport failures")
        .next()
        .expect("bounded subscription client builder");
    for required in [
        "external_https_client_builder()",
        "HeaderValue::from_static(\"identity\")",
        ".referer(FORWARD_SUBSCRIPTION_REFERER)",
        ".no_proxy()",
        ".no_gzip()",
        ".no_brotli()",
        ".no_deflate()",
        ".no_zstd()",
        ".dns_resolver(PublicSubscriptionDnsResolver::new(",
        ".redirect(Policy::custom(",
    ] {
        assert!(
            builder.contains(required),
            "missing transport policy: {required}"
        );
    }
}

#[test]
fn subscription_response_content_encoding_is_closed_to_identity() {
    let empty = HeaderMap::new();
    validate_subscription_content_encoding(&empty).expect("absent coding means identity");

    let mut identity = HeaderMap::new();
    identity.insert(CONTENT_ENCODING, HeaderValue::from_static("identity"));
    validate_subscription_content_encoding(&identity).expect("explicit identity coding");

    for value in ["gzip", "br", "identity, gzip", "", "identity,"] {
        let mut headers = HeaderMap::new();
        headers.insert(
            CONTENT_ENCODING,
            HeaderValue::from_str(value).expect("synthetic Content-Encoding"),
        );
        let error = validate_subscription_content_encoding(&headers)
            .expect_err("unsupported content coding must fail closed");
        assert!(error.contains("Content-Encoding"), "{value}: {error}");
    }
}

#[test]
fn ipv4_special_purpose_ranges_are_classified_fail_closed() {
    for accepted in [
        Ipv4Addr::new(93, 184, 216, 34),
        Ipv4Addr::new(100, 128, 0, 1),
        Ipv4Addr::new(172, 32, 0, 1),
        Ipv4Addr::new(192, 0, 0, 9),
        Ipv4Addr::new(192, 0, 0, 10),
        Ipv4Addr::new(192, 0, 1, 1),
        Ipv4Addr::new(198, 20, 0, 1),
    ] {
        assert!(is_public_ipv4(accepted), "rejected public {accepted}");
    }
    for rejected in [
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::new(0, 255, 255, 255),
        Ipv4Addr::LOCALHOST,
        Ipv4Addr::new(10, 0, 0, 1),
        Ipv4Addr::new(172, 16, 0, 1),
        Ipv4Addr::new(192, 168, 0, 1),
        Ipv4Addr::new(169, 254, 0, 1),
        Ipv4Addr::new(100, 64, 0, 1),
        Ipv4Addr::new(100, 127, 255, 255),
        Ipv4Addr::new(192, 0, 0, 8),
        Ipv4Addr::new(192, 88, 99, 2),
        Ipv4Addr::new(198, 18, 0, 1),
        Ipv4Addr::new(198, 19, 255, 255),
        Ipv4Addr::new(224, 0, 0, 1),
        Ipv4Addr::new(239, 255, 255, 255),
        Ipv4Addr::new(240, 0, 0, 1),
        Ipv4Addr::BROADCAST,
        Ipv4Addr::new(192, 0, 2, 1),
        Ipv4Addr::new(198, 51, 100, 1),
        Ipv4Addr::new(203, 0, 113, 1),
    ] {
        assert!(!is_public_ipv4(rejected), "accepted {rejected}");
    }
}

#[test]
fn ipv6_special_mapped_and_translation_ranges_are_classified_fail_closed() {
    for accepted in [
        "2606:4700::1111",
        "2001:1::1",
        "2001:1::2",
        "2001:1::3",
        "2001:3::1",
        "2001:4:112::1",
        "2001:20::1",
        "2001:30::1",
        "2001:200::1",
        "::ffff:93.184.216.34",
        "64:ff9b::5db8:d822",
    ] {
        let address = accepted.parse().expect("public IPv6 address");
        assert!(is_public_ipv6(address), "rejected public {accepted}");
    }
    for rejected in [
        "::",
        "::1",
        "::ffff:127.0.0.1",
        "::ffff:10.0.0.1",
        "64:ff9b::7f00:1",
        "64:ff9b:1::1",
        "100::1",
        "100:0:0:1::1",
        "2001::1",
        "2001:2::1",
        "2001:db8::1",
        "2002::1",
        "3fff::1",
        "5f00::1",
        "fc00::1",
        "fdff::1",
        "fe80::1",
        "fec0::1",
        "ff02::1",
        "4000::1",
    ] {
        let address = rejected.parse().expect("non-public IPv6 address");
        assert!(!is_public_ipv6(address), "accepted {rejected}");
    }
}

#[tokio::test]
async fn resolver_rejects_empty_and_mixed_public_private_answers() {
    let oversized = std::iter::repeat_n(
        SocketAddr::from(([93, 184, 216, 34], 0)),
        MAX_SUBSCRIPTION_DNS_ADDRESSES + 1,
    )
    .collect();
    for addresses in [
        vec![],
        oversized,
        vec![
            SocketAddr::from(([93, 184, 216, 34], 0)),
            SocketAddr::from(([127, 0, 0, 1], 0)),
        ],
        vec![SocketAddr::from(([100, 64, 0, 1], 0))],
        vec!["[fc00::1]:0".parse().expect("ULA socket address")],
        vec![
            "[::ffff:127.0.0.1]:0"
                .parse()
                .expect("mapped loopback socket address"),
        ],
    ] {
        let resolver = PublicSubscriptionDnsResolver::new(FixedDnsResolver { addresses });
        let name = "subscription.example".parse::<Name>().expect("DNS name");
        assert!(resolver.resolve(name).await.is_err());
    }
}

#[tokio::test]
async fn resolver_returns_the_exact_validated_public_answer_set() {
    let expected = vec![
        SocketAddr::from(([93, 184, 216, 34], 0)),
        "[2606:4700::1111]:0"
            .parse()
            .expect("public IPv6 socket address"),
    ];
    let resolver = PublicSubscriptionDnsResolver::new(FixedDnsResolver {
        addresses: expected.clone(),
    });
    let actual = resolver
        .resolve("subscription.example".parse::<Name>().expect("DNS name"))
        .await
        .expect("public answer")
        .collect::<Vec<_>>();
    assert_eq!(actual, expected);
}

#[test]
fn imports_require_a_profile_that_projects_for_both_modes() {
    let settings = EngineSettings::default();
    let profile = validated_profile(PROFILE_JSON, &settings).expect("valid profile");
    assert_eq!(profile.credential_references().len(), 1);

    // The projection owns listeners, logging, DNS and the experimental
    // controller, so a document that tries to supply them is refused before
    // anything is stored.
    for rejected in [
        r#"{"outbounds":[{"type":"direct","tag":"direct"}],"experimental":{"clash_api":{"external_controller":"0.0.0.0:9090"}}}"#,
        r#"{"outbounds":[{"type":"direct","tag":"direct"}],"inbounds":[{"type":"mixed","listen":"0.0.0.0","listen_port":7890}]}"#,
        r#"{"outbounds":[{"type":"direct","tag":"direct"}],"log":{"level":"debug"}}"#,
        "not json",
        "{}",
    ] {
        assert!(
            validated_profile(rejected, &settings).is_err(),
            "accepted unsupported document: {rejected}"
        );
    }
}

#[test]
fn profile_text_payload_carries_no_projection_or_path() {
    let payload = serde_json::to_value(UiProfileText {
        digest: "ab".repeat(32),
        id: "34db18b6-9903-4e9f-8854-15648e19e4f3".into(),
        name: "Work".into(),
        body: PROFILE_JSON.to_owned(),
        proxy_selections: std::collections::BTreeMap::new(),
        active: true,
        source_url: Some("https://example.com/sub?token=t".into()),
        bytes: PROFILE_JSON.len(),
        updated_epoch_secs: 42,
    })
    .expect("serialize profile text");
    let keys = payload
        .as_object()
        .expect("object payload")
        .keys()
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    assert_eq!(
        keys,
        [
            "active",
            "body",
            "bytes",
            "digest",
            "id",
            "name",
            "proxy_selections",
            "source_url",
            "updated_epoch_secs",
        ]
        .into_iter()
        .map(str::to_owned)
        .collect::<std::collections::BTreeSet<_>>()
    );
    assert!(!payload.to_string().contains("generated_body"));
    assert!(!payload.to_string().contains("clash_api"));
}

#[tokio::test]
async fn fetch_errors_never_echo_the_subscription_url() {
    let secret = "token-must-not-leak";
    let host = "malformed host";
    crate::transport_security::ensure_tls_crypto_provider().expect("test TLS provider");
    let error = Client::builder()
        .timeout(Duration::from_millis(50))
        .build()
        .expect("test client")
        .get(format!("http://{host}/sub?token={secret}"))
        .send()
        .await
        .expect_err("malformed URL must be rejected");
    let rendered = sanitized_fetch_error("request", &error);
    assert!(!rendered.contains(secret));
    assert!(!rendered.contains(host));
    assert!(rendered.starts_with("subscription request "));
}

#[test]
fn local_imports_reject_directories_symlinks_and_relative_paths() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let file = temporary.path().join("profile.json");
    std::fs::write(&file, PROFILE_JSON).expect("write profile");
    assert_eq!(
        read_local_profile(&file).expect("read profile"),
        PROFILE_JSON
    );

    let link = temporary.path().join("link.json");
    std::os::unix::fs::symlink(&file, &link).expect("create symlink");
    assert!(read_local_profile(&link).is_err());
    assert!(read_local_profile(temporary.path()).is_err());
    assert!(read_local_profile(Path::new("relative.json")).is_err());
}

#[test]
fn opened_profile_inode_is_stable_across_path_replacement() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profile = temporary.path().join("profile.json");
    let retained = temporary.path().join("opened-profile.json");
    let replacement = temporary.path().join("replacement.json");
    std::fs::write(&profile, PROFILE_JSON).expect("write original profile");
    std::fs::write(&replacement, "replacement").expect("write replacement");

    let opened = open_local_profile(&profile).expect("open original profile once");
    std::fs::rename(&profile, &retained).expect("retain opened inode under another name");
    std::os::unix::fs::symlink(&replacement, &profile).expect("replace original path");

    assert_eq!(
        read_opened_local_profile(opened).expect("read the already-opened inode"),
        PROFILE_JSON
    );
    assert!(read_local_profile(&profile).is_err());
}

#[test]
fn opened_profile_read_is_bounded_even_when_metadata_exceeds_the_limit() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profile = temporary.path().join("oversized.json");
    std::fs::write(&profile, vec![b'x'; MAX_SUBSCRIPTION_DOCUMENT_BYTES + 1])
        .expect("write oversized profile");
    assert!(read_local_profile(&profile).is_err());
}

#[test]
fn local_source_limit_allows_clash_metadata_without_widening_stored_profiles() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let path = temporary.path().join("nodes.yaml");
    let body = format!(
        "# {}\nproxies:\n  - {{ name: SOCKS5, type: socks5, server: proxy.example.com, port: 1080, udp: true }}\n",
        "x".repeat(MAX_PROFILE_BYTES)
    );
    assert!(body.len() < MAX_SUBSCRIPTION_DOCUMENT_BYTES);
    std::fs::write(&path, &body).expect("write bounded source");
    let loaded = read_local_profile(&path).expect("read larger source document");
    let imported = validated_subscription_import(&loaded, &EngineSettings::default())
        .expect("convert source metadata");
    assert!(imported.profile.as_json().len() < MAX_PROFILE_BYTES);
    assert!(imported.credentials.is_empty());
}

#[tokio::test]
async fn local_socks5_sources_provision_both_credentials_before_profile_visibility() {
    for (extension, body) in [
        (
            "txt",
            "socks://synthetic-user:synthetic-secret@proxy.example.com:29177",
        ),
        (
            "yaml",
            "proxies:\n  - { name: SOCKS5, type: socks5, server: proxy.example.com, port: 29177, username: synthetic-user, password: synthetic-secret, udp: true }",
        ),
        (
            "json",
            r#"{"outbounds":[{"type":"socks","tag":"SOCKS5","server":"proxy.example.com","server_port":29177,"username":"synthetic-user","password":"synthetic-secret"}]}"#,
        ),
    ] {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let path = temporary.path().join(format!("nodes.{extension}"));
        std::fs::write(&path, body).expect("write local source");
        let loaded = read_local_profile(&path).expect("read local source");
        let imported = validated_subscription_import(&loaded, &EngineSettings::default())
            .expect("convert local SOCKS5 source");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let vault = ScriptedCredentialVault::new(
            temporary.path().join("profiles"),
            vec![Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported))],
        );
        let record = commit_profile_import(
            &repository,
            &vault,
            TRANSACTION_PROFILE_ID,
            Some("SOCKS5"),
            ProfileImportSource::Local,
            &imported,
            true,
        )
        .await
        .expect("local vault-first import");
        let requests = vault.requests();
        assert_eq!(requests.len(), 1);
        assert!(!requests[0].repository_profile_visible);
        assert_eq!(requests[0].required_references.len(), 2);
        assert_eq!(requests[0].entries.len(), 2);
        for credential in &imported.credentials {
            let expected_secret: [u8; 32] = Sha256::digest(credential.secret.as_bytes()).into();
            assert!(
                requests[0]
                    .entries
                    .contains(&(credential.reference.clone(), expected_secret))
            );
        }
        let stored = repository
            .load(&record.id)
            .expect("load")
            .expect("stored profile");
        assert_eq!(stored.profile, imported.profile);
        assert!(stored.source_url.is_none());
        assert!(!stored.profile.as_json().contains("synthetic-user"));
        assert!(!stored.profile.as_json().contains("synthetic-secret"));
        assert_eq!(
            repository
                .snapshot()
                .expect("snapshot")
                .selected_profile_id
                .as_deref(),
            Some(record.id.as_str())
        );
    }
}

#[tokio::test]
async fn local_socks5_vault_failures_never_commit_or_select_a_partial_profile() {
    let imported = validated_subscription_import(
        "socks://synthetic-user:synthetic-secret@proxy.example.com:1080",
        &EngineSettings::default(),
    )
    .expect("SOCKS5 source");
    for (responses, expected_attempts, expected_error) in [
        (
            vec![Err(CredentialVaultError::AccessDenied)],
            1,
            "access was denied",
        ),
        (
            vec![
                Err(CredentialVaultError::OutcomeUnknown),
                Err(CredentialVaultError::OutcomeUnknown),
            ],
            2,
            "after one outcome-unknown replay",
        ),
        (
            vec![
                Ok(CredentialVaultReceipt {
                    profile_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
                    profile_digest: imported.profile.digest().into(),
                }),
                Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported)),
            ],
            1,
            "different profile audience",
        ),
        (
            vec![
                Err(CredentialVaultError::IdentityRejected),
                Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported)),
            ],
            1,
            "the operation result is unconfirmed",
        ),
    ] {
        let temporary = tempfile::TempDir::new().expect("temporary directory");
        let repository = ProfileRepository::new(temporary.path().join("profiles"));
        let original = repository
            .import(Some("Original"), &ValidatedSingBoxProfile::direct())
            .expect("original profile");
        repository.select(&original.id).expect("select original");
        let before = repository.snapshot().expect("original snapshot");
        let vault = ScriptedCredentialVault::new(temporary.path().join("profiles"), responses);
        let error = commit_profile_import(
            &repository,
            &vault,
            TRANSACTION_PROFILE_ID,
            Some("SOCKS5"),
            ProfileImportSource::Local,
            &imported,
            true,
        )
        .await
        .expect_err("unconfirmed credentials must not become visible");
        assert_eq!(repository.snapshot().expect("unchanged snapshot"), before);
        assert_eq!(vault.requests().len(), expected_attempts);
        assert_eq!(vault.garbage_collection_requests(), 0);
        if expected_attempts == 2 {
            assert_eq!(vault.requests()[0], vault.requests()[1]);
        }
        assert!(error.contains(expected_error), "{error}");
        assert!(!error.contains("data is corrupt"));
        assert!(!error.contains("synthetic-user"));
        assert!(!error.contains("synthetic-secret"));
    }
}

#[tokio::test]
async fn local_canonical_reference_only_profiles_preserve_manual_provisioning() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let imported = validated_subscription_import(PROFILE_JSON, &EngineSettings::default())
        .expect("canonical profile awaiting manual provisioning");
    let vault = ScriptedCredentialVault::new(temporary.path().join("profiles"), Vec::new());
    let record = commit_profile_import(
        &repository,
        &vault,
        TRANSACTION_PROFILE_ID,
        Some("Manual"),
        ProfileImportSource::Local,
        &imported,
        false,
    )
    .await
    .expect("manual setup remains available");
    assert!(vault.requests().is_empty());
    assert_eq!(
        repository
            .load(&record.id)
            .expect("load")
            .expect("profile")
            .profile,
        imported.profile
    );
    assert!(
        repository
            .snapshot()
            .expect("snapshot")
            .selected_profile_id
            .is_none()
    );
}

#[tokio::test]
async fn subscription_import_provisions_complete_audience_before_repository_visibility() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let imported = credential_subscription("11111111-1111-5111-8111-111111111111");
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported))],
    );

    let record = commit_profile_import(
        &repository,
        &vault,
        TRANSACTION_PROFILE_ID,
        Some("Imported"),
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &imported,
        false,
    )
    .await
    .expect("vault-first import");

    assert_eq!(record.id, TRANSACTION_PROFILE_ID);
    let requests = vault.requests();
    assert_eq!(requests.len(), 1);
    assert_eq!(requests[0].profile_id, TRANSACTION_PROFILE_ID);
    assert_eq!(requests[0].profile_digest, imported.profile.digest());
    assert!(!requests[0].repository_profile_visible);
    assert_eq!(requests[0].entries.len(), imported.credentials.len());
    assert_eq!(
        requests[0]
            .required_references
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        imported
            .profile
            .credential_references()
            .into_iter()
            .collect::<BTreeSet<_>>()
    );
    let catalog = repository
        .credential_snapshot()
        .expect("credential snapshot")
        .catalog;
    let committed = catalog
        .iter()
        .find(|entry| entry.audience.profile_id() == TRANSACTION_PROFILE_ID)
        .expect("committed audience");
    assert_eq!(
        committed.audience.profile_digest(),
        imported.profile.digest()
    );
    assert_eq!(
        committed
            .references
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>(),
        requests[0]
            .required_references
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn credential_gc_cannot_enter_between_vault_success_and_repository_commit() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let stale_preview_snapshot = repository
        .credential_snapshot()
        .expect("pre-provision credential snapshot");
    let imported = credential_subscription("77777777-7777-5777-8777-777777777777");
    let (vault, provision_entered, provision_release) = ScriptedCredentialVault::new_paused(
        profiles_dir,
        Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported)),
    );
    let vault = Arc::new(vault);
    let import_repository = repository.clone();
    let import_vault = Arc::clone(&vault);
    let import_candidate = imported.clone();
    let import_task = tokio::spawn(async move {
        commit_profile_import(
            &import_repository,
            import_vault.as_ref(),
            TRANSACTION_PROFILE_ID,
            Some("Imported"),
            ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
            &import_candidate,
            false,
        )
        .await
    });

    provision_entered
        .recv_timeout(Duration::from_secs(2))
        .expect("vault provision entered while repository lock is held");
    let gc_repository = repository.clone();
    let (gc_sender, gc_receiver) = std::sync::mpsc::channel();
    let gc_reread = std::thread::spawn(move || {
        let locked = gc_repository
            .lock_credential_snapshot()
            .expect("competing GC snapshot lock");
        gc_sender
            .send(locked.snapshot().clone())
            .expect("send competing GC snapshot");
    });
    assert!(matches!(
        gc_receiver.recv_timeout(Duration::from_millis(50)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));

    provision_release
        .send(())
        .expect("release vault provision result");
    let record = import_task
        .await
        .expect("import task")
        .expect("vault-first import commit");
    let current = gc_receiver
        .recv_timeout(Duration::from_secs(2))
        .expect("GC reread unblocked after repository commit");
    gc_reread.join().expect("GC reread thread");

    assert_eq!(record.id, TRANSACTION_PROFILE_ID);
    assert_ne!(
        current.snapshot_digest, stale_preview_snapshot.snapshot_digest,
        "a GC commit bound to the pre-provision snapshot must fail closed"
    );
    let live = current
        .catalog
        .iter()
        .find(|entry| entry.audience.profile_id() == TRANSACTION_PROFILE_ID)
        .expect("prepared audience is live before GC can acquire the lock");
    assert_eq!(live.audience.profile_digest(), imported.profile.digest());
    assert!(!vault.requests()[0].repository_profile_visible);
}

#[tokio::test]
async fn vault_rejection_and_two_unknown_outcomes_commit_no_profile() {
    let imported = credential_subscription("22222222-2222-5222-8222-222222222222");

    let deterministic_directory = tempfile::TempDir::new().expect("temporary directory");
    let deterministic_repository =
        ProfileRepository::new(deterministic_directory.path().join("profiles"));
    let deterministic_vault = ScriptedCredentialVault::new(
        deterministic_directory.path().join("profiles"),
        vec![Err(CredentialVaultError::AccessDenied)],
    );
    let deterministic_error = commit_profile_import(
        &deterministic_repository,
        &deterministic_vault,
        TRANSACTION_PROFILE_ID,
        None,
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &imported,
        false,
    )
    .await
    .expect_err("deterministic vault rejection");
    assert_eq!(deterministic_vault.requests().len(), 1);
    assert!(
        deterministic_repository
            .snapshot()
            .expect("empty repository snapshot")
            .profiles
            .is_empty()
    );
    assert!(!deterministic_error.contains(IMPORT_SECRET));

    let unknown_directory = tempfile::TempDir::new().expect("temporary directory");
    let unknown_repository = ProfileRepository::new(unknown_directory.path().join("profiles"));
    let unknown_vault = ScriptedCredentialVault::new(
        unknown_directory.path().join("profiles"),
        vec![
            Err(CredentialVaultError::OutcomeUnknown),
            Err(CredentialVaultError::OutcomeUnknown),
        ],
    );
    let unknown_error = commit_profile_import(
        &unknown_repository,
        &unknown_vault,
        TRANSACTION_PROFILE_ID,
        None,
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &imported,
        false,
    )
    .await
    .expect_err("two unknown outcomes must fail closed");
    let requests = unknown_vault.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1], "the replay must be exact");
    assert!(
        unknown_repository
            .snapshot()
            .expect("empty repository snapshot")
            .profiles
            .is_empty()
    );
    assert!(unknown_error.contains("after one outcome-unknown replay"));
    assert!(!unknown_error.contains(IMPORT_SECRET));
}

#[tokio::test]
async fn typed_profile_with_refs_requires_vault_confirmation_even_without_entries() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let imported = validated_subscription_import(PROFILE_JSON, &EngineSettings::default())
        .expect("typed credential profile");
    assert!(imported.credentials.is_empty());
    assert_eq!(imported.profile.credential_references().len(), 1);
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Err(CredentialVaultError::AccessDenied)],
    );

    commit_profile_import(
        &repository,
        &vault,
        TRANSACTION_PROFILE_ID,
        None,
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &imported,
        false,
    )
    .await
    .expect_err("missing existing material must not become repository-visible");

    let requests = vault.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].entries.is_empty());
    assert_eq!(requests[0].required_references.len(), 1);
    assert!(
        repository
            .snapshot()
            .expect("empty repository snapshot")
            .profiles
            .is_empty()
    );
}

#[tokio::test]
async fn receipt_audience_mismatch_commits_no_profile_and_is_not_replayed() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let imported = credential_subscription("33333333-3333-5333-8333-333333333333");
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Ok(CredentialVaultReceipt {
            profile_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb".into(),
            profile_digest: imported.profile.digest().to_owned(),
        })],
    );

    let error = commit_profile_import(
        &repository,
        &vault,
        TRANSACTION_PROFILE_ID,
        None,
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &imported,
        false,
    )
    .await
    .expect_err("wrong receipt audience");

    assert_eq!(vault.requests().len(), 1);
    assert!(error.contains("different profile audience"));
    assert!(!error.contains(IMPORT_SECRET));
    assert!(
        repository
            .snapshot()
            .expect("empty repository snapshot")
            .profiles
            .is_empty()
    );
}

#[tokio::test]
async fn stale_update_is_rejected_before_vault_provisioning() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let original = selected_direct_profile(&repository);
    let mut stale_expected = original.clone();
    stale_expected.source_url = Some("https://subscription.example/stale".into());
    let imported = credential_subscription("44444444-4444-5444-8444-444444444444");
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported))],
    );

    let error = commit_subscription_update(
        &repository,
        &vault,
        &stale_expected,
        "https://subscription.example/replacement",
        &imported,
    )
    .await
    .expect_err("stale update CAS");

    assert!(error.contains("could not begin before credential provisioning"));
    assert_eq!(
        repository
            .load(TRANSACTION_PROFILE_ID)
            .expect("load unchanged profile")
            .expect("unchanged profile"),
        original
    );
    assert_eq!(
        repository
            .load_selected()
            .expect("load selected profile")
            .expect("selected profile"),
        original
    );
    assert!(
        vault.requests().is_empty(),
        "a stale response must not write a vault audience"
    );
    let catalog = repository
        .credential_snapshot()
        .expect("credential snapshot")
        .catalog;
    let live = catalog
        .iter()
        .find(|entry| entry.audience.profile_id() == TRANSACTION_PROFILE_ID)
        .expect("live original audience");
    assert_eq!(live.audience.profile_digest(), original.profile.digest());
}

#[tokio::test]
async fn selected_update_is_visible_only_with_the_complete_vault_audience() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let original = selected_direct_profile(&repository);
    let imported = credential_subscription("55555555-5555-5555-8555-555555555555");
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported))],
    );

    let updated = commit_subscription_update(
        &repository,
        &vault,
        &original,
        "https://subscription.example/replacement",
        &imported,
    )
    .await
    .expect("vault-first selected update");

    assert_eq!(updated.id, TRANSACTION_PROFILE_ID);
    assert_eq!(updated.digest, imported.profile.digest());
    let requests = vault.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].repository_profile_visible);
    let selected = repository
        .load_selected()
        .expect("load selected profile")
        .expect("selected replacement");
    assert_eq!(selected.record.id, TRANSACTION_PROFILE_ID);
    assert_eq!(selected.profile, imported.profile);
    assert_eq!(
        selected.source_url.as_deref(),
        Some("https://subscription.example/replacement")
    );
    let catalog = repository
        .credential_snapshot()
        .expect("credential snapshot")
        .catalog;
    let live = catalog
        .iter()
        .find(|entry| entry.audience.profile_id() == TRANSACTION_PROFILE_ID)
        .expect("selected replacement audience");
    assert_eq!(live.audience.profile_digest(), requests[0].profile_digest);
    assert_eq!(
        live.references.iter().cloned().collect::<BTreeSet<_>>(),
        requests[0]
            .required_references
            .iter()
            .cloned()
            .collect::<BTreeSet<_>>()
    );
}

#[tokio::test]
async fn unchanged_subscription_updates_keep_one_stable_vault_audience() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let body = format!("trojan://{IMPORT_SECRET}@proxy.example.com:443?sni=proxy.example.com#Work");
    let initial = validated_subscription_import(&body, &EngineSettings::default())
        .expect("initial subscription");
    let receipt = successful_receipt(TRANSACTION_PROFILE_ID, &initial);
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Ok(receipt.clone()), Ok(receipt.clone()), Ok(receipt)],
    );

    commit_profile_import(
        &repository,
        &vault,
        TRANSACTION_PROFILE_ID,
        Some("Work"),
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &initial,
        false,
    )
    .await
    .expect("initial import");

    for _ in 0..2 {
        let stored = repository
            .load(TRANSACTION_PROFILE_ID)
            .expect("load profile")
            .expect("stored profile");
        let replay = validated_subscription_import_with_reusable_references(
            &body,
            &EngineSettings::default(),
            stored.profile.credential_references_in_outbound_order(),
        )
        .expect("stable update import");
        assert_eq!(replay.profile.digest(), initial.profile.digest());
        commit_subscription_update_attempt(
            &repository,
            &vault,
            &stored,
            TRANSACTION_SOURCE_URL,
            &replay,
        )
        .await
        .expect("unchanged update");
    }

    let requests = vault.requests();
    assert_eq!(requests.len(), 3);
    assert!(requests.windows(2).all(|pair| {
        pair[0].profile_digest == pair[1].profile_digest
            && pair[0].required_references == pair[1].required_references
    }));
}

#[tokio::test]
async fn immutable_secret_change_rotates_once_and_commits_the_fresh_reference() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let old_body = "trojan://old-secret@proxy.example.com:443?sni=proxy.example.com#Work";
    let new_body = "trojan://new-secret@proxy.example.com:443?sni=proxy.example.com#Work";
    let initial = validated_subscription_import_with_namespace(
        old_body,
        &EngineSettings::default(),
        Uuid::parse_str("77777777-7777-4777-8777-777777777777").expect("credential namespace"),
    )
    .expect("initial subscription");
    repository
        .import_with_id_and_source(
            TRANSACTION_PROFILE_ID,
            Some("Work"),
            &initial.profile,
            Some(TRANSACTION_SOURCE_URL),
        )
        .expect("seed subscription profile");
    repository
        .select(TRANSACTION_PROFILE_ID)
        .expect("select initial profile");
    let stored = repository
        .load(TRANSACTION_PROFILE_ID)
        .expect("load initial profile")
        .expect("initial profile");
    let reused = validated_subscription_import_with_reusable_references(
        new_body,
        &EngineSettings::default(),
        stored.profile.credential_references_in_outbound_order(),
    )
    .expect("reused-reference candidate");
    assert_eq!(reused.profile.digest(), stored.profile.digest());
    let vault = RotationCredentialVault::new(profiles_dir, RotationVaultMode::ImmutableThenEcho);

    let updated = commit_subscription_update_with_rotation(
        &repository,
        &vault,
        &stored,
        TRANSACTION_SOURCE_URL,
        new_body,
        &EngineSettings::default(),
        &reused,
    )
    .await
    .expect("immutable conflict rotation");

    let requests = vault.requests();
    assert_eq!(requests.len(), 2, "rotation is attempted exactly once");
    assert_eq!(
        requests[0].required_references,
        stored.profile.credential_references_in_outbound_order()
    );
    assert_ne!(
        requests[1].required_references, requests[0].required_references,
        "changed material must receive a fresh UUID"
    );
    assert_eq!(requests[0].entries.len(), requests[1].entries.len());
    assert!(
        requests[0]
            .entries
            .iter()
            .zip(&requests[1].entries)
            .all(|(first, second)| first.1 == second.1),
        "rotation changes only the UUID, not the requested secret"
    );
    assert_ne!(requests[1].profile_digest, requests[0].profile_digest);
    let committed = repository
        .load(TRANSACTION_PROFILE_ID)
        .expect("load rotated profile")
        .expect("rotated profile");
    assert_eq!(updated.id, TRANSACTION_PROFILE_ID);
    assert_eq!(committed.record.digest, requests[1].profile_digest);
    assert_eq!(
        committed.profile.credential_references_in_outbound_order(),
        requests[1].required_references
    );
    assert_eq!(
        repository
            .load_selected()
            .expect("load selected profile")
            .expect("selected rotated profile")
            .record
            .digest,
        requests[1].profile_digest
    );
}

#[tokio::test]
async fn outcome_unknown_replays_exactly_and_never_rotates_references() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let profiles_dir = temporary.path().join("profiles");
    let repository = ProfileRepository::new(&profiles_dir);
    let body = "trojan://new-secret@proxy.example.com:443?sni=proxy.example.com#Work";
    let initial = validated_subscription_import_with_namespace(
        body,
        &EngineSettings::default(),
        Uuid::parse_str("88888888-8888-4888-8888-888888888888").expect("credential namespace"),
    )
    .expect("initial subscription");
    repository
        .import_with_id_and_source(
            TRANSACTION_PROFILE_ID,
            Some("Work"),
            &initial.profile,
            Some(TRANSACTION_SOURCE_URL),
        )
        .expect("seed subscription profile");
    let stored = repository
        .load(TRANSACTION_PROFILE_ID)
        .expect("load initial profile")
        .expect("initial profile");
    let reused = validated_subscription_import_with_reusable_references(
        body,
        &EngineSettings::default(),
        stored.profile.credential_references_in_outbound_order(),
    )
    .expect("reused-reference candidate");
    let vault = RotationCredentialVault::new(profiles_dir, RotationVaultMode::AlwaysOutcomeUnknown);

    let error = commit_subscription_update_with_rotation(
        &repository,
        &vault,
        &stored,
        TRANSACTION_SOURCE_URL,
        body,
        &EngineSettings::default(),
        &reused,
    )
    .await
    .expect_err("two unknown outcomes must fail closed");

    assert!(error.contains("after one outcome-unknown replay"));
    let requests = vault.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1], "the replay must be exact");
    assert_eq!(
        repository
            .load(TRANSACTION_PROFILE_ID)
            .expect("load unchanged profile")
            .expect("unchanged profile"),
        stored
    );
}

#[tokio::test]
async fn exact_id_replay_is_not_reported_as_a_new_subscription_import() {
    let temporary = tempfile::TempDir::new().expect("temporary directory");
    let repository = ProfileRepository::new(temporary.path().join("profiles"));
    let imported = credential_subscription("66666666-6666-5666-8666-666666666666");
    let original = repository
        .import_with_id_and_source(
            TRANSACTION_PROFILE_ID,
            Some("Imported"),
            &imported.profile,
            Some(TRANSACTION_SOURCE_URL),
        )
        .expect("seed exact-ID profile");
    let vault = ScriptedCredentialVault::new(
        temporary.path().join("profiles"),
        vec![Ok(successful_receipt(TRANSACTION_PROFILE_ID, &imported))],
    );

    let error = commit_profile_import(
        &repository,
        &vault,
        TRANSACTION_PROFILE_ID,
        Some("Imported"),
        ProfileImportSource::Subscription(TRANSACTION_SOURCE_URL),
        &imported,
        false,
    )
    .await
    .expect_err("unexpected exact-ID replay");

    assert!(error.contains("unexpected exact-ID replay"));
    assert_eq!(
        repository
            .load(TRANSACTION_PROFILE_ID)
            .expect("load original")
            .expect("original exact-ID profile")
            .record,
        repository
            .load(&original.id)
            .expect("reload original")
            .expect("reloaded original")
            .record
    );
}

#[test]
fn activation_failure_reports_that_the_complete_import_remains_committed() {
    let rendered = profile_import_activation_error("selection storage unavailable");
    assert_eq!(
        rendered,
        "profile import committed, but selection failed: selection storage unavailable"
    );
}

#[test]
fn qrcode_rendering_encodes_only_a_subscription_url() {
    let code = QrCode::new(b"https://example.com/sub?token=t").expect("qr code");
    let rendered = code
        .render::<svg::Color<'_>>()
        .min_dimensions(190, 190)
        .dark_color(svg::Color("#2c3e50"))
        .light_color(svg::Color("#ffffff"))
        .build();
    assert!(rendered.starts_with("<?xml"));
    assert!(rendered.contains("svg"));
    assert!(
        !rendered.contains("token=t"),
        "the URL is encoded, not written"
    );
}
