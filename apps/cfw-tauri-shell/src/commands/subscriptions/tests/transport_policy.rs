//! The subscription transport: public HTTPS endpoints only, redirects that
//! never forward credentials, identity encoding, a bounded redirect chain, and
//! a resolver that refuses private answers.

use super::*;

#[test]
fn subscription_transport_bound_accepts_legacy_yaml_but_not_unbounded_profiles() {
    let observed_legacy_document = vec![b'x'; 494_575];
    assert!(observed_legacy_document.len() > 384 * 1024);
    assert!(observed_legacy_document.len() < MAX_PROFILE_BYTES);
    assert!(observed_legacy_document.len() < MAX_SUBSCRIPTION_DOCUMENT_BYTES);
    const { assert!(MAX_PROFILE_BYTES < MAX_SUBSCRIPTION_DOCUMENT_BYTES) };
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
    let source = include_str!("../fetch.rs");
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

/// Serves `/k` as a redirect to `/k+1` until `/length`, which answers 200.
async fn redirect_chain_server(length: usize) -> SocketAddr {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("redirect chain listener");
    let address = listener.local_addr().expect("redirect chain address");
    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                return;
            };
            let mut request = Vec::new();
            let mut buffer = [0u8; 1024];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                let count = stream.read(&mut buffer).await.expect("redirect request");
                assert!(count > 0, "redirect request closed early");
                request.extend_from_slice(&buffer[..count]);
            }
            let line = String::from_utf8_lossy(&request);
            let step = line
                .split_whitespace()
                .nth(1)
                .and_then(|path| path.trim_start_matches('/').parse::<usize>().ok())
                .expect("redirect step");
            let response = if step < length {
                format!(
                    "HTTP/1.1 302 Found\r\nLocation: /{}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    step + 1
                )
            } else {
                "HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok".to_owned()
            };
            stream
                .write_all(response.as_bytes())
                .await
                .expect("redirect response");
        }
    });
    address
}

#[tokio::test]
async fn subscription_redirect_budget_follows_exactly_the_maximum() {
    crate::transport_security::ensure_tls_crypto_provider().expect("rustls provider");
    // A plain loopback client: the counting rule, not URL admission, is tested.
    let client = Client::builder()
        .no_proxy()
        .redirect(Policy::custom(|attempt| {
            if subscription_redirect_budget_exhausted(&attempt) {
                attempt.error("too many subscription redirects")
            } else {
                attempt.follow()
            }
        }))
        .build()
        .expect("redirect test client");
    let within = redirect_chain_server(MAX_SUBSCRIPTION_REDIRECTS).await;
    let response = client
        .get(format!("http://{within}/0"))
        .send()
        .await
        .expect("a chain of exactly the maximum redirects");
    assert_eq!(response.status(), 200);
    let beyond = redirect_chain_server(MAX_SUBSCRIPTION_REDIRECTS + 1).await;
    let error = client
        .get(format!("http://{beyond}/0"))
        .send()
        .await
        .expect_err("one redirect beyond the maximum");
    assert!(error.is_redirect(), "{error}");
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
