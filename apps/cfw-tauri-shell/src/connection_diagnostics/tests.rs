use super::{DiagnosticsGate, dns, http};
use std::net::IpAddr;
use uuid::Uuid;

#[test]
fn trace_requires_an_unambiguous_ip_and_never_accepts_an_html_challenge() {
    let value = http::parse_trace(b"ip=2001:db8::2\nloc=GB\ncolo=LHR\n").unwrap();
    assert_eq!(value.ip, "2001:db8::2".parse::<IpAddr>().unwrap());
    assert_eq!(value.country.as_deref(), Some("GB"));
    assert_eq!(value.colo.as_deref(), Some("LHR"));
    for text in [
        "<html>challenge</html>",
        "ip=garbage",
        "ip=1.1.1.1\nip=8.8.8.8",
    ] {
        assert!(http::parse_trace(text.as_bytes()).is_err());
    }
}

#[test]
fn metadata_is_bound_to_the_requested_ip_and_bounded_plain_text() {
    let expected: IpAddr = "1.1.1.1".parse().unwrap();
    let mut document = serde_json::json!({"ip":"1.1.1.1", "company":"Cloudflare", "asn":"AS13335", "city":null, "region":null, "country":"Australia", "timezone":null});
    let value =
        http::parse_ip_information(&serde_json::to_vec(&document).unwrap(), expected).unwrap();
    assert!(value.city.is_none());
    document["ip"] = serde_json::json!("8.8.8.8");
    assert!(http::parse_ip_information(&serde_json::to_vec(&document).unwrap(), expected).is_err());
    document["ip"] = serde_json::json!("1.1.1.1");
    document["company"] = serde_json::json!("x".repeat(257));
    assert!(http::parse_ip_information(&serde_json::to_vec(&document).unwrap(), expected).is_err());
    document["company"] = serde_json::json!(false);
    assert!(http::parse_ip_information(&serde_json::to_vec(&document).unwrap(), expected).is_err());
    assert!(http::parse_ip_information(br#"{"error":"quota exceeded"}"#, expected).is_err());
    assert!(http::parse_ip_information(br#"{"ip":"1.1.1.1"}"#, expected).is_err());
}

#[test]
fn authoritative_dns_requires_real_resolver_records_not_a_conclusion() {
    let value = dns::parse_resolvers(br#"[{"type":"dns","ip":"1.1.1.1","asn":"Cloudflare","country_name":"Australia"},{"type":"dns","ip":"1.1.1.1"}]"#).unwrap();
    assert_eq!(value.len(), 1);
    for bytes in [
        br#"[]"#.as_slice(),
        br#"[{"type":"conclusion","ip":"DNS is not leaking"}]"#,
        br#"[{"type":"dns","ip":"not an address"}]"#,
        br#"[{"type":"error","text":"error"}]"#,
    ] {
        assert!(dns::parse_resolvers(bytes).is_err());
    }
}

#[test]
fn dns_ids_cannot_inject_a_host_path_or_query() {
    assert_eq!(dns::test_id(b"12345\n"), Ok("12345"));
    for id in ["", "../x", "foo.example", "a?b", "a/b", "<html>"] {
        assert!(dns::test_id(id.as_bytes()).is_err());
    }
    assert!(dns::test_id("1".repeat(49).as_bytes()).is_err());
}

#[test]
fn diagnostics_cancel_release_and_refuse_concurrency() {
    let gate = DiagnosticsGate::default();
    let id = Uuid::new_v4();
    let activity = gate.begin(id, false).unwrap();
    assert!(gate.begin(Uuid::new_v4(), false).is_err());
    assert!(gate.cancel(Uuid::new_v4()).is_err());
    assert!(!*activity.cancelled.borrow());
    gate.cancel(id).unwrap();
    assert!(*activity.cancelled.borrow());
    drop(activity);
    assert!(gate.begin(Uuid::new_v4(), false).is_ok());
}

#[test]
fn cancellation_before_admission_and_provider_backoff_are_not_lost() {
    let gate = DiagnosticsGate::default();
    let id = Uuid::new_v4();
    gate.cancel(id).unwrap();
    assert!(gate.begin(id, false).is_err());
    drop(gate.begin(Uuid::new_v4(), true).unwrap());
    assert!(gate.begin(Uuid::new_v4(), true).is_err());
    // IP provider quota does not disable connectivity or DNS checks.
    gate.block_lookup().unwrap();
    assert!(gate.begin(Uuid::new_v4(), false).is_ok());
}

#[tokio::test]
async fn oversized_chunked_http_bodies_are_rejected_without_content_length() {
    use std::io::{Read, Write};
    crate::transport_security::ensure_tls_crypto_provider().unwrap();
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (mut socket, _) = listener.accept().unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        while !request.ends_with(b"\r\n\r\n") {
            assert!(request.len() < 1024);
            let mut byte = [0];
            socket.read_exact(&mut byte).unwrap();
            request.push(byte[0]);
        }
        assert!(request.starts_with(b"GET / HTTP/1.1"));
        let body = vec![b'x'; http::BODY_LIMIT + 1];
        let header = format!(
            "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n{:x}\r\n",
            body.len()
        );
        let mut wire = header.into_bytes();
        wire.extend_from_slice(&body);
        wire.extend_from_slice(b"\r\n0\r\n\r\n");
        socket.write_all(&wire).unwrap();
    });
    let client = reqwest::Client::builder()
        .no_proxy()
        .timeout(std::time::Duration::from_secs(3))
        .build()
        .unwrap();
    let response = client
        .get(format!("http://{address}/"))
        .send()
        .await
        .unwrap();
    assert_eq!(http::body(response).await, Err("response_too_large"));
    server.join().unwrap();
}
