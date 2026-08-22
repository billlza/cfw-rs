//! Process-wide crypto initialization and the closed policy for external HTTPS.
//!
//! The loopback controller remains plain HTTP. Subscription and updater clients
//! start from this builder so they cannot accidentally admit plaintext URLs or
//! negotiate below the product-owned TLS floor.

use reqwest::{Client, ClientBuilder};
use thiserror::Error;

#[derive(Debug, Error)]
pub(crate) enum TransportSecurityError {
    #[error("the process TLS crypto provider is unavailable")]
    CryptoProviderUnavailable,
}

/// Installs the one process-global rustls provider. A concurrent initializer
/// may win the one-time race, so success is determined by the final read.
pub(crate) fn ensure_tls_crypto_provider() -> Result<(), TransportSecurityError> {
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _already_installed = rustls::crypto::ring::default_provider().install_default();
    }
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        return Err(TransportSecurityError::CryptoProviderUnavailable);
    }
    Ok(())
}

/// Starts an external-network client with the interoperable TLS floor from
/// BCP 195: TLS 1.2 remains available while normal negotiation prefers TLS
/// 1.3. This is one negotiation policy, not a retry-based version fallback.
/// Callers retain ownership of operation-specific bounds, redirects, DNS, and
/// proxy policy before building the client. QUIC continues to require TLS 1.3
/// at the transport protocol layer.
pub(crate) fn external_https_client_builder() -> Result<ClientBuilder, TransportSecurityError> {
    ensure_tls_crypto_provider()?;
    Ok(Client::builder()
        .tls_backend_rustls()
        .https_only(true)
        .tls_version_min(reqwest::tls::Version::TLS_1_2))
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::net::{SocketAddr, TcpListener};
    use std::sync::{Arc, mpsc};
    use std::time::Duration;

    use rustls::pki_types::pem::PemObject as _;
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use rustls::{ProtocolVersion, ServerConfig, ServerConnection, StreamOwned};

    use super::external_https_client_builder;

    // Test-only self-signed localhost CA and identity. Tests add this exact CA
    // to their client trust store; certificate and hostname verification stay
    // enabled on the same path production uses.
    const TEST_ROOT_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIIBojCCAUigAwIBAgIUUk0Ke747EApk9f5Nos5Eq9DyFhwwCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRQ0ZNIFRMUyBUZXN0IFJvb3QwIBcNMjYwODIwMDcyNDEwWhgP
MjEyNjA3MjcwNzI0MTBaMBwxGjAYBgNVBAMMEUNGTSBUTFMgVGVzdCBSb290MFkw
EwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEuRUpLZGL+1JyuNNYuwXn17CjObaGbUVN
iDuJJAeY04PbQ3j6JrVZhDo9cD9zBR4chKRD6KCJPSXZv02n1FkfyKNmMGQwHwYD
VR0jBBgwFoAUwk3iLRVGAV38iQz/n4SBRnRaypUwEgYDVR0TAQH/BAgwBgEB/wIB
ADAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFMJN4i0VRgFd/IkM/5+EgUZ0WsqV
MAoGCCqGSM49BAMCA0gAMEUCIQCx98zFbwWUUYm3vqweR6VL2pAe5uiR2lHWiUIn
u+xt8QIgWO8iL0ucE6wJE5+/HGcio3XNMx9RAZ2gaCXLwHxDRN0=
-----END CERTIFICATE-----"#;
    const TEST_CERTIFICATE: &str = r#"-----BEGIN CERTIFICATE-----
MIIBxzCCAW2gAwIBAgIUSnhUB3XFmST77dHBb24lE2ITMPwwCgYIKoZIzj0EAwIw
HDEaMBgGA1UEAwwRQ0ZNIFRMUyBUZXN0IFJvb3QwIBcNMjYwODIwMDcyNDEwWhgP
MjEyNjA3MjcwNzI0MTBaMBQxEjAQBgNVBAMMCWxvY2FsaG9zdDBZMBMGByqGSM49
AgEGCCqGSM49AwEHA0IABJ5h0XBnOJg7MfelceUM0KfUOIeYlZ3VBUX4L6D9CweN
nNyT+W7xQmJGURBNNqUHoitLH2byILn8N6Nvo1j5e0yjgZIwgY8wGgYDVR0RBBMw
EYIJbG9jYWxob3N0hwR/AAABMAwGA1UdEwEB/wQCMAAwDgYDVR0PAQH/BAQDAgeA
MBMGA1UdJQQMMAoGCCsGAQUFBwMBMB0GA1UdDgQWBBTaCZPYuIp4irgRgTVGg4N6
HmJvLjAfBgNVHSMEGDAWgBTCTeItFUYBXfyJDP+fhIFGdFrKlTAKBggqhkjOPQQD
AgNIADBFAiEAgFTSPM315VgpQqkRpgnke6sDba4fRmIgCMcasNWNe+cCIHPYylFh
kkVhZwJp7sMf/+B0+QYXnDbfnqEjacbWdpaQ
-----END CERTIFICATE-----"#;
    const TEST_PRIVATE_KEY: &str = r#"-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgAV8LvfbYXzOFYhoq
UtyRE8g3Ll74B+8SsGO3zdDgp1GhRANCAASeYdFwZziYOzH3pXHlDNCn1DiHmJWd
1QVF+C+g/QsHjZzck/lu8UJiRlEQTTalB6IrSx9m8iC5/Dejb6NY+XtM
-----END PRIVATE KEY-----"#;

    fn spawn_server(
        version: &'static rustls::SupportedProtocolVersion,
    ) -> (
        SocketAddr,
        mpsc::Receiver<Result<ProtocolVersion, String>>,
        std::thread::JoinHandle<()>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind test TLS server");
        let address = listener.local_addr().expect("test TLS address");
        let (outcome_sender, outcome_receiver) = mpsc::channel();
        let handle = std::thread::spawn(move || {
            let result = (|| -> Result<ProtocolVersion, String> {
                let certificate = CertificateDer::from_pem_slice(TEST_CERTIFICATE.as_bytes())
                    .map_err(|error| error.to_string())?;
                let root_certificate =
                    CertificateDer::from_pem_slice(TEST_ROOT_CERTIFICATE.as_bytes())
                        .map_err(|error| error.to_string())?;
                let private_key = PrivateKeyDer::from_pem_slice(TEST_PRIVATE_KEY.as_bytes())
                    .map_err(|error| error.to_string())?;
                let config = ServerConfig::builder_with_provider(Arc::new(
                    rustls::crypto::ring::default_provider(),
                ))
                .with_protocol_versions(&[version])
                .map_err(|error| error.to_string())?
                .with_no_client_auth()
                .with_single_cert(vec![certificate, root_certificate], private_key)
                .map_err(|error| error.to_string())?;
                let (socket, _) = listener.accept().map_err(|error| error.to_string())?;
                socket
                    .set_read_timeout(Some(Duration::from_secs(3)))
                    .map_err(|error| error.to_string())?;
                socket
                    .set_write_timeout(Some(Duration::from_secs(3)))
                    .map_err(|error| error.to_string())?;
                let connection =
                    ServerConnection::new(Arc::new(config)).map_err(|error| error.to_string())?;
                let mut stream = StreamOwned::new(connection, socket);
                let mut request = [0_u8; 2_048];
                let count = stream
                    .read(&mut request)
                    .map_err(|error| error.to_string())?;
                if !request[..count].starts_with(b"GET /") {
                    return Err("test TLS client did not send the expected request".into());
                }
                let negotiated = stream.conn.protocol_version().ok_or_else(|| {
                    "TLS handshake completed without a protocol version".to_owned()
                })?;
                stream
                    .write_all(b"HTTP/1.1 204 No Content\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    .map_err(|error| error.to_string())?;
                stream.flush().map_err(|error| error.to_string())?;
                Ok(negotiated)
            })();
            let _result_observed = outcome_sender.send(result);
        });
        (address, outcome_receiver, handle)
    }

    #[tokio::test]
    async fn external_https_policy_completes_a_tls13_handshake() {
        let (address, outcome, server) = spawn_server(&rustls::version::TLS13);
        let client = external_https_client_builder()
            .expect("external HTTPS policy")
            .tls_certs_only([
                reqwest::Certificate::from_pem(TEST_ROOT_CERTIFICATE.as_bytes())
                    .expect("test root certificate"),
            ])
            .no_proxy()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .build()
            .expect("TLS 1.3 test client");
        let response = client
            .get(format!("https://localhost:{}/", address.port()))
            .send()
            .await
            .expect("TLS 1.3 request");
        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
        assert_eq!(
            outcome
                .recv_timeout(Duration::from_secs(3))
                .expect("TLS 1.3 server outcome")
                .expect("TLS 1.3 server request"),
            ProtocolVersion::TLSv1_3
        );
        server.join().expect("TLS 1.3 server thread");
    }

    #[tokio::test]
    async fn external_https_policy_interoperates_with_a_tls12_only_server() {
        let (address, outcome, server) = spawn_server(&rustls::version::TLS12);
        let client = external_https_client_builder()
            .expect("external HTTPS policy")
            .tls_certs_only([
                reqwest::Certificate::from_pem(TEST_ROOT_CERTIFICATE.as_bytes())
                    .expect("test root certificate"),
            ])
            .no_proxy()
            .connect_timeout(Duration::from_secs(2))
            .timeout(Duration::from_secs(3))
            .build()
            .expect("TLS 1.2-or-newer test client");
        let response = client
            .get(format!("https://localhost:{}/", address.port()))
            .send()
            .await
            .expect("TLS 1.2 request");
        assert_eq!(response.status(), reqwest::StatusCode::NO_CONTENT);
        assert_eq!(
            outcome
                .recv_timeout(Duration::from_secs(3))
                .expect("TLS 1.2 server outcome")
                .expect("TLS 1.2 server request"),
            ProtocolVersion::TLSv1_2
        );
        server.join().expect("TLS 1.2 server thread");
    }

    #[tokio::test]
    async fn external_https_policy_rejects_plain_http() {
        let client = external_https_client_builder()
            .expect("external HTTPS policy")
            .build()
            .expect("external HTTPS client");
        client
            .get("http://example.com/")
            .send()
            .await
            .expect_err("plain HTTP must be rejected before transport");
    }
}
