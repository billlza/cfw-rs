//! Real SOCKS negotiation proves that the public resolver runs before proxy
//! dispatch; rejecting the selected proxy must not create a direct retry.
use super::fetch::*;
use reqwest::dns::{Addrs, Name, Resolve, Resolving};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

#[derive(Debug)]
struct TestResolver(SocketAddr);
impl Resolve for TestResolver {
    fn resolve(&self, _: Name) -> Resolving {
        let address = self.0;
        Box::pin(async move { Ok(Box::new([address].into_iter()) as Addrs) })
    }
}

#[tokio::test]
async fn subscription_proxy_receives_only_checked_numeric_destinations_and_failure_is_terminal() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let observed = tokio::spawn(async move {
        tokio::time::timeout(Duration::from_secs(3), async move {
            let (mut connection, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            connection.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting[0], 5);
            let mut methods = vec![0; greeting[1] as usize];
            connection.read_exact(&mut methods).await.unwrap();
            assert!(methods.contains(&0));
            connection.write_all(&[5, 0]).await.unwrap();
            let mut connect = [0u8; 10];
            connection.read_exact(&mut connect).await.unwrap();
            assert_eq!(&connect[..4], &[5, 1, 0, 1]);
            assert_eq!(&connect[4..8], &[1, 1, 1, 1]);
            assert_eq!(&connect[8..], &443u16.to_be_bytes());
            connection
                .write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        })
        .await
        .expect("bounded real proxy handshake")
    });
    let client = subscription_client_with_resolver(
        SubscriptionRoute::LocalProxy(port),
        TestResolver("1.1.1.1:443".parse().unwrap()),
    )
    .unwrap();
    let error = client
        .get("https://provider.example/")
        .send()
        .await
        .unwrap_err();
    assert!(error.is_connect());
    observed.await.unwrap();
}

#[tokio::test]
async fn subscription_proxy_cannot_bypass_private_dns_rejection() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let client = subscription_client_with_resolver(
        SubscriptionRoute::LocalProxy(listener.local_addr().unwrap().port()),
        TestResolver("192.168.1.2:443".parse().unwrap()),
    )
    .unwrap();
    assert!(
        client
            .get("https://provider.example/")
            .send()
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), listener.accept())
            .await
            .is_err()
    );
}
