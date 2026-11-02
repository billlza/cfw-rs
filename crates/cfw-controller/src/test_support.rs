//! A loopback HTTP/1.1 fixture that stands in for the engine controller.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::{ControllerClient, ControllerEndpoint};

/// How long a held reply waits for the concurrency it was told to expect.
const HOLD_LIMIT: Duration = Duration::from_secs(5);

/// A request as the fixture received it.
#[derive(Debug, Clone)]
pub(crate) struct RecordedRequest {
    pub(crate) method: String,
    pub(crate) target: String,
    headers: Vec<(String, String)>,
    pub(crate) body: String,
}

impl RecordedRequest {
    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub(crate) fn json(&self) -> serde_json::Value {
        serde_json::from_str(&self.body).expect("JSON request body")
    }
}

/// The fixture's answer to one request.
pub(crate) struct Reply {
    status: u16,
    body: Vec<u8>,
    declared_length: Option<usize>,
    delay: Duration,
    hold_until_in_flight: Option<usize>,
}

impl Reply {
    pub(crate) fn json(status: u16, body: impl Into<String>) -> Self {
        let body = body.into().into_bytes();
        Self {
            status,
            declared_length: Some(body.len()),
            body,
            delay: Duration::ZERO,
            hold_until_in_flight: None,
        }
    }

    /// `204 No Content`, which carries neither a body nor a length.
    pub(crate) fn no_content() -> Self {
        Self {
            declared_length: None,
            ..Self::json(204, "")
        }
    }

    /// A body whose length the response does not declare, so the client reads
    /// it until the fixture closes the connection.
    pub(crate) fn undeclared(status: u16, body: Vec<u8>) -> Self {
        Self {
            declared_length: None,
            ..Self::json(status, "").with_body(body)
        }
    }

    /// Declares `length` bytes whatever the body holds.
    pub(crate) fn declaring(mut self, length: usize) -> Self {
        self.declared_length = Some(length);
        self
    }

    pub(crate) fn after(mut self, delay: Duration) -> Self {
        self.delay = delay;
        self
    }

    /// Answers only once `count` requests were in flight together, or after
    /// `HOLD_LIMIT`; a client that never reaches `count` fails the caller's
    /// `max_in_flight` assertion instead of hanging the test.
    pub(crate) fn held_until_in_flight(mut self, count: usize) -> Self {
        self.hold_until_in_flight = Some(count);
        self
    }

    fn with_body(mut self, body: Vec<u8>) -> Self {
        self.body = body;
        self
    }

    fn head(&self) -> String {
        let mut head = format!(
            "HTTP/1.1 {} Fixture\r\nContent-Type: application/json\r\nConnection: close\r\n",
            self.status
        );
        if let Some(length) = self.declared_length {
            head.push_str(&format!("Content-Length: {length}\r\n"));
        }
        head.push_str("\r\n");
        head
    }
}

type Responder = dyn Fn(&RecordedRequest) -> Reply + Send + Sync;

struct Shared {
    respond: Box<Responder>,
    requests: Mutex<Vec<RecordedRequest>>,
    in_flight: AtomicUsize,
    max_in_flight: watch::Sender<usize>,
}

/// Serves every connection with the reply `respond` chooses and records each
/// request. Dropping the fixture stops accepting connections.
pub(crate) struct FakeController {
    address: SocketAddr,
    shared: Arc<Shared>,
    server: JoinHandle<()>,
}

impl FakeController {
    pub(crate) async fn start(
        respond: impl Fn(&RecordedRequest) -> Reply + Send + Sync + 'static,
    ) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake controller");
        let address = listener.local_addr().expect("fake controller address");
        let shared = Arc::new(Shared {
            respond: Box::new(respond),
            requests: Mutex::new(Vec::new()),
            in_flight: AtomicUsize::new(0),
            max_in_flight: watch::Sender::new(0),
        });
        let server = tokio::spawn({
            let shared = Arc::clone(&shared);
            async move {
                loop {
                    let (stream, _) = listener.accept().await.expect("accept controller request");
                    tokio::spawn(serve(stream, Arc::clone(&shared)));
                }
            }
        });
        Self {
            address,
            shared,
            server,
        }
    }

    pub(crate) fn endpoint(&self, secret: Option<&str>) -> ControllerEndpoint {
        ControllerEndpoint::new(
            self.address.ip().to_string(),
            self.address.port(),
            secret.map(str::to_owned),
        )
    }

    pub(crate) fn client(&self, secret: Option<&str>) -> ControllerClient {
        ControllerClient::new(self.endpoint(secret)).expect("controller client")
    }

    pub(crate) fn url(&self, path: &str) -> String {
        format!("http://{}{path}", self.address)
    }

    pub(crate) fn requests(&self) -> Vec<RecordedRequest> {
        self.shared
            .requests
            .lock()
            .expect("recorded requests")
            .clone()
    }

    pub(crate) fn max_in_flight(&self) -> usize {
        *self.shared.max_in_flight.borrow()
    }
}

impl Drop for FakeController {
    fn drop(&mut self) {
        self.server.abort();
    }
}

async fn serve(stream: TcpStream, shared: Arc<Shared>) {
    let mut reader = BufReader::new(stream);
    let Some(request) = read_request(&mut reader).await else {
        return;
    };
    shared
        .requests
        .lock()
        .expect("recorded requests")
        .push(request.clone());
    let reply = (shared.respond)(&request);

    let in_flight = shared.in_flight.fetch_add(1, Ordering::SeqCst) + 1;
    shared
        .max_in_flight
        .send_modify(|max| *max = (*max).max(in_flight));
    if let Some(count) = reply.hold_until_in_flight {
        let mut observed = shared.max_in_flight.subscribe();
        if let Ok(reached) =
            tokio::time::timeout(HOLD_LIMIT, observed.wait_for(|max| *max >= count)).await
        {
            reached.expect("the fixture owns the sender");
        }
    }
    tokio::time::sleep(reply.delay).await;
    // Leave the in-flight set before answering: a client that waits for this
    // reply cannot have sent its next request yet.
    shared.in_flight.fetch_sub(1, Ordering::SeqCst);

    let response = [reply.head().into_bytes(), reply.body].concat();
    // The write fails only when the client already gave up on this request (a
    // timeout or an early size refusal); the test asserts what it observed.
    let _client_gone = reader.into_inner().write_all(&response).await.is_err();
}

/// `None` when the client closed the connection without sending a request.
async fn read_request(reader: &mut BufReader<TcpStream>) -> Option<RecordedRequest> {
    let mut line = String::new();
    if reader
        .read_line(&mut line)
        .await
        .expect("read request line")
        == 0
    {
        return None;
    }
    let mut parts = line.trim_end().splitn(3, ' ');
    let method = parts.next().expect("request method").to_owned();
    let target = parts.next().expect("request target").to_owned();

    let mut headers = Vec::new();
    loop {
        line.clear();
        reader.read_line(&mut line).await.expect("read header line");
        let header = line.trim_end();
        if header.is_empty() {
            break;
        }
        let (name, value) = header.split_once(':').expect("HTTP header");
        headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
    }
    let length = headers
        .iter()
        .find(|(name, _)| name == "content-length")
        .map_or(0, |(_, value)| {
            value.parse().expect("request content length")
        });
    let mut body = vec![0; length];
    reader
        .read_exact(&mut body)
        .await
        .expect("read request body");

    Some(RecordedRequest {
        method,
        target,
        headers,
        body: String::from_utf8(body).expect("UTF-8 request body"),
    })
}
