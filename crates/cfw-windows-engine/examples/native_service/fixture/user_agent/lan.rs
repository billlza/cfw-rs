use super::*;
use std::net::{IpAddr, SocketAddr, UdpSocket};

pub(super) struct Fixture {
    reservation: Option<TcpListener>,
    interface: Ipv4Addr,
    port: u16,
}
impl Fixture {
    pub(super) fn new() -> Result<Self> {
        // Route selection sends no datagram. Only this runner's private IPv4
        // address is admitted as a source; loopback is deliberately excluded.
        let route = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| e.to_string())?;
        route
            .connect((Ipv4Addr::new(192, 0, 2, 1), 9))
            .map_err(|e| e.to_string())?;
        let IpAddr::V4(interface) = route.local_addr().map_err(|e| e.to_string())?.ip() else {
            return Err("LAN fixture requires an IPv4 interface".into());
        };
        if !interface.is_private() {
            return Err("LAN fixture requires a private interface".into());
        }
        let reservation =
            TcpListener::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|e| e.to_string())?;
        let port = reservation.local_addr().map_err(|e| e.to_string())?.port();
        Ok(Self {
            reservation: Some(reservation),
            interface,
            port,
        })
    }
    pub(super) fn settings(&self) -> cfw_singbox_config::LanProxySettings {
        cfw_singbox_config::LanProxySettings {
            listen: Ipv4Addr::UNSPECIFIED,
            port: self.port,
            allowed_source_cidrs: vec![format!("{}/32", self.interface)],
        }
    }
    pub(super) fn release_reservation(&mut self) -> Result<()> {
        self.reservation
            .take()
            .ok_or("LAN fixture reservation already released")?;
        Ok(())
    }
    pub(super) fn exercise(&self) -> Result<()> {
        if self.reservation.is_some() {
            return Err("LAN fixture still owns the listener".into());
        }
        traffic(SocketAddr::from((self.interface, self.port)))?;
        require_rejected(SocketAddr::from((Ipv4Addr::LOCALHOST, self.port)))
    }
    pub(super) fn require_released(&self) -> Result<()> {
        let _held = TcpListener::bind((Ipv4Addr::UNSPECIFIED, self.port))
            .map_err(|e| format!("LAN listener remained after runtime cleanup: {e}"))?;
        Ok(())
    }
}

fn closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::BrokenPipe
    )
}
fn rejection_response(bytes: &[u8]) -> bool {
    bytes.is_empty() || bytes.len() <= 8192 && bytes.starts_with(b"HTTP/1.1 502 ")
}
fn require_rejected(proxy: SocketAddr) -> Result<()> {
    let origin = reserve()?;
    origin.set_nonblocking(true).map_err(|e| e.to_string())?;
    let destination = origin.local_addr().map_err(|e| e.to_string())?;
    let mut socket =
        TcpStream::connect_timeout(&proxy, Duration::from_secs(5)).map_err(|e| e.to_string())?;
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    socket
        .set_write_timeout(Some(Duration::from_secs(5)))
        .map_err(|e| e.to_string())?;
    let request = format!(
        "GET http://{destination}/untrusted-source HTTP/1.1\r\nHost: {destination}\r\nConnection: close\r\n\r\n"
    );
    match socket.write_all(request.as_bytes()) {
        Ok(()) => {
            let mut response = Vec::new();
            match socket.take(8193).read_to_end(&mut response) {
                Ok(_) if rejection_response(&response) => {}
                Ok(_) => {
                    return Err("untrusted LAN source received a non-rejection response".into());
                }
                Err(error) if closed(&error) && rejection_response(&response) => {}
                Err(error) => {
                    return Err(format!(
                        "untrusted LAN source did not receive a bounded rejection: {error}"
                    ));
                }
            }
        }
        Err(error) if closed(&error) => {}
        Err(error) => return Err(format!("LAN denial request failed unexpectedly: {error}")),
    }
    // A rejected route must not even connect to the controlled origin. A
    // timeout is never accepted as denial; the client must first observe close
    // or an explicit proxy failure response above.
    match origin.accept() {
        Err(error) if error.kind() == io::ErrorKind::WouldBlock => Ok(()),
        Err(error) => Err(format!("observe denied LAN origin: {error}")),
        Ok(_) => Err("untrusted LAN source reached the origin".into()),
    }
}
