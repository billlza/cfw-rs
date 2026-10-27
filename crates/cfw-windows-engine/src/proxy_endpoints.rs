//! Project WinINet's manual proxy list to local port reservations only.
//! Raw proxy/PAC values never become frontend data or diagnostic strings.
use std::collections::BTreeSet;

pub(crate) fn loopback_ports(enabled: bool, server: &[u16]) -> Result<BTreeSet<u16>, ()> {
    if !enabled {
        // Disabled retained settings do not reserve a listener; PAC/WPAD is
        // not evaluated and no network request is made to resolve a policy.
        return Ok(BTreeSet::new());
    }
    if server.is_empty() || server.len() > 8192 || server.contains(&0) {
        return Err(());
    }
    let text = String::from_utf16(server).map_err(|_| ())?;
    if text.chars().any(char::is_control) {
        return Err(());
    }
    let mut ports = BTreeSet::new();
    let mut entries = 0;
    // WinINet documents space-separated protocol mappings; the system
    // settings UI also stores semicolon-separated mappings.
    for entry in text.split([' ', ';']).filter(|value| !value.is_empty()) {
        entries += 1;
        let (protocol, endpoint) = match entry.split_once('=') {
            Some((protocol, endpoint))
                if ["http", "https", "ftp", "socks"]
                    .iter()
                    .any(|known| protocol.eq_ignore_ascii_case(known)) =>
            {
                (protocol, endpoint)
            }
            Some(_) => return Err(()),
            None => ("http", entry),
        };
        if endpoint.is_empty() || endpoint.contains('=') {
            return Err(());
        }
        let uri = if endpoint.contains("://") {
            endpoint.to_owned()
        } else {
            let scheme = if protocol.eq_ignore_ascii_case("socks") {
                "socks4"
            } else {
                "http"
            };
            format!("{scheme}://{endpoint}")
        };
        let (_, authority) = uri.split_once("://").ok_or(())?;
        if authority.is_empty() || authority.contains(['/', '\\', '?', '#', '@']) {
            return Err(());
        }
        let parsed = url::Url::parse(&uri).map_err(|_| ())?;
        let default_port = match parsed.scheme() {
            "http" => 80,
            "https" => 443,
            "ftp" => 21,
            "socks" | "socks4" | "socks5" => 1080,
            _ => return Err(()),
        };
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
            || !matches!(parsed.path(), "" | "/")
        {
            return Err(());
        }
        let port = parsed.port().unwrap_or(default_port);
        if port == 0 {
            return Err(());
        }
        let local = match parsed.host().ok_or(())? {
            url::Host::Ipv4(address) => address.is_loopback(),
            url::Host::Ipv6(address) => address.is_loopback(),
            url::Host::Domain(host) => {
                host.trim_end_matches('.').eq_ignore_ascii_case("localhost")
                    || host
                        .parse::<std::net::IpAddr>()
                        .is_ok_and(|address| address.is_loopback())
            }
        };
        if local {
            ports.insert(port);
        }
    }
    if entries == 0 {
        return Err(());
    }
    Ok(ports)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn parse(value: &str) -> Result<BTreeSet<u16>, ()> {
        loopback_ports(true, &value.encode_utf16().collect::<Vec<_>>())
    }

    #[test]
    fn manual_lists_reserve_every_local_endpoint_without_resolving_remote_names() {
        assert_eq!(
            parse("http=127.0.0.1:7890;https=http://localhost.:9090 socks=socks5://[::1]:1080 proxy.example:8080").unwrap(),
            BTreeSet::from([1080, 7890, 9090])
        );
        assert_eq!(
            parse("HTTP=https://localhost:443").unwrap(),
            BTreeSet::from([443])
        );
        assert_eq!(parse("socks=localhost").unwrap(), BTreeSet::from([1080]));
        assert_eq!(
            parse("socks=socks5://127.0.0.1:7890").unwrap(),
            BTreeSet::from([7890])
        );
        assert_eq!(parse("localhost").unwrap(), BTreeSet::from([80]));
    }

    #[test]
    fn disabled_manual_settings_do_not_parse_stale_values_or_evaluate_automatic_policy() {
        assert!(loopback_ports(false, &[0, 0xd800]).unwrap().is_empty());
    }

    #[test]
    fn ambiguous_or_incomplete_enabled_lists_fail_without_echoing_native_values() {
        for value in [
            "",
            " ; ",
            "http=",
            "http==localhost:7890",
            "unknown=localhost:7890",
            "localhost:0",
            "localhost:65536",
            "http://user:password@localhost:7890",
            "http://localhost:7890/path",
            "http://localhost:7890?secret=x",
            "http://localhost:7890/path/..",
            "http://@localhost:7890",
            "http://localhost:7890#fragment",
            "localhost:7890\nother:8080",
            "file:///private",
        ] {
            assert!(parse(value).is_err(), "malformed proxy list was accepted");
        }
        assert!(loopback_ports(true, &[0xd800]).is_err());
        assert!(loopback_ports(true, &[0]).is_err());
        assert!(loopback_ports(true, &vec![u16::from(b'a'); 8193]).is_err());
    }
}
