use std::process::Command;

const MAX_COMMAND_OUTPUT_BYTES: usize = 1024 * 1024;
const MAX_CAPTURED_ROUTES: usize = 4096;
const LEGACY_IPV4: &str = "198.18.0.1";
const LEGACY_IPV4_NETMASK: &str = "0xfffffffc";
const LEGACY_IPV6: &str = "fdfe:dcba:9876::1";
const LEGACY_IPV6_PREFIX: &str = "126";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct LegacyNetworkFingerprint {
    interface: String,
    route_rows: Vec<String>,
    scoped_dns_resolvers: usize,
}

impl LegacyNetworkFingerprint {
    pub(super) fn verify_absent() -> Result<(), String> {
        let interfaces = command_output("/sbin/ifconfig", &[])?;
        let matches = legacy_interfaces(&interfaces);
        if matches.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "legacy TUN fingerprint remains on interfaces {}; fresh-install absence is not proven",
                matches.join(", ")
            ))
        }
    }

    pub(super) fn interface(&self) -> &str {
        &self.interface
    }

    pub(super) fn for_recovery(interface: impl Into<String>) -> Result<Self, String> {
        let interface = interface.into();
        if !interface
            .strip_prefix("utun")
            .is_some_and(|suffix| !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit()))
        {
            return Err("recovery journal contains an invalid legacy interface".into());
        }
        Ok(Self {
            interface,
            route_rows: Vec::new(),
            scoped_dns_resolvers: 0,
        })
    }

    pub(super) fn capture() -> Result<Self, String> {
        let interfaces = command_output("/sbin/ifconfig", &[])?;
        let matches = legacy_interfaces(&interfaces);
        let interface = match matches.as_slice() {
            [interface] => interface.clone(),
            [] => {
                return Err(
                    "legacy TUN ownership cannot be proven: no interface has the exact 198.18.0.1/30 and fdfe:dcba:9876::1/126 fingerprint; the existing VPN was not changed"
                        .into(),
                );
            }
            _ => {
                return Err(format!(
                    "legacy TUN ownership is ambiguous across interfaces {}; the existing VPN was not changed",
                    matches.join(", ")
                ));
            }
        };
        let route_rows = capture_routes(&interface)?;
        if route_rows.is_empty() {
            return Err(format!(
                "legacy TUN interface {interface} has no attributable routes; the existing VPN was not changed"
            ));
        }
        let dns = command_output("/usr/sbin/scutil", &["--dns"])?;
        let scoped_dns_resolvers = scoped_dns_resolver_count(&dns, &interface);
        Ok(Self {
            interface,
            route_rows,
            scoped_dns_resolvers,
        })
    }

    pub(super) fn verify_removed(&self) -> Result<(), String> {
        let interfaces = command_output("/sbin/ifconfig", &[])?;
        if interface_names(&interfaces)
            .iter()
            .any(|name| name == &self.interface)
        {
            return Err(format!(
                "legacy TUN interface {} remains after the managed core stopped; no unrelated interface was removed",
                self.interface
            ));
        }
        let routes = capture_routes(&self.interface)?;
        if !routes.is_empty() {
            return Err(format!(
                "{} legacy routes still reference {} after retirement",
                routes.len(),
                self.interface
            ));
        }
        let dns = command_output("/usr/sbin/scutil", &["--dns"])?;
        let remaining_dns = scoped_dns_resolver_count(&dns, &self.interface);
        if remaining_dns != 0 {
            return Err(format!(
                "{remaining_dns} DNS resolvers still reference legacy interface {} after retirement",
                self.interface
            ));
        }
        Ok(())
    }

    pub(super) fn verify_still_present(&self) -> Result<(), String> {
        let current = Self::capture()?;
        if current.interface == self.interface && !current.route_rows.is_empty() {
            Ok(())
        } else {
            Err("legacy TUN fingerprint changed after preparation".into())
        }
    }
}

fn command_output(program: &str, args: &[&str]) -> Result<String, String> {
    let output = Command::new(program)
        .args(args)
        .output()
        .map_err(|error| format!("failed to execute {program}: {error}"))?;
    if output.stdout.len() > MAX_COMMAND_OUTPUT_BYTES || output.stderr.len() > 64 * 1024 {
        return Err(format!(
            "{program} output exceeded its migration safety bound"
        ));
    }
    if !output.status.success() {
        return Err(format!(
            "{program} failed with status {}: {}",
            output.status,
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    String::from_utf8(output.stdout).map_err(|_| format!("{program} returned non-UTF-8 output"))
}

fn interface_blocks(input: &str) -> Vec<(&str, Vec<&str>)> {
    let mut blocks = Vec::<(&str, Vec<&str>)>::new();
    for line in input.lines() {
        if !line.starts_with(char::is_whitespace)
            && let Some((name, _)) = line.split_once(':')
        {
            blocks.push((name, vec![line]));
        } else if let Some((_, lines)) = blocks.last_mut() {
            lines.push(line);
        }
    }
    blocks
}

fn interface_names(input: &str) -> Vec<String> {
    interface_blocks(input)
        .into_iter()
        .map(|(name, _)| name.to_owned())
        .collect()
}

fn legacy_interfaces(input: &str) -> Vec<String> {
    interface_blocks(input)
        .into_iter()
        .filter(|(name, lines)| {
            name.strip_prefix("utun").is_some_and(|suffix| {
                !suffix.is_empty() && suffix.bytes().all(|b| b.is_ascii_digit())
            }) && lines.iter().any(|line| {
                let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
                fields.first() == Some(&"inet")
                    && fields.get(1) == Some(&LEGACY_IPV4)
                    && fields
                        .windows(2)
                        .any(|pair| pair == ["netmask", LEGACY_IPV4_NETMASK])
            }) && lines.iter().any(|line| {
                let fields = line.split_ascii_whitespace().collect::<Vec<_>>();
                fields.first() == Some(&"inet6")
                    && fields.get(1) == Some(&LEGACY_IPV6)
                    && fields
                        .windows(2)
                        .any(|pair| pair == ["prefixlen", LEGACY_IPV6_PREFIX])
            })
        })
        .map(|(name, _)| name.to_owned())
        .collect()
}

fn capture_routes(interface: &str) -> Result<Vec<String>, String> {
    let mut routes = Vec::new();
    for family in ["inet", "inet6"] {
        let output = command_output("/usr/sbin/netstat", &["-rn", "-f", family])?;
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.split_ascii_whitespace().last() == Some(interface) {
                if routes.len() >= MAX_CAPTURED_ROUTES {
                    return Err("legacy route fingerprint exceeded 4096 rows".into());
                }
                routes.push(format!("{family}:{trimmed}"));
            }
        }
    }
    Ok(routes)
}

fn scoped_dns_resolver_count(input: &str, interface: &str) -> usize {
    let marker = format!("({interface})");
    input
        .split("resolver #")
        .filter(|resolver| {
            resolver
                .lines()
                .any(|line| line.trim_start().starts_with("if_index") && line.contains(&marker))
        })
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;

    const INTERFACES: &str = r#"utun5: flags=8051<UP> mtu 1380
	inet 10.0.0.1 --> 10.0.0.1 netmask 0xffffffff
utun6: flags=8051<UP> mtu 9000
	inet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc
	inet6 fe80::1%utun6 prefixlen 64 scopeid 0x23
	inet6 fdfe:dcba:9876::1 prefixlen 126 secured
utun7: flags=8051<UP> mtu 1500
	inet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc
	inet6 2001:db8::1 prefixlen 126 secured
"#;

    #[test]
    fn only_the_complete_legacy_dual_stack_fingerprint_is_owned() {
        assert_eq!(legacy_interfaces(INTERFACES), ["utun6"]);
        assert_eq!(interface_names(INTERFACES), ["utun5", "utun6", "utun7"]);
    }

    #[test]
    fn dns_scope_matching_is_interface_exact() {
        let dns = r#"resolver #1
  if_index : 35 (utun6)
resolver #2
  if_index : 36 (utun60)
resolver #3
  if_index : 14 (en0)
"#;
        assert_eq!(scoped_dns_resolver_count(dns, "utun6"), 1);
    }
}
