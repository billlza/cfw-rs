use super::*;

const COMPLETE_INTERFACE: &str = r#"utun6: flags=8051<UP> mtu 9000
	inet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc
	inet6 fe80::1%utun6 prefixlen 64 scopeid 0x23
	inet6 fdfe:dcba:9876::1 prefixlen 126 secured
"#;

const COMPLETE_AND_PARTIAL_INTERFACES: &str = r#"utun5: flags=8051<UP> mtu 1380
	inet 10.0.0.1 --> 10.0.0.1 netmask 0xffffffff
utun6: flags=8051<UP> mtu 9000
	inet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc
	inet6 fe80::1%utun6 prefixlen 64 scopeid 0x23
	inet6 fdfe:dcba:9876::1 prefixlen 126 secured
utun7: flags=8051<UP> mtu 1500
	inet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc
	inet6 2001:db8::1 prefixlen 126 secured
"#;

const IPV4_ROUTES: &str = r#"Routing tables
Destination        Gateway            Flags               Netif Expire
default            link#24            UCSg                utun6
10/8               link#24            UCS                 utun6 5
192.0.2/24         link#25            UCS                 utun7
"#;

const IPV6_ROUTES: &str = r#"Routing tables
Internet6:
Destination                             Gateway                         Flags         Netif Expire
default                                 link#24                         UCSg          utun6
"#;

const ROUTE_HEADER: &str = "Destination Gateway Flags Netif Expire\n";

const DNS: &str = r#"resolver #1
  nameserver[0] : 198.18.0.2
  if_index : 35 (utun6)
resolver #2
  nameserver[0] : 192.0.2.53
  if_index : 36 (utun60)
resolver #3
  nameserver[0] : 198.51.100.53
  if_index : 37 (utun7)
"#;

fn observation(
    interfaces: &str,
    ipv4_routes: &str,
    ipv6_routes: &str,
    dns: &str,
) -> LegacyNetworkObservation {
    LegacyNetworkObservation {
        interfaces: interfaces.into(),
        ipv4_routes: ipv4_routes.into(),
        ipv6_routes: ipv6_routes.into(),
        dns: dns.into(),
    }
}

#[test]
fn complete_and_partial_address_components_are_both_observed() {
    assert_eq!(
        legacy_address_matches(COMPLETE_AND_PARTIAL_INTERFACES),
        [
            LegacyInterfaceMatch {
                interface: "utun6".into(),
                address_state: LegacyAddressState::Complete,
            },
            LegacyInterfaceMatch {
                interface: "utun7".into(),
                address_state: LegacyAddressState::Partial,
            },
        ]
    );
    assert_eq!(
        interface_names(COMPLETE_AND_PARTIAL_INTERFACES),
        ["utun5", "utun6", "utun7"]
    );
}

#[test]
fn absence_fails_closed_with_address_route_and_dns_evidence() {
    let observation = observation(
        COMPLETE_AND_PARTIAL_INTERFACES,
        IPV4_ROUTES,
        IPV6_ROUTES,
        DNS,
    );

    let error = LegacyNetworkFingerprint::verify_absent_in(&observation)
        .expect_err("legacy evidence must block absence");

    assert!(
        error.contains("utun6 (complete address fingerprint, 3 routes, 1 scoped DNS resolvers)")
    );
    assert!(
        error.contains(
            "utun7 (partial or route-only fingerprint, 1 routes, 1 scoped DNS resolvers)"
        )
    );
}

// Captured from the release Mac while a different Clash product (Clash for
// Windows) held the network. 198.18.0.0/15 is the RFC2544 benchmarking range
// the whole Clash tool family uses for TUN, so the bare address collides with
// the retired product. Only the exact /30 qualifier and the .2 DNS peer are
// attributable to the retired cfw-rs network.
const FOREIGN_CLASH_INTERFACES: &str = r#"utun6: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 9000
	inet 198.18.0.1 --> 198.18.0.1 netmask 0xffff0000
"#;

const FOREIGN_CLASH_IPV4_ROUTES: &str = r#"Routing tables
Destination        Gateway            Flags               Netif Expire
128.0/1            198.18.0.1         UGSc                utun6
198.18.0/16        utun6              UGSc                utun6
198.18.0.1         198.18.0.1         UH                  utun6
"#;

const FOREIGN_CLASH_DNS: &str = r#"resolver #1
  nameserver[0] : 192.168.0.1
  if_index : 35 (utun6)
"#;

#[test]
fn foreign_clash_tunnel_does_not_block_absence() {
    let observation = observation(
        FOREIGN_CLASH_INTERFACES,
        FOREIGN_CLASH_IPV4_ROUTES,
        ROUTE_HEADER,
        FOREIGN_CLASH_DNS,
    );

    LegacyNetworkFingerprint::verify_absent_in(&observation).expect(
        "a foreign product holding 198.18.0.1 with a non-legacy netmask, whose routes all \
             name a live interface and whose DNS has no legacy peer, is not legacy evidence",
    );
}

#[test]
fn exact_legacy_netmask_still_blocks_even_without_ipv6() {
    let observation = observation(
        "utun6: flags=8051<UP> mtu 9000\n\tinet 198.18.0.1 --> 198.18.0.1 netmask 0xfffffffc\n",
        ROUTE_HEADER,
        ROUTE_HEADER,
        "resolver #1\n  nameserver[0] : 192.168.0.1\n  if_index : 35 (utun6)\n",
    );

    let error = LegacyNetworkFingerprint::verify_absent_in(&observation)
        .expect_err("the exact legacy /30 qualifier is attributable even without IPv6");
    assert!(error.contains("utun6"), "{error}");
}

#[test]
fn unrelated_tunnel_routes_and_dns_do_not_invent_legacy_ownership() {
    let observation = observation(
        "utun5: flags=8051<UP> mtu 1380\n\tinet 10.0.0.1 netmask 0xffffffff\n",
        &format!("{ROUTE_HEADER}default link#5 UCS utun5\n"),
        &format!("{ROUTE_HEADER}default link#5 UCS utun5\n"),
        "resolver #1\n  if_index : 5 (utun5)\n",
    );

    LegacyNetworkFingerprint::verify_absent_in(&observation)
        .expect("unrelated tunnel evidence is not a legacy fingerprint");
}

#[test]
fn dangling_legacy_route_carries_its_scoped_dns_into_absence_evidence() {
    // utun10 is absent from the interface block, so nothing can still own
    // this route: it is retirement residue and must block.
    let observation = observation(
        "utun9: flags=8051<UP> mtu 9000\n\tinet 10.0.0.1 netmask 0xffffffff\n",
        &format!("{ROUTE_HEADER}1 198.18.0.1 UGSc utun10\n"),
        ROUTE_HEADER,
        "resolver #1\n  if_index : 40 (utun10)\n",
    );

    let error = LegacyNetworkFingerprint::verify_absent_in(&observation)
        .expect_err("a dangling legacy gateway route prevents an absence proof");

    assert!(error.contains("utun10"), "{error}");
    assert!(LegacyNetworkFingerprint::from_observation(&observation).is_err());
}

#[test]
fn legacy_gateway_route_on_a_live_interface_is_not_attributable() {
    // Same route, but utun10 is live and carries no attributable legacy
    // address. In the shared benchmarking range that is a foreign product
    // holding its own tunnel, not residue of the retired network.
    let observation = observation(
        "utun10: flags=8051<UP> mtu 9000\n\tinet 10.0.0.1 netmask 0xffffffff\n",
        &format!("{ROUTE_HEADER}1 198.18.0.1 UGSc utun10\n"),
        ROUTE_HEADER,
        "resolver #1\n  if_index : 40 (utun10)\n",
    );

    LegacyNetworkFingerprint::verify_absent_in(&observation)
        .expect("a live foreign interface's gateway route is not legacy evidence");
}

#[test]
fn legacy_dns_only_residue_blocks_absence_and_requires_a_unique_scope() {
    let dns_only = observation(
        "utun12: flags=8051<UP> mtu 1500\n\tinet 10.0.0.1 netmask 0xffffffff\n",
        ROUTE_HEADER,
        ROUTE_HEADER,
        "resolver #1\n  nameserver[0] : 198.18.0.2\n  if_index : 44 (utun12)\n",
    );
    let error = LegacyNetworkFingerprint::verify_absent_in(&dns_only)
        .expect_err("legacy DNS-only residue must block absence");
    assert!(error.contains("utun12 (partial or route-only fingerprint"));

    let unscoped = observation(
        "utun12: flags=8051<UP> mtu 1500\n",
        ROUTE_HEADER,
        ROUTE_HEADER,
        "resolver #1\n  nameserver[0] : fdfe:dcba:9876::2\n",
    );
    assert!(
        LegacyNetworkFingerprint::verify_absent_in(&unscoped)
            .expect_err("unscoped legacy DNS is unverifiable")
            .contains("no unique valid utun scope")
    );
}

#[test]
fn partial_or_non_utun_legacy_addresses_never_capture() {
    for interfaces in [
        "utun8: flags=8051<UP>\n\tinet 198.18.0.1 netmask 0xffffff00\n\tinet6 fdfe:dcba:9876::1 prefixlen 126\n",
        "en9: flags=8051<UP>\n\tinet 198.18.0.1 netmask 0xfffffffc\n\tinet6 fdfe:dcba:9876::1 prefixlen 126\n",
    ] {
        let observation = observation(
            interfaces,
            &format!("{ROUTE_HEADER}default link#8 UCS utun8\n"),
            &format!("{ROUTE_HEADER}default link#8 UCS utun8\n"),
            "No DNS configuration available\n",
        );
        let error = LegacyNetworkFingerprint::from_observation(&observation)
            .expect_err("partial ownership must fail closed");
        assert!(error.contains("partial address fingerprint"));
    }
}

#[test]
fn any_second_partial_candidate_makes_capture_ambiguous() {
    let observation = observation(
        COMPLETE_AND_PARTIAL_INTERFACES,
        IPV4_ROUTES,
        IPV6_ROUTES,
        DNS,
    );

    let error = LegacyNetworkFingerprint::from_observation(&observation)
        .expect_err("complete plus partial candidates are ambiguous");

    assert!(error.contains("ownership is ambiguous"));
    assert!(error.contains("utun6"));
    assert!(error.contains("utun7"));
}

#[test]
fn unique_complete_candidate_requires_attributable_routes() {
    let observation = observation(COMPLETE_INTERFACE, ROUTE_HEADER, ROUTE_HEADER, DNS);

    let error = LegacyNetworkFingerprint::from_observation(&observation)
        .expect_err("an address without routes is not a complete fingerprint");

    assert!(error.contains("has no attributable routes"));
}

#[test]
fn unverifiable_route_or_dns_output_fails_closed() {
    let malformed_routes = observation(
        COMPLETE_INTERFACE,
        "Routing tables without a schema\n",
        IPV6_ROUTES,
        DNS,
    );
    let route_error = LegacyNetworkFingerprint::from_observation(&malformed_routes)
        .expect_err("a missing Netif column is unverifiable");
    assert!(route_error.contains("route table has no"));
    assert!(route_error.contains("unverifiable"));

    let malformed_dns = observation(
        COMPLETE_INTERFACE,
        IPV4_ROUTES,
        IPV6_ROUTES,
        "unexpected DNS output\n",
    );
    let dns_error = LegacyNetworkFingerprint::from_observation(&malformed_dns)
        .expect_err("unknown DNS output is unverifiable");
    assert!(dns_error.contains("no verifiable resolver records"));
}

#[test]
fn complete_fingerprint_revalidation_is_normalized_and_exact() {
    let prepared = LegacyNetworkFingerprint::from_observation(&observation(
        COMPLETE_INTERFACE,
        IPV4_ROUTES,
        IPV6_ROUTES,
        DNS,
    ))
    .expect("complete fingerprint");
    assert_eq!(prepared.identity.interface, "utun6");
    assert_eq!(prepared.identity.route_count, 3);
    assert_eq!(prepared.identity.scoped_dns_resolvers, 1);
    assert_eq!(prepared.identity.route_digest.len(), 64);
    assert_eq!(
        LegacyNetworkFingerprint::for_recovery(prepared.journal_identity())
            .expect("journal identity"),
        prepared
    );

    let reordered = observation(
        COMPLETE_INTERFACE,
        &format!("{ROUTE_HEADER}10/8  link#24 UCS utun6 3\ndefault link#24 UCSg utun6\n"),
        &format!("{ROUTE_HEADER}default       link#24       UCSg       utun6\n"),
        DNS,
    );
    prepared
        .verify_observation(&reordered)
        .expect("row order and whitespace are normalized");

    let changed_routes = observation(
        COMPLETE_INTERFACE,
        &format!("{ROUTE_HEADER}default link#24 UCSg utun6\n"),
        &format!("{ROUTE_HEADER}default link#24 UCSg utun6\n"),
        DNS,
    );
    assert_eq!(
        prepared.verify_observation(&changed_routes),
        Err("legacy TUN fingerprint changed after preparation".into())
    );

    let changed_dns = observation(
        COMPLETE_INTERFACE,
        IPV4_ROUTES,
        IPV6_ROUTES,
        &format!("{DNS}resolver #4\n  if_index : 38 (utun6)\n"),
    );
    assert_eq!(
        prepared.verify_observation(&changed_dns),
        Err("legacy TUN fingerprint changed after preparation".into())
    );
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
    assert_eq!(scoped_dns_resolver_count(dns, "utun6"), Ok(1));
}
