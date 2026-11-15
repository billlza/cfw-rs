//! Actual Windows TCP and UDP over IPv4 and IPv6 -> Wintun -> packet pump ->
//! the real engine's gVisor packet endpoint -> its SOCKS5 outbound -> a local
//! fixture node, and every reply back the same way. Validation only: the CI runner account owns
//! the adapter, the fixture address/host route, the pump and the engine. No
//! Authority lease, SYSTEM endpoint handoff, default route, DNS, firewall or
//! product backend is involved; the installed-host Tunnel suite covers the
//! product path. The same path carries the probes of the two leak protection
//! switches: passed on with the switches off in every case, refused in a last
//! case that runs the engine with both on.
use super::{
    Result,
    library::{self, Library},
    network, record,
};
use crate::{
    CheckedStartConfiguration, EngineProcess, VerifiedExecutable,
    tunnel::{
        DeliveryPolicy, InterfaceCounters, PacketPump, PacketServer, PumpReport, Refusal,
        RefusedClass,
    },
};
use cfw_engine_api::{EngineCommandContext, EngineStartRequest, TunnelNetworkOptions};
use cfw_singbox_config::{EngineSettings, ProjectionMode, TunnelStack, ValidatedSingBoxProfile};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener, UdpSocket},
    path::Path,
    thread,
    time::{Duration, Instant},
};
use windows_sys::Win32::NetworkManagement::IpHelper::IP_ADAPTER_DHCP_ENABLED;

mod exchange;
mod leak_protection;
mod socks;
use socks::{Fixture, HTTP_TARGETS, UDP_TARGETS, family, udp_overhead};

const PROFILE: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const TIMEOUT: Duration = Duration::from_secs(15);

/// One adapter lifetime: its MTU, and whether the engine runs with both leak
/// protection switches on.
#[derive(Clone, Copy)]
struct Case {
    mtu: u16,
    leak_protection: bool,
}
impl Case {
    /// The prefix of this case's receipts.
    fn label(self) -> String {
        if self.leak_protection {
            format!("mtu-{}-leak-protection", self.mtu)
        } else {
            format!("mtu-{}", self.mtu)
        }
    }
}

/// Every MTU with the switches off, then one case with both on.
const CASES: [Case; 4] = [
    Case {
        mtu: 1280,
        leak_protection: false,
    },
    Case {
        mtu: 1500,
        leak_protection: false,
    },
    Case {
        mtu: 9000,
        leak_protection: false,
    },
    Case {
        mtu: 1500,
        leak_protection: true,
    },
];

/// The pinned engine image every run admits afresh.
struct EngineImage<'a> {
    path: &'a Path,
    digest: [u8; 32],
    version: &'a str,
}

/// What every MTU case shares: the loaded driver, the engine, the fixture
/// node's host address and where receipts go.
struct Run<'a> {
    library: &'a Library,
    engine: EngineImage<'a>,
    host: Ipv4Addr,
    output: &'a Path,
    source: &'a str,
}

/// The engine's private working directory for one case. Declared before the
/// engine owner so it is removed after that owner, also on a failed case.
struct RuntimeDirectory(std::path::PathBuf);
impl Drop for RuntimeDirectory {
    fn drop(&mut self) {
        if self.0.exists()
            && let Err(error) = std::fs::remove_dir_all(&self.0)
        {
            eprintln!("forwarding runtime directory cleanup failed: {error}");
        }
    }
}

/// One adapter's native identity.
struct Owned<'a> {
    id: uuid::Uuid,
    name: &'a str,
    luid: u64,
}

pub(super) fn run(
    dll: &Path,
    engine: &Path,
    engine_sha256: &str,
    engine_version: &str,
    output: &Path,
    source: &str,
) -> Result<()> {
    if !dll.is_absolute() || !engine.is_absolute() || !output.is_absolute() || output.exists() {
        return Err("invalid Wintun forwarding validation paths".into());
    }
    let digest = sha256(engine_sha256)?;
    std::fs::create_dir(output).map_err(|error| error.to_string())?;
    let peer =
        crate::NativePeerProcess::open(std::process::id()).map_err(|error| error.to_string())?;
    // Chosen before any adapter exists: the fixture node lives on the
    // runner's own private address, outside the single owned host route.
    let host = private_address()?;
    record(
        output,
        "initial.json",
        &json!({"source":source,"process_id":peer.process_id(),
        "process_creation_time":peer.identity().process_creation_time(),
        "integrity_rid":peer.identity().integrity_rid(),"local_system":peer.identity().is_local_system(),
        "dll_sha256":crate::runtime_host::wintun_image_pin().map_err(|error| error.to_string())?.sha256,
        "engine_sha256":engine_sha256,"engine_version":engine_version,"fixture_host":host.to_string(),
        "release_accepted":false}),
    )?;
    let mut cases = Vec::new();
    let result = (|| {
        let library = Library::load_for_validation(dll).map_err(|error| error.to_string())?;
        let run = Run {
            library: &library,
            engine: EngineImage {
                path: engine,
                digest,
                version: engine_version,
            },
            host,
            output,
            source,
        };
        let operation = (|| {
            for case in CASES {
                cases.push(forward(&run, case)?);
            }
            Ok(())
        })();
        combine(
            operation,
            library.close().map_err(|error| error.to_string()),
        )
    })();
    let saved = record(
        output,
        "result.json",
        &json!({"source":source,"success":result.is_ok(),"failure":result.as_ref().err(),
        "cases":cases,"ip_families":["ipv4","ipv6"],
        "owned_addresses":["192.0.2.10/32","2001:db8:1::10/128"],
        "owned_host_routes":["192.0.2.123/32","2001:db8:1::123/128"],
        "wintun_engine_forwarding_verified":result.is_ok(),
        "leak_protection_verified":result.is_ok(),
        "authority_lease_exercised":false,"system_to_user_handoff_exercised":false,
        "default_routes_modified":false,"dns_modified":false,"firewall_modified":false,
        "product_tunnel_backend_exercised":false,"release_accepted":false}),
    );
    combine(result, saved)
}

fn combine<T>(operation: Result<T>, cleanup: Result<()>) -> Result<T> {
    match (operation, cleanup) {
        (Ok(value), Ok(())) => Ok(value),
        (Err(error), Ok(())) | (Ok(_), Err(error)) => Err(error),
        (Err(error), Err(cleanup)) => Err(format!("{error}; cleanup: {cleanup}")),
    }
}

fn sha256(text: &str) -> Result<[u8; 32]> {
    let mut digest = [0u8; 32];
    if text.len() != 64
        || !text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("engine digest is not lowercase SHA-256 hex".into());
    }
    for (index, value) in digest.iter_mut().enumerate() {
        *value = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16)
            .map_err(|error| error.to_string())?;
    }
    Ok(digest)
}

/// UDP connect selects a route without sending a datagram.
fn private_address() -> Result<Ipv4Addr> {
    let route = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).map_err(|error| error.to_string())?;
    route
        .connect((Ipv4Addr::new(192, 0, 2, 1), 9))
        .map_err(|error| error.to_string())?;
    match route.local_addr().map_err(|error| error.to_string())?.ip() {
        IpAddr::V4(address) if address.is_private() => Ok(address),
        other => Err(format!(
            "forwarding fixture requires a private IPv4 interface, found {other}"
        )),
    }
}

fn reserve_loopback_port() -> Result<u16> {
    let listener =
        TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|error| error.to_string())?;
    Ok(listener
        .local_addr()
        .map_err(|error| error.to_string())?
        .port())
}

/// The product Tunnel projection, admitted through the checked shared request.
fn tunnel_request(node: SocketAddr, case: Case) -> Result<EngineStartRequest> {
    let mtu = case.mtu;
    let profile = ValidatedSingBoxProfile::parse(
        &json!({"outbounds":[{"type":"socks5","tag":"proxy",
            "server":node.ip().to_string(),"server_port":node.port()}]})
        .to_string(),
    )
    .map_err(|error| error.to_string())?;
    let settings = EngineSettings {
        tunnel_mtu: mtu,
        controller_port: reserve_loopback_port()?,
        dns_leak_protection: case.leak_protection,
        webrtc_leak_protection: case.leak_protection,
        ..EngineSettings::default()
    };
    let projection = profile
        .project_with_tunnel_stack(
            PROFILE,
            ProjectionMode::Tunnel,
            &settings,
            TunnelStack::Gvisor,
        )
        .map_err(|error| error.to_string())?;
    Ok(EngineStartRequest {
        context: EngineCommandContext {
            installation_id: uuid::Uuid::new_v4().to_string(),
            config_epoch: 1,
            generation: 1,
        },
        mode: ProjectionMode::Tunnel,
        credential_audience: projection.credential_audience().clone(),
        config_json: projection.as_json().to_owned(),
        config_content_digest: projection.configuration_digest().to_owned(),
        config_digest: projection.digest().to_owned(),
        credential_slots: projection.credential_slots().to_vec(),
        tunnel_options: Some(TunnelNetworkOptions {
            ipv6_enabled: settings.enable_ipv6,
            bypass_private_networks: settings.bypass_private_networks,
            direct_ipv4_hosts: projection.direct_ipv4_hosts(),
            mtu,
            system_proxy_port: None,
        }),
    })
}

fn forward(run: &Run<'_>, case: Case) -> Result<Value> {
    let (output, source, mtu) = (run.output, run.source, case.mtu);
    let id = uuid::Uuid::new_v4();
    let adapter = run.library.create(id).map_err(|error| error.to_string())?;
    let luid = adapter.luid();
    let name = adapter.name().to_owned();
    // Observed only: whether a new Wintun adapter starts with DHCPv4 enabled.
    let flags_at_creation = network::adapter_flags(luid);
    record(
        output,
        &format!("{}-created.json", case.label()),
        &json!({"source":source,"mtu":mtu,"interface_guid":id,"luid":luid,"name":name,"adapter_created":true,
        "adapter_flags_at_creation":flags_at_creation.as_ref().ok()}),
    )?;
    let operation = (|| {
        let flags_at_creation = flags_at_creation?;
        let mut session = adapter.session(mtu).map_err(|error| error.to_string())?;
        let mut owned = network::OwnedNetwork::configure(&adapter, id, mtu, true)?;
        let flags_with_fixture = network::adapter_flags(luid);
        let identity = Owned {
            id,
            name: &name,
            luid,
        };
        let exercised = owned
            .delivery_policy()
            .and_then(|policy| exercise(run, &mut session, &identity, case, policy));
        let restored = owned.restore();
        drop(session);
        let mut receipt = combine(exercised, restored)?;
        let flags_with_fixture = flags_with_fixture?;
        receipt["adapter_flags_at_creation"] = json!(flags_at_creation);
        receipt["adapter_flags_with_fixture_addresses"] = json!(flags_with_fixture);
        receipt["adapter_dhcpv4_enabled_at_creation"] =
            json!(flags_at_creation & IP_ADAPTER_DHCP_ENABLED != 0);
        receipt["adapter_dhcpv4_enabled_with_fixture_addresses"] =
            json!(flags_with_fixture & IP_ADAPTER_DHCP_ENABLED != 0);
        receipt["original_mtu"] = json!(owned.original_mtu());
        receipt["original_ipv6_interface"] = json!(owned.original_ipv6().map(|original| {
            json!({"mtu":original.mtu,"dad_transmits":original.dad_transmits,
            "router_discovery":original.router_discovery})
        }));
        receipt["owned_route_address_mtu_restored"] = json!(true);
        Ok(receipt)
    })();
    drop(adapter);
    let absent = library::wait_absent(luid, &name).map_err(|error| error.to_string());
    let mut receipt = combine(operation, absent)?;
    network::require_unused_addresses_and_route()?;
    receipt["source"] = json!(source);
    receipt["mtu"] = json!(mtu);
    receipt["interface_guid"] = json!(id);
    receipt["luid"] = json!(luid);
    receipt["name"] = json!(name);
    receipt["adapter_absence_observed"] = json!(true);
    receipt["fixture_addresses_and_host_route_absent"] = json!(true);
    receipt["release_accepted"] = json!(false);
    record(output, &format!("{}-complete.json", case.label()), &receipt)?;
    Ok(receipt)
}

fn exercise(
    run: &Run<'_>,
    session: &mut crate::tunnel::Session<'_>,
    adapter: &Owned<'_>,
    case: Case,
    policy: DeliveryPolicy,
) -> Result<Value> {
    let mtu = case.mtu;
    let nonce = uuid::Uuid::new_v4().simple().to_string();
    // Fixture threads start before the inheritable packet endpoint exists.
    let fixture = Fixture::start(run.host, &nonce)?;
    let request = tunnel_request(fixture.address(), case)?;
    let configuration_digest = request.config_digest.clone();
    let config = CheckedStartConfiguration::new(request)
        .and_then(|checked| checked.prepare_tunnel_data_plane([]))
        .map_err(|error| error.to_string())?;
    let executable =
        VerifiedExecutable::open(run.engine.path, run.engine.digest, run.engine.version)
            .map_err(|error| error.to_string())?;
    let (server, client) =
        PacketServer::create(adapter.id, mtu).map_err(|error| error.to_string())?;
    let runtime =
        RuntimeDirectory(std::env::temp_dir().join(format!("cfw-tunnel-forwarding-{nonce}")));
    let mut process =
        EngineProcess::spawn_with_packet_endpoint(executable, &runtime.0, TIMEOUT, None, client)
            .map_err(|error| error.to_string())?;
    let running = process
        .start(&config, TIMEOUT)
        .map_err(|error| error.to_string())?;
    let before =
        library::counters(adapter.luid, adapter.name).map_err(|error| error.to_string())?;
    // The leak protection probes record what the adapter counted while each ran.
    let adapter_counters =
        || library::counters(adapter.luid, adapter.name).map_err(|error| error.to_string());
    let (traffic, observed, stopped, retired) = thread::scope(|scope| {
        let pump = match PacketPump::start(scope, &mut *session, server, policy) {
            Ok(pump) => pump,
            Err(error) => {
                let stopped = process.stop(TIMEOUT).map_err(|error| error.to_string());
                return (
                    Err(format!("start the packet pump: {error}")),
                    None,
                    stopped,
                    None,
                );
            }
        };
        let control = pump.control();
        // The leak protection probes follow the bulk exchange on the same
        // engine and pump.
        let pump_report = || pump.report();
        let sources = leak_protection::Sources {
            adapter: &adapter_counters,
            pump: &pump_report,
        };
        let traffic = exchange::exchange(&fixture, mtu).map(|bulk| {
            (
                bulk,
                leak_protection::probe(&fixture, &sources, case.leak_protection),
            )
        });
        let observed = traffic
            .as_ref()
            .ok()
            .map(|_| process.observe(TIMEOUT).map_err(|error| error.to_string()));
        // The engine closes its endpoint first; the pump only observes it.
        control.expect_peer_close();
        let stopped = process.stop(TIMEOUT).map_err(|error| error.to_string());
        let retired = if stopped.is_ok() {
            pump.finish(Instant::now() + Duration::from_secs(5))
                .map(Some)
                .map_err(|error| error.to_string())
        } else {
            pump.stop().map(|_| None).map_err(|error| error.to_string())
        };
        (traffic, observed, stopped, Some(retired))
    });
    // The leak protection observation is kept before any verdict on the case.
    let traffic = traffic.and_then(|(bulk, probes)| {
        record(
            run.output,
            &format!("{}-probes.json", case.label()),
            &probes.observed,
        )
        .map(|()| (bulk, probes))
    });
    let mut failures = Vec::new();
    let traffic = traffic
        .map_err(|error| failures.push(format!("traffic: {error}")))
        .ok();
    let observed = match observed {
        Some(Ok(observed)) => Some(observed),
        Some(Err(error)) => {
            failures.push(format!("engine observation after traffic: {error}"));
            None
        }
        None => None,
    };
    let stopped = stopped
        .map_err(|error| failures.push(format!("engine stop: {error}")))
        .ok();
    let retirement = match retired {
        Some(Ok(Some(retirement))) => Some(retirement),
        Some(Ok(None)) => None,
        Some(Err(error)) => {
            failures.push(format!("pump retirement: {error}"));
            None
        }
        None => None,
    };
    let (Some((traffic, probes)), Some(observed), Some(stopped), Some(retirement)) =
        (traffic, observed, stopped, retirement)
    else {
        drop(process);
        let fixture = fixture
            .finish()
            .err()
            .map(|error| format!("; fixture: {error}"))
            .unwrap_or_default();
        return Err(format!("{}{fixture}", failures.join("; ")));
    };
    if observed.process_id != running.process_id
        || observed.configuration_digest != configuration_digest
        || stopped.process_id != running.process_id
        || stopped.configuration_digest != configuration_digest
    {
        return Err("engine observation or stop belongs to another runtime".into());
    }
    let report = *retirement.report();
    if report.to_engine.largest_packet != usize::from(mtu)
        || report.to_system.largest_packet != usize::from(mtu)
        || report.to_engine.packets == 0
        || report.to_system.packets == 0
    {
        return Err(format!(
            "pump did not carry full-MTU packets in both directions: {report:?}"
        ));
    }
    // Genuine engine output is always addressed to the adapter from a
    // remote peer; only sing-tun's echoes of Windows' own multicast,
    // broadcast and link-local packets may be refused, by destination.
    if report.refused.source.packets != 0 || report.refused.protocol.packets != 0 {
        return Err(format!(
            "the delivery policy refused engine packets other than echoes: {:?}",
            report.refused
        ));
    }
    let after = received_equals_delivered(adapter, &before, &report)?;
    let control = exchange::causal_control(&fixture)?;
    let accepted = fixture.accepted();
    let observations = fixture.finish()?;
    require_fixture_flows(&observations, mtu)?;
    leak_protection::require_flows(&observations, &nonce, case.leak_protection)?;
    probes.verdict()?;
    drop(process);
    std::fs::remove_dir_all(&runtime.0)
        .map_err(|error| format!("remove the engine runtime directory: {error}"))?;
    Ok(json!({
        "nonce":nonce,"engine_process_id":running.process_id,"configuration_digest":configuration_digest,
        "engine_observed_running_after_traffic":true,"engine_stopped_cleanly":true,
        "traffic":traffic,"leak_protection":probes.observed,"pump":{
            "to_engine":{"packets":report.to_engine.packets,"bytes":report.to_engine.bytes,"largest_packet":report.to_engine.largest_packet},
            "to_system":{"packets":report.to_system.packets,"bytes":report.to_system.bytes,"largest_packet":report.to_system.largest_packet},
            "ring_full_waits":report.ring_full_waits,"peer_close_code":retirement.peer_close_code(),
            "server_endpoint_closed":true,"refused":{
                "destination":refused(&report.refused.destination),
                "source":refused(&report.refused.source),
                "protocol":refused(&report.refused.protocol)}},
        "delivery_policy":{"ipv4":policy.ipv4().to_string(),
            "ipv6":policy.ipv6().map(|address| address.to_string())},
        "interface_counters":{"before":before,"after":after,"received_equals_delivered":true},
        "causal_control":control,"fixture_accepted_connections":accepted,"fixture":observations,
        "windows_to_engine_forwarding_verified":true,"engine_to_windows_forwarding_verified":true
    }))
}

fn refused(class: &RefusedClass) -> Value {
    let sample = |refusal: &Refusal| {
        json!({"reason":refusal.reason.to_string(),
        "source":refusal.source.to_string(),"destination":refusal.destination.to_string()})
    };
    json!({"packets":class.packets,"bytes":class.bytes,"first":class.first.as_ref().map(sample)})
}

/// The adapter's receive counters grew by exactly the packets and bytes the
/// pump delivered, with no non-unicast, discarded or erroneous receive. That
/// refused packets were withheld from the session is the pump tests' proof.
/// Wintun indicates packets asynchronously, so the counters may trail the
/// pump's retirement briefly.
fn received_equals_delivered(
    adapter: &Owned<'_>,
    before: &InterfaceCounters,
    report: &PumpReport,
) -> Result<InterfaceCounters> {
    let delivered = report.to_system;
    let deadline = Instant::now() + Duration::from_secs(2);
    loop {
        let after =
            library::counters(adapter.luid, adapter.name).map_err(|error| error.to_string())?;
        let grew = |now: u64, then: u64| now.checked_sub(then);
        let matches = grew(after.in_unicast_packets, before.in_unicast_packets)
            == Some(delivered.packets)
            && grew(after.in_octets, before.in_octets) == Some(delivered.bytes)
            && after.in_non_unicast_packets == before.in_non_unicast_packets
            && after.in_discards == before.in_discards
            && after.in_errors == before.in_errors;
        if matches {
            return Ok(after);
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "adapter receive counters differ from the pump's deliveries: before {before:?}, after {after:?}, pump {report:?}"
            ));
        }
        thread::sleep(Duration::from_millis(20));
    }
}

/// Exactly one CONNECT and one UDP datagram per family for this run's fixed
/// targets. Other background flows are recorded by the fixture, never served.
fn require_fixture_flows(observations: &Value, mtu: u16) -> Result<()> {
    let flows = observations["observations"]
        .as_array()
        .ok_or("fixture observations are missing")?;
    for (http, udp) in HTTP_TARGETS.into_iter().zip(UDP_TARGETS) {
        let connects = flows
            .iter()
            .filter(|flow| flow["command"] == "connect" && flow["target"] == http.to_string())
            .count();
        let served: Vec<_> = flows
            .iter()
            .filter(|flow| flow["command"] == "udp_associate")
            .filter_map(|flow| flow["served"].as_array())
            .flatten()
            .filter(|datagram| datagram["target"] == udp.to_string())
            .collect();
        if connects != 1
            || served.len() != 1
            || served[0]["bytes"] != json!(usize::from(mtu) - udp_overhead(udp))
        {
            return Err(format!(
                "fixture did not observe exactly the run's {} flows: {observations}",
                family(http)
            ));
        }
    }
    Ok(())
}
