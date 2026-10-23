//! A disposable SYSTEM service hands one packet endpoint to its
//! medium-integrity client. Validation only: no lease, engine or adapter.
use super::*;
use cfw_windows_engine::tunnel::{
    AdoptedEndpointProbe, EndpointOffer, HandoffError, PacketHandoffProbe,
};

const REPORT: &str = "packet-handoff.validation.json";
const VERIFY: &[u8] = b"packet-handoff-verify:";

fn report() -> serde_json::Value {
    serde_json::json!({"success":true,"system_created_endpoint":true,"recipient_medium_or_high_integrity":true,"local_substitutes_refused":true,"substitute_refused_by_system_object_check":true,"retained_client_reference_dropped":true,"full_mtu_packet_each_way":true,"peer_close_observed":true,"mtu":1500,"authority_lease_exercised":false,"engine_started":false,"wintun_adapter_created":false,"routes_or_dns_changed":false,"release_accepted":false})
}

/// SYSTEM's replies to the client's handoff requests; None for other bodies.
pub(super) fn handle(
    state: &mut Option<PacketHandoffProbe>,
    request: &cfw_windows_engine::ServicePeerAuthorization,
    body: &[u8],
) -> Result<Option<Vec<u8>>> {
    if body == b"packet-handoff-begin" && state.is_none() {
        let created = PacketHandoffProbe::new(request).map_err(|e| e.to_string())?;
        let offer = created.offer().map_err(|e| e.to_string())?;
        *state = Some(created);
        return Ok(Some(serde_json::to_vec(&offer).map_err(|e| e.to_string())?));
    }
    let known = body.starts_with(VERIFY)
        || matches!(
            body,
            b"packet-handoff-renew"
                | b"packet-handoff-send"
                | b"packet-handoff-receive"
                | b"packet-handoff-release"
        );
    if !known {
        return Ok(None);
    }
    let probe = state.as_mut().ok_or("missing packet handoff fixture")?;
    Ok(Some(match body {
        body if body.starts_with(VERIFY) => {
            let bytes: [u8; 8] = body[VERIFY.len()..]
                .try_into()
                .map_err(|_| "invalid packet handoff verification frame")?;
            if probe
                .verify(request, u64::from_le_bytes(bytes))
                .map_err(|e| e.to_string())?
            {
                b"verified".to_vec()
            } else {
                b"unrelated".to_vec()
            }
        }
        b"packet-handoff-renew" => {
            serde_json::to_vec(&probe.renew(request).map_err(|e| e.to_string())?)
                .map_err(|e| e.to_string())?
        }
        b"packet-handoff-send" => {
            probe.send(request).map_err(|e| e.to_string())?;
            b"sent".to_vec()
        }
        b"packet-handoff-receive" => {
            probe.receive(request).map_err(|e| e.to_string())?;
            b"received".to_vec()
        }
        _ => {
            let code = probe.observe_release(request).map_err(|e| e.to_string())?;
            let refused = probe.substitutes_refused();
            if !matches!(code, 109 | 232) || refused != 1 {
                return Err(format!(
                    "packet handoff ended with code {code} after {refused} refused substitutes"
                ));
            }
            let mut output = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(authority_journal::root()?.join(REPORT))
                .map_err(|e| e.to_string())?;
            std::io::Write::write_all(
                &mut output,
                &serde_json::to_vec(&report()).map_err(|e| e.to_string())?,
            )
            .map_err(|e| e.to_string())?;
            output.sync_all().map_err(|e| e.to_string())?;
            b"released".to_vec()
        }
    }))
}

/// A started handoff must have retired its endpoint before the client ends.
pub(super) fn require_complete(state: &Option<PacketHandoffProbe>) -> Result<()> {
    if state.as_ref().is_some_and(|probe| !probe.released()) {
        return Err("packet handoff fixture ended before its endpoint retired".into());
    }
    Ok(())
}

pub(super) fn require_report(root: &Path) -> Result<()> {
    let bytes = std::fs::read(root.join(REPORT)).map_err(|e| e.to_string())?;
    if bytes.len() > 4096
        || serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|e| e.to_string())?
            != report()
    {
        return Err("packet handoff report differs from the required checks".into());
    }
    Ok(())
}

pub(super) fn client(channel: &mut ServiceChannel) -> Result<()> {
    let authority = channel.packet_authority().map_err(|e| e.to_string())?;
    let first = offer(channel, b"packet-handoff-begin")?;
    AdoptedEndpointProbe::refuse_substitutes(&first, &authority, |handle| confirm(channel, handle))
        .map_err(|e| e.to_string())?;
    let fresh = offer(channel, b"packet-handoff-renew")?;
    let probe = AdoptedEndpointProbe::adopt(&fresh, &authority, |handle| confirm(channel, handle))
        .map_err(|e| e.to_string())?;
    probe.require_reduced_access().map_err(|e| e.to_string())?;
    expect(channel, b"packet-handoff-send", b"sent")?;
    probe.echo().map_err(|e| e.to_string())?;
    expect(channel, b"packet-handoff-receive", b"received")?;
    probe.close().map_err(|e| e.to_string())?;
    expect(channel, b"packet-handoff-release", b"released")
}

fn offer(channel: &mut ServiceChannel, request: &[u8]) -> Result<EndpointOffer> {
    let bytes = channel
        .request(request, Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?;
    if bytes.as_bytes().len() > 512 {
        return Err("invalid packet handoff offer length".into());
    }
    serde_json::from_slice(bytes.as_bytes()).map_err(|e| e.to_string())
}

fn confirm(channel: &mut ServiceChannel, handle: u64) -> std::result::Result<(), HandoffError> {
    let mut request = VERIFY.to_vec();
    request.extend_from_slice(&handle.to_le_bytes());
    match channel
        .request(&request, Instant::now() + LIMIT)?
        .as_bytes()
    {
        b"verified" => Ok(()),
        b"unrelated" => Err(HandoffError::Substituted),
        _ => Err(HandoffError::Phase("confirmed by SYSTEM")),
    }
}

fn expect(channel: &mut ServiceChannel, request: &[u8], reply: &[u8]) -> Result<()> {
    if channel
        .request(request, Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
        .as_bytes()
        != reply
    {
        return Err(format!(
            "packet handoff step {} was not acknowledged",
            String::from_utf8_lossy(request)
        ));
    }
    Ok(())
}
