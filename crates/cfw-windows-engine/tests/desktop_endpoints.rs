#![cfg(windows)]

// Compile the actual desktop selector and its portable cursor regressions.
// This observer is read-only and needs no disposable proxy mutation opt-in.
#[path = "../../../apps/cfw-tauri-shell/src/engine/endpoints.rs"]
mod desktop_endpoints;

use cfw_singbox_config::{DEFAULT_CLASH_API_PORT, EngineSettings};
use desktop_endpoints::{
    CANDIDATE_COUNT, EndpointCandidateCursor, EndpointRole, EndpointSelectionError,
    observe_reserved_ports, select_configured_engine_settings,
};

#[test]
fn desktop_selector_reads_native_settings_and_retains_bounded_retry_state() {
    let (selected, cursor) =
        select_configured_engine_settings(EngineSettings::default(), None, observe_reserved_ports)
            .unwrap();
    let (unchanged, _) = cursor
        .with_runtime_preferences(selected.clone(), None, observe_reserved_ports)
        .unwrap();
    assert_eq!(unchanged, selected);
    let recovered = EndpointCandidateCursor::from_persisted(selected.clone()).unwrap();
    match recovered.advance(EndpointRole::Controller) {
        Ok((next, _)) => {
            assert_eq!(next.mixed_port, selected.mixed_port);
            assert!(next.controller_port > selected.controller_port);
            assert!(usize::from(next.controller_port - DEFAULT_CLASH_API_PORT) < CANDIDATE_COUNT);
        }
        Err(EndpointSelectionError::Exhausted {
            role: EndpointRole::Controller,
        }) => {
            // Every later candidate may legitimately be reserved by the OS.
            let reserved = cfw_windows_engine::observe_lan_proxy_ports().unwrap();
            for port in selected.controller_port + 1
                ..DEFAULT_CLASH_API_PORT + u16::try_from(CANDIDATE_COUNT).unwrap()
            {
                assert!(reserved.contains(&port) || port == selected.mixed_port);
            }
        }
        Err(error) => panic!("desktop retry observation failed: {error}"),
    }
}

/// The cursor says which port preference it was selected with: none for a
/// port it chose itself, and the port it keeps for one that is named.
#[test]
fn desktop_cursor_says_which_port_preference_it_keeps() {
    let (selected, automatic) =
        select_configured_engine_settings(EngineSettings::default(), None, observe_reserved_ports)
            .unwrap();
    assert!(automatic.has_port_preference(None));
    assert!(!automatic.has_port_preference(Some(selected.mixed_port)));
    let (kept, named) = automatic
        .with_runtime_preferences(
            selected.clone(),
            Some(selected.mixed_port),
            observe_reserved_ports,
        )
        .unwrap();
    assert_eq!(kept, selected);
    assert!(named.has_port_preference(Some(selected.mixed_port)));
    assert!(!named.has_port_preference(None));
}
