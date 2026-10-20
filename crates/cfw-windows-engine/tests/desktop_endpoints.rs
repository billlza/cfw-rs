#![cfg(windows)]

// Compile the actual desktop selector and its portable cursor regressions.
// This observer is read-only and needs no disposable proxy mutation opt-in.
#[path = "../../../apps/cfw-tauri-shell/src/engine/endpoints.rs"]
mod desktop_endpoints;

use cfw_singbox_config::{DEFAULT_CLASH_API_PORT, EngineSettings};
use desktop_endpoints::{
    CANDIDATE_COUNT, EndpointCandidateCursor, EndpointRole, EndpointSelectionError,
    select_configured_engine_settings,
};

#[test]
fn desktop_selector_reads_native_settings_and_retains_bounded_retry_state() {
    let (selected, cursor) =
        select_configured_engine_settings(EngineSettings::default(), None).unwrap();
    let (unchanged, _) = cursor
        .with_runtime_preferences(selected.clone(), None)
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
