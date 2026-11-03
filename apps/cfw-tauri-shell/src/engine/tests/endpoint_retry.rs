//! A mode change's endpoint retry: advancing the loopback endpoints after an
//! exact Off, the bound on attempts, and the one pause before a conflict on the
//! same endpoint is retried.

use super::*;

fn advance_test_mixed_endpoint(
    endpoints: &std::sync::RwLock<EngineEndpointBinding>,
    conflict: BackendErrorKind,
) -> Result<(), String> {
    if conflict != BackendErrorKind::MixedEndpointInUse {
        return Err("unexpected endpoint conflict role".into());
    }
    let mut current = endpoints
        .write()
        .map_err(|_| "endpoint test lock is poisoned".to_owned())?;
    let mut settings = current.controller.settings().clone();
    let maximum = EngineSettings::default().mixed_port + (CANDIDATE_COUNT as u16 - 1);
    if settings.mixed_port >= maximum {
        return Err("mixed endpoint candidates are exhausted".into());
    }
    settings.mixed_port += 1;
    *current = endpoint_binding(settings);
    Ok(())
}

#[tokio::test]
async fn mode_retry_loop_advances_endpoints_and_generation_after_exact_off() {
    let backend = Arc::new(EndpointRetryBackend::new(2));
    let coordinator = endpoint_retry_coordinator(backend.clone());
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));

    let snapshot = set_mode_with_endpoint_rebind(
        &coordinator,
        &endpoints,
        EngineMode::SystemProxy,
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        &ValidatedSingBoxProfile::direct(),
        || Ok(()),
        |conflict| advance_test_mixed_endpoint(&endpoints, conflict),
    )
    .await
    .expect("the second bounded endpoint starts after one retry of the first");

    // The first conflict is retried on the same endpoint once (a listener the
    // coordinator just stopped may still be closing); the second moves on.
    let base_port = EngineSettings::default().mixed_port;
    assert_eq!(
        backend.starts(),
        vec![(1, base_port), (2, base_port), (3, base_port + 1)]
    );
    assert_eq!(backend.stops.load(Ordering::Acquire), 2);
    assert_eq!(snapshot.generation, 3);
    assert!(matches!(snapshot.state, EngineState::ProxyActive { .. }));
    assert!(
        read_active_controller_access(
            &endpoints,
            3,
            snapshot.config_digest.as_deref().expect("digest")
        )
        .is_ok()
    );
}

#[tokio::test]
async fn mode_retry_loop_stops_after_the_last_bounded_endpoint() {
    let backend = Arc::new(EndpointRetryBackend::new(CANDIDATE_COUNT + 1));
    let coordinator = endpoint_retry_coordinator(backend.clone());
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));

    let error = set_mode_with_endpoint_rebind(
        &coordinator,
        &endpoints,
        EngineMode::SystemProxy,
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        &ValidatedSingBoxProfile::direct(),
        || Ok(()),
        |conflict| advance_test_mixed_endpoint(&endpoints, conflict),
    )
    .await
    .expect_err("the ninth endpoint attempt is forbidden");

    assert_eq!(error, "mixed endpoint candidates are exhausted");
    let starts = backend.starts();
    // Eight candidates plus the one same-endpoint retry of the first conflict.
    assert_eq!(starts.len(), CANDIDATE_COUNT + 1);
    assert_eq!(backend.stops.load(Ordering::Acquire), CANDIDATE_COUNT + 1);
    assert_eq!(
        starts
            .iter()
            .map(|(generation, _)| *generation)
            .collect::<Vec<_>>(),
        (1..=CANDIDATE_COUNT as u64 + 1).collect::<Vec<_>>()
    );
    assert_eq!(
        starts[0].1, starts[1].1,
        "the first conflict is retried in place"
    );
    assert!(
        starts[1..]
            .windows(2)
            .all(|pair| pair[1].1 == pair[0].1 + 1)
    );
    assert_eq!(coordinator.snapshot().state, EngineState::Off);
}

#[tokio::test]
async fn a_single_endpoint_conflict_keeps_the_same_port_after_a_pause() {
    let backend = Arc::new(EndpointRetryBackend::new(1));
    let coordinator = endpoint_retry_coordinator(backend.clone());
    let endpoints = std::sync::RwLock::new(endpoint_binding(EngineSettings::default()));
    let rebinds = AtomicUsize::new(0);
    let started = std::time::Instant::now();

    let snapshot = set_mode_with_endpoint_rebind(
        &coordinator,
        &endpoints,
        EngineMode::SystemProxy,
        "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        &ValidatedSingBoxProfile::direct(),
        || Ok(()),
        |_conflict| {
            rebinds.fetch_add(1, Ordering::AcqRel);
            Err("a transient conflict must not move the endpoint cursor".into())
        },
    )
    .await
    .expect("the same endpoint starts on the retry");

    let base_port = EngineSettings::default().mixed_port;
    assert_eq!(backend.starts(), vec![(1, base_port), (2, base_port)]);
    assert_eq!(rebinds.load(Ordering::Acquire), 0);
    assert!(
        started.elapsed() >= crate::engine::ENDPOINT_CONFLICT_RETRY_DELAY,
        "the retry waits for the previous listener to close"
    );
    assert_eq!(backend.stops.load(Ordering::Acquire), 1);
    assert!(matches!(snapshot.state, EngineState::ProxyActive { .. }));
    assert_eq!(
        read_active_controller_access(
            &endpoints,
            2,
            snapshot.config_digest.as_deref().expect("digest")
        )
        .map(|access| access.settings().mixed_port),
        Ok(base_port)
    );
}
