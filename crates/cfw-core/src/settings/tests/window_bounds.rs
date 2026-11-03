//! The window bounds document: its private canonical round trip apart from the
//! preferences, malformed or out-of-range bounds, links, unbounded platform
//! values, and readers that run while it is written.

use super::*;

#[test]
fn window_bounds_round_trip_is_private_canonical_and_independent() {
    let (root, store) = test_store("window-bounds-round-trip");
    let bounds = WindowBounds::new(-1440, 25, 1200, 800).expect("valid bounds");
    store
        .write_window_bounds(bounds)
        .expect("write window bounds");

    assert_eq!(
        store.window_bounds().expect("read window bounds"),
        Some(bounds)
    );
    assert_eq!(
        fs::read(&store.paths.window_state_file).expect("read canonical state"),
        br#"{"schema_version":1,"bounds":{"x":-1440,"y":25,"width":1200,"height":800}}"#,
    );
    assert_private_file(&store.paths.window_state_file);
    assert!(!store.paths.preferences_file.exists());

    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn malformed_noncanonical_and_out_of_range_window_bounds_fail_closed() {
    let (root, store) = test_store("invalid-window-bounds");
    store.ensure_layout().expect("create layout");
    let cases = [
        b"not json".as_slice(),
        br#"{ "schema_version": 1, "bounds": {"x":0,"y":0,"width":850,"height":603} }"#,
        br#"{"schema_version":2,"bounds":{"x":0,"y":0,"width":850,"height":603}}"#,
        br#"{"schema_version":1,"bounds":{"x":0,"y":0,"width":0,"height":603}}"#,
        br#"{"schema_version":1,"bounds":{"x":1000001,"y":0,"width":850,"height":603}}"#,
    ];
    for bytes in cases {
        write_private(&store.paths.window_state_file, bytes);
        assert!(store.window_bounds().is_err(), "accepted {bytes:?}");
    }

    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn symlink_and_hard_link_window_state_are_rejected() {
    let (root, store) = test_store("unsafe-window-state");
    store.ensure_layout().expect("create layout");
    let outside = root.join("outside-window-state");
    fs::write(&outside, b"{}").expect("write outside file");
    symlink(&outside, &store.paths.window_state_file).expect("create window state symlink");
    assert!(matches!(
        store.window_bounds(),
        Err(SettingsStoreError::UnsafeFile)
    ));
    fs::remove_file(&store.paths.window_state_file).expect("remove symlink");

    store
        .write_window_bounds(WindowBounds::new(0, 25, 850, 603).expect("valid bounds"))
        .expect("write window state");
    fs::hard_link(
        &store.paths.window_state_file,
        root.join("window-state-hard-link"),
    )
    .expect("create hard link");
    assert!(matches!(
        store.window_bounds(),
        Err(SettingsStoreError::UnsafeFile)
    ));

    fs::remove_dir_all(root).expect("remove test root");
}

#[test]
fn window_bounds_constructor_rejects_unbounded_platform_values() {
    assert!(WindowBounds::new(0, 0, 0, 603).is_err());
    assert!(WindowBounds::new(0, 0, 850, 0).is_err());
    assert!(WindowBounds::new(0, 0, MAX_WINDOW_DIMENSION + 1, 603).is_err());
    assert!(WindowBounds::new(MAX_WINDOW_COORDINATE_MAGNITUDE + 1, 0, 850, 603).is_err());
}

#[test]
fn concurrent_window_state_readers_never_observe_partial_json() {
    let (root, store) = test_store("concurrent-window-state");
    store
        .write_window_bounds(WindowBounds::new(0, 25, 850, 603).expect("initial bounds"))
        .expect("write initial window state");
    let store = Arc::new(store);
    let barrier = Arc::new(Barrier::new(2));
    let writer_store = Arc::clone(&store);
    let writer_barrier = Arc::clone(&barrier);
    let writer = std::thread::spawn(move || {
        writer_barrier.wait();
        for index in 0..24 {
            writer_store
                .write_window_bounds(
                    WindowBounds::new(index * 10, 25, 850 + index as u32, 603)
                        .expect("valid concurrent bounds"),
                )
                .expect("atomic window state write");
        }
    });
    barrier.wait();
    for _ in 0..64 {
        let bounds = store
            .window_bounds()
            .expect("complete window state")
            .expect("window bounds");
        assert!(bounds.width >= 850);
        assert_eq!(bounds.height, 603);
    }
    writer.join().expect("writer thread");
    fs::remove_dir_all(root).expect("remove test root");
}
