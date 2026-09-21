//! Actual Rust -> Swift -> AppKit ABI/resource/lifecycle integration. Uses an
//! explicit presentation fixture; never registers or invokes network services.
use std::sync::atomic::{AtomicUsize, Ordering};

unsafe extern "C" {
    fn cfm_dashboard_present_v1(
        bytes: *const u8,
        count: usize,
        closed: extern "C" fn(usize),
        context: usize,
    ) -> i32;
    fn cfm_dashboard_publish_v1(bytes: *const u8, count: usize) -> i32;
    fn cfm_dashboard_close_v1(session: u64) -> i32;
    fn cfm_dashboard_invalidate_v1(session: u64) -> i32;
}
static RELEASES: AtomicUsize = AtomicUsize::new(0);
extern "C" fn closed(context: usize) {
    assert_eq!(context, 1);
    RELEASES.fetch_add(1, Ordering::SeqCst);
}

fn main() {
    let first =
        include_bytes!("../../../native/dashboard/Tests/CFMNativeDashboardTests/Fixtures/off.json");
    // SAFETY: this harness runs AppKit on the process main thread, lends live
    // buffers for synchronous calls and uses a static, scalar callback context.
    unsafe {
        assert_eq!(
            cfm_dashboard_present_v1(first.as_ptr(), first.len(), closed, 1),
            1
        );
        assert_eq!(
            cfm_dashboard_publish_v1(first.as_ptr(), first.len()),
            0,
            "replay must fail"
        );
        let mut next: serde_json::Value = serde_json::from_slice(first).unwrap();
        next["sequence"] = 10.into();
        let prior_late_frame = serde_json::to_vec(&next).unwrap();
        assert_eq!(
            cfm_dashboard_publish_v1(prior_late_frame.as_ptr(), prior_late_frame.len()),
            1
        );
        next["sequence"] = 2.into();
        next["session"] = 2.into();
        next["locale"] = "zh-Hans".into();
        let next = serde_json::to_vec(&next).unwrap();
        assert_eq!(
            cfm_dashboard_present_v1(next.as_ptr(), next.len(), closed, 1),
            1
        );
        assert_eq!(
            RELEASES.load(Ordering::SeqCst),
            1,
            "replacement releases the prior observer"
        );
        assert_eq!(
            cfm_dashboard_publish_v1(first.as_ptr(), first.len()),
            2,
            "old session cannot update a reopened window"
        );
        assert_eq!(cfm_dashboard_invalidate_v1(1), 2);
        assert_eq!(cfm_dashboard_close_v1(1), 2);
        assert_eq!(cfm_dashboard_close_v1(2), 1);
        assert_eq!(RELEASES.load(Ordering::SeqCst), 2);
        assert_eq!(cfm_dashboard_close_v1(2), 2);
        assert_eq!(RELEASES.load(Ordering::SeqCst), 2);
    }
    println!(
        "Native dashboard ABI: actual SwiftUI window/resource loading, replay rejection, session isolation and exactly-once close callbacks passed; no network operations."
    );
}
