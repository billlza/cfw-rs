//! Process-local connection lifetime, never a wire identity or runtime grant.
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicU64, Ordering},
};

struct Lifetime {
    open: AtomicBool,
    pending: AtomicU64,
}
#[derive(Clone)]
pub(crate) struct ConnectionBinding(Arc<Lifetime>);
impl ConnectionBinding {
    pub(crate) fn new() -> Self {
        Self(Arc::new(Lifetime {
            open: AtomicBool::new(true),
            pending: AtomicU64::new(0),
        }))
    }
    pub(crate) fn is_open(&self) -> bool {
        self.0.open.load(Ordering::Acquire)
    }
    pub(crate) fn has_pending(&self, sequence: u64) -> bool {
        sequence != 0 && self.is_open() && self.0.pending.load(Ordering::Acquire) == sequence
    }
    pub(crate) fn received(&self, sequence: u64) {
        self.0.pending.store(sequence, Ordering::Release);
    }
    pub(crate) fn replied(&self) {
        self.0.pending.store(0, Ordering::Release);
    }
    pub(crate) fn close(&self) {
        self.0.open.store(false, Ordering::Release);
        self.replied();
    }
}
impl PartialEq for ConnectionBinding {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for ConnectionBinding {}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn a_new_connection_cannot_inherit_an_old_pending_request_or_closed_owner() {
        let first = ConnectionBinding::new();
        let held = first.clone();
        let next = ConnectionBinding::new();
        first.received(1);
        next.received(1);
        assert!(first == held);
        assert!(first != next);
        assert!(held.has_pending(1));
        first.replied();
        assert!(!held.has_pending(1));
        assert!(held.is_open());
        first.received(2);
        assert!(!held.has_pending(1));
        assert!(held.has_pending(2));
        first.close();
        assert!(!held.is_open());
        assert!(!held.has_pending(2));
        assert!(next.has_pending(1));
    }
}
