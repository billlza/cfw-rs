//! One observation of the network settings at a time.
//!
//! A probe reads native interface and proxy APIs on a thread of its own, and
//! the request that started it is answered within a limit. A probe can run on
//! beyond that limit, and the next one must not run beside it: a request that
//! comes while a probe runs waits for it to end, for a limit of its own, and
//! then makes its own observation. Every answer so comes from a probe that
//! began after the request did, and no two probes run at once.

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Mutex;

/// How long a request waits for the probe under way to end.
pub(super) const PROBE_WAIT: Duration = Duration::from_secs(5);
/// How long a request waits for its own probe.
pub(super) const PROBE_LIMIT: Duration = Duration::from_secs(5);

/// The turn of the probe: held by a probe from its start to its end.
#[derive(Default)]
pub(crate) struct NetworkDiagnosticsGate {
    probe: Arc<Mutex<()>>,
}

impl NetworkDiagnosticsGate {
    /// Runs `probe` once no other probe runs, waiting `wait` at most for its
    /// turn, and answers with what it found within `limit`. A probe that runs
    /// out of time keeps its turn until it ends, so the next request waits for
    /// it.
    pub(super) async fn observe<T: Send + 'static>(
        &self,
        wait: Duration,
        limit: Duration,
        probe: impl FnOnce() -> Result<T, String> + Send + 'static,
    ) -> Result<T, String> {
        let turn = tokio::time::timeout(wait, Arc::clone(&self.probe).lock_owned())
            .await
            .map_err(|_| {
                format!(
                    "network diagnostics did not start: the probe before them still ran after {} seconds",
                    wait.as_secs()
                )
            })?;
        let task = tauri::async_runtime::spawn_blocking(move || {
            let _turn = turn;
            probe()
        });
        match tokio::time::timeout(limit, task).await {
            Ok(result) => {
                result.map_err(|error| format!("network diagnostics task failed: {error}"))?
            }
            Err(_) => Err(format!(
                "network diagnostics timed out after {} seconds; the isolated probe will not be duplicated while it is still running",
                limit.as_secs()
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::mpsc;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;

    use super::NetworkDiagnosticsGate;

    /// A wait or a limit that a test which passes runs out of.
    const BRIEF: Duration = Duration::from_millis(50);
    /// What a request that a test which passes answers well within, and
    /// what it is given where a wait or a limit must not run out.
    const DEADLINE: Duration = Duration::from_secs(10);
    const AMPLE: Duration = Duration::from_secs(60);

    /// A probe that ends once the test sends to `release`, and then says so in `log`.
    fn held(
        release: mpsc::Receiver<()>,
        log: &Arc<StdMutex<Vec<&'static str>>>,
        ended: &'static str,
    ) -> impl FnOnce() -> Result<&'static str, String> + Send + 'static {
        let log = Arc::clone(log);
        move || {
            release.recv().map_err(|error| error.to_string())?;
            log.lock().expect("log").push(ended);
            Ok(ended)
        }
    }

    /// A first request that runs out of time while its probe still runs.
    async fn ran_out_of_time(
        gate: &NetworkDiagnosticsGate,
        log: &Arc<StdMutex<Vec<&'static str>>>,
    ) -> mpsc::Sender<()> {
        let (release, waiting) = mpsc::channel();
        let answer = tokio::time::timeout(
            DEADLINE,
            gate.observe(AMPLE, BRIEF, held(waiting, log, "the first probe ended")),
        )
        .await
        .expect("the first request is answered within its limit");
        let error = answer.expect_err("the first probe ran out of time");
        assert!(
            error.starts_with("network diagnostics timed out"),
            "{error}"
        );
        release
    }

    #[tokio::test]
    async fn an_observation_answers_with_what_its_probe_found_and_frees_the_turn() {
        let gate = NetworkDiagnosticsGate::default();
        assert_eq!(gate.observe(AMPLE, AMPLE, || Ok(7)).await, Ok(7));
        assert_eq!(
            gate.observe(AMPLE, AMPLE, || Err::<(), _>("refused".to_owned()))
                .await,
            Err("refused".to_owned())
        );
        assert!(gate.probe.try_lock().is_ok(), "no probe runs");
    }

    #[tokio::test]
    async fn a_probe_keeps_its_turn_until_it_ends_also_once_its_request_ran_out_of_time() {
        let gate = NetworkDiagnosticsGate::default();
        let log = Arc::new(StdMutex::new(Vec::new()));
        let release = ran_out_of_time(&gate, &log).await;
        assert!(
            gate.probe.try_lock().is_err(),
            "the probe still has its turn"
        );
        release.send(()).expect("release the probe");
        drop(
            tokio::time::timeout(DEADLINE, gate.probe.lock())
                .await
                .expect("the turn is free once the probe has ended"),
        );
        assert_eq!(*log.lock().expect("log"), ["the first probe ended"]);
    }

    #[tokio::test]
    async fn a_request_waits_for_the_probe_under_way_and_then_makes_its_own() {
        let gate = Arc::new(NetworkDiagnosticsGate::default());
        let log = Arc::new(StdMutex::new(Vec::new()));
        let release = ran_out_of_time(&gate, &log).await;
        let second = tokio::spawn({
            let gate = Arc::clone(&gate);
            let log = Arc::clone(&log);
            async move {
                gate.observe(AMPLE, AMPLE, move || {
                    log.lock().expect("log").push("the second probe began");
                    Ok("the second probe")
                })
                .await
            }
        });
        // The second request is made while the first probe still runs: it
        // waits, and no probe has ended or begun since.
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            !second.is_finished(),
            "the second request waits for the probe under way"
        );
        assert!(log.lock().expect("log").is_empty());
        release.send(()).expect("release the first probe");
        let answer = tokio::time::timeout(DEADLINE, second)
            .await
            .expect("the second request is answered once the first probe has ended")
            .expect("the second request");
        assert_eq!(answer, Ok("the second probe"));
        assert_eq!(
            *log.lock().expect("log"),
            ["the first probe ended", "the second probe began"]
        );
    }

    #[tokio::test]
    async fn a_request_is_refused_when_the_probe_before_it_runs_on_beyond_its_wait() {
        let gate = NetworkDiagnosticsGate::default();
        let log = Arc::new(StdMutex::new(Vec::new()));
        let release = ran_out_of_time(&gate, &log).await;
        let probed = Arc::new(AtomicBool::new(false));
        let answer = tokio::time::timeout(
            DEADLINE,
            gate.observe(BRIEF, AMPLE, {
                let probed = Arc::clone(&probed);
                move || {
                    probed.store(true, Ordering::SeqCst);
                    Ok(())
                }
            }),
        )
        .await
        .expect("the second request is answered within its wait");
        let error = answer.expect_err("the probe before it still runs");
        assert!(
            error.starts_with("network diagnostics did not start"),
            "{error}"
        );
        release.send(()).expect("release the first probe");
        drop(
            tokio::time::timeout(DEADLINE, gate.probe.lock())
                .await
                .expect("the turn is free once the probe has ended"),
        );
        assert!(
            !probed.load(Ordering::SeqCst),
            "the refused request made no observation"
        );
    }
}
