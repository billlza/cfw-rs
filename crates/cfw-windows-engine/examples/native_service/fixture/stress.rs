//! Stage timing for the unchanged post-stop admission stress contract.
//! Evidence records success and failure without retrying or extending its budget.
use super::*;
use std::io::Write;
use std::sync::Arc;

#[derive(Default)]
struct Timings {
    completed: usize,
    image_verifications: usize,
    stopped_observations: usize,
    pacing: Duration,
    connect: Duration,
    image: Duration,
    stopped: Duration,
    exchange: Duration,
    maximum_exchange: Duration,
}
pub(super) fn run(stopped: &str, running: &str, image: &Path, expected: [u8; 32]) -> Result<()> {
    let mut timing = Timings::default();
    let image_bytes = std::fs::metadata(image).map_err(|e| e.to_string())?.len();
    let runner = runtime()?;
    let started = Instant::now();
    let deadline = started + Duration::from_secs(45);
    let outcome = runner.block_on(async {
        let began = Instant::now();
        timing.image_verifications += 1;
        let pinned = verified(image, expected);
        timing.image += began.elapsed();
        let pinned = Arc::new(pinned?);
        for iteration in 0..POST_STOP_EXCHANGES {
            if Instant::now() >= deadline {
                return Err(format!(
                    "post-stop stress deadline after {iteration} exchanges"
                ));
            }
            let began = Instant::now();
            tokio::time::sleep(Duration::from_millis(if iteration % 32 == 0 {
                100
            } else {
                (iteration % 7) as u64
            }))
            .await;
            timing.pacing += began.elapsed();
            let exchange = async {
                let began = Instant::now();
                let pipe = connect(running).await;
                timing.connect += began.elapsed();
                let mut pipe = pipe?;
                let began = Instant::now();
                timing.stopped_observations += 1;
                let observed =
                    WindowsServicePeer::from_pipe_server(stopped, Arc::clone(&pinned), &pipe);
                timing.stopped += began.elapsed();
                match observed {
                    Err(ServicePeerError::NotRunning {
                        state: SERVICE_STOPPED,
                        ..
                    }) => {}
                    Err(error) => {
                        return Err(format!(
                            "stopped service returned a different rejection: {error}"
                        ));
                    }
                    Ok(_) => return Err("stopped service was admitted as authority".into()),
                }
                let began = Instant::now();
                let completed = ping(&mut pipe).and_then(|()| finish(&mut pipe));
                let elapsed = began.elapsed();
                timing.exchange += elapsed;
                timing.maximum_exchange = timing.maximum_exchange.max(elapsed);
                completed
            }
            .await;
            exchange.map_err(|error| format!("post-stop exchange {iteration}: {error}"))?;
            timing.completed += 1;
        }
        Ok::<_, String>(())
    });
    let report = serde_json::json!({"success":outcome.is_ok(),"source":std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e|e.to_string())?,"requested_exchanges":POST_STOP_EXCHANGES,"completed_exchanges":timing.completed,"total_limit_ms":45000,"elapsed_us":started.elapsed().as_micros(),"pacing_us":timing.pacing.as_micros(),"connect_us":timing.connect.as_micros(),"image_verification_us":timing.image.as_micros(),"stopped_observation_us":timing.stopped.as_micros(),"exchange_us":timing.exchange.as_micros(),"maximum_exchange_us":timing.maximum_exchange.as_micros(),"image_verifications":timing.image_verifications,"stopped_service_observations":timing.stopped_observations,"image_pin_scope":"whole_batch","image_bytes":image_bytes,"error":outcome.as_ref().err()});
    let written = (|| -> Result<()> {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(
                image
                    .parent()
                    .ok_or("missing stress fixture parent")?
                    .join("post-stop.stress-validation.json"),
            )
            .map_err(|e| e.to_string())?;
        let bytes = serde_json::to_vec(&report).map_err(|e| e.to_string())?;
        file.write_all(&bytes).map_err(|e| e.to_string())?;
        file.sync_all().map_err(|e| e.to_string())?;
        println!(
            "post-stop stage timings: {}",
            serde_json::to_string(&report).map_err(|e| e.to_string())?
        );
        Ok(())
    })();
    match (outcome, written) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) | (Ok(()), Err(error)) => Err(error),
        (Err(error), Err(record)) => Err(format!("{error}; stress timing evidence: {record}")),
    }
}
