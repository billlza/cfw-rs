//! Bounded fixture receipts retained before disposable directories are removed.
use std::path::Path;
type Result<T> = std::result::Result<T, String>;

/// SCM services have no captured terminal. A join failure must retain the
/// native assertion/error message in the existing failed-service receipt.
pub(super) fn worker_panic(worker: &str, payload: Box<dyn std::any::Any + Send>) -> String {
    let message = payload
        .downcast_ref::<String>()
        .map(String::as_str)
        .or_else(|| payload.downcast_ref::<&str>().copied());
    match message {
        Some(message) => format!("{worker} panicked: {message}"),
        None => format!("{worker} panicked with a non-string payload"),
    }
}

pub(super) fn collect_fixture_diagnostics(root: &Path, output: &Path) -> Result<()> {
    for entry in std::fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let Some(text) = name.to_str() else {
            return Err("non-Unicode fixture diagnostic filename".into());
        };
        if !text.ends_with(".failure.txt")
            && text != "installed-service-maintenance.json"
            && !text.ends_with("-client.json")
            && !text.ends_with("-client-output.txt")
            && !text.ends_with(".rejection.json")
            && !text.ends_with(".journal-validation.json")
            && !text.ends_with(".authority-validation.json")
            && !text.ends_with(".wire-validation.json")
            && !text.ends_with(".stress-validation.json")
            && !text.ends_with(".off-admission.json")
            && !(text.starts_with("service-request-timing-") && text.ends_with(".txt"))
            && !(text.starts_with("runtime-restart-") && text.ends_with(".json"))
            && !(text.starts_with("runtime-stop-") && text.ends_with(".json"))
        {
            continue;
        }
        if !entry.file_type().map_err(|e| e.to_string())?.is_file()
            || entry.metadata().map_err(|e| e.to_string())?.len() > 16384
        {
            return Err("invalid fixture diagnostic file".into());
        }
        let bytes = std::fs::read(entry.path()).map_err(|e| e.to_string())?;
        let destination = output.join(name);
        let mut target = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&destination)
            .map_err(|e| format!("create diagnostic {}: {e}", destination.display()))?;
        std::io::Write::write_all(&mut target, &bytes).map_err(|e| e.to_string())?;
        target.sync_all().map_err(|e| e.to_string())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn service_request_timing_survives_fixture_directory_cleanup() {
        let root = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        let mut trace = super::super::request_timing::Trace::new("a".repeat(40)).unwrap();
        let request = trace.begin("ready", "user-agent").unwrap();
        trace
            .mark(
                &request,
                super::super::request_timing::Phase::DispatchFailed,
            )
            .unwrap();
        let bytes = trace.encode(123).unwrap();
        let record: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        let name = format!(
            "service-request-timing-{}-123.txt",
            record["trace_id"].as_str().unwrap()
        );
        trace.persist(root.path(), 123).unwrap();
        std::fs::write(
            root.path().join("fixture-installation.json"),
            b"private descriptor",
        )
        .unwrap();
        collect_fixture_diagnostics(root.path(), output.path()).unwrap();
        root.close().unwrap();
        assert_eq!(std::fs::read(output.path().join(name)).unwrap(), bytes);
        assert!(!output.path().join("fixture-installation.json").exists());
    }

    #[test]
    fn reused_process_id_keeps_both_service_timing_receipts() {
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        for root in [first.path(), second.path()] {
            let trace = super::super::request_timing::Trace::new("a".repeat(40)).unwrap();
            trace.persist(root, 123).unwrap();
            assert!(trace.persist(root, 123).is_err());
            collect_fixture_diagnostics(root, output.path()).unwrap();
            let error = collect_fixture_diagnostics(root, output.path()).unwrap_err();
            assert!(error.contains("create diagnostic"));
            assert!(error.contains("service-request-timing-"));
        }
        first.close().unwrap();
        second.close().unwrap();
        let files: Vec<_> = std::fs::read_dir(output.path())
            .unwrap()
            .map(|entry| entry.unwrap().path())
            .collect();
        assert_eq!(files.len(), 2);
        let mut trace_ids = std::collections::HashSet::new();
        for file in files {
            let record: serde_json::Value =
                serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
            let trace_id = record["trace_id"].as_str().unwrap();
            assert!(!uuid::Uuid::parse_str(trace_id).unwrap().is_nil());
            assert!(trace_ids.insert(trace_id.to_owned()));
            assert_eq!(
                file.file_name().unwrap().to_str().unwrap(),
                format!("service-request-timing-{trace_id}-123.txt")
            );
            assert_eq!(record["document"], "cfw-native-authority-request-timing-v2");
            assert_eq!(record["process_id"], 123);
            assert_eq!(record["source"], "a".repeat(40));
        }
    }
}

pub(super) fn with_diagnostics(
    root: &Path,
    receipts: &Path,
    operation: impl FnOnce() -> Result<()>,
) -> Result<()> {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(operation));
    let diagnostics = collect_fixture_diagnostics(root, receipts);
    let result = match result {
        Ok(result) => result,
        Err(payload) => {
            if let Err(error) = diagnostics {
                eprintln!("runtime fixture diagnostic collection also failed: {error}");
            }
            std::panic::resume_unwind(payload)
        }
    };
    match (result, diagnostics) {
        (Ok(()), Ok(())) => Ok(()),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Err(error)) => Err(format!("fixture diagnostic collection: {error}")),
        (Err(test), Err(diagnostics)) => {
            Err(format!("{test}; diagnostic collection: {diagnostics}"))
        }
    }
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;
    #[test]
    fn worker_join_preserves_both_string_panic_payloads_and_unknown_type_failure() {
        for payload in [
            Box::new("native operation failed") as Box<dyn std::any::Any + Send>,
            Box::new(String::from("native operation failed")),
            Box::new(7u32),
        ] {
            let text = payload.is::<String>() || payload.is::<&str>();
            let failed = std::thread::spawn(move || std::panic::resume_unwind(payload));
            let result = failed
                .join()
                .map_err(|payload| worker_panic("connection", payload));
            assert_eq!(
                result.unwrap_err(),
                if text {
                    "connection panicked: native operation failed"
                } else {
                    "connection panicked with a non-string payload"
                }
            );
        }
    }

    #[test]
    fn cleanup_panic_still_exports_diagnostics_and_remains_a_panic() {
        let root = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("runtime-client-output.txt"),
            b"original runtime error",
        )
        .unwrap();
        let result = std::panic::catch_unwind(|| {
            with_diagnostics(root.path(), output.path(), || panic!("disposal fault"))
        });
        let payload = result.unwrap_err();
        assert_eq!(payload.downcast_ref::<&str>(), Some(&"disposal fault"));
        assert_eq!(
            std::fs::read(output.path().join("runtime-client-output.txt")).unwrap(),
            b"original runtime error"
        );
    }
    #[test]
    fn diagnostic_failure_preserves_the_original_operation_error() {
        let root = tempfile::tempdir().unwrap();
        let output = tempfile::tempdir().unwrap();
        std::fs::create_dir(root.path().join("invalid-client-output.txt")).unwrap();
        let error = with_diagnostics(root.path(), output.path(), || {
            Err("primary runtime error".into())
        })
        .unwrap_err();
        assert!(error.contains("primary runtime error"));
        assert!(error.contains("invalid fixture diagnostic file"));
    }
}
