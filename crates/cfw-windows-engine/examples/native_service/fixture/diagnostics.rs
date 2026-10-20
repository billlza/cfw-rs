//! Bounded fixture receipts retained before disposable directories are removed.
use std::path::Path;
type Result<T> = std::result::Result<T, String>;

pub(super) fn collect_fixture_diagnostics(root: &Path, output: &Path) -> Result<()> {
    for entry in std::fs::read_dir(root).map_err(|e| e.to_string())? {
        let entry = entry.map_err(|e| e.to_string())?;
        let name = entry.file_name();
        let Some(text) = name.to_str() else {
            return Err("non-Unicode fixture diagnostic filename".into());
        };
        if !text.ends_with(".failure.txt")
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
        let mut target = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(output.join(name))
            .map_err(|e| e.to_string())?;
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
        let name = "service-request-timing-123.txt";
        std::fs::write(root.path().join(name), &bytes).unwrap();
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
}
