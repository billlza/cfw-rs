fn main() {
    #[cfg(windows)]
    let result = run();
    #[cfg(not(windows))]
    let result: Result<(), String> = Err("Windows runtime requires Windows x64".into());
    if let Err(error) = result {
        eprintln!("{error}");
        std::process::exit(1);
    }
}
#[cfg(windows)]
fn run() -> Result<(), String> {
    use cfw_windows_engine::runtime_host::{self, InstalledRuntime};
    let args: Vec<_> = std::env::args_os().skip(1).collect();
    // SCM identity admission requires the exact quoted executable with no
    // arguments. Keep the service entrypoint aligned with that installation
    // contract; interactive Agent/check modes are separate invocations.
    if args.is_empty() {
        return runtime_host::run_service().map_err(|e| e.to_string());
    }
    if args == [std::ffi::OsStr::new("--inspect-update")] {
        let code = runtime_host::run_update_inspector().map_err(|e| e.to_string())?;
        if code != 0 {
            std::process::exit(code);
        }
        return Ok(());
    }
    let installation = InstalledRuntime::open().map_err(|e| e.to_string())?;
    installation
        .require_runtime_process()
        .map_err(|e| e.to_string())?;
    if args.len() == 2
        && matches!(
            args[0].to_str(),
            Some("--prepare-maintenance" | "--rollback-maintenance")
        )
    {
        let value = args[1]
            .to_str()
            .ok_or("maintenance transaction is not Unicode")?;
        let transaction =
            uuid::Uuid::parse_str(value).map_err(|_| "invalid maintenance transaction")?;
        if transaction.is_nil() || transaction.to_string() != value {
            return Err("maintenance transaction must be a canonical non-nil UUID".into());
        }
        let report = if args[0] == "--prepare-maintenance" {
            installation.prepare_service_maintenance(transaction)
        } else {
            installation.rollback_service_maintenance(transaction)
        }
        .map_err(|e| e.to_string())?;
        println!("{report}");
        return Ok(());
    }
    if (args.len() == 1 || args.len() == 2) && args[0] == "--check-installation" {
        if let Some(expected) = args.get(1) {
            installation
                .require_manifest_sha256(
                    expected
                        .to_str()
                        .ok_or("expected manifest digest is not Unicode")?,
                )
                .map_err(|e| e.to_string())?;
        }
        println!(
            "{}",
            serde_json::json!({
                "product": "CFW", "version": env!("CARGO_PKG_VERSION"),
                "architecture": "x86_64", "installation_verified": true,
                "release": installation.release(),
            })
        );
        return Ok(());
    }
    if args
        == [
            std::ffi::OsStr::new("--user-agent"),
            std::ffi::OsStr::new(runtime_host::SERVICE_NAME),
        ]
    {
        return runtime_host::run_agent(installation).map_err(|e| e.to_string());
    }
    Err(
        "expected SCM, --check-installation [manifest-sha256], --inspect-update, installed --user-agent or SYSTEM --prepare-maintenance/--rollback-maintenance with a transaction UUID"
            .into(),
    )
}
