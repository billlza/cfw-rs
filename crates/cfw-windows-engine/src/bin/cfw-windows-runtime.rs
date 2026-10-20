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
    let installation = InstalledRuntime::open().map_err(|e| e.to_string())?;
    installation
        .require_runtime_process()
        .map_err(|e| e.to_string())?;
    if args == [std::ffi::OsStr::new("--check-installation")] {
        println!(
            "{{\"product\":\"CFW\",\"version\":\"0.5.0\",\"architecture\":\"x86_64\",\"installation_verified\":true}}"
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
        "expected no arguments for SCM, --check-installation or installed --user-agent invocation"
            .into(),
    )
}
