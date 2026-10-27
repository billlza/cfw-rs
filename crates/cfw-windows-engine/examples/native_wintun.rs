//! Opted-in disposable Windows driver lifecycle probe, never a product entrypoint.
fn main() {
    #[cfg(windows)]
    if let Err(error) = cfw_windows_engine::native_wintun_validation::run(
        &std::env::args().skip(1).collect::<Vec<_>>(),
    ) {
        eprintln!("native Wintun validation failed: {error}");
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    {
        eprintln!("native Wintun validation requires Windows");
        std::process::exit(1);
    }
}
