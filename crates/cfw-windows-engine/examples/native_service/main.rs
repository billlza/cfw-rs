//! Disposable SCM integration fixture, never a product/service executable.
//! Native mutation is opt-in in the Windows CI VM only.
#[cfg(windows)]
mod fixture;

fn main() {
    #[cfg(windows)]
    if let Err(error) = fixture::main() {
        eprintln!("native service validation failed: {error}");
        std::process::exit(1);
    }
    #[cfg(not(windows))]
    {
        eprintln!("native service validation requires Windows");
        std::process::exit(1);
    }
}
