//! Counterexamples for the production native process owner. This executable
//! cannot inspect packages, start services or authorize an installation.
fn main() {
    #[cfg(windows)]
    let result = run();
    #[cfg(not(windows))]
    let result: Result<i32, Box<dyn std::error::Error>> =
        Err("native worker fixture requires Windows".into());
    match result {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("{error}");
            std::process::exit(1);
        }
    }
}

#[cfg(windows)]
fn run() -> Result<i32, Box<dyn std::error::Error>> {
    use std::{
        io::{Read, Write},
        process::{Command, Stdio},
        time::Duration,
    };
    if std::env::var("CFW_NATIVE_PACKAGE_TESTS").as_deref() != Ok("1") {
        return Err("native worker fixture requires disposable CI opt-in".into());
    }
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args == ["--fixture-descendant"] {
        record("descendant")?;
        std::thread::sleep(Duration::from_secs(60));
        return Err("descendant outlived the owning Job deadline".into());
    }
    if args != ["--inspect-update"] {
        return Err("unexpected native worker arguments".into());
    }
    let mut input = std::io::stdin().lock();
    let mut mode = [0; 4];
    input.read_exact(&mut mode)?;
    record("worker")?;
    if &mode == b"writ" {
        // Leave the large request unread to exercise a blocked parent write.
        std::thread::sleep(Duration::from_secs(60));
        return Err("unread request outlived the owning Job deadline".into());
    }
    let mut remainder = Vec::new();
    input.take(16 * 1024).read_to_end(&mut remainder)?;
    let mut output = std::io::stdout().lock();
    match &mode {
        b"okay" => output.write_all(b"verified")?,
        b"deny" => {
            output.write_all(b"rejected")?;
            output.flush()?;
            return Ok(2);
        }
        b"junk" => output.write_all(&[b'x'; 5000])?,
        b"empt" => {}
        b"exit" => {
            output.write_all(b"failure")?;
            output.flush()?;
            return Ok(7);
        }
        b"tree" => {
            // The descendant inherits the owned Job and pipe handles. No
            // breakaway flag or independently owned process is requested.
            let mut child = Command::new(std::env::current_exe()?)
                .arg("--fixture-descendant")
                .stdin(Stdio::inherit())
                .stdout(Stdio::inherit())
                .stderr(Stdio::inherit())
                .spawn()?;
            let status = child.wait()?;
            return Err(format!("descendant exited before Job cancellation: {status}").into());
        }
        b"read" => {
            std::thread::sleep(Duration::from_secs(60));
            return Err("unanswered request outlived the owning Job deadline".into());
        }
        _ => return Err("unknown worker counterexample".into()),
    }
    output.flush()?;
    Ok(0)
}

#[cfg(windows)]
fn record(name: &str) -> Result<(), Box<dyn std::error::Error>> {
    let process = cfw_windows_engine::NativePeerProcess::open(std::process::id())?;
    let bytes = serde_json::to_vec(&serde_json::json!({
        "pid": std::process::id(),
        "creation_filetime": process.identity().process_creation_time(),
    }))?;
    let pending = format!("{name}.pending");
    std::fs::write(&pending, bytes)?;
    std::fs::rename(pending, format!("{name}.json"))?;
    Ok(())
}
