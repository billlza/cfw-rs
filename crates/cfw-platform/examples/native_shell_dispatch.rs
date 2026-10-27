//! Disposable CI file-association recipient, never a product executable.
fn main() {
    if let Err(error) = receive() {
        eprintln!("native shell recipient: {error:#}");
        std::process::exit(1);
    }
}

fn receive() -> anyhow::Result<()> {
    use anyhow::{Context, bail};
    use std::{io::Write, path::PathBuf};
    if !cfg!(windows)
        || std::env::var("GITHUB_ACTIONS").as_deref() != Ok("true")
        || std::env::var("CFW_NATIVE_SHELL_TESTS").as_deref() != Ok("1")
    {
        bail!("requires opted-in disposable Windows CI");
    }
    let arguments: Vec<_> = std::env::args_os().collect();
    if arguments.len() != 2 {
        bail!("shell changed the argument count");
    }
    let item = PathBuf::from(&arguments[1]);
    let parent = item.parent().context("missing fixture directory")?;
    let root = PathBuf::from(std::env::var_os("RUNNER_TEMP").context("missing CI temporary root")?);
    if !item.is_absolute()
        || !item.is_file()
        || !parent
            .file_name()
            .and_then(|n| n.to_str())
            .is_some_and(|n| n.starts_with("cfw-native-shell-"))
        || parent
            .parent()
            .context("missing parent root")?
            .canonicalize()?
            != root.canonicalize()?
    {
        bail!("recipient path is outside its disposable fixture");
    }
    let payload = serde_json::to_vec(&serde_json::json!({
        "path":item.to_str().context("fixture path is not Unicode")?,
        "arguments":1,"pid":std::process::id(),
        "source":std::env::var("CFW_NATIVE_SHELL_SOURCE").context("missing source identity")?,
    }))?;
    let temporary = parent.join("receipt.partial");
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&temporary)?;
    file.write_all(&payload)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(temporary, parent.join("receipt.json"))?;
    Ok(())
}
