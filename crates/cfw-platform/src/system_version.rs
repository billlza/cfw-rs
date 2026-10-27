//! Observe the running OS. This does not infer optional-feature availability.

#[cfg(target_os = "macos")]
pub fn operating_system_version() -> anyhow::Result<String> {
    use anyhow::Context;
    const NAME: &std::ffi::CStr = c"kern.osproductversion";
    let mut buffer = [0_u8; 64];
    let mut length = buffer.len();
    // SAFETY: bounded output, terminated constant key, and no new value.
    if unsafe {
        libc::sysctlbyname(
            NAME.as_ptr(),
            buffer.as_mut_ptr().cast(),
            &mut length,
            std::ptr::null_mut(),
            0,
        )
    } != 0
    {
        return Err(std::io::Error::last_os_error()).context("read macOS product version");
    }
    let value = buffer
        .get(..length)
        .and_then(|bytes| bytes.strip_suffix(&[0]))
        .and_then(|bytes| std::str::from_utf8(bytes).ok())
        .filter(|value| !value.is_empty())
        .context("the reported macOS version is not text")?;
    Ok(value.to_owned())
}

#[cfg(windows)]
pub fn operating_system_version() -> anyhow::Result<String> {
    crate::windows::operating_system_version()
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn operating_system_version() -> anyhow::Result<String> {
    anyhow::bail!("system version observation is unsupported on this platform")
}
