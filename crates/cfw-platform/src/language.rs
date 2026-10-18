/// Read the ordered macOS language preference list without changing system or
/// application preferences. Callers keep this OS-service read off AppKit.
#[cfg(target_os = "macos")]
pub fn preferred_languages() -> anyhow::Result<Vec<String>> {
    Ok(objc2::rc::autoreleasepool(|_| {
        objc2_foundation::NSLocale::preferredLanguages()
            .iter()
            .map(|language| language.to_string())
            .collect()
    }))
}

#[cfg(windows)]
pub fn preferred_languages() -> anyhow::Result<Vec<String>> {
    crate::windows::preferred_languages()
}

#[cfg(not(any(target_os = "macos", windows)))]
pub fn preferred_languages() -> anyhow::Result<Vec<String>> {
    anyhow::bail!("UI language observation is unsupported on this platform")
}
