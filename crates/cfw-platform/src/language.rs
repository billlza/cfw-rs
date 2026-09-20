/// Read the ordered macOS language preference list without changing system or
/// application preferences. Callers keep this OS-service read off AppKit.
#[cfg(target_os = "macos")]
pub fn preferred_languages() -> Vec<String> {
    objc2::rc::autoreleasepool(|_| {
        objc2_foundation::NSLocale::preferredLanguages()
            .iter()
            .map(|language| language.to_string())
            .collect()
    })
}

#[cfg(not(target_os = "macos"))]
pub fn preferred_languages() -> Vec<String> {
    Vec::new()
}
