use super::*;
use serde_json::json;

fn manifest(target: ReleaseTarget, version: &str) -> Value {
    let url = target.download_url(version, &target.archive_name(version));
    let platforms = target
        .platform_keys()
        .iter()
        .map(|key| {
            (
                (*key).to_owned(),
                json!({ "url": url, "signature": "signed-envelope" }),
            )
        })
        .collect::<serde_json::Map<_, _>>();
    json!({
        "version": version, "notes": "notes", "pub_date": "2026-10-20T00:00:00Z",
        "platforms": platforms,
    })
}

fn admit(target: ReleaseTarget, value: &Value) -> Result<UpdateAuthorization, UpdateContractError> {
    let entry = &value["platforms"][target.platform_key()];
    validate_update(
        target,
        value["version"].as_str().unwrap(),
        &Url::parse(entry["url"].as_str().unwrap()).unwrap(),
        entry["signature"].as_str().unwrap(),
        value,
    )
}

#[test]
fn platform_selection_never_falls_back_to_another_os_or_architecture() {
    assert_eq!(
        ReleaseTarget::for_platform("macos", "aarch64"),
        Ok(ReleaseTarget::MacArm64)
    );
    assert_eq!(
        ReleaseTarget::for_platform("windows", "x86_64"),
        Ok(ReleaseTarget::WindowsX64)
    );
    for (os, arch) in [
        ("windows", "aarch64"),
        ("windows", "x64"),
        ("macos", "x86_64"),
        ("linux", "x86_64"),
        ("", ""),
        ("macos", "arm64"),
    ] {
        assert_eq!(
            ReleaseTarget::for_platform(os, arch),
            Err(UpdateContractError::UnsupportedTarget)
        );
    }
}

#[test]
fn windows_metadata_names_one_msi_and_its_independent_versioned_release() {
    let value = manifest(ReleaseTarget::WindowsX64, "0.5.1");
    let update = admit(ReleaseTarget::WindowsX64, &value).unwrap();
    assert_eq!(update.archive_name, "Clash.for.Windows_0.5.1_x64.msi");
    assert_eq!(
        update.download_url,
        "https://github.com/billlza/cfw-rs/releases/download/cfw-v0.5.1/Clash.for.Windows_0.5.1_x64.msi"
    );
    assert_eq!(
        ReleaseTarget::WindowsX64.release_page_url("0.5.1").unwrap(),
        "https://github.com/billlza/cfw-rs/releases/tag/cfw-v0.5.1"
    );
    assert_eq!(
        ReleaseTarget::MacArm64.release_page_url("0.5.1").unwrap(),
        "https://github.com/billlza/cfw-rs/releases/tag/v0.5.1"
    );
    assert_ne!(
        ReleaseTarget::MacArm64.metadata_url(),
        ReleaseTarget::WindowsX64.metadata_url()
    );
}

#[test]
fn persisted_authorization_revalidates_the_release_family_and_exact_archive() {
    let original = admit(
        ReleaseTarget::WindowsX64,
        &manifest(ReleaseTarget::WindowsX64, "0.5.1"),
    )
    .unwrap();
    let decoded: UpdateAuthorization =
        serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
    decoded.validate_for(ReleaseTarget::WindowsX64).unwrap();
    assert!(decoded.validate_for(ReleaseTarget::MacArm64).is_err());
    for field in ["version", "download_url", "archive_name", "signature"] {
        let mut value = serde_json::to_value(&decoded).unwrap();
        value[field] = serde_json::json!("");
        let changed: UpdateAuthorization = serde_json::from_value(value).unwrap();
        assert!(
            changed.validate_for(ReleaseTarget::WindowsX64).is_err(),
            "{field}"
        );
    }
    let mut extra = serde_json::to_value(&decoded).unwrap();
    extra["trusted"] = serde_json::json!(true);
    assert!(serde_json::from_value::<UpdateAuthorization>(extra).is_err());
}

#[test]
fn release_families_cannot_accept_each_others_manifests_or_asset_names() {
    for (target, other) in [
        (ReleaseTarget::WindowsX64, ReleaseTarget::MacArm64),
        (ReleaseTarget::MacArm64, ReleaseTarget::WindowsX64),
    ] {
        let value = manifest(target, "0.5.1");
        let update = admit(target, &value).unwrap();
        assert_eq!(
            validate_update(
                target,
                &update.version,
                &Url::parse(&update.download_url).unwrap(),
                &update.signature,
                &manifest(other, "0.5.1")
            ),
            Err(UpdateContractError::UnexpectedPlatforms),
        );
        let other_url = other.download_url("0.5.1", &other.archive_name("0.5.1"));
        assert_eq!(
            validate_update(
                target,
                "0.5.1",
                &Url::parse(&other_url).unwrap(),
                &update.signature,
                &value
            ),
            Err(UpdateContractError::UnexpectedDownloadUrl),
        );
    }
}

#[test]
fn windows_rejects_alias_drift_extra_fields_and_alternate_download_forms() {
    let target = ReleaseTarget::WindowsX64;
    let valid = manifest(target, "0.5.1");
    let url = valid["platforms"][target.platform_key()]["url"]
        .as_str()
        .unwrap();
    for changed_url in [
        url.replace("cfw-v0.5.1", "v0.5.1"),
        url.replace("_x64.msi", "_arm64.msi"),
        url.replace("_x64.msi", "_x64.exe"),
        url.replace("Clash.for.Windows", "Clash%2Efor%2EWindows"),
        format!("{url}?download=1"),
        url.replace("github.com", "other.example"),
        url.replace("github.com", "user@github.com"),
    ] {
        let mut changed = valid.clone();
        changed["platforms"][target.platform_key()]["url"] = json!(changed_url);
        assert!(admit(target, &changed).is_err(), "{changed_url}");
    }
    let mut extra = valid.clone();
    extra["platforms"]["windows-x64"] = extra["platforms"][target.platform_key()].clone();
    assert_eq!(
        admit(target, &extra),
        Err(UpdateContractError::UnexpectedPlatforms)
    );
    let mut extra = valid.clone();
    extra["platforms"][target.platform_key()]["install_args"] = json!("/quiet");
    assert_eq!(
        admit(target, &extra),
        Err(UpdateContractError::UnexpectedManifestFields)
    );
    let mut drift = valid.clone();
    drift["platforms"][target.platform_key()]["signature"] = json!("different");
    assert_eq!(
        validate_update(
            target,
            "0.5.1",
            &Url::parse(url).unwrap(),
            "signed-envelope",
            &drift
        ),
        Err(UpdateContractError::ManifestSignatureMismatch)
    );
}

#[test]
fn windows_version_bounds_match_the_native_msi_identity_boundary() {
    let target = ReleaseTarget::WindowsX64;
    admit(target, &manifest(target, "255.255.65535")).unwrap();
    for version in ["256.0.0", "0.256.0", "0.0.65536"] {
        assert_eq!(
            admit(target, &manifest(target, version)),
            Err(UpdateContractError::InvalidMsiVersion)
        );
        assert_eq!(
            target.release_page_url(version),
            Err(UpdateContractError::InvalidMsiVersion)
        );
    }
    let long = format!("0.5.1+{}", "a".repeat(123));
    assert_eq!(
        admit(target, &manifest(target, &long)),
        Err(UpdateContractError::InvalidMsiVersion)
    );
    for version in ["01.5.1", "0.5", "0.5.1/other", "0.5.1?ignored"] {
        assert!(target.release_page_url(version).is_err(), "{version}");
    }
}

#[test]
fn metadata_redirects_cannot_cross_channels_or_extend_the_fixed_chain() {
    let mac = ReleaseTarget::MacArm64;
    let windows = ReleaseTarget::WindowsX64;
    let mac_initial = Url::parse(mac.metadata_url()).unwrap();
    let windows_initial = Url::parse(windows.metadata_url()).unwrap();
    let versioned =
        Url::parse("https://github.com/billlza/cfw-rs/releases/download/v0.5.1/latest.json")
            .unwrap();
    let asset = Url::parse("https://release-assets.githubusercontent.com/github-production-release-asset/12345/asset?sp=read").unwrap();
    mac.validate_metadata_redirect(std::slice::from_ref(&mac_initial), &versioned)
        .unwrap();
    mac.validate_metadata_redirect(&[mac_initial.clone(), versioned.clone()], &asset)
        .unwrap();
    windows
        .validate_metadata_redirect(std::slice::from_ref(&windows_initial), &asset)
        .unwrap();
    assert!(
        mac.validate_metadata_redirect(std::slice::from_ref(&windows_initial), &versioned)
            .is_err()
    );
    assert!(
        windows
            .validate_metadata_redirect(std::slice::from_ref(&mac_initial), &asset)
            .is_err()
    );
    assert!(
        windows
            .validate_metadata_redirect(std::slice::from_ref(&windows_initial), &versioned)
            .is_err()
    );
    assert!(
        mac.validate_metadata_redirect(std::slice::from_ref(&mac_initial), &asset)
            .is_err()
    );
    assert!(
        windows
            .validate_metadata_redirect(&[windows_initial.clone(), asset.clone()], &asset)
            .is_err()
    );
    assert!(
        mac.validate_metadata_redirect(&[mac_initial, versioned, asset.clone()], &asset)
            .is_err()
    );
    for value in [
        "https://evil.example/github-production-release-asset/12345/asset?sp=read",
        "https://release-assets.githubusercontent.com/github-production-release-asset/12345/asset",
        "https://release-assets.githubusercontent.com/github-production-release-asset/12345/asset/extra?sp=read",
        "https://release-assets.githubusercontent.com/github-production-release-asset/not-a-number/asset?sp=read",
        "https://user@release-assets.githubusercontent.com/github-production-release-asset/12345/asset?sp=read",
    ] {
        assert!(
            windows
                .validate_metadata_redirect(
                    std::slice::from_ref(&windows_initial),
                    &Url::parse(value).unwrap()
                )
                .is_err(),
            "{value}"
        );
    }
}

#[test]
fn packaged_windows_endpoint_matches_the_runtime_contract_without_replacing_mac_latest() {
    let windows: Value = serde_json::from_str(include_str!(
        "../../../../apps/cfw-tauri-shell/tauri.windows.conf.json"
    ))
    .unwrap();
    let mac: Value = serde_json::from_str(include_str!(
        "../../../../apps/cfw-tauri-shell/tauri.conf.json"
    ))
    .unwrap();
    assert_eq!(
        windows["plugins"]["updater"]["endpoints"],
        json!([ReleaseTarget::WindowsX64.metadata_url()])
    );
    assert_eq!(
        mac["plugins"]["updater"]["endpoints"],
        json!([ReleaseTarget::MacArm64.metadata_url()])
    );
}
