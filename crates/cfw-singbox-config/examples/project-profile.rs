//! Project a secret-free profile for local protocol interoperability checks.
//! Reads bounded JSON from stdin and never starts an engine or changes networking.

use std::io::{self, Read};

use cfw_singbox_config::{
    EngineSettings, MAX_PROFILE_BYTES, ProjectionMode, RuntimePreferences, ValidatedSingBoxProfile,
};
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    profile: Value,
    profile_id: String,
    #[serde(default)]
    settings: EngineSettings,
    #[serde(default)]
    runtime_preferences: Option<RuntimePreferences>,
    #[serde(default)]
    tunnel: bool,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut input = String::new();
    io::stdin()
        .take((MAX_PROFILE_BYTES + 4097) as u64)
        .read_to_string(&mut input)?;
    if input.len() > MAX_PROFILE_BYTES + 4096 {
        return Err("projection input exceeds its bound".into());
    }
    let input: Input = serde_json::from_str(&input)?;
    let profile = ValidatedSingBoxProfile::parse(&input.profile.to_string())?;
    let settings = match input.runtime_preferences {
        Some(preferences) => preferences.apply_to(input.settings)?,
        None => input.settings,
    };
    let projected = profile.project(
        &input.profile_id,
        if input.tunnel {
            ProjectionMode::Tunnel
        } else {
            ProjectionMode::SystemProxy
        },
        &settings,
    )?;
    println!(
        "{}",
        json!({
            "configuration": serde_json::from_str::<Value>(projected.as_json())?,
            "credential_slots": projected.credential_slots(),
        })
    );
    Ok(())
}
