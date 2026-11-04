//! Typed values read out of SystemConfiguration dictionaries.

use anyhow::{Result, bail};
use objc2_core_foundation::{CFDictionary, CFNumber, CFString, CFType};

use crate::sysproxy_sc::ConfigDict;

pub(crate) fn as_config_dict(dict: &CFDictionary) -> &ConfigDict {
    // SAFETY: SystemConfiguration proxy dictionaries use CFString keys and
    // CoreFoundation values.
    unsafe { dict.cast_unchecked::<CFString, CFType>() }
}

pub(crate) fn enabled_flag(dict: &ConfigDict, key: &CFString, label: &str) -> Result<bool> {
    let Some(value) = dict.get(key) else {
        return Ok(false);
    };
    let number = value.downcast::<CFNumber>().map_err(|_| {
        anyhow::anyhow!("{label} enable flag has an unexpected CoreFoundation type")
    })?;
    let value = number
        .as_i32()
        .ok_or_else(|| anyhow::anyhow!("{label} enable flag is not an integer"))?;
    validate_enabled_flag_value(label, value)
}

pub(crate) fn number_value(dict: &ConfigDict, key: &CFString, label: &str) -> Result<Option<i32>> {
    let Some(value) = dict.get(key) else {
        return Ok(None);
    };
    value
        .downcast::<CFNumber>()
        .map_err(|_| anyhow::anyhow!("{label} has an unexpected CoreFoundation type"))?
        .as_i32()
        .ok_or_else(|| anyhow::anyhow!("{label} is not an integer"))
        .map(Some)
}

pub(crate) fn string_value(
    dict: &ConfigDict,
    key: &CFString,
    label: &str,
) -> Result<Option<String>> {
    let Some(value) = dict.get(key) else {
        return Ok(None);
    };
    value
        .downcast::<CFString>()
        .map_err(|_| anyhow::anyhow!("{label} has an unexpected CoreFoundation type"))
        .map(|value| Some(value.to_string()))
}

fn validate_enabled_flag_value(label: &str, value: i32) -> Result<bool> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => bail!("{label} enable flag has invalid value {value}; expected 0 or 1"),
    }
}

#[cfg(test)]
mod tests;
