//! Bounded adapter status for diagnostics, independent of physical-policy
//! selection, route preference, Wi-Fi permissions and per-user proxy settings.
use anyhow::{Context, bail};
use serde::Serialize;
use windows_sys::Win32::NetworkManagement::IpHelper::{
    FreeMibTable, GetIfTable2, MIB_IF_ROW2, MIB_IF_TABLE2,
};

const MAX_ADAPTERS: usize = 128;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsAdapterObservation {
    pub index: u32,
    pub display_name: String,
    /// IANA interface type from Windows; this is not a route-priority rank.
    pub interface_type: u32,
    /// IF_OPER_STATUS value. Unknown values remain visible, never become Up.
    pub operational_status: i32,
}

pub fn observe_windows_adapters() -> anyhow::Result<Vec<WindowsAdapterObservation>> {
    let mut table = std::ptr::null_mut();
    // SAFETY: GetIfTable2 owns and initializes this output allocation.
    let status = unsafe { GetIfTable2(&mut table) };
    if status != 0 {
        return Err(std::io::Error::from_raw_os_error(status as i32))
            .context("read Windows interface status");
    }
    if table.is_null() {
        bail!("Windows interface table is missing");
    }
    struct Table(*mut MIB_IF_TABLE2);
    impl Drop for Table {
        fn drop(&mut self) {
            // SAFETY: this is the unique live allocation returned by GetIfTable2.
            unsafe { FreeMibTable(self.0.cast()) };
        }
    }
    let table = Table(table);
    // SAFETY: the successful API initializes the table header and NumEntries rows.
    let count = unsafe { (*table.0).NumEntries } as usize;
    if count > MAX_ADAPTERS {
        bail!("Windows interface table exceeds the observation bound");
    }
    let rows: &[MIB_IF_ROW2] =
        unsafe { std::slice::from_raw_parts(std::ptr::addr_of!((*table.0).Table).cast(), count) };
    let mut result = Vec::with_capacity(count);
    for row in rows {
        let end = row
            .Alias
            .iter()
            .position(|unit| *unit == 0)
            .filter(|length| *length > 0)
            .context("Windows interface alias is invalid")?;
        let display_name = String::from_utf16(&row.Alias[..end])
            .context("Windows interface alias is not UTF-16")?;
        if row.InterfaceIndex == 0
            || result
                .iter()
                .any(|item: &WindowsAdapterObservation| item.index == row.InterfaceIndex)
        {
            bail!("Windows interface indices are missing or duplicated");
        }
        result.push(WindowsAdapterObservation {
            index: row.InterfaceIndex,
            display_name,
            interface_type: row.Type,
            operational_status: row.OperStatus,
        });
    }
    result.sort_by_key(|row| row.index);
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn native_interface_table_has_bounded_distinct_indices_and_real_names() {
        let rows = observe_windows_adapters().expect("native interface table");
        assert!(
            !rows.is_empty(),
            "the CI host must have its loopback interface"
        );
        assert!(rows.len() <= MAX_ADAPTERS);
        assert!(rows.windows(2).all(|pair| pair[0].index < pair[1].index));
        assert!(
            rows.iter()
                .all(|row| row.index > 0 && !row.display_name.is_empty())
        );
        assert!(
            rows.iter().any(|row| row.interface_type == 24),
            "Windows software loopback"
        );
    }
}
