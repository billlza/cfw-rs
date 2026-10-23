use std::{
    collections::BTreeSet,
    mem::{offset_of, size_of},
    net::{Ipv4Addr, Ipv6Addr, SocketAddr},
    ptr::null_mut,
};

use windows_sys::Win32::{
    Foundation::{ERROR_INSUFFICIENT_BUFFER, NO_ERROR},
    NetworkManagement::IpHelper::{
        GetExtendedTcpTable, MIB_TCP6ROW_OWNER_PID, MIB_TCP6TABLE_OWNER_PID, MIB_TCPROW_OWNER_PID,
        MIB_TCPTABLE_OWNER_PID, TCP_TABLE_OWNER_PID_LISTENER,
    },
    Networking::WinSock::{AF_INET, AF_INET6},
};

use crate::Error;

pub(crate) fn owned(pid: u32) -> Result<BTreeSet<SocketAddr>, Error> {
    let mut result = BTreeSet::new();
    for_each(|owner, address| {
        if owner == pid {
            result.insert(address);
        }
    })?;
    Ok(result)
}

/// A read-only, port-scoped native observation for disposable-host validation.
/// It is not an ownership proof and never admits or retires a product runtime.
#[cfg(feature = "native-service-validation")]
pub fn observe_tcp_listeners_at_port(port: u16) -> Result<BTreeSet<(u32, SocketAddr)>, Error> {
    if port == 0 {
        return Err(Error::Protocol(
            "listener observation requires a nonzero port",
        ));
    }
    let mut result = BTreeSet::new();
    for_each(|owner, address| {
        if address.port() == port {
            result.insert((owner, address));
        }
    })?;
    Ok(result)
}

fn for_each(mut observe: impl FnMut(u32, SocketAddr)) -> Result<(), Error> {
    for family in [AF_INET, AF_INET6] {
        let mut size = 0u32;
        let status = unsafe {
            GetExtendedTcpTable(
                null_mut(),
                &mut size,
                0,
                u32::from(family),
                TCP_TABLE_OWNER_PID_LISTENER,
                0,
            )
        };
        if status != ERROR_INSUFFICIENT_BUFFER {
            return Err(Error::Protocol("TCP listener table size query"));
        }
        let mut complete = false;
        for _ in 0..3 {
            if !(4..=16 * 1024 * 1024).contains(&size) {
                return Err(Error::Protocol("TCP listener table capacity"));
            }
            let mut words = vec![0u64; (size as usize).div_ceil(size_of::<u64>())];
            let status = unsafe {
                GetExtendedTcpTable(
                    words.as_mut_ptr().cast(),
                    &mut size,
                    0,
                    u32::from(family),
                    TCP_TABLE_OWNER_PID_LISTENER,
                    0,
                )
            };
            if status == ERROR_INSUFFICIENT_BUFFER {
                continue;
            }
            if status != NO_ERROR {
                return Err(std::io::Error::from_raw_os_error(status as i32).into());
            }
            let available = words.len() * size_of::<u64>();
            let pointer = words.as_ptr().cast::<u8>();
            // The API returned success into this aligned, owned allocation.
            // Check both reported count and row bounds before reading rows.
            let count = unsafe { pointer.cast::<u32>().read_unaligned() } as usize;
            let (offset, row_size) = if family == AF_INET {
                (
                    offset_of!(MIB_TCPTABLE_OWNER_PID, table),
                    size_of::<MIB_TCPROW_OWNER_PID>(),
                )
            } else {
                (
                    offset_of!(MIB_TCP6TABLE_OWNER_PID, table),
                    size_of::<MIB_TCP6ROW_OWNER_PID>(),
                )
            };
            if count > available.saturating_sub(offset) / row_size || offset > available {
                return Err(Error::Protocol("truncated TCP listener table"));
            }
            for index in 0..count {
                let row = unsafe { pointer.add(offset + index * row_size) };
                let (owner, state, address) = if family == AF_INET {
                    let row = unsafe { row.cast::<MIB_TCPROW_OWNER_PID>().read_unaligned() };
                    (
                        row.dwOwningPid,
                        row.dwState,
                        SocketAddr::new(
                            Ipv4Addr::from(row.dwLocalAddr.to_ne_bytes()).into(),
                            u16::from_be(row.dwLocalPort as u16),
                        ),
                    )
                } else {
                    let row = unsafe { row.cast::<MIB_TCP6ROW_OWNER_PID>().read_unaligned() };
                    (
                        row.dwOwningPid,
                        row.dwState,
                        SocketAddr::V6(std::net::SocketAddrV6::new(
                            Ipv6Addr::from(row.ucLocalAddr),
                            u16::from_be(row.dwLocalPort as u16),
                            0,
                            row.dwLocalScopeId,
                        )),
                    )
                };
                if state != 2 {
                    return Err(Error::Protocol("TCP table returned a non-listener"));
                }
                observe(owner, address);
            }
            complete = true;
            break;
        }
        if !complete {
            return Err(Error::Protocol(
                "TCP listener table changed during three bounded reads",
            ));
        }
    }
    Ok(())
}
