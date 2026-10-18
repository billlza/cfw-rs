use super::*;

#[test]
fn real_adapter_observation_never_fabricates_an_active_interface() {
    // A hosted VM may have no OS-reported physical adapter. That documented
    // absence is valid; a native API error is not converted to this absence.
    if let Some(context) = current_network_context().unwrap() {
        assert!(!context.interface.is_empty());
        assert!(!context.addresses.is_empty());
        for address in context.addresses {
            let address: IpAddr = address.parse().unwrap();
            assert!(!address.is_loopback() && !address.is_unspecified());
        }
        if context.kind == NetworkKind::Wired {
            assert!(context.ssid.is_none());
        }
    }
}

#[test]
fn virtual_filtered_paused_and_disconnected_interfaces_are_not_triggers() {
    let mut row = MIB_IF_ROW2 {
        Type: IF_TYPE_ETHERNET_CSMACD,
        OperStatus: IfOperStatusUp,
        MediaConnectState: MediaConnectStateConnected,
        ..MIB_IF_ROW2::default()
    };
    row.InterfaceAndOperStatusFlags._bitfield = 1;
    assert_eq!(physical_kind(&row), Some(NetworkKind::Wired));
    row.Type = IF_TYPE_IEEE80211;
    assert_eq!(physical_kind(&row), Some(NetworkKind::Wifi));
    for flags in [0, 3, 9, 17, 33, 65, 129] {
        row.InterfaceAndOperStatusFlags._bitfield = flags;
        assert_eq!(physical_kind(&row), None, "flags={flags}");
    }
    row.InterfaceAndOperStatusFlags._bitfield = 1;
    for kind in [24, 131] {
        row.Type = kind;
        assert_eq!(physical_kind(&row), None);
    }
    row.Type = IF_TYPE_ETHERNET_CSMACD;
    row.OperStatus = 2;
    assert_eq!(physical_kind(&row), None);
    row.OperStatus = IfOperStatusUp;
    row.MediaConnectState = 0;
    assert_eq!(physical_kind(&row), None);
}

#[test]
fn native_address_bytes_are_decoded_with_bounds_and_network_byte_order() {
    let mut buffer = Buffer(vec![0; 8]);
    let pointer = buffer.0.as_mut_ptr().cast::<SOCKADDR_IN>();
    let mut value = SOCKADDR_IN {
        sin_family: AF_INET,
        ..SOCKADDR_IN::default()
    };
    value.sin_addr.S_un.S_addr = u32::from_ne_bytes([192, 0, 2, 17]);
    unsafe {
        pointer.write(value);
    }
    let mut socket = SOCKET_ADDRESS {
        lpSockaddr: pointer.cast(),
        iSockaddrLength: size_of::<SOCKADDR_IN>() as i32,
    };
    assert_eq!(
        buffer.address(&socket).unwrap(),
        "192.0.2.17".parse::<IpAddr>().unwrap()
    );
    socket.iSockaddrLength = 1;
    assert!(buffer.address(&socket).is_err());
    socket.iSockaddrLength = i32::MAX;
    assert!(buffer.address(&socket).is_err());
    assert!(buffer.read::<SOCKADDR_IN>(null()).is_err());
    assert!(
        buffer
            .read::<SOCKADDR_IN>((pointer as *const u8).wrapping_add(1).cast())
            .is_err()
    );
    assert!(
        buffer
            .read::<SOCKADDR_IN>((pointer as *const u8).wrapping_add(64).cast())
            .is_err()
    );

    let pointer = buffer.0.as_mut_ptr().cast::<SOCKADDR_IN6>();
    let mut value = SOCKADDR_IN6 {
        sin6_family: AF_INET6,
        ..SOCKADDR_IN6::default()
    };
    value.sin6_addr.u.Byte = "2001:db8::1".parse::<Ipv6Addr>().unwrap().octets();
    unsafe {
        pointer.write(value);
    }
    let socket = SOCKET_ADDRESS {
        lpSockaddr: pointer.cast(),
        iSockaddrLength: size_of::<SOCKADDR_IN6>() as i32,
    };
    assert_eq!(
        buffer.address(&socket).unwrap(),
        "2001:db8::1".parse::<IpAddr>().unwrap()
    );
}

#[test]
fn unicast_readiness_and_record_integrity_control_network_triggers() {
    let record_size = size_of::<IP_ADAPTER_UNICAST_ADDRESS_LH>();
    let mut buffer = Buffer(vec![
        0;
        (record_size + size_of::<SOCKADDR_IN>()).div_ceil(8)
    ]);
    let pointer = buffer
        .0
        .as_mut_ptr()
        .cast::<IP_ADAPTER_UNICAST_ADDRESS_LH>();
    let socket_pointer = buffer
        .0
        .as_mut_ptr()
        .cast::<u8>()
        .wrapping_add(record_size)
        .cast::<SOCKADDR_IN>();
    let mut socket = SOCKADDR_IN {
        sin_family: AF_INET,
        ..SOCKADDR_IN::default()
    };
    socket.sin_addr.S_un.S_addr = u32::from_ne_bytes([192, 0, 2, 17]);
    let mut record = IP_ADAPTER_UNICAST_ADDRESS_LH {
        Address: SOCKET_ADDRESS {
            lpSockaddr: socket_pointer.cast(),
            iSockaddrLength: size_of::<SOCKADDR_IN>() as i32,
        },
        ..IP_ADAPTER_UNICAST_ADDRESS_LH::default()
    };
    record.Anonymous.Anonymous.Length = record_size as u32;
    unsafe { socket_pointer.write(socket) };
    for state in [IP_DAD_STATE_PREFERRED, IP_DAD_STATE_DEPRECATED] {
        record.DadState = state;
        unsafe { pointer.write(record) };
        assert_eq!(
            buffer.unicast_addresses(pointer).unwrap(),
            ["192.0.2.17".parse::<IpAddr>().unwrap()]
        );
    }
    for state in [
        IP_DAD_STATE_INVALID,
        IP_DAD_STATE_TENTATIVE,
        IP_DAD_STATE_DUPLICATE,
    ] {
        record.DadState = state;
        unsafe { pointer.write(record) };
        assert!(buffer.unicast_addresses(pointer).unwrap().is_empty());
    }
    record.DadState = 99;
    unsafe { pointer.write(record) };
    assert!(buffer.unicast_addresses(pointer).is_err());
    record.DadState = IP_DAD_STATE_PREFERRED;
    record.Next = pointer;
    unsafe { pointer.write(record) };
    assert!(buffer.unicast_addresses(pointer).is_err());
    record.Next = null_mut();
    record.Anonymous.Anonymous.Length = 8;
    unsafe { pointer.write(record) };
    assert!(buffer.unicast_addresses(pointer).is_err());
}

#[test]
fn gateway_ranking_requires_a_real_address_and_a_complete_valid_list() {
    let record_size = size_of::<IP_ADAPTER_GATEWAY_ADDRESS_LH>();
    let mut buffer = Buffer(vec![
        0;
        (record_size * 2 + size_of::<SOCKADDR_IN>()).div_ceil(8)
    ]);
    let first = buffer
        .0
        .as_mut_ptr()
        .cast::<IP_ADAPTER_GATEWAY_ADDRESS_LH>();
    let second = first.wrapping_add(1);
    let socket_pointer = second.wrapping_add(1).cast::<SOCKADDR_IN>();
    let mut socket = SOCKADDR_IN {
        sin_family: AF_INET,
        ..SOCKADDR_IN::default()
    };
    let mut record = IP_ADAPTER_GATEWAY_ADDRESS_LH {
        Address: SOCKET_ADDRESS {
            lpSockaddr: socket_pointer.cast(),
            iSockaddrLength: size_of::<SOCKADDR_IN>() as i32,
        },
        ..IP_ADAPTER_GATEWAY_ADDRESS_LH::default()
    };
    record.Anonymous.Anonymous.Length = record_size as u32;
    unsafe { first.write(record) };
    assert!(!buffer.has_gateway(null()).unwrap());
    for bytes in [[0, 0, 0, 0], [127, 0, 0, 1], [224, 0, 0, 1], [255; 4]] {
        socket.sin_addr.S_un.S_addr = u32::from_ne_bytes(bytes);
        unsafe { socket_pointer.write(socket) };
        assert!(!buffer.has_gateway(first).unwrap());
    }
    socket.sin_addr.S_un.S_addr = u32::from_ne_bytes([192, 0, 2, 1]);
    unsafe { socket_pointer.write(socket) };
    assert!(buffer.has_gateway(first).unwrap());
    record.Next = second;
    unsafe {
        first.write(record);
        second.write(record);
    }
    // A valid first gateway must not hide a malformed later node.
    assert!(buffer.has_gateway(first).is_err());
    record.Next = null_mut();
    record.Anonymous.Anonymous.Length = 8;
    unsafe { second.write(record) };
    assert!(buffer.has_gateway(first).is_err());
}

#[test]
fn wifi_names_preserve_unicode_without_lossy_or_empty_defaults() {
    assert_eq!(
        decode_wifi_name(&"café".encode_utf16().collect::<Vec<_>>()).unwrap(),
        "café"
    );
    for units in [
        vec![],
        vec![0xd800],
        vec![0],
        vec![b'\n' as u16],
        vec![b'a' as u16; 33],
        vec![0x4e2d; 11],
    ] {
        assert!(decode_wifi_name(&units).is_err());
    }
}

#[test]
fn native_connection_profile_metadata_is_available_without_wifi_scans() {
    let count = with_connection_profiles(|profiles| Ok(profiles.len())).unwrap();
    assert!(count <= MAX_ADAPTERS);
}
