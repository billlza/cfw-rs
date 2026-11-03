//! Frames on the control channel: async reads that yield to an outer deadline
//! or end at a truncated body; non-canonical, unknown or oversized frames and
//! frames that carry descriptors; and the Host's canonical frames, which carry
//! no error text.

use super::*;

#[tokio::test]
async fn async_readiness_wait_yields_to_the_outer_deadline() {
    let (mut app, _collector, _peer) = async_pair();
    let result =
        tokio::time::timeout(Duration::from_millis(25), app.receive::<CollectorRequest>()).await;
    assert!(result.is_err(), "idle read must yield to Tokio's timer");
}

#[tokio::test]
async fn async_truncated_body_reaches_eof_without_blocking() {
    let (app, mut collector) = UnixStream::pair().expect("pair");
    app.set_nonblocking(true).expect("app nonblocking");
    collector
        .write_all(&10_u32.to_be_bytes())
        .expect("declared length");
    collector.write_all(b"{}").expect("partial body");
    collector
        .shutdown(std::net::Shutdown::Write)
        .expect("collector shutdown");
    let mut app =
        AsyncPacketEvidenceChannel::new(tokio::net::UnixStream::from_std(app).expect("async app"));
    let result = tokio::time::timeout(Duration::from_secs(1), app.receive::<CollectorRequest>())
        .await
        .expect("EOF timeout");
    assert!(matches!(
        result,
        Err(PacketEvidenceTransportError::TruncatedFrame)
    ));
}

/// The proxy reports an early end as a control failure, not as invalid input.
#[test]
fn truncated_body_is_a_truncated_frame_not_an_invalid_one() {
    let (host, mut collector) = UnixStream::pair().expect("pair");
    collector
        .write_all(&10_u32.to_be_bytes())
        .expect("declared length");
    collector.write_all(b"{}").expect("partial body");
    collector
        .shutdown(std::net::Shutdown::Write)
        .expect("collector shutdown");
    let mut channel = PacketEvidenceChannel::from_fd(host.into_raw_fd()).expect("channel");
    let result: Result<CollectorRequest, _> = channel.receive();
    assert!(matches!(
        result,
        Err(PacketEvidenceTransportError::TruncatedFrame)
    ));
}

#[test]
fn noncanonical_unknown_and_oversized_frames_fail_closed() {
    for (body, expected) in [
            (
                br#"{ "case_id":"dns-a-primary","document":"cfw-packet-collector-request-v5","schema_version":5,"sequence":1,"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.as_slice(),
                "invalid",
            ),
            (
                br#"{"case_id":"dns-a-primary","document":"cfw-packet-collector-request-v5","extra":true,"schema_version":5,"sequence":1,"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#.as_slice(),
                "invalid",
            ),
        ] {
            let (host, mut collector) = UnixStream::pair().expect("pair");
            collector
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("collector timeout");
            write_body(&mut collector, body);
            let mut channel =
                PacketEvidenceChannel::from_fd(host.into_raw_fd()).expect("channel");
            let result: Result<CollectorRequest, _> = channel.receive();
            assert!(matches!(
                result,
                Err(PacketEvidenceTransportError::InvalidFrame)
            ));
            assert_eq!(expected, "invalid");
        }

    let (host, mut collector) = UnixStream::pair().expect("pair");
    collector
        .write_all(&((MAX_FRAME_BYTES as u32) + 1).to_be_bytes())
        .expect("oversized length");
    let mut channel = PacketEvidenceChannel::from_fd(host.into_raw_fd()).expect("channel");
    let result: Result<CollectorRequest, _> = channel.receive();
    assert!(matches!(
        result,
        Err(PacketEvidenceTransportError::FrameBound)
    ));
}

/// Sends the frame `{}` in one message that also carries one end of a fresh
/// socket pair, then closes the sender's copy of that end. The returned end
/// reads EOF once the receiver closes its copy too.
fn send_frame_with_attached_socket(collector: &UnixStream) -> UnixStream {
    let (witness, attached) = UnixStream::pair().expect("witness pair");
    let mut message = libc::msghdr {
        msg_name: std::ptr::null_mut(),
        msg_namelen: 0,
        msg_iov: std::ptr::null_mut(),
        msg_iovlen: 0,
        msg_control: std::ptr::null_mut(),
        msg_controllen: 0,
        msg_flags: 0,
    };
    let bytes = b"\0\0\0\x02{}";
    let mut iovec = libc::iovec {
        iov_base: bytes.as_ptr().cast_mut().cast(),
        iov_len: bytes.len(),
    };
    let mut control = [0_usize; 8];
    message.msg_iov = &mut iovec;
    message.msg_iovlen = 1;
    message.msg_control = control.as_mut_ptr().cast();
    message.msg_controllen = unsafe { libc::CMSG_SPACE(size_of::<RawFd>() as _) } as _;
    unsafe {
        let header = libc::CMSG_FIRSTHDR(&message);
        (*header).cmsg_level = libc::SOL_SOCKET;
        (*header).cmsg_type = libc::SCM_RIGHTS;
        (*header).cmsg_len = libc::CMSG_LEN(size_of::<RawFd>() as _) as _;
        *libc::CMSG_DATA(header).cast::<RawFd>() = attached.as_raw_fd();
        assert_eq!(
            libc::sendmsg(collector.as_raw_fd(), &message, 0),
            bytes.len() as isize
        );
    }
    drop(attached);
    witness.set_nonblocking(true).expect("nonblocking witness");
    witness
}

/// A copy the receiver kept open would leave the witness waiting for data.
fn assert_attached_socket_closed(mut witness: UnixStream) {
    let read = witness.read(&mut [0_u8; 1]);
    assert!(
        matches!(read, Ok(0)),
        "every copy of the attached socket must be closed: {read:?}"
    );
}

#[test]
fn ancillary_descriptors_are_closed_and_rejected() {
    let (host, collector) = UnixStream::pair().expect("pair");
    let mut channel = PacketEvidenceChannel::from_fd(host.into_raw_fd()).expect("channel");
    let witness = send_frame_with_attached_socket(&collector);
    let result: Result<CollectorRequest, _> = channel.receive();
    assert!(matches!(
        result,
        Err(PacketEvidenceTransportError::AncillaryData)
    ));
    assert_attached_socket_closed(witness);
}

#[tokio::test]
async fn async_ancillary_descriptors_are_closed_and_rejected() {
    let (app, collector) = UnixStream::pair().expect("pair");
    app.set_nonblocking(true).expect("app nonblocking");
    let mut app =
        AsyncPacketEvidenceChannel::new(tokio::net::UnixStream::from_std(app).expect("async app"));
    let witness = send_frame_with_attached_socket(&collector);
    let result = tokio::time::timeout(Duration::from_secs(1), app.receive::<CollectorRequest>())
        .await
        .expect("bounded receive");
    assert!(matches!(
        result,
        Err(PacketEvidenceTransportError::AncillaryData)
    ));
    assert_attached_socket_closed(witness);
}

#[test]
fn host_frames_are_canonical_and_do_not_expose_error_text() {
    let (host, mut collector) = UnixStream::pair().expect("pair");
    let mut channel = PacketEvidenceChannel::from_fd(host.into_raw_fd()).expect("channel");
    channel
        .send(&host_failed(
            &"a".repeat(64),
            "dns-a-primary",
            "baseline_mismatch",
        ))
        .expect("failure");
    let body = read_frame(&mut collector);
    assert_eq!(
            body,
            br#"{"case_id":"dns-a-primary","code":"baseline_mismatch","document":"cfw-packet-host-failed-v5","schema_version":5,"sequence":8,"session_id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}"#
        );
}
