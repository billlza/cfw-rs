use super::*;
use crate::user_agent::tests::launch;
use cfw_singbox_config::ProjectionMode;

fn executable() -> Arc<VerifiedExecutable> {
    let path = std::env::current_exe().unwrap();
    let digest = Sha256::digest(std::fs::read(&path).unwrap()).into();
    Arc::new(VerifiedExecutable::open(&path, digest, "0.5.0").unwrap())
}

#[test]
fn inherited_launch_channel_preserves_one_frame_and_correlates_its_acknowledgement() {
    let launch = launch(ProjectionMode::LocalProxy);
    let expected = launch.encode().unwrap();
    let message = launch.encode().unwrap();
    let (sender, input) = LaunchSender::create().unwrap();
    let receiver = LaunchReceiver::from_inherited(input, executable()).unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let worker =
        std::thread::spawn(move || sender.send(message, deadline, &AtomicBool::new(false)));
    let received = receiver.receive(deadline, &AtomicBool::new(false)).unwrap();
    worker.join().unwrap().unwrap();
    assert!(received.encode().unwrap().as_bytes() == expected.as_bytes());
}

#[test]
fn inherited_launch_send_timeout_does_not_claim_delivery_without_acknowledgement() {
    let message = launch(ProjectionMode::LocalProxy).encode().unwrap();
    let (sender, _held_unread_receiver) = LaunchSender::create().unwrap();
    assert!(matches!(
        sender.send(
            message,
            Instant::now() + Duration::from_millis(50),
            &AtomicBool::new(false)
        ),
        Err(LaunchChannelError::Transport(
            ServiceTransportError::Deadline
        ))
    ));
}

#[test]
fn inherited_launch_requires_the_exact_installed_parent_image() {
    let path = std::env::current_exe().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let copy = directory.path().join("other-desktop.exe");
    std::fs::copy(&path, &copy).unwrap();
    let digest = Sha256::digest(std::fs::read(&copy).unwrap()).into();
    let expected = Arc::new(VerifiedExecutable::open(&copy, digest, "0.5.0").unwrap());
    let (_sender, input) = LaunchSender::create().unwrap();
    assert!(matches!(
        LaunchReceiver::from_inherited(input, expected),
        Err(LaunchChannelError::Peer(PeerIdentityError::Executable(
            crate::Error::ExecutableIdentity
        )))
    ));
}

#[test]
fn inherited_launch_rejects_an_uncorrelated_acknowledgement() {
    let message = launch(ProjectionMode::LocalProxy).encode().unwrap();
    let (sender, input) = LaunchSender::create().unwrap();
    let deadline = Instant::now() + Duration::from_secs(5);
    let worker =
        std::thread::spawn(move || sender.send(message, deadline, &AtomicBool::new(false)));
    let received = native_io::read_bounded(&input, deadline, MAX_FRAME_BYTES, None).unwrap();
    let mut ack = acknowledgement(received.as_bytes());
    ack[ACK_BYTES - 1] ^= 1;
    native_io::write_bounded(&input, &ack, deadline, ACK_BYTES, None).unwrap();
    assert!(matches!(
        worker.join().unwrap(),
        Err(LaunchChannelError::Acknowledgement)
    ));
}

#[test]
fn inherited_launch_read_cancellation_is_an_error_and_releases_its_endpoint() {
    let (_sender, input) = LaunchSender::create().unwrap();
    let receiver = LaunchReceiver::from_inherited(input, executable()).unwrap();
    let cancel = Arc::new(AtomicBool::new(false));
    let worker_cancel = Arc::clone(&cancel);
    let worker = std::thread::spawn(move || {
        receiver.receive(Instant::now() + Duration::from_secs(5), &worker_cancel)
    });
    cancel.store(true, std::sync::atomic::Ordering::Release);
    assert!(matches!(
        worker.join().unwrap(),
        Err(LaunchChannelError::Transport(
            ServiceTransportError::Cancelled
        ))
    ));
}
