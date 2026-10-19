use super::*;
use std::{
    process::{Child, Command, Stdio},
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::windows::named_pipe::{ClientOptions, NamedPipeServer, ServerOptions},
};
use windows_sys::Win32::Security::{
    Authorization::{ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1},
    ImpersonateSelf, RevertToSelf, SECURITY_ATTRIBUTES, SecurityImpersonation,
};

const CHILD: &str = "CFW_NATIVE_PEER_TEST";
const PARENT: &str = "CFW_NATIVE_PEER_PARENT";
const TEST_NAME: &str =
    "peer::tests::native_pipe_identity_uses_the_actual_peer_and_expires_with_its_process";
const LIMIT: Duration = Duration::from_secs(10);

struct ChildCleanup(Child);
impl Drop for ChildCleanup {
    fn drop(&mut self) {
        match self.0.try_wait() {
            Ok(Some(_)) => {}
            Ok(None) => {
                self.0.kill().expect("peer fixture cleanup kill failed");
                self.0.wait().expect("peer fixture cleanup reap failed");
            }
            Err(error) => panic!("peer fixture lifetime observation failed: {error}"),
        }
    }
}

fn pipe_name(id: &str) -> String {
    assert_eq!(uuid::Uuid::parse_str(id).unwrap().to_string(), id);
    format!(r"\\.\pipe\CFW-peer-test-{id}")
}

fn private_pipe(name: &str, principal: &str) -> NamedPipeServer {
    let text: Vec<u16> = format!("O:{principal}D:P(A;;GA;;;{principal})(A;;GA;;;SY)\0")
        .encode_utf16()
        .collect();
    let mut descriptor = null_mut();
    assert_ne!(
        unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                text.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        },
        0
    );
    struct Descriptor(*mut std::ffi::c_void);
    impl Drop for Descriptor {
        fn drop(&mut self) {
            unsafe { LocalFree(self.0) };
        }
    }
    let allocation = Descriptor(descriptor.cast());
    let mut attributes = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
        lpSecurityDescriptor: descriptor.cast(),
        bInheritHandle: 0,
    };
    let server = unsafe {
        ServerOptions::new()
            .first_pipe_instance(true)
            .reject_remote_clients(true)
            .create_with_security_attributes_raw(
                name,
                (&mut attributes as *mut SECURITY_ATTRIBUTES).cast(),
            )
    }
    .unwrap();
    drop(allocation);
    server
}

#[test]
fn native_pipe_identity_uses_the_actual_peer_and_expires_with_its_process() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        if let Ok(id) = std::env::var(CHILD) {
            let parent: u32 = std::env::var(PARENT).unwrap().parse().unwrap();
            let mut client = ClientOptions::new().open(pipe_name(&id)).unwrap();
            let expected = NativePeerProcess::open(parent).unwrap();
            expected.verify_pipe_server(&client).unwrap();
            let observed = NativePeerProcess::from_pipe_server(&client).unwrap();
            assert_eq!(observed.process_id(), parent);
            assert_eq!(observed.identity(), expected.identity());
            // The peer deliberately claims the server PID in its message. The
            // server's OS observation must still identify this child process.
            tokio::time::timeout(LIMIT, async {
                client.write_all(&parent.to_le_bytes()).await.unwrap();
                let mut answer = [0; 4];
                client.read_exact(&mut answer).await.unwrap();
                assert_eq!(&answer, b"done");
            })
            .await
            .unwrap();
            return;
        }
        let id = uuid::Uuid::new_v4().to_string();
        let current = NativePeerProcess::open(std::process::id()).unwrap();
        let mut server = private_pipe(&pipe_name(&id), current.identity().user_sid());
        let mut child = ChildCleanup(
            Command::new(std::env::current_exe().unwrap())
                .args(["--exact", TEST_NAME, "--nocapture", "--test-threads=1"])
                .env(CHILD, &id)
                .env(PARENT, std::process::id().to_string())
                .env("RUST_BACKTRACE", "0")
                .stdout(Stdio::null())
                .stderr(Stdio::inherit())
                .spawn()
                .unwrap(),
        );
        let expected = NativePeerProcess::open(child.0.id()).unwrap();
        tokio::time::timeout(LIMIT, server.connect())
            .await
            .unwrap()
            .unwrap();
        let mut claimed_pid = [0; 4];
        tokio::time::timeout(LIMIT, server.read_exact(&mut claimed_pid))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(u32::from_le_bytes(claimed_pid), current.process_id());
        assert!(matches!(
            current.verify_pipe_client(&server),
            Err(PeerIdentityError::WrongProcess)
        ));
        expected.verify_pipe_client(&server).unwrap();
        cfw_windows_storage::require_process_identity().unwrap();
        let observed = NativePeerProcess::from_pipe_client(&server).unwrap();
        assert_eq!(observed.process_id(), child.0.id());
        assert_eq!(observed.identity(), expected.identity());
        assert_eq!(
            observed.identity().user_sid(),
            current.identity().user_sid()
        );
        assert_eq!(
            observed.identity().authentication_id(),
            current.identity().authentication_id()
        );
        assert_eq!(
            observed.identity().session_id(),
            current.identity().session_id()
        );
        let mut stale = NativePeerProcess::open(child.0.id()).unwrap();
        stale.identity.user_session.authentication_id ^= 1;
        assert!(matches!(
            stale.verify_pipe_client(&server),
            Err(PeerIdentityError::IdentityChanged)
        ));
        tokio::time::timeout(LIMIT, server.write_all(b"done"))
            .await
            .unwrap()
            .unwrap();
        let deadline = Instant::now() + LIMIT;
        loop {
            if let Some(status) = child.0.try_wait().unwrap() {
                assert!(status.success());
                break;
            }
            assert!(Instant::now() < deadline, "peer child did not exit");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        assert!(matches!(
            expected.verify_pipe_client(&server),
            Err(PeerIdentityError::Exited)
        ));
    });
}

#[test]
fn non_pipe_handles_and_invalid_processes_cannot_attest_a_peer() {
    assert!(matches!(
        NativePeerProcess::open(0),
        Err(PeerIdentityError::InvalidIdentity)
    ));
    let current = NativePeerProcess::open(std::process::id()).unwrap();
    let file = tempfile::tempfile().unwrap();
    assert!(matches!(
        current.verify_pipe_client(&file),
        Err(PeerIdentityError::Native {
            operation: "query pipe process",
            ..
        })
    ));
    assert!(NativePeerProcess::from_pipe_server(&file).is_err());
    assert!(!format!("{:?}", current.identity()).contains(current.identity().user_sid()));
    assert!(current.identity().user_sid().starts_with("S-1-"));
}

#[test]
fn impersonation_cannot_choose_the_peer_observers_authority() {
    struct Revert;
    impl Drop for Revert {
        fn drop(&mut self) {
            assert_ne!(unsafe { RevertToSelf() }, 0);
        }
    }
    assert_ne!(unsafe { ImpersonateSelf(SecurityImpersonation) }, 0);
    let guard = Revert;
    let result = NativePeerProcess::open(std::process::id());
    drop(guard);
    assert!(matches!(
        result,
        Err(PeerIdentityError::Observer(
            cfw_windows_storage::Error::ImpersonatedIdentity
        ))
    ));
}

#[test]
fn embedded_sid_reads_are_bounded_before_calling_native_sid_apis() {
    let mut buffer = TokenData {
        storage: vec![0; 12usize.div_ceil(size_of::<usize>())],
        length: 12,
    };
    let system_sid = [1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0];
    unsafe {
        std::ptr::copy_nonoverlapping(
            system_sid.as_ptr(),
            buffer.storage.as_mut_ptr().cast::<u8>(),
            system_sid.len(),
        );
    }
    let pointer = buffer.storage.as_mut_ptr().cast();
    assert_eq!(buffer.sid(pointer).unwrap(), system_sid);
    assert_eq!(sid_text(pointer).unwrap(), "S-1-5-18");
    assert!(buffer.sid(null_mut()).is_err());
    assert!(
        buffer
            .sid((pointer as *mut u8).wrapping_add(12).cast())
            .is_err()
    );
    buffer.length = 1;
    assert!(buffer.sid(pointer).is_err());
    buffer.length = 8;
    assert!(buffer.sid(pointer).is_err());
    buffer.length = 12;
    unsafe {
        *buffer.storage.as_mut_ptr().cast::<u8>().add(1) = 16;
    }
    assert!(buffer.sid(pointer).is_err());
}
