use super::*;
use cfw_windows_engine::user_agent::launcher::{
    UserAgentChild, UserAgentInvocation, ValidationAgent,
};
use std::os::windows::io::AsHandle;
use windows_sys::Win32::System::SystemServices::SE_GROUP_INTEGRITY;

#[derive(Clone, Copy)]
pub(super) enum ClientCase {
    UserAgent,
    CopiedImage,
    AuthorityRuntime,
    RuntimeDesktop,
    RuntimeLocal,
    RuntimeSystem,
    RuntimeRestartDesktop,
    RuntimeRestartSystem,
    RuntimeRestartLocal,
    RuntimeLocalRestartDesktop,
    InstalledHostDesktop,
    InstalledBackendDesktop,
    InstalledBackendExitDesktop,
    InstalledProfileDesktop,
    InstalledCoordinatorDesktop,
    InstalledStartupDesktop,
    ProcessObservation,
    UpdateInspection,
    RejectedRuntime,
}
impl ClientCase {
    fn flag(self) -> &'static str {
        match self {
            Self::UserAgent => "--client",
            Self::CopiedImage => "--rejected-client",
            Self::AuthorityRuntime => "--authority-runtime",
            Self::RuntimeDesktop => "--runtime-desktop",
            Self::RuntimeLocal => "--local-agent-runtime",
            Self::RuntimeSystem => "--system-agent-runtime",
            Self::RuntimeRestartDesktop => "--restart-runtime-desktop",
            Self::RuntimeRestartSystem => "--restart-system-agent-runtime",
            Self::RuntimeRestartLocal => "--restart-local-agent-runtime",
            Self::RuntimeLocalRestartDesktop => "--restart-local-runtime-desktop",
            Self::InstalledHostDesktop => "--installed-host-client",
            Self::InstalledBackendDesktop => "--installed-backend-client",
            Self::InstalledBackendExitDesktop => "--installed-backend-exit-client",
            Self::InstalledProfileDesktop => "--installed-profile-client",
            Self::InstalledCoordinatorDesktop => "--installed-coordinator-client",
            Self::InstalledStartupDesktop => "--installed-startup-client",
            Self::ProcessObservation => "--desktop-process-client",
            Self::UpdateInspection => "--update-package-client",
            Self::RejectedRuntime => "--rejected-agent-runtime",
        }
    }
    fn report_prefix(self, name: &str) -> String {
        match self {
            Self::UserAgent => name.to_owned(),
            Self::CopiedImage => format!("{name}-copy"),
            Self::AuthorityRuntime => format!("{name}-authority"),
            Self::RuntimeDesktop => format!("{name}-desktop"),
            Self::RuntimeLocal => format!("{name}-runtime-local"),
            Self::RuntimeSystem => format!("{name}-runtime-system"),
            Self::RuntimeRestartDesktop => format!("{name}-restart-desktop"),
            Self::RuntimeRestartSystem => format!("{name}-restart-system"),
            Self::RuntimeRestartLocal => format!("{name}-restart-local"),
            Self::RuntimeLocalRestartDesktop => format!("{name}-restart-desktop"),
            Self::InstalledHostDesktop => "installed-host".into(),
            Self::InstalledBackendDesktop => "installed-host-backend".into(),
            Self::InstalledBackendExitDesktop => "installed-host-backend-exit".into(),
            Self::InstalledProfileDesktop => "installed-host-profile".into(),
            Self::InstalledCoordinatorDesktop => "installed-host-coordinator".into(),
            Self::InstalledStartupDesktop => "installed-host-startup".into(),
            Self::ProcessObservation => format!("{name}-process"),
            Self::UpdateInspection => format!("{name}-update"),
            Self::RejectedRuntime => format!("{name}-runtime-rejected"),
        }
    }
    fn report(self) -> serde_json::Value {
        match self {
            Self::ProcessObservation => {
                serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,"actual_desktop_process_observation":true})
            }
            Self::UpdateInspection => {
                serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,"installed_package_inspector":true,"installed_desktop_identity":true,"protected_manifest_write_denied":true,"signed_msi_verified":true,"different_publisher_rejected":true,"precreation_cancellation_observed":true,"private_staged_copy_inspected":true,"staging_cleanup_observed":true,"desktop_staging_owner_retained":true})
            }
            Self::UserAgent => {
                serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,"query_only_service_process":true,"desktop_role_rejected":true,"pipe_instance_creation_rejected":true,"live_console_authorized":true,"missing_lease_rejected":true,"foreign_lease_rejected":true,"unleased_observation_admitted":true,"machine_record_access_denied":true,"zero_access_job_keeper_isolated":true,"job_keeper_prevents_name_loss":true,"job_keeper_release_observed":true,"keeper_object_identity_checked":true,"unrelated_keeper_handle_preserved":true})
            }
            Self::CopiedImage => {
                serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,"client_image_rejected":true})
            }
            Self::AuthorityRuntime => {
                serde_json::json!({"success":true,"medium_integrity":true,"administrator_member":false,"native_authority_binding":true,"wrong_ticket_rejected":true,"new_connection_cannot_inherit_lease":true,"synthetic_runtime_reports":true,"actual_engine_started":false})
            }
            Self::RuntimeDesktop => user_agent::desktop_report(),
            Self::RuntimeLocal => {
                user_agent::agent_report(cfw_singbox_config::ProjectionMode::LocalProxy)
            }
            Self::RuntimeSystem => {
                user_agent::agent_report(cfw_singbox_config::ProjectionMode::SystemProxy)
            }
            Self::RejectedRuntime => user_agent::rejected_report(),
            Self::RuntimeRestartDesktop => {
                user_agent::restart::desktop_report(user_agent::restart::Mode::System)
            }
            Self::RuntimeLocalRestartDesktop => {
                user_agent::restart::desktop_report(user_agent::restart::Mode::Local)
            }
            Self::RuntimeRestartSystem => {
                user_agent::restart::agent_report(user_agent::restart::Mode::System)
            }
            Self::RuntimeRestartLocal => {
                user_agent::restart::agent_report(user_agent::restart::Mode::Local)
            }
            Self::InstalledHostDesktop
            | Self::InstalledBackendDesktop
            | Self::InstalledBackendExitDesktop
            | Self::InstalledCoordinatorDesktop => {
                serde_json::json!({"product_service":true,"product_agent":true,"desktop_is_fixture":true,"release_accepted":false})
            }
            Self::InstalledProfileDesktop => {
                serde_json::json!({"product_service":true,"product_agent":false,"desktop_is_fixture":true,"release_accepted":false})
            }
            Self::InstalledStartupDesktop => {
                serde_json::json!({"product_service":false,"product_agent":false,"desktop_is_fixture":true,"release_accepted":false})
            }
        }
    }
    fn is_installed(self) -> bool {
        matches!(
            self,
            Self::InstalledHostDesktop
                | Self::InstalledBackendDesktop
                | Self::InstalledBackendExitDesktop
                | Self::InstalledProfileDesktop
                | Self::InstalledCoordinatorDesktop
                | Self::InstalledStartupDesktop
        )
    }
    fn installed_suite(self) -> Result<installed_host::InstalledSuite> {
        match self {
            Self::InstalledHostDesktop => Ok(installed_host::InstalledSuite::Host),
            Self::InstalledBackendDesktop => Ok(installed_host::InstalledSuite::Backend),
            Self::InstalledBackendExitDesktop => Ok(installed_host::InstalledSuite::BackendExit),
            Self::InstalledProfileDesktop => Ok(installed_host::InstalledSuite::Profile),
            Self::InstalledCoordinatorDesktop => Ok(installed_host::InstalledSuite::Coordinator),
            Self::InstalledStartupDesktop => Ok(installed_host::InstalledSuite::Startup),
            _ => Err("client is not an installed suite".into()),
        }
    }
}

struct Sid(*mut c_void);
impl Sid {
    fn new(text: &str) -> Result<Self> {
        let mut sid = null_mut();
        if unsafe { ConvertStringSidToSidW(wide(text).as_ptr(), &mut sid) } == 0 {
            return Err(error("create fixture SID"));
        }
        Ok(Self(sid))
    }
}
impl Drop for Sid {
    fn drop(&mut self) {
        unsafe { LocalFree(self.0) };
    }
}

pub(super) fn token() -> Result<OwnedHandle> {
    let mut original = null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            // CreateRestrictedToken preserves these handle access rights.
            // Only the new token is adjusted to medium integrity below.
            TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ASSIGN_PRIMARY | TOKEN_ADJUST_DEFAULT,
            &mut original,
        )
    } == 0
    {
        return Err(error("open fixture process token"));
    }
    let original = unsafe { OwnedHandle::from_raw_handle(original) };
    let admins = Sid::new("S-1-5-32-544")?;
    let disabled = SID_AND_ATTRIBUTES {
        Sid: admins.0,
        Attributes: 0,
    };
    let mut restricted = null_mut();
    if unsafe {
        CreateRestrictedToken(
            original.as_raw_handle(),
            DISABLE_MAX_PRIVILEGE,
            1,
            &disabled,
            0,
            null(),
            0,
            null(),
            &mut restricted,
        )
    } == 0
    {
        return Err(error("create unprivileged fixture token"));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(restricted) };
    let medium = Sid::new("S-1-16-8192")?;
    let label = TOKEN_MANDATORY_LABEL {
        Label: SID_AND_ATTRIBUTES {
            Sid: medium.0,
            Attributes: SE_GROUP_INTEGRITY as u32,
        },
    };
    if unsafe {
        SetTokenInformation(
            token.as_raw_handle(),
            TokenIntegrityLevel,
            (&label as *const TOKEN_MANDATORY_LABEL).cast(),
            size_of::<TOKEN_MANDATORY_LABEL>() as u32 + GetLengthSid(medium.0),
        )
    } == 0
    {
        return Err(error("set fixture token medium integrity"));
    }
    // The hosted runner's elevated default DACL grants full access to BA/SY
    // and only read/execute to its logon SID. After disabling BA that no longer
    // gives the child normal control of objects it creates during startup.
    // Change only this new token's defaults, not existing objects or the parent.
    let user = NativePeerProcess::open(std::process::id()).map_err(|e| e.to_string())?;
    let descriptor = Descriptor::new(&format!(
        "D:P(A;;GA;;;{})(A;;GA;;;SY)",
        user.identity().user_sid()
    ))?;
    let mut present = 0;
    let mut defaulted = 0;
    let mut dacl = null_mut();
    if unsafe { GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut dacl, &mut defaulted) }
        == 0
    {
        return Err(error("read fixture user default DACL"));
    }
    if present == 0 || defaulted != 0 || dacl.is_null() {
        return Err("invalid fixture user default DACL".into());
    }
    let defaults = TOKEN_DEFAULT_DACL { DefaultDacl: dacl };
    if unsafe {
        SetTokenInformation(
            token.as_raw_handle(),
            TokenDefaultDacl,
            (&defaults as *const TOKEN_DEFAULT_DACL).cast(),
            size_of::<TOKEN_DEFAULT_DACL>() as u32,
        )
    } == 0
    {
        return Err(error("set fixture user default DACL"));
    }
    Ok(token)
}

pub(super) fn require_non_admin_process(process: &OwnedHandle) -> Result<()> {
    let mut primary = null_mut();
    if unsafe {
        OpenProcessToken(
            process.as_raw_handle(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut primary,
        )
    } == 0
    {
        return Err(error("open GUI process token"));
    }
    let primary = unsafe { OwnedHandle::from_raw_handle(primary) };
    let mut copied = null_mut();
    if unsafe {
        DuplicateTokenEx(
            primary.as_raw_handle(),
            TOKEN_QUERY,
            null(),
            SecurityIdentification,
            TokenImpersonation,
            &mut copied,
        )
    } == 0
    {
        return Err(error("copy GUI token for group observation"));
    }
    let copied = unsafe { OwnedHandle::from_raw_handle(copied) };
    let admins = Sid::new("S-1-5-32-544")?;
    let mut member = 1;
    if unsafe { CheckTokenMembership(copied.as_raw_handle(), admins.0, &mut member) } == 0 {
        return Err(error("observe GUI administrator membership"));
    }
    if member != 0 {
        return Err("installed GUI has administrator membership".into());
    }
    Ok(())
}

pub(super) fn with_medium_impersonation(action: impl FnOnce() -> Result<()>) -> Result<()> {
    cfw_windows_storage::require_process_identity().map_err(|e| e.to_string())?;
    let primary = token()?;
    let mut raw = null_mut();
    if unsafe {
        DuplicateTokenEx(
            primary.as_raw_handle(),
            TOKEN_QUERY | TOKEN_IMPERSONATE,
            null(),
            SecurityImpersonation,
            TokenImpersonation,
            &mut raw,
        )
    } == 0
    {
        return Err(error("duplicate fixture message token"));
    }
    let token = unsafe { OwnedHandle::from_raw_handle(raw) };
    if unsafe { SetThreadToken(null(), token.as_raw_handle()) } == 0 {
        return Err(error("select fixture message token"));
    }
    struct Restore;
    impl Drop for Restore {
        fn drop(&mut self) {
            if unsafe { RevertToSelf() } == 0 {
                std::process::abort();
            }
        }
    }
    let guard = Restore;
    let result = action();
    drop(guard);
    cfw_windows_storage::require_process_identity().map_err(|e| e.to_string())?;
    result
}

pub(super) fn run(image: &Path, name: &str, expected: [u8; 32]) -> Result<()> {
    run_case(image, name, expected, ClientCase::UserAgent, None)
}
pub(super) fn run_desktop_runtime(image: &Path, name: &str, expected: [u8; 32]) -> Result<()> {
    run_case(image, name, expected, ClientCase::RuntimeDesktop, None)
}
pub(super) fn run_restart_desktop(
    image: &Path,
    name: &str,
    expected: [u8; 32],
    mode: user_agent::restart::Mode,
) -> Result<()> {
    run_case(
        image,
        name,
        expected,
        match mode {
            user_agent::restart::Mode::System => ClientCase::RuntimeRestartDesktop,
            user_agent::restart::Mode::Local => ClientCase::RuntimeLocalRestartDesktop,
        },
        None,
    )
}
type Activity<'a> = &'a mut dyn FnMut(&UserAgentChild, Instant) -> Result<()>;
pub(super) fn run_runtime(
    image: &Path,
    name: &str,
    expected: [u8; 32],
    case: ClientCase,
    launch: cfw_windows_engine::user_agent::handoff::UserAgentLaunch,
    activity: Option<Activity<'_>>,
) -> Result<()> {
    let selector = match case {
        ClientCase::RuntimeLocal => ValidationAgent::Local,
        ClientCase::RuntimeSystem => ValidationAgent::System,
        ClientCase::RuntimeRestartSystem => ValidationAgent::RestartSystem,
        ClientCase::RuntimeRestartLocal => ValidationAgent::RestartLocal,
        ClientCase::RejectedRuntime => ValidationAgent::Rejected,
        _ => return Err("invalid product UserAgent fixture case".into()),
    };
    let prefix = case.report_prefix(name);
    let parent = image.parent().ok_or("missing agent fixture parent")?;
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(parent.join(format!("{prefix}-client-output.txt")))
        .map_err(|e| e.to_string())?;
    let invocation =
        UserAgentInvocation::for_validation(name, selector, expected).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + Duration::from_secs(60);
    let launched = UserAgentChild::launch(
        verified(image, expected)?,
        invocation,
        launch,
        &output,
        Instant::now() + LIMIT,
        std::sync::Arc::new(AtomicBool::new(false)),
    );
    let (mut owner, startup) = match launched {
        Ok(owner) => (owner, Ok(())),
        Err(failure) => match failure.owner {
            Some(owner) => (*owner, Err(failure.error.to_string())),
            None => return Err(failure.error.to_string()),
        },
    };
    let exercised = match activity {
        Some(activity) => activity(&owner, deadline),
        None => Ok(()),
    };
    if startup.is_err() || exercised.is_err() {
        owner.cancel_handoff();
    }
    let completed = owner
        .wait_for_exit(deadline)
        .map(|_| ())
        .map_err(|e| e.to_string());
    let report = match owner.exit_observation() {
        Some(exit) => check_report(parent, &prefix, case, exit.exit_code()),
        None => Err("product UserAgent process exit was not observed".into()),
    };
    let errors: Vec<_> = [
        ("launch", startup),
        ("exercise", exercised),
        ("completion", completed),
        ("report", report),
    ]
    .into_iter()
    .filter_map(|(stage, result)| result.err().map(|error| format!("{stage}: {error}")))
    .collect();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors.join("; "))
    }
}
pub(super) fn run_rejected_copy(image: &Path, name: &str, expected: [u8; 32]) -> Result<()> {
    run_case(image, name, expected, ClientCase::CopiedImage, None)
}
pub(super) fn run_authority(
    image: &Path,
    name: &str,
    expected: [u8; 32],
    handoff: &[u8],
) -> Result<()> {
    if handoff.is_empty() || handoff.len() > cfw_windows_engine::authority::wire::MAX_MESSAGE_BYTES
    {
        return Err("invalid authority handoff length".into());
    }
    run_case(
        image,
        name,
        expected,
        ClientCase::AuthorityRuntime,
        Some(zeroize::Zeroizing::new(handoff.to_vec())),
    )
}
fn run_case(
    image: &Path,
    name: &str,
    expected: [u8; 32],
    case: ClientCase,
    handoff: Option<zeroize::Zeroizing<Vec<u8>>>,
) -> Result<()> {
    let token = token()?;
    let mut desktop = desktop::Desktop::new()?;
    let hex: String = expected.iter().map(|b| format!("{b:02x}")).collect();
    let mut command = wide(&format!(
        "\"{}\" {} {name} {hex}",
        image.display(),
        case.flag()
    ));
    let report_prefix = case.report_prefix(name);
    let installed_receipts = if case.is_installed() || matches!(case, ClientCase::UpdateInspection)
    {
        let path = PathBuf::from(
            std::env::var_os("CFW_NATIVE_SERVICE_RECEIPTS")
                .ok_or("missing installed runtime receipts")?,
        );
        if !path.is_absolute() || !path.is_dir() {
            return Err("invalid installed runtime receipts".into());
        }
        Some(path)
    } else {
        None
    };
    let parent = installed_receipts
        .as_deref()
        .unwrap_or(image.parent().ok_or("missing fixture image parent")?);
    let output_path = parent.join(format!("{report_prefix}-client-output.txt"));
    let output = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&output_path)
        .map_err(|e| e.to_string())?;
    let (input, writer) = match handoff {
        Some(bytes) => {
            let mut read = null_mut();
            let mut write = null_mut();
            if unsafe {
                windows_sys::Win32::System::Pipes::CreatePipe(&mut read, &mut write, null(), 8192)
            } == 0
            {
                return Err(error("create authority handoff pipe"));
            }
            let read = std::fs::File::from(unsafe { OwnedHandle::from_raw_handle(read) });
            let write = std::fs::File::from(unsafe { OwnedHandle::from_raw_handle(write) });
            (read, Some((write, bytes)))
        }
        None => (std::fs::File::open("NUL").map_err(|e| e.to_string())?, None),
    };
    let handles = [input.as_raw_handle(), output.as_raw_handle()];
    for handle in handles {
        if unsafe { SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT) } == 0 {
            return Err(error("mark fixture diagnostic handle inheritable"));
        }
    }
    // Inherit only the explicit input and diagnostic output. The ticket's
    // input-pipe writer, token, service and process handles stay private.
    let mut attributes =
        cfw_windows_engine::ProcessHandleList::new(&[input.as_handle(), output.as_handle()])
            .map_err(|e| e.to_string())?;
    let startup = STARTUPINFOEXW {
        StartupInfo: STARTUPINFOW {
            cb: size_of::<STARTUPINFOEXW>() as u32,
            dwFlags: STARTF_USESTDHANDLES,
            lpDesktop: desktop.path(),
            hStdInput: handles[0],
            hStdOutput: handles[1],
            hStdError: handles[1],
            ..Default::default()
        },
        lpAttributeList: attributes.pointer(),
    };
    let mut info = PROCESS_INFORMATION::default();
    if unsafe {
        CreateProcessAsUserW(
            token.as_raw_handle(),
            path_wide(image).as_ptr(),
            command.as_mut_ptr(),
            null(),
            null(),
            1,
            CREATE_NO_WINDOW | EXTENDED_STARTUPINFO_PRESENT,
            null(),
            null(),
            &startup.StartupInfo,
            &mut info,
        )
    } == 0
    {
        return Err(error("start unprivileged fixture client"));
    }
    let process = unsafe { OwnedHandle::from_raw_handle(info.hProcess) };
    let _thread = unsafe { OwnedHandle::from_raw_handle(info.hThread) };
    drop(attributes);
    drop(input);
    // Only the small Authority-policy fixture still uses this anonymous
    // input. Product runtime creation and handoff run through UserAgentChild.
    let writer = writer.map(|(mut output, bytes)| {
        thread::spawn(move || std::io::Write::write_all(&mut output, bytes.as_slice()))
    });
    let limit = if matches!(
        case,
        ClientCase::RuntimeDesktop
            | ClientCase::RuntimeRestartDesktop
            | ClientCase::RuntimeLocalRestartDesktop
            | ClientCase::InstalledHostDesktop
            | ClientCase::InstalledBackendDesktop
            | ClientCase::InstalledBackendExitDesktop
            | ClientCase::InstalledProfileDesktop
            | ClientCase::InstalledCoordinatorDesktop
            | ClientCase::InstalledStartupDesktop
            | ClientCase::UpdateInspection
    ) {
        Duration::from_secs(60)
    } else {
        LIMIT
    };
    let deadline = Instant::now() + limit;
    let waited = cfw_windows_storage::wait_until(&process, deadline).map_err(|e| e.to_string())?;
    if waited != cfw_windows_storage::WaitOutcome::Signaled {
        let diagnostic = if case.is_installed() {
            installed_host::timeout_snapshot(parent, &report_prefix)
        } else {
            Ok(())
        };
        if unsafe { TerminateProcess(process.as_raw_handle(), 3) } == 0 {
            return Err(error("terminate expired fixture client"));
        }
        if cfw_windows_storage::wait_until(&process, Instant::now() + LIMIT)
            .map_err(|e| e.to_string())?
            != cfw_windows_storage::WaitOutcome::Signaled
        {
            return Err("expired fixture client cleanup was not observed".into());
        }
        if let Some(writer) = writer {
            let written = writer
                .join()
                .map_err(|_| "authority handoff writer panicked")?;
            return Err(format!(
                "unprivileged fixture client exceeded its deadline; handoff writer: {written:?}"
            ));
        }
        return Err(match diagnostic {
            Ok(()) => "unprivileged fixture client exceeded its deadline".into(),
            Err(error) => {
                format!("unprivileged fixture client exceeded its deadline; diagnostic: {error}")
            }
        });
    }
    if let Some(writer) = writer {
        writer
            .join()
            .map_err(|_| "authority handoff writer panicked")?
            .map_err(|e| format!("authority handoff write: {e}"))?;
    }
    let mut exit = 0;
    if unsafe { GetExitCodeProcess(process.as_raw_handle(), &mut exit) } == 0 {
        return Err(error("read fixture client exit"));
    }
    if case.is_installed() {
        installed_host::check_output(parent, &output_path, exit, case.installed_suite()?)?;
    } else {
        check_report(parent, &report_prefix, case, exit)?;
    }
    desktop.close()?;
    Ok(())
}
pub(super) fn run_installed_host(image: &Path, expected: [u8; 32]) -> Result<()> {
    if std::env::var("CFW_NATIVE_SERVICE_MUTATION_TESTS").as_deref() != Ok("1") {
        return Err("installed runtime requires disposable CI opt-in".into());
    }
    // Separate independent suites keep the existing per-client 60-second
    // deadline. All run in the same installation/service and retain every
    // generation/assertion; product operation timeouts are unchanged.
    let directory = PathBuf::from(
        std::env::var_os("CFW_NATIVE_SERVICE_RECEIPTS")
            .ok_or("missing installed report directory")?,
    );
    for case in [
        ClientCase::InstalledHostDesktop,
        ClientCase::InstalledBackendDesktop,
        ClientCase::InstalledBackendExitDesktop,
        ClientCase::InstalledProfileDesktop,
        ClientCase::InstalledCoordinatorDesktop,
        ClientCase::InstalledStartupDesktop,
    ] {
        let exercise = || {
            run_case(
                image,
                cfw_windows_engine::runtime_host::SERVICE_NAME,
                expected,
                case,
                None,
            )
        };
        if matches!(case, ClientCase::InstalledCoordinatorDesktop) {
            release_trace::capture(&directory, exercise)?;
        } else {
            exercise()?;
        }
    }
    installed_host::combine_reports(&directory)
}

pub(super) fn run_desktop_process_observation() -> Result<()> {
    if std::env::var("CFW_NATIVE_PROCESS_OBSERVATION_TESTS").as_deref() != Ok("1") {
        return Err("desktop process observation requires disposable CI opt-in".into());
    }
    let image = std::env::current_exe().map_err(|e| e.to_string())?;
    let name = format!("CFW-scm-fixture-process-{}", std::process::id());
    let case = ClientCase::ProcessObservation;
    run_case(&image, &name, digest(&image)?, case, None)?;
    // check_report already bounded this output and required a successful exit.
    let bytes = std::fs::read(
        image
            .parent()
            .ok_or("missing fixture image parent")?
            .join(format!("{}-client-output.txt", case.report_prefix(&name))),
    )
    .map_err(|error| error.to_string())?;
    let observation: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    println!(
        "{}",
        serde_json::json!({
            "source": std::env::var("CFW_NATIVE_SERVICE_SOURCE").map_err(|e| e.to_string())?,
            "process_observation": observation,
            "release_accepted": false,
        })
    );
    Ok(())
}

pub(super) fn run_update_package_inspection() -> Result<()> {
    if std::env::var("CFW_NATIVE_PACKAGE_TESTS").as_deref() != Ok("1") {
        return Err("update inspection requires disposable CI opt-in".into());
    }
    let image = std::env::current_exe().map_err(|e| e.to_string())?;
    let name = format!("CFW-scm-fixture-update-{}", std::process::id());
    let case = ClientCase::UpdateInspection;
    run_case(&image, &name, digest(&image)?, case, None)?;
    let parent = PathBuf::from(
        std::env::var_os("CFW_NATIVE_SERVICE_RECEIPTS").ok_or("missing update receipts")?,
    );
    // run_case checked this exact bounded output, report and process exit.
    let bytes =
        std::fs::read(parent.join(format!("{}-client-output.txt", case.report_prefix(&name))))
            .map_err(|e| e.to_string())?;
    let observation: serde_json::Value =
        serde_json::from_slice(&bytes).map_err(|e| e.to_string())?;
    println!(
        "{}",
        serde_json::json!({
            "source": std::env::var("CFW_PACKAGE_SOURCE").map_err(|e| e.to_string())?,
            "package_inspection": observation, "release_accepted": false,
        })
    );
    Ok(())
}

pub(super) fn check_report(
    parent: &Path,
    report_prefix: &str,
    case: ClientCase,
    exit: u32,
) -> Result<()> {
    let diagnostics = std::fs::read(parent.join(format!("{report_prefix}-client-output.txt")))
        .map_err(|e| e.to_string())?;
    if diagnostics.len() > 16384 {
        return Err("fixture client diagnostics exceed bound".into());
    }
    let diagnostics = String::from_utf8_lossy(&diagnostics);
    let report = std::fs::read(parent.join(format!("{report_prefix}-client.json")))
        .map_err(|e| format!("unprivileged client exit={exit:#x}; report unavailable: {e}; diagnostics: {diagnostics}"))?;
    if report.len() > 8192 {
        return Err("fixture client report exceeds bound".into());
    }
    let report: serde_json::Value = serde_json::from_slice(&report).map_err(|e| e.to_string())?;
    if exit != 0 || report != case.report() {
        return Err(format!(
            "unprivileged client exit={exit:#x}, report={report}; diagnostics: {diagnostics}"
        ));
    }
    Ok(())
}

pub(super) fn client(name: &str, hex: &str, case: ClientCase) -> Result<()> {
    let report_prefix = case.report_prefix(name);
    let image = std::env::current_exe().map_err(|e| e.to_string())?;
    if !name.starts_with("CFW-scm-fixture-")
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        || name.len() > 80
    {
        return Err("invalid fixture client service name".into());
    }
    let result = client_body(name, hex, case);
    let report = match &result {
        Ok(()) => case.report(),
        Err(e) => serde_json::json!({"success":false,"error":e}),
    };
    let written = (|| -> Result<()> {
        let parent = if matches!(case, ClientCase::UpdateInspection) {
            let parent = PathBuf::from(
                std::env::var_os("CFW_NATIVE_SERVICE_RECEIPTS").ok_or("missing update receipts")?,
            );
            if !parent.is_absolute() || !parent.is_dir() {
                return Err("invalid update receipt directory".into());
            }
            parent
        } else {
            image
                .parent()
                .ok_or("missing fixture image parent")?
                .to_owned()
        };
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(parent.join(format!("{report_prefix}-client.json")))
            .map_err(|e| e.to_string())?;
        std::io::Write::write_all(
            &mut output,
            serde_json::to_string(&report)
                .map_err(|e| e.to_string())?
                .as_bytes(),
        )
        .map_err(|e| e.to_string())?;
        output.sync_all().map_err(|e| e.to_string())?;
        Ok(())
    })();
    if let Err(error) = written {
        let admission = match &result {
            Ok(()) => "admission passed".to_owned(),
            Err(failure) => format!("admission failed: {failure}"),
        };
        return Err(format!("{admission}; client report write failed: {error}"));
    }
    result
}

pub(super) fn require_medium_user_context() -> Result<NativePeerProcess> {
    let identity = NativePeerProcess::open(std::process::id()).map_err(|e| e.to_string())?;
    if identity.identity().integrity_rid() != 0x2000 {
        return Err("fixture client does not have medium integrity".into());
    }
    let admins = Sid::new("S-1-5-32-544")?;
    let mut member = 1;
    if unsafe { CheckTokenMembership(null_mut(), admins.0, &mut member) } == 0 {
        return Err(error("observe fixture client group"));
    }
    if member != 0 {
        return Err("fixture client still has administrator membership".into());
    }
    Ok(identity)
}

fn client_body(name: &str, hex: &str, case: ClientCase) -> Result<()> {
    require_medium_user_context()?;
    if hex.len() != 64 || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err("invalid fixture executable identity".into());
    }
    let mut expected = [0; 32];
    for (index, value) in expected.iter_mut().enumerate() {
        *value =
            u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).map_err(|e| e.to_string())?;
    }
    let (image, installed_digest) = if matches!(
        case,
        ClientCase::ProcessObservation | ClientCase::UpdateInspection
    ) {
        let opt_in = if matches!(case, ClientCase::ProcessObservation) {
            "CFW_NATIVE_PROCESS_OBSERVATION_TESTS"
        } else {
            "CFW_NATIVE_PACKAGE_TESTS"
        };
        if std::env::var(opt_in).as_deref() != Ok("1") {
            return Err("desktop process client requires disposable CI opt-in".into());
        }
        let image = std::env::current_exe().map_err(|e| e.to_string())?;
        let digest = digest(&image)?;
        (image, digest)
    } else {
        transport::service_image()?
    };
    if expected != installed_digest {
        return Err("fixture service digest differs from installation".into());
    }
    match case {
        ClientCase::ProcessObservation => {
            println!("{}", desktop_process::observe()?);
            return Ok(());
        }
        ClientCase::UpdateInspection => {
            println!("{}", update_package::observe()?);
            return Ok(());
        }
        ClientCase::InstalledHostDesktop
        | ClientCase::InstalledBackendDesktop
        | ClientCase::InstalledBackendExitDesktop
        | ClientCase::InstalledProfileDesktop
        | ClientCase::InstalledCoordinatorDesktop
        | ClientCase::InstalledStartupDesktop => {
            return Err("installed host client must use its separate test entrypoint".into());
        }
        ClientCase::RuntimeRestartDesktop => {
            return user_agent::restart::desktop(name, hex, user_agent::restart::Mode::System);
        }
        ClientCase::RuntimeLocalRestartDesktop => {
            return user_agent::restart::desktop(name, hex, user_agent::restart::Mode::Local);
        }
        ClientCase::RuntimeDesktop => {
            // The client preflight must work without weakening the privileged
            // observer used by SYSTEM for full console-token admission.
            if !matches!(
                LiveConsoleSession::observe(),
                Err(ServiceAuthorizationError::Observer(
                    ServicePeerError::InvalidServiceProcessIdentity {
                        local_system: false,
                        ..
                    }
                ))
            ) {
                return Err("ordinary Desktop accessed the privileged console observer".into());
            }
            return user_agent::desktop(name, hex);
        }
        ClientCase::RuntimeLocal
        | ClientCase::RuntimeSystem
        | ClientCase::RuntimeRestartSystem
        | ClientCase::RuntimeRestartLocal
        | ClientCase::RejectedRuntime => {
            return user_agent::agent(name, &image, expected, case);
        }
        ClientCase::AuthorityRuntime => return authority_wire::agent(name, &image, expected),
        ClientCase::CopiedImage => {
            let mut channel = ServiceChannel::connect(
                name,
                ServiceClientRole::UserAgent,
                verified(&image, expected)?,
            )
            .map_err(|e| e.to_string())?;
            require_rejection(channel.request(b"ping", Instant::now() + LIMIT))?;
            return Ok(());
        }
        ClientCase::UserAgent => {
            machine_record::require_user_denied(name)?;
            verify_pipe_instance_denied(name, &image, expected)?;
            let mut wrong_role = ServiceChannel::connect(
                name,
                ServiceClientRole::Desktop,
                verified(&image, expected)?,
            )
            .map_err(|e| e.to_string())?;
            require_rejection(wrong_role.request(b"ping", Instant::now() + LIMIT))?;
        }
    }
    for command in [b"agent-without-lease".as_slice(), b"agent-foreign-lease"] {
        let mut denied = ServiceChannel::connect(
            name,
            ServiceClientRole::UserAgent,
            verified(&image, expected)?,
        )
        .map_err(|e| e.to_string())?;
        require_rejection(denied.request(command, Instant::now() + LIMIT))?;
    }
    let mut observation = ServiceChannel::connect(
        name,
        ServiceClientRole::UserAgent,
        verified(&image, expected)?,
    )
    .map_err(|e| e.to_string())?;
    if observation
        .request(b"agent-observe-without-lease", Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
        .as_bytes()
        != b"seen"
    {
        return Err("unleased fixture observation was not admitted".into());
    }
    drop(observation);
    let mut channel = ServiceChannel::connect(
        name,
        ServiceClientRole::UserAgent,
        verified(&image, expected)?,
    )
    .map_err(|e| e.to_string())?;
    verify_query_only_service_access(channel.process_id().map_err(|e| e.to_string())?)?;
    job_keeper::client(&mut channel)?;
    if channel
        .request(b"ping", Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
        .as_bytes()
        != b"pong"
    {
        return Err("authenticated service channel reply mismatch".into());
    }
    if channel
        .request(b"done", Instant::now() + LIMIT)
        .map_err(|e| e.to_string())?
        .as_bytes()
        != b"end!"
    {
        return Err("authenticated service channel completion mismatch".into());
    }
    Ok(())
}

fn verify_query_only_service_access(pid: u32) -> Result<()> {
    use windows_sys::Win32::Storage::FileSystem::{WRITE_DAC, WRITE_OWNER};
    for access in [
        PROCESS_VM_READ,
        PROCESS_VM_WRITE,
        PROCESS_VM_OPERATION,
        PROCESS_DUP_HANDLE,
        PROCESS_CREATE_THREAD,
        PROCESS_TERMINATE,
        PROCESS_SET_INFORMATION,
        PROCESS_SUSPEND_RESUME,
        WRITE_DAC,
        WRITE_OWNER,
    ] {
        let handle = unsafe { OpenProcess(access, 0, pid) };
        if !handle.is_null() {
            drop(unsafe { OwnedHandle::from_raw_handle(handle) });
            return Err(format!(
                "unprivileged client obtained service mutation/memory access {access:#x}"
            ));
        }
        if io::Error::last_os_error().raw_os_error() != Some(ERROR_ACCESS_DENIED as i32) {
            return Err(error("unexpected service process access rejection"));
        }
    }
    let process = unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, 0, pid) };
    if process.is_null() {
        return Err(error("open read-only fixture service process"));
    }
    let process = unsafe { OwnedHandle::from_raw_handle(process) };
    let mut token = null_mut();
    if unsafe { OpenProcessToken(process.as_raw_handle(), TOKEN_QUERY, &mut token) } != 0 {
        drop(unsafe { OwnedHandle::from_raw_handle(token) });
        return Err("unprivileged client obtained SYSTEM token access".into());
    }
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_ACCESS_DENIED as i32) {
        return Err(error("unexpected service token access rejection"));
    }
    Ok(())
}

fn verify_pipe_instance_denied(name: &str, image: &Path, expected: [u8; 32]) -> Result<()> {
    use windows_sys::Win32::{
        Storage::FileSystem::{FILE_FLAG_OVERLAPPED, PIPE_ACCESS_DUPLEX},
        System::Pipes::{
            CreateNamedPipeW, GetNamedPipeInfo, PIPE_READMODE_MESSAGE, PIPE_REJECT_REMOTE_CLIENTS,
            PIPE_TYPE_MESSAGE, PIPE_WAIT,
        },
    };
    let mut pipe =
        LocalServicePipe::open(name, ServiceClientRole::UserAgent).map_err(|e| e.to_string())?;
    let peer = WindowsServicePeer::from_pipe_server(name, verified(image, expected)?, &pipe)
        .map_err(|e| e.to_string())?;
    let mut flags = 0;
    let mut instances = 0;
    if unsafe {
        GetNamedPipeInfo(
            pipe.as_raw_handle(),
            &mut flags,
            null_mut(),
            null_mut(),
            &mut instances,
        )
    } == 0
    {
        return Err(error("query fixture pipe instance contract"));
    }
    if flags & PIPE_TYPE_MESSAGE == 0 || instances != 16 {
        return Err("fixture pipe instance contract differs from the expected endpoint".into());
    }
    let path = wide(&format!(r"\\.\pipe\{name}.user-agent"));
    let raw = unsafe {
        CreateNamedPipeW(
            path.as_ptr(),
            PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
            PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT | PIPE_REJECT_REMOTE_CLIENTS,
            instances,
            16384,
            16384,
            0,
            null(),
        )
    };
    if raw != INVALID_HANDLE_VALUE {
        drop(unsafe { OwnedHandle::from_raw_handle(raw) });
        return Err("unprivileged client created another service pipe instance".into());
    }
    if io::Error::last_os_error().raw_os_error() != Some(ERROR_ACCESS_DENIED as i32) {
        return Err(error(
            "pipe instance creation returned a different rejection",
        ));
    }
    ping(&mut pipe)?;
    peer.verify_pipe_server(&pipe).map_err(|e| e.to_string())?;
    finish(&mut pipe)
}

fn require_rejection(
    result: std::result::Result<cfw_windows_engine::ServicePayload, ServiceTransportError>,
) -> Result<()> {
    match result {
        Err(ServiceTransportError::Io(error))
            if matches!(error.raw_os_error(), Some(109 | 232 | 233)) =>
        {
            Ok(())
        }
        Err(error) => Err(format!(
            "client rejection returned an unexpected failure: {error}"
        )),
        Ok(_) => Err("untrusted client image/role was admitted".into()),
    }
}
