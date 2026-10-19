use super::{ControlError, Result, UserAgentError};
use crate::{
    ServiceClientRole, VerifiedExecutable,
    authority::{
        AuthorityChannel, AuthoritySnapshot, ReadyReport, StoppedReport,
        wire::{BindRequest, BoundGrant, Command, Request, Response},
    },
};
use cfw_engine_api::authority_v1::{AuthorityState, COMMAND_TIMEOUT_MS};
use std::{
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    thread::{self, JoinHandle},
    time::{Duration, Instant},
};

const COMMAND: Duration = Duration::from_millis(COMMAND_TIMEOUT_MS);
const HEARTBEAT: Duration = Duration::from_secs(1);
type ControlResult<T> = std::result::Result<T, Arc<ControlError>>;
enum Work {
    Ready(
        ReadyReport,
        Instant,
        SyncSender<ControlResult<AuthoritySnapshot>>,
    ),
    Stopped(
        StoppedReport,
        Instant,
        SyncSender<ControlResult<AuthoritySnapshot>>,
    ),
    Close,
}
struct Health {
    failure: Mutex<Option<Arc<ControlError>>>,
    finished: AtomicBool,
    closing: AtomicBool,
    cancel: Arc<AtomicBool>,
}
struct Finished(Arc<Health>);
impl Drop for Finished {
    fn drop(&mut self) {
        self.0.finished.store(true, Ordering::Release);
    }
}
pub(super) struct ControlSession {
    sender: SyncSender<Work>,
    bound: Option<Receiver<ControlResult<BoundGrant>>>,
    health: Arc<Health>,
    worker: Option<JoinHandle<()>>,
}

impl ControlSession {
    pub(super) fn start(
        service: String,
        image: Arc<VerifiedExecutable>,
        binding: BindRequest,
        cancel: Arc<AtomicBool>,
    ) -> Result<Self> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let (bound_sender, bound) = mpsc::sync_channel(1);
        let health = Arc::new(Health {
            failure: Mutex::new(None),
            finished: AtomicBool::new(false),
            closing: AtomicBool::new(false),
            cancel,
        });
        let watched = Arc::clone(&health);
        let deadline = Instant::now() + COMMAND;
        let worker = thread::Builder::new()
            .name("cfw-agent-authority".into())
            .spawn(move || {
                let _finished = Finished(Arc::clone(&watched));
                if let Err(error) = run(service, image, binding, deadline, bound_sender, receiver, &watched) {
                    match watched.failure.lock() {
                        Ok(mut failure) => *failure = Some(error),
                        Err(_) => eprintln!("Windows user-agent authority failure could not be recorded: poisoned synchronization"),
                    }
                    watched.cancel.store(true, Ordering::Release);
                }
            })?;
        Ok(Self {
            sender,
            bound: Some(bound),
            health,
            worker: Some(worker),
        })
    }
    pub(super) fn wait_bound(&mut self) -> Result<BoundGrant> {
        let receiver = self.bound.take().ok_or(UserAgentError::State)?;
        self.receive(receiver, Instant::now() + COMMAND)
    }
    fn receive<T>(&self, receiver: Receiver<ControlResult<T>>, deadline: Instant) -> Result<T> {
        let result = receiver
            .recv_timeout(left(deadline).map_err(shared)?)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => shared(ControlError::Deadline),
                mpsc::RecvTimeoutError::Disconnected => self
                    .failure()
                    .err()
                    .unwrap_or_else(|| shared(ControlError::Disconnected)),
            })?;
        result.map_err(UserAgentError::Control)
    }
    pub(super) fn failure(&self) -> Result<()> {
        let failure = self
            .health
            .failure
            .lock()
            .map_err(|_| UserAgentError::Poisoned)?;
        if let Some(error) = failure.as_ref() {
            return Err(UserAgentError::Control(Arc::clone(error)));
        }
        if self.health.finished.load(Ordering::Acquire)
            && !self.health.closing.load(Ordering::Acquire)
        {
            return Err(UserAgentError::WorkerEnded);
        }
        Ok(())
    }
    fn enqueue(&self, work: Work) -> Result<()> {
        self.failure()?;
        self.sender.try_send(work).map_err(|error| {
            shared(match error {
                mpsc::TrySendError::Full(_) => ControlError::Busy,
                mpsc::TrySendError::Disconnected(_) => ControlError::Disconnected,
            })
        })
    }
    pub(super) fn ready(&self, report: ReadyReport) -> Result<AuthoritySnapshot> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let deadline = Instant::now() + COMMAND;
        self.enqueue(Work::Ready(report, deadline, sender))?;
        self.receive(receiver, deadline)
    }
    pub(super) fn stopped(&self, report: StoppedReport) -> Result<AuthoritySnapshot> {
        let (sender, receiver) = mpsc::sync_channel(1);
        let deadline = Instant::now() + COMMAND;
        self.enqueue(Work::Stopped(report, deadline, sender))?;
        self.receive(receiver, deadline)
    }
    pub(super) fn close(&mut self) -> Result<()> {
        self.health.closing.store(true, Ordering::Release);
        match self.sender.try_send(Work::Close) {
            Ok(()) | Err(mpsc::TrySendError::Full(_) | mpsc::TrySendError::Disconnected(_)) => {}
        }
        let deadline = Instant::now() + COMMAND;
        if let Some(worker) = self.worker.as_ref() {
            while !worker.is_finished() {
                left(deadline).map_err(shared)?;
                thread::sleep(Duration::from_millis(5));
            }
        }
        if let Some(worker) = self.worker.take() {
            worker.join().map_err(|_| UserAgentError::WorkerEnded)?;
        }
        Ok(())
    }
}
impl Drop for ControlSession {
    fn drop(&mut self) {
        self.health.closing.store(true, Ordering::Release);
        self.health.cancel.store(true, Ordering::Release);
        // No new request is possible once closing is observed. A bounded native
        // exchange already in progress owns its buffers until cancellation drains.
        // Normal completion explicitly joins through close(); drop is abandonment.
        if self
            .worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
        {
            eprintln!(
                "Windows user-agent authority owner dropped before worker termination was confirmed"
            );
        }
    }
}
fn shared(error: ControlError) -> UserAgentError {
    UserAgentError::Control(Arc::new(error))
}
fn left(deadline: Instant) -> std::result::Result<Duration, ControlError> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|time| !time.is_zero())
        .ok_or(ControlError::Deadline)
}
fn exchange(
    channel: &mut AuthorityChannel,
    command: Command,
    deadline: Instant,
) -> ControlResult<AuthoritySnapshot> {
    left(deadline).map_err(Arc::new)?;
    match channel
        .request(
            Request::new(command).map_err(|e| Arc::new(ControlError::Wire(e)))?,
            deadline,
        )
        .map_err(|e| Arc::new(ControlError::Wire(e)))?
    {
        Response::Status(state) => Ok(state),
        _ => Err(Arc::new(ControlError::Response)),
    }
}
fn send_result<T>(
    sender: SyncSender<ControlResult<T>>,
    result: ControlResult<T>,
) -> ControlResult<()> {
    let failure = result.as_ref().err().cloned();
    sender
        .send(result)
        .map_err(|_| Arc::new(ControlError::Disconnected))?;
    match failure {
        Some(error) => Err(error),
        None => Ok(()),
    }
}
fn run(
    service: String,
    image: Arc<VerifiedExecutable>,
    binding: BindRequest,
    deadline: Instant,
    bound: SyncSender<ControlResult<BoundGrant>>,
    receiver: Receiver<Work>,
    health: &Health,
) -> ControlResult<()> {
    let context = binding.context.clone();
    let connected = (|| {
        if health.closing.load(Ordering::Acquire) || health.cancel.load(Ordering::Acquire) {
            return Err(Arc::new(ControlError::Cancelled));
        }
        let mut channel = AuthorityChannel::connect(&service, ServiceClientRole::UserAgent, image)
            .map_err(|e| Arc::new(ControlError::Wire(e)))?;
        left(deadline).map_err(Arc::new)?;
        if health.closing.load(Ordering::Acquire) || health.cancel.load(Ordering::Acquire) {
            return Err(Arc::new(ControlError::Cancelled));
        }
        let response = channel
            .request(
                Request::new(Command::BindUserAgent(binding))
                    .map_err(|e| Arc::new(ControlError::Wire(e)))?,
                deadline,
            )
            .map_err(|e| Arc::new(ControlError::Wire(e)))?;
        let Response::Bound(grant) = response else {
            return Err(Arc::new(ControlError::Response));
        };
        Ok((channel, grant))
    })();
    let (mut channel, grant) = match connected {
        Ok(value) => value,
        Err(error) => {
            send_result(bound, Err(Arc::clone(&error)))?;
            return Err(error);
        }
    };
    send_result(bound, Ok(grant))?;
    loop {
        if health.closing.load(Ordering::Acquire) {
            return Ok(());
        }
        match receiver.recv_timeout(HEARTBEAT) {
            Ok(Work::Ready(report, deadline, reply)) => send_result(
                reply,
                exchange(&mut channel, Command::Ready(report), deadline),
            )?,
            Ok(Work::Stopped(report, deadline, reply)) => {
                let result = exchange(&mut channel, Command::Stopped(report), deadline);
                health.closing.store(true, Ordering::Release);
                send_result(reply, result)?;
                return Ok(());
            }
            Ok(Work::Close) | Err(mpsc::RecvTimeoutError::Disconnected) => return Ok(()),
            Err(mpsc::RecvTimeoutError::Timeout) => {
                let state = exchange(
                    &mut channel,
                    Command::Heartbeat(context.clone()),
                    Instant::now() + COMMAND,
                )?;
                if state.state == AuthorityState::Stopping {
                    health.cancel.store(true, Ordering::Release);
                }
            }
        }
    }
}
