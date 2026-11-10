//! Root-only M2 local control transport. Even read operations require uid 0;
//! scupper-admin ownership prepares installation, but grants no M2 authorization.
//! Socket workers decode and enqueue; the scheduler owns mutations and starts read-only checks.
use std::os::fd::AsRawFd;
static BIND_NEXT: AtomicUsize = AtomicUsize::new(0);

use scupper_proto::{ApiError, ApiErrorCode, Identifier, Op, OpResult, Request, Response, Schema};
use std::{
    collections::VecDeque,
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{DirBuilderExt, FileTypeExt, MetadataExt, OpenOptionsExt, PermissionsExt},
        net::{UnixListener, UnixStream},
    },
    path::Path,
    sync::{
        Arc, RwLock,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    time::{Duration, Instant},
};

/// Linux pathname Unix socket capacity, including the terminating NUL byte.
pub const SOCKET_PATH_LIMIT: usize = 108;

/// Report whether a run root's control socket path fits in `sun_path` when used directly. The
/// daemon and the CLI never use the path directly (they resolve through a held directory
/// descriptor), so this is for diagnostics and lab path checks only.
/// # Errors
/// Returns an invalid-input error naming paths that do not fit in `sun_path`.
pub fn validate_socket_path(root: &Path) -> io::Result<()> {
    let path = root.join("control.sock");
    let length = path.as_os_str().len();
    if length >= SOCKET_PATH_LIMIT {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "control socket path '{}' is {length} bytes; Unix socket path must be shorter than {SOCKET_PATH_LIMIT} bytes (including space for the terminating NUL)",
                path.display()
            ),
        ));
    }
    Ok(())
}

/// Maximum queue residence, including a bounded full apply and tick margin.
pub const QUEUE_TIMEOUT: Duration = Duration::from_secs(180);
/// Queue residence plus fresh verification and response margin.
pub const RESPONSE_TIMEOUT: Duration = Duration::from_secs(240);
/// Short socket wait before independent read-only observations.
pub const CHECK_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Default)]
pub(crate) struct Snapshot {
    pub ping: Option<OpResult>,
    pub last_complete: Option<Instant>,
    pub current_iteration: Option<Instant>,
    pub operation: Option<(scupper_proto::OperationProgress, Instant)>,
}
pub(crate) type SharedSnapshot = Arc<RwLock<Snapshot>>;

impl Snapshot {
    fn ping(&self) -> Result<OpResult, ApiError> {
        let mut ping = self
            .ping
            .clone()
            .ok_or_else(|| api(ApiErrorCode::SupervisorUnavailable))?;
        if let OpResult::Ping {
            last_complete_iteration_age,
            current_iteration_age,
            operation,
            ..
        } = &mut ping
        {
            *last_complete_iteration_age = self.last_complete.map(|at| at.elapsed().as_secs());
            *current_iteration_age = self.current_iteration.map(|at| at.elapsed().as_secs());
            *operation = self.operation.as_ref().map(|(progress, start)| {
                let mut progress = progress.clone();
                progress.age = start.elapsed().as_secs();
                progress
            });
        }
        Ok(ping)
    }
}

#[derive(Default)]
pub(crate) struct FailureSummary {
    last: Option<Instant>,
    count: u64,
}
impl FailureSummary {
    pub(crate) fn record(&mut self, now: Instant) -> Option<u64> {
        self.count = self.count.saturating_add(1);
        if self
            .last
            .is_some_and(|at| now.saturating_duration_since(at) < Duration::from_secs(60))
        {
            return None;
        }
        self.last = Some(now);
        Some(std::mem::take(&mut self.count))
    }
}

pub(crate) fn api(code: ApiErrorCode) -> ApiError {
    ApiError {
        code,
        observation: None,
    }
}

pub(crate) fn peer_connected(peer: &UnixStream) -> bool {
    let mut byte = [0];
    match rustix::net::recv(
        peer,
        &mut byte,
        rustix::net::RecvFlags::PEEK | rustix::net::RecvFlags::DONTWAIT,
    ) {
        Ok((0, _)) => false,
        Ok(_) | Err(rustix::io::Errno::WOULDBLOCK) => true,
        Err(_) => false,
    }
}

/// All M2 operations, including reads, require a root peer.
#[must_use]
pub fn authorized(uid: u32) -> bool {
    uid == 0
}

/// Decode one newline-terminated request without allocating an unbounded line.
/// # Errors
/// Refuses EOF, oversized or malformed requests and read timeouts.
pub fn read_request(reader: impl Read) -> io::Result<Request> {
    let mut line = Vec::new();
    BufReader::new(reader.take((scupper_proto::MAX_REQUEST_SIZE + 1) as u64))
        .read_until(b'\n', &mut line)?;
    if line.last() != Some(&b'\n') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unterminated control request",
        ));
    }
    scupper_proto::decode_request(&line).map_err(io::Error::other)
}

fn validate_directory(meta: &fs::Metadata, owner: u32) -> io::Result<()> {
    if !meta.is_dir() || meta.uid() != owner || meta.mode() & 0o022 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "control directory must be root-owned and not writable by group or others",
        ));
    }
    Ok(())
}
struct SocketStage(std::path::PathBuf);
impl Drop for SocketStage {
    fn drop(&mut self) {
        let _ = fs::remove_file(self.0.join("control.sock"));
        let _ = fs::remove_dir(&self.0);
    }
}

pub(crate) struct Pending {
    pub request: Request,
    pub uid: u32,
    pub until: Instant,
    pub reply: SyncSender<Response>,
    pub peer: Option<UnixStream>,
}

/// Listener lifetime. Shutdown never unlinks a replacement socket.
pub struct Server {
    pub(crate) receive: Receiver<Pending>,
    pub(crate) errors: Receiver<String>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    pub(crate) fn alive(&self) -> bool {
        self.worker
            .as_ref()
            .is_some_and(|worker| !worker.is_finished())
    }
    /// Bind the root-owned local socket. A stale root-owned socket may be removed;
    /// any other existing filesystem object is refused. Missing group uses root.
    /// # Errors
    /// Returns ownership, bind, permission or thread-start errors.
    #[allow(clippy::too_many_lines)] // Keep guarded publication and listener ownership together.
    pub fn bind(root: &Path) -> io::Result<Self> {
        Self::bind_snapshot(root, SharedSnapshot::default())
    }
    pub(crate) fn bind_snapshot(root: &Path, snapshot: SharedSnapshot) -> io::Result<Self> {
        Self::bind_owned(root, snapshot, 0, None)
    }
    #[allow(clippy::too_many_lines)] // Guarded publication retains one directory capability.
    fn bind_owned(
        root: &Path,
        snapshot: SharedSnapshot,
        owner: u32,
        group: Option<u32>,
    ) -> io::Result<Self> {
        fs::create_dir_all(root)?;
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW)
                    .bits()
                    .cast_signed(),
            )
            .open(root)?;
        validate_directory(&directory.metadata()?, owner)?;
        // Resolve through the held directory, so replacing a parent path cannot redirect writes.
        let root = std::path::PathBuf::from(format!("/proc/self/fd/{}/.", directory.as_raw_fd()));
        let path = root.join("control.sock");
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_socket() && meta.uid() == owner => {
                match UnixStream::connect(&path) {
                    Err(e) if e.kind() == io::ErrorKind::ConnectionRefused => {
                        fs::remove_file(&path)?;
                    }
                    Err(e) => return Err(e),
                    Ok(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::AddrInUse,
                            "control socket is live",
                        ));
                    }
                }
            }
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "unsafe existing control socket",
                ));
            }
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(e) => return Err(e),
        }
        let temporary = root.join(format!(
            ".control-{}-{}",
            std::process::id(),
            BIND_NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::DirBuilder::new().mode(0o700).create(&temporary)?;
        let stage = SocketStage(temporary);
        let staged = stage.0.join("control.sock");
        let listener = UnixListener::bind(&staged)?;
        let bound = fs::symlink_metadata(&staged)?;
        let gid = match group {
            Some(group) => group,
            None => fs::read_to_string("/etc/group")?
                .lines()
                .find_map(|line| {
                    let mut fields = line.split(':');
                    (fields.next()? == "scupper-admin")
                        .then(|| fields.nth(1)?.parse::<u32>().ok())
                        .flatten()
                })
                .unwrap_or(0),
        };
        std::os::unix::fs::chown(&staged, Some(owner), Some(gid))?;
        fs::set_permissions(&staged, fs::Permissions::from_mode(0o660))?;
        fs::rename(&staged, &path)?;
        let identity = fs::symlink_metadata(&path)?;
        if identity.dev() != bound.dev()
            || identity.ino() != bound.ino()
            || !identity.file_type().is_socket()
        {
            return Err(io::Error::other(
                "control socket identity changed during bind",
            ));
        }
        drop(stage);
        listener.set_nonblocking(true)?;
        let (send, receive) = mpsc::sync_channel(16);
        let (errors_send, errors) = mpsc::sync_channel(8);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let worker = std::thread::Builder::new()
            .name("scupper-control".into())
            .spawn(move || {
                let _directory = directory;
                accept_loop(
                    &stopping,
                    || listener.accept().map(|(stream, _)| stream),
                    |stream| {
                        if !reserve_peer(&stream, &active) {
                            return;
                        }
                        let send = send.clone();
                        let count = active.clone();
                        let snapshot = snapshot.clone();
                        if std::thread::Builder::new()
                            .name("scupper-control-peer".into())
                            .spawn(move || {
                                let _ = serve(stream, &send, &snapshot);
                                count.fetch_sub(1, Ordering::Relaxed);
                            })
                            .is_err()
                        {
                            active.fetch_sub(1, Ordering::Relaxed);
                        }
                    },
                    |error| {
                        let _ = errors_send.try_send(error.to_string());
                    },
                );
                if fs::symlink_metadata(&path)
                    .is_ok_and(|m| m.dev() == identity.dev() && m.ino() == identity.ino())
                {
                    let _ = fs::remove_file(path);
                }
            })?;
        Ok(Self {
            receive,
            errors,
            stop,
            worker: Some(worker),
        })
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
struct DeadlineRead<'a> {
    stream: &'a UnixStream,
    until: Instant,
}
impl Read for DeadlineRead<'_> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        let remaining = self.until.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "control request timeout",
            ));
        }
        self.stream.set_read_timeout(Some(remaining))?;
        self.stream.read(buffer)
    }
}
fn accept_loop(
    stop: &AtomicBool,
    mut accept: impl FnMut() -> io::Result<UnixStream>,
    mut serve: impl FnMut(UnixStream),
    mut error: impl FnMut(&io::Error),
) {
    while !stop.load(Ordering::Relaxed) {
        match accept() {
            Ok(stream) => serve(stream),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                std::thread::sleep(Duration::from_millis(10));
            }
            Err(e) => {
                error(&e);
                std::thread::sleep(Duration::from_millis(100));
            }
        }
    }
}
fn reserve_authorized_peer(uid: u32, active: &AtomicUsize) -> bool {
    if !authorized(uid) || active.load(Ordering::Relaxed) >= 16 {
        return false;
    }
    active.fetch_add(1, Ordering::Relaxed);
    true
}
fn reserve_peer(stream: &UnixStream, active: &AtomicUsize) -> bool {
    rustix::net::sockopt::socket_peercred(stream)
        .is_ok_and(|peer| reserve_authorized_peer(peer.uid.as_raw(), active))
}

fn serve(
    mut stream: UnixStream,
    send: &SyncSender<Pending>,
    snapshot: &SharedSnapshot,
) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let uid = rustix::net::sockopt::socket_peercred(&stream)?.uid.as_raw();
    let request = read_request(DeadlineRead {
        stream: &stream,
        until: Instant::now() + Duration::from_secs(5),
    })?;
    let response = answer(request, uid, send, snapshot, Some(&stream))?;
    serde_json::to_writer(&mut stream, &response)?;
    stream.write_all(b"\n")
}

fn answer(
    request: Request,
    uid: u32,
    send: &SyncSender<Pending>,
    snapshot: &SharedSnapshot,
    peer: Option<&UnixStream>,
) -> io::Result<Response> {
    Ok(if authorized(uid) && matches!(request.op, Op::Ping {}) {
        let result = snapshot
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .ping();
        response(request.request_id, result)
    } else if authorized(uid) {
        let (reply, receive) = mpsc::sync_channel(1);
        send.try_send(Pending {
            request,
            uid,
            until: Instant::now() + QUEUE_TIMEOUT,
            reply,
            peer: peer.map(UnixStream::try_clone).transpose()?,
        })
        .map_err(io::Error::other)?;
        let deadline = Instant::now() + RESPONSE_TIMEOUT;
        loop {
            match receive.recv_timeout(Duration::from_millis(100)) {
                Ok(response) => break response,
                Err(mpsc::RecvTimeoutError::Timeout)
                    if Instant::now() < deadline && peer.is_none_or(peer_connected) => {}
                Err(error) => return Err(io::Error::other(error)),
            }
        }
    } else {
        Response {
            request_id: request.request_id,
            schema: Schema,
            replayed: false,
            observed_at: None,
            result: Err(api(ApiErrorCode::Unauthorized)),
        }
    })
}

pub(crate) fn response(request_id: Identifier, result: Result<OpResult, ApiError>) -> Response {
    Response {
        request_id,
        schema: Schema,
        replayed: false,
        observed_at: Some(scupper_proto::UnixSeconds(super::unix())),
        result,
    }
}

/// Tick-owned bounded outcomes retained for ten-minute retry deduplication.
#[derive(Default)]
pub struct Dedupe {
    entries: VecDeque<(Instant, Op, Response)>,
}
impl Dedupe {
    pub(crate) fn lookup(&mut self, request: &Request, now: Instant) -> Option<Response> {
        self.entries
            .retain(|(at, _, _)| now.saturating_duration_since(*at) < Duration::from_secs(600));
        self.entries
            .iter()
            .find(|(_, _, r)| r.request_id == request.request_id)
            .map(|(_, op, cached)| {
                if op == &request.op {
                    let mut replay = cached.clone();
                    replay.replayed = true;
                    replay
                } else {
                    response(request.request_id.clone(), Err(api(ApiErrorCode::Conflict)))
                }
            })
    }
    pub(crate) fn remember(&mut self, request: Request, response: Response, now: Instant) {
        if matches!(
            response.result,
            Err(ApiError {
                code: ApiErrorCode::Timeout | ApiErrorCode::SupervisorUnavailable,
                ..
            })
        ) || matches!(
            request.op,
            Op::Ping {} | Op::Check {} | Op::Status {} | Op::RepairStatus {}
        ) {
            return;
        }
        while self.entries.len() >= 256 {
            self.entries.pop_front();
        }
        self.entries.push_back((now, request.op, response));
    }
    /// Execute at most once per identifier and operation within the retention window.
    pub fn execute(
        &mut self,
        request: Request,
        now: Instant,
        run: impl FnOnce(Op) -> Result<OpResult, ApiError>,
    ) -> Response {
        if let Some(cached) = self.lookup(&request, now) {
            return cached;
        }
        let response = response(request.request_id.clone(), run(request.op.clone()));
        self.remember(request, response.clone(), now);
        response
    }
}

/// Failure before delivery permits local fallback; an uncertain outcome must never
/// be replayed as a local mutation.
#[derive(Debug)]
pub enum ClientError {
    /// No request was delivered.
    Unavailable(io::Error),
    /// A sent request may have executed; retain its request identifier.
    OutcomeUnknown(io::Error),
}
/// Send one correlated operation, bounded by a single response deadline.
/// # Errors
/// Distinguishes unavailable transport from an uncertain delivered outcome.
pub fn call(root: &Path, request: &Request, timeout: Duration) -> Result<Response, ClientError> {
    // Connect through a held directory descriptor so the run root's length never meets the
    // 108-byte `sun_path` limit; the descriptor stays open until the connect returns.
    let directory = fs::OpenOptions::new()
        .read(true)
        .custom_flags(rustix::fs::OFlags::DIRECTORY.bits().cast_signed())
        .open(root)
        .map_err(ClientError::Unavailable)?;
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
        .map_err(ClientError::Unavailable)?;
    let address = socket2::SockAddr::unix(format!(
        "/proc/self/fd/{}/control.sock",
        directory.as_raw_fd()
    ))
    .map_err(ClientError::Unavailable)?;
    let deadline = Instant::now() + timeout;
    socket
        .connect_timeout(&address, timeout.min(Duration::from_secs(2)))
        .map_err(ClientError::Unavailable)?;
    let mut stream = UnixStream::from(std::os::fd::OwnedFd::from(socket));
    stream
        .set_read_timeout(Some(
            deadline
                .saturating_duration_since(Instant::now())
                .max(Duration::from_millis(1)),
        ))
        .map_err(ClientError::Unavailable)?;
    stream
        .set_write_timeout(Some(Duration::from_secs(1)))
        .map_err(ClientError::Unavailable)?;
    let mut bytes =
        serde_json::to_vec(request).map_err(|e| ClientError::Unavailable(io::Error::other(e)))?;
    bytes.push(b'\n');
    stream
        .write_all(&bytes)
        .map_err(ClientError::OutcomeUnknown)?;
    let mut line = Vec::new();
    let mut reader = BufReader::new(stream);
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(ClientError::OutcomeUnknown(io::Error::new(
                io::ErrorKind::TimedOut,
                "control response timeout",
            )));
        }
        reader
            .get_ref()
            .set_read_timeout(Some(remaining))
            .map_err(ClientError::OutcomeUnknown)?;
        let buffer = reader.fill_buf().map_err(ClientError::OutcomeUnknown)?;
        if buffer.is_empty() || line.len() + buffer.len() > 1024 * 1024 {
            return Err(ClientError::OutcomeUnknown(io::Error::other(
                "invalid control response",
            )));
        }
        let end = buffer.iter().position(|b| *b == b'\n');
        let len = end.map_or(buffer.len(), |i| i + 1);
        line.extend_from_slice(&buffer[..len]);
        reader.consume(len);
        if end.is_some() {
            break;
        }
    }
    let response: Response = serde_json::from_slice(&line)
        .map_err(|e| ClientError::OutcomeUnknown(io::Error::other(e)))?;
    if response.request_id != request.request_id
        || response.result.as_ref().is_ok_and(|result| {
            !matches!(
                (&request.op, result),
                (Op::Ping {}, OpResult::Ping { .. })
                    | (Op::Status {}, OpResult::Status { .. })
                    | (Op::Check {}, OpResult::Check { .. })
                    | (Op::Connect { .. }, OpResult::Connect { .. })
                    | (Op::Disconnect {}, OpResult::Disconnect {})
                    | (Op::Apply { .. }, OpResult::Apply { .. })
                    | (Op::Commit { .. }, OpResult::Commit { .. })
                    | (Op::RepairStatus {}, OpResult::RepairStatus { .. })
                    | (Op::RepairClear { .. }, OpResult::RepairClear {})
            )
        })
    {
        return Err(ClientError::OutcomeUnknown(io::Error::other(
            "control response id or operation mismatch",
        )));
    }
    Ok(response)
}
/// Generate a non-secret, unique operational request id without credentials.
#[must_use]
pub fn request(op: Op) -> Request {
    use sha2::{Digest, Sha256};
    use std::fmt::Write as _;
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let mut random = [0u8; 8];
    let _ = rustix::rand::getrandom(&mut random, rustix::rand::GetRandomFlags::empty());
    let hash = Sha256::new()
        .chain_update(std::process::id().to_ne_bytes())
        .chain_update(nanos.to_ne_bytes())
        .chain_update(random)
        .chain_update(NEXT.fetch_add(1, Ordering::Relaxed).to_ne_bytes())
        .finalize();
    let mut value = String::from("r-");
    for byte in &hash[..15] {
        let _ = write!(value, "{byte:02x}");
    }
    Request {
        request_id: Identifier::from(&scupper_core::config::ExitId(value)),
        op,
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn client_connects_through_run_roots_longer_than_sun_path() {
        let temporary = Path::new(env!("CARGO_TARGET_TMPDIR"));
        let root = temporary.join(format!(
            "long-{}-{}",
            std::process::id(),
            "x".repeat(SOCKET_PATH_LIMIT)
        ));
        fs::create_dir_all(&root).unwrap();
        assert!(root.join("control.sock").as_os_str().len() >= SOCKET_PATH_LIMIT);
        assert!(validate_socket_path(&root).is_err());
        let directory = fs::File::open(&root).unwrap();
        let listener = UnixListener::bind(format!(
            "/proc/self/fd/{}/control.sock",
            directory.as_raw_fd()
        ))
        .unwrap();
        let accepted = std::thread::spawn(move || listener.accept().is_ok());
        // The listener never answers: a delivered request is OutcomeUnknown, never Unavailable.
        let result = call(&root, &request(Op::Ping {}), Duration::from_millis(300));
        assert!(
            matches!(result, Err(ClientError::OutcomeUnknown(_))),
            "long run root must still connect: {result:?}"
        );
        assert!(accepted.join().unwrap());
        fs::remove_dir_all(&root).unwrap();
        for (bytes, valid) in [(107, true), (108, false)] {
            let root = std::path::PathBuf::from(format!("/{}", "x".repeat(bytes - 14)));
            assert_eq!(root.join("control.sock").as_os_str().len(), bytes);
            assert_eq!(validate_socket_path(&root).is_ok(), valid);
        }
    }

    #[test]
    fn bounds_ids_and_unknown_fields() {
        for line in [
            b"".as_slice(),
            b"{}\n",
            b"{\"request_id\":\"bad/id\",\"op\":{\"kind\":\"Ping\",\"args\":{}}}\n",
            b"{\"request_id\":\"r1\",\"op\":{\"kind\":\"Ping\",\"args\":{\"extra\":0}}}\n",
        ] {
            assert!(read_request(line).is_err());
        }
        let mut bytes = serde_json::to_vec(&request(Op::Ping {})).unwrap();
        assert!(read_request(bytes.as_slice()).is_err());
        bytes.resize(scupper_proto::MAX_REQUEST_SIZE - 1, b' ');
        bytes.push(b'\n');
        assert!(read_request(bytes.as_slice()).is_ok());
        bytes.insert(0, b' ');
        assert!(read_request(bytes.as_slice()).is_err());
        assert!(!authorized(1));
        assert!(!authorized(1000));
        assert!(authorized(0));
    }
    #[test]
    fn dedupe_success_failure_and_ten_minute_expiry() {
        let now = Instant::now();
        let mut cache = Dedupe::default();
        let original = request(Op::Disconnect {});
        let first = cache.execute(original.clone(), now, |_| Ok(OpResult::Disconnect {}));
        let duplicate = cache.execute(original.clone(), now + Duration::from_secs(599), |_| {
            unreachable!("dedupe executed twice")
        });
        assert!(!first.replayed);
        assert!(duplicate.replayed);
        assert_eq!(first.result, duplicate.result);
        assert_eq!(first.observed_at, duplicate.observed_at);
        let expired = cache.execute(original.clone(), now + Duration::from_secs(600), |_| {
            Err(api(ApiErrorCode::DisconnectNotEffective))
        });
        assert!(expired.result.is_err());
        let replay = cache.execute(original, now + Duration::from_secs(601), |_| {
            unreachable!("failed response reexecuted")
        });
        assert!(replay.replayed);
        assert_eq!(expired.result, replay.result);
    }
    #[test]
    fn socket_client_timeout_is_bounded_and_marks_uncertain_delivery() {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || {
                    std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/tmp"
                    ))
                },
                std::path::PathBuf::from,
            )
            .join(format!("ct-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let directory = fs::File::open(&root).unwrap();
        let socket_root =
            std::path::PathBuf::from(format!("/proc/self/fd/{}/.", directory.as_raw_fd()));
        let listener = UnixListener::bind(socket_root.join("control.sock")).unwrap();
        let worker = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            read_request(&stream).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let start = Instant::now();
        assert!(matches!(
            call(
                &socket_root,
                &request(Op::Ping {}),
                Duration::from_millis(50)
            ),
            Err(ClientError::OutcomeUnknown(_))
        ));
        assert!(start.elapsed() < Duration::from_millis(180));
        worker.join().unwrap();
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn real_peer_credentials_refuse_non_root_before_dispatch_and_echo_ids() {
        let (server, mut client) = UnixStream::pair().unwrap();
        let uid = rustix::net::sockopt::socket_peercred(&server)
            .unwrap()
            .uid
            .as_raw();
        assert_eq!(uid, rustix::process::geteuid().as_raw());
        let (send, receive) = mpsc::sync_channel(1);
        let worker =
            std::thread::spawn(move || serve(server, &send, &SharedSnapshot::default()).unwrap());
        let original = request(Op::Disconnect {});
        serde_json::to_writer(&mut client, &original).unwrap();
        client.write_all(b"\n").unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        if uid == 0 {
            let pending = receive.recv_timeout(Duration::from_secs(2)).unwrap();
            assert_eq!(pending.uid, 0);
            pending
                .reply
                .send(Response {
                    request_id: pending.request.request_id,
                    schema: Schema,
                    replayed: false,
                    observed_at: None,
                    result: Ok(OpResult::Disconnect {}),
                })
                .unwrap();
        }
        let mut line = String::new();
        BufReader::new(client).read_line(&mut line).unwrap();
        let response: Response = serde_json::from_str(&line).unwrap();
        assert_eq!(response.request_id, original.request_id);
        if uid != 0 {
            assert_eq!(
                response.result.unwrap_err().code,
                ApiErrorCode::Unauthorized
            );
            assert!(receive.try_recv().is_err());
        }
        worker.join().unwrap();
    }
    #[test]
    fn partial_lines_obey_an_absolute_read_deadline() {
        let (stream, _held_open) = UnixStream::pair().unwrap();
        let start = Instant::now();
        let result = read_request(DeadlineRead {
            stream: &stream,
            until: start + Duration::from_millis(40),
        });
        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_millis(300));
    }
    #[test]
    fn dedupe_conflict_timeout_retry_and_capacity() {
        let now = Instant::now();
        let mut cache = Dedupe::default();
        let original = request(Op::Disconnect {});
        cache.execute(original.clone(), now, |_| Ok(OpResult::Disconnect {}));
        let mut different = original.clone();
        different.op = Op::Connect { exit: None };
        assert_eq!(
            cache
                .execute(different, now, |_| unreachable!())
                .result
                .unwrap_err()
                .code,
            ApiErrorCode::Conflict
        );
        let delayed = request(Op::Disconnect {});
        assert!(
            cache
                .execute(delayed.clone(), now, |_| Err(api(ApiErrorCode::Timeout)))
                .result
                .is_err()
        );
        assert!(
            cache
                .execute(delayed, now, |_| Ok(OpResult::Disconnect {}))
                .result
                .is_ok()
        );
        let unavailable = request(Op::Disconnect {});
        cache.execute(unavailable.clone(), now, |_| {
            Err(api(ApiErrorCode::SupervisorUnavailable))
        });
        assert!(
            cache
                .execute(unavailable, now, |_| Ok(OpResult::Disconnect {}))
                .result
                .is_ok()
        );
        for _ in 0..300 {
            cache.execute(request(Op::Disconnect {}), now, |_| {
                Ok(OpResult::Disconnect {})
            });
        }
        assert_eq!(cache.entries.len(), 256);
        assert!(cache.lookup(&original, now).is_none());
    }
    #[test]
    fn accept_errors_retry_until_shutdown() {
        let stop = AtomicBool::new(false);
        let count = AtomicUsize::new(0);
        accept_loop(
            &stop,
            || Err(io::Error::from_raw_os_error(24)),
            |_| unreachable!(),
            |_| {
                if count.fetch_add(1, Ordering::Relaxed) == 2 {
                    stop.store(true, Ordering::Relaxed);
                }
            },
        );
        assert_eq!(count.load(Ordering::Relaxed), 3);
    }
    #[test]
    fn unauthorized_peers_are_rejected_without_reading_or_using_slots() {
        let (stream, _client_with_no_request) = UnixStream::pair().unwrap();
        let started = Instant::now();
        let active = AtomicUsize::new(0);
        assert_eq!(
            reserve_peer(&stream, &active),
            rustix::process::geteuid().as_raw() == 0
        );
        assert!(started.elapsed() < Duration::from_millis(100));
        let active = AtomicUsize::new(0);
        for _ in 0..64 {
            for uid in [1, 1000, 65534] {
                assert!(!reserve_authorized_peer(uid, &active));
            }
        }
        assert_eq!(active.load(Ordering::Relaxed), 0);
        for _ in 0..16 {
            assert!(reserve_authorized_peer(0, &active));
        }
        assert!(!reserve_authorized_peer(0, &active));
        assert_eq!(active.load(Ordering::Relaxed), 16);
    }
    #[test]
    fn unsafe_control_directory_is_refused() {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || {
                    std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/tmp"
                    ))
                },
                std::path::PathBuf::from,
            )
            .join(format!("unsafe-control-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        let directory = fs::File::open(&root).unwrap();
        let socket_root =
            std::path::PathBuf::from(format!("/proc/self/fd/{}/.", directory.as_raw_fd()));
        let owner = rustix::process::geteuid().as_raw();
        assert_eq!(
            Server::bind_owned(
                &socket_root,
                SharedSnapshot::default(),
                owner,
                Some(rustix::process::getegid().as_raw())
            )
            .err()
            .unwrap()
            .kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(fs::metadata(&root).unwrap().uid(), owner);
        assert!(!root.join("control.sock").exists());
        fs::remove_dir(root).unwrap();
    }
    #[test]
    fn generated_request_ids_are_valid_unique_and_bounded() {
        let ids: std::collections::BTreeSet<_> = (0..512)
            .map(|_| String::from(request(Op::Ping {}).request_id))
            .collect();
        assert_eq!(ids.len(), 512);
        assert!(ids.iter().all(|id| id.len() == 32 && id != "invalid-id"));
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod round_two_tests {
    use super::*;
    fn root(label: &str) -> std::path::PathBuf {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || {
                    std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/tmp"
                    ))
                },
                std::path::PathBuf::from,
            )
            .join(format!("{label}-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        root
    }
    #[test]
    fn ping_snapshot_does_not_wait_for_dispatch() {
        let root = root("ping");
        let guard = crate::lock::WriterLock::acquire(&root).unwrap();
        let snapshot = SharedSnapshot::default();
        let ping = OpResult::Ping {
            last_complete_iteration_age: None,
            current_iteration_age: None,
            operation: None,
            netns: scupper_core::verdict::v2::NetnsIdentity {
                device: 5,
                inode: 7,
            },
            version: 11,
            quarantined: true,
            selection: scupper_core::verdict::v2::Selection::Disconnected,
        };
        *snapshot.write().unwrap() = Snapshot {
            operation: None,
            ping: Some(ping),
            last_complete: Instant::now().checked_sub(Duration::from_secs(3)),
            current_iteration: Instant::now().checked_sub(Duration::from_secs(6)),
        };
        let (send, receive) = mpsc::sync_channel(1);
        // No tick owner drains this queue. Ping still answers under writer contention.
        let start = Instant::now();
        let response = answer(request(Op::Ping {}), 0, &send, &snapshot, None).unwrap();
        assert!(start.elapsed() < Duration::from_millis(100));
        assert!(matches!(
            response.result,
            Ok(OpResult::Ping {
                version: 11,
                quarantined: true,
                last_complete_iteration_age: Some(3),
                current_iteration_age: Some(6),
                selection: scupper_core::verdict::v2::Selection::Disconnected,
                ..
            })
        ));
        assert!(receive.try_recv().is_err());
        snapshot.write().unwrap().last_complete = None;
        snapshot.write().unwrap().operation = Some((
            scupper_proto::OperationProgress {
                kind: scupper_proto::OperationKind::Apply,
                from: 11,
                to: 12,
                age: 0,
            },
            Instant::now().checked_sub(Duration::from_secs(7)).unwrap(),
        ));
        assert!(matches!(
            answer(request(Op::Ping {}), 0, &send, &snapshot, None)
                .unwrap()
                .result,
            Ok(OpResult::Ping {
                last_complete_iteration_age: None,
                operation: Some(scupper_proto::OperationProgress {
                    from: 11,
                    to: 12,
                    age: 7,
                    ..
                }),
                ..
            })
        ));
        drop(guard);
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn bind_publication_stale_removal_replacement_and_rebind() {
        let root = root("bind2");
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        let owner = rustix::process::geteuid().as_raw();
        let group = Some(rustix::process::getegid().as_raw());
        // Bind via a directory capability to keep sockaddr_un short in deep worktrees.
        let dir = fs::File::open(&root).unwrap();
        let socket_root = std::path::PathBuf::from(format!("/proc/self/fd/{}/.", dir.as_raw_fd()));
        let path = socket_root.join("control.sock");
        drop(UnixListener::bind(&path).unwrap());
        if let Err(error) = fs::set_permissions(&path, fs::Permissions::from_mode(0o660)) {
            // Some shared worktree filesystems cannot chmod Unix sockets.
            // Refusal is mandatory there; never turn this into a mode bypass.
            assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
                ),
                "{error}"
            );
            let error = Server::bind_owned(&socket_root, SharedSnapshot::default(), owner, group)
                .err()
                .unwrap();
            assert!(
                matches!(
                    error.kind(),
                    io::ErrorKind::InvalidInput | io::ErrorKind::Unsupported
                ),
                "{error}"
            );
            assert!(!fs::read_dir(&root).unwrap().any(|entry| {
                entry
                    .unwrap()
                    .file_name()
                    .to_string_lossy()
                    .starts_with(".control-")
            }));
            assert!(
                std::env::var_os("CI").is_none(),
                "CI must exercise socket publication: {error}"
            );
            eprintln!(
                "socket chmod unsupported: verified fail-closed bind; publication checks require a supporting filesystem"
            );
            fs::remove_dir_all(root).unwrap();
            return;
        }
        let first =
            Server::bind_owned(&socket_root, SharedSnapshot::default(), owner, group).unwrap();
        assert!(first.alive());
        let metadata = fs::metadata(&path).unwrap();
        assert_eq!(metadata.uid(), owner);
        assert_eq!(metadata.mode() & 0o777, 0o660);
        assert!(Server::bind_owned(&socket_root, SharedSnapshot::default(), owner, group).is_err());
        // A listener must not unlink a replacement when it dies.
        fs::remove_file(&path).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        let inode = fs::metadata(&path).unwrap().ino();
        drop(first);
        assert_eq!(fs::metadata(&path).unwrap().ino(), inode);
        drop(replacement);
        let second =
            Server::bind_owned(&socket_root, SharedSnapshot::default(), owner, group).unwrap();
        second.stop.store(true, Ordering::Relaxed);
        let deadline = Instant::now() + Duration::from_secs(2);
        while second.alive() {
            assert!(Instant::now() < deadline);
            std::thread::sleep(Duration::from_millis(10));
        }
        drop(second);
        let third =
            Server::bind_owned(&socket_root, SharedSnapshot::default(), owner, group).unwrap();
        assert!(third.alive());
        drop(third);
        assert!(!path.exists());
        fs::remove_dir_all(root).unwrap();
    }
    #[test]
    fn control_failures_are_counted_once_per_minute() {
        let now = Instant::now();
        let mut summary = FailureSummary::default();
        assert_eq!(summary.record(now), Some(1));
        for offset in 1..600 {
            assert_eq!(
                summary.record(now + Duration::from_millis(offset * 100)),
                None
            );
        }
        assert_eq!(summary.record(now + Duration::from_secs(60)), Some(600));
        assert_eq!(summary.record(now + Duration::from_secs(120)), Some(1));
    }
}
