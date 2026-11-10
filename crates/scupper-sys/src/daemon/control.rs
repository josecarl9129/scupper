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
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
        mpsc::{self, Receiver, SyncSender},
    },
    time::{Duration, Instant},
};

pub(crate) fn api(code: ApiErrorCode) -> ApiError {
    ApiError {
        code,
        observation: None,
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

fn validate_directory(meta: &fs::Metadata) -> io::Result<()> {
    if !meta.is_dir() || meta.uid() != 0 || meta.mode() & 0o022 != 0 {
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
        fs::create_dir_all(root)?;
        let directory = fs::OpenOptions::new()
            .read(true)
            .custom_flags(
                (rustix::fs::OFlags::DIRECTORY | rustix::fs::OFlags::NOFOLLOW)
                    .bits()
                    .cast_signed(),
            )
            .open(root)?;
        validate_directory(&directory.metadata()?)?;
        // Resolve through the held directory, so replacing a parent path cannot redirect writes.
        let root = std::path::PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()));
        let path = root.join("control.sock");
        match fs::symlink_metadata(&path) {
            Ok(meta) if meta.file_type().is_socket() && meta.uid() == 0 => {
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
        let gid = fs::read_to_string("/etc/group")?
            .lines()
            .find_map(|line| {
                let mut fields = line.split(':');
                (fields.next()? == "scupper-admin")
                    .then(|| fields.nth(1)?.parse::<u32>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        std::os::unix::fs::chown(&staged, Some(0), Some(gid))?;
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
                        if std::thread::Builder::new()
                            .name("scupper-control-peer".into())
                            .spawn(move || {
                                let _ = serve(stream, &send);
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

fn serve(mut stream: UnixStream, send: &SyncSender<Pending>) -> io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(5)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let uid = rustix::net::sockopt::socket_peercred(&stream)?.uid.as_raw();
    let request = read_request(DeadlineRead {
        stream: &stream,
        until: Instant::now() + Duration::from_secs(5),
    })?;
    let response = if authorized(uid) {
        let (reply, receive) = mpsc::sync_channel(1);
        send.try_send(Pending {
            request,
            uid,
            until: Instant::now() + Duration::from_secs(2),
            reply,
        })
        .map_err(io::Error::other)?;
        receive
            .recv_timeout(Duration::from_secs(50))
            .map_err(io::Error::other)?
    } else {
        Response {
            request_id: request.request_id,
            schema: Schema,
            replayed: false,
            observed_at: None,
            result: Err(api(ApiErrorCode::Unauthorized)),
        }
    };
    serde_json::to_writer(&mut stream, &response)?;
    stream.write_all(b"\n")
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
    let socket = socket2::Socket::new(socket2::Domain::UNIX, socket2::Type::STREAM, None)
        .map_err(ClientError::Unavailable)?;
    let address =
        socket2::SockAddr::unix(root.join("control.sock")).map_err(ClientError::Unavailable)?;
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
        let root =
            std::path::PathBuf::from("../../target").join(format!("ct-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let listener = UnixListener::bind(root.join("control.sock")).unwrap();
        let worker = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            read_request(&stream).unwrap();
            std::thread::sleep(Duration::from_millis(200));
        });
        let start = Instant::now();
        assert!(matches!(
            call(&root, &request(Op::Ping {}), Duration::from_millis(50)),
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
        let worker = std::thread::spawn(move || serve(server, &send).unwrap());
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
        let root = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target")
            .join(format!("unsafe-control-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Server::bind(&root).is_err());
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
