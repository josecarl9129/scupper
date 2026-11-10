//! Root-only M2 local control transport. Even read operations require uid 0;
//! scupper-admin ownership prepares installation, but grants no M2 authorization.
//! Socket workers only decode and enqueue: the tick owner executes every request.
use scupper_proto::{ApiError, ApiErrorCode, Identifier, Op, OpResult, Request, Response, Schema};
use std::{
    collections::VecDeque,
    fs,
    io::{self, BufRead, BufReader, Read, Write},
    os::unix::{
        fs::{FileTypeExt, MetadataExt, PermissionsExt},
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

pub(crate) struct Pending {
    pub request: Request,
    pub uid: u32,
    pub until: Instant,
    pub reply: SyncSender<Response>,
}

/// Listener lifetime. Shutdown never unlinks a replacement socket.
pub struct Server {
    pub(crate) receive: Receiver<Pending>,
    stop: Arc<AtomicBool>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl Server {
    /// Bind the root-owned local socket. A stale root-owned socket may be removed;
    /// any other existing filesystem object is refused. Missing group uses root.
    /// # Errors
    /// Returns ownership, bind, permission or thread-start errors.
    pub fn bind(root: &Path) -> io::Result<Self> {
        fs::create_dir_all(root)?;
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
        let listener = UnixListener::bind(&path)?;
        let gid = fs::read_to_string("/etc/group")?
            .lines()
            .find_map(|line| {
                let mut fields = line.split(':');
                (fields.next()? == "scupper-admin")
                    .then(|| fields.nth(1)?.parse::<u32>().ok())
                    .flatten()
            })
            .unwrap_or(0);
        std::os::unix::fs::chown(&path, Some(0), Some(gid))?;
        fs::set_permissions(&path, fs::Permissions::from_mode(0o660))?;
        let identity = fs::symlink_metadata(&path)?;
        listener.set_nonblocking(true)?;
        let (send, receive) = mpsc::sync_channel(16);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = stop.clone();
        let active = Arc::new(AtomicUsize::new(0));
        let worker = std::thread::Builder::new()
            .name("scupper-control".into())
            .spawn(move || {
                while !stopping.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            if active.load(Ordering::Relaxed) >= 16 {
                                continue;
                            }
                            let send = send.clone();
                            let count = active.clone();
                            count.fetch_add(1, Ordering::Relaxed);
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
                        }
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(10));
                        }
                        Err(_) => break,
                    }
                }
                if fs::symlink_metadata(&path)
                    .is_ok_and(|m| m.dev() == identity.dev() && m.ino() == identity.ino())
                {
                    let _ = fs::remove_file(path);
                }
            })?;
        Ok(Self {
            receive,
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
            result: Err(api(ApiErrorCode::Unauthorized)),
        }
    };
    serde_json::to_writer(&mut stream, &response)?;
    stream.write_all(b"\n")
}

/// Tick-owned response cache, including failures, for ten-minute retry deduplication.
#[derive(Default)]
pub struct Dedupe {
    entries: VecDeque<(Instant, Response)>,
}
impl Dedupe {
    /// Execute at most once for an identifier within the retention window.
    pub fn execute(
        &mut self,
        request: Request,
        now: Instant,
        run: impl FnOnce(Op) -> Result<OpResult, ApiError>,
    ) -> Response {
        self.entries
            .retain(|(at, _)| now.saturating_duration_since(*at) < Duration::from_secs(600));
        if let Some((_, response)) = self
            .entries
            .iter()
            .find(|(_, r)| r.request_id == request.request_id)
        {
            return response.clone();
        }
        let response = Response {
            request_id: request.request_id,
            schema: Schema,
            result: run(request.op),
        };
        self.entries.push_back((now, response.clone()));
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
    if response.request_id != request.request_id {
        return Err(ClientError::OutcomeUnknown(io::Error::other(
            "control response id mismatch",
        )));
    }
    Ok(response)
}
/// Generate a non-secret, unique operational request id without credentials.
#[must_use]
pub fn request(op: Op) -> Request {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let value = format!("r-{:x}-{:x}", nanos, NEXT.fetch_add(1, Ordering::Relaxed));
    Request {
        request_id: Identifier::try_from(value)
            .unwrap_or_else(|_| Identifier::from(&scupper_core::config::ExitId("request".into()))),
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
        assert_eq!(first, duplicate);
        let expired = cache.execute(original.clone(), now + Duration::from_secs(600), |_| {
            Err(api(ApiErrorCode::DisconnectNotEffective))
        });
        assert!(expired.result.is_err());
        assert_eq!(
            expired,
            cache.execute(original, now + Duration::from_secs(601), |_| unreachable!(
                "failed response reexecuted"
            ))
        );
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
}
