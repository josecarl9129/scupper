//! Host-namespace heartbeat delivery. The URL and absolute `CLOCK_MONOTONIC`
//! deadline travel only over stdin. GET uses the existing rustls/webpki client,
//! with no redirects, proxies, custom trust roots or response body logging.
use crate::{
    probe,
    probe_child::{ProbeIdentity, Url},
    secrets::SecretFile,
};
use scupper_core::config::SecretName;
use serde::{Deserialize, Serialize};
use std::{
    fmt,
    io::Read,
    path::Path,
    time::{Duration, Instant},
};
use zeroize::{Zeroize, Zeroizing};

/// Value-free delivery failures and distinct child exit statuses.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum Failure {
    /// Valid HTTP response with a non-success status.
    #[error("heartbeat HTTP non-2xx")]
    Http,
    /// Deadline elapsed or transport timed out.
    #[error("heartbeat timeout or deadline")]
    Deadline,
    /// Malformed child protocol or local setup failure.
    #[error("heartbeat internal protocol or setup failure")]
    Internal,
    /// Child could not be executed.
    #[error("heartbeat child exec failed")]
    Exec,
    /// TLS protocol failure other than certificate verification.
    #[error("heartbeat TLS handshake failed")]
    Tls,
    /// Current `TCP_INFO/RTO` could not be read before a write.
    #[error("heartbeat TCP_INFO/RTO read failed")]
    RtoRead,
    /// A socket write lacked the required retransmission margin.
    #[error("heartbeat write refused by deadline/RTO rule")]
    WriteRefused,
    /// Connection reset or broken by the peer.
    #[error("heartbeat connection reset")]
    Reset,
    /// Peer certificate or certificate verification failed.
    #[error("heartbeat certificate/verification failed")]
    Certificate,
    /// DNS, connect or socket transport failed.
    #[error("heartbeat network transport failed")]
    Transport,
    /// Missing, unreadable, unsafe or invalid URL secret file.
    #[error("heartbeat URL reference missing, unreadable, unsafe or invalid")]
    Secret,
    /// Dedicated nonroot local account unavailable or invalid.
    #[error("heartbeat scupper-alert account unavailable or invalid")]
    Account,
}
impl Failure {
    /// Stable, value-free child status; 0 means delivered.
    #[must_use]
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Http => 20,
            Self::Deadline => 21,
            Self::Internal => 22,
            Self::Account => 23,
            Self::Tls => 24,
            Self::Transport => 25,
            Self::Exec => 26,
            Self::Secret => 27,
            Self::RtoRead => 28,
            Self::WriteRefused => 29,
            Self::Reset => 30,
            Self::Certificate => 31,
        }
    }
}

/// Resolved URL whose formatting is always redacted.
pub struct SecretUrl(Zeroizing<String>);
impl fmt::Debug for SecretUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SecretUrl([redacted])")
    }
}
impl SecretUrl {
    /// Borrow only for constructing the secret stdin message.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

/// Secret stdin protocol. Formatting never reveals the URL or its path.
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    url: String,
    deadline_ns: u64,
    #[cfg(feature = "testing")]
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) test_hold: Option<std::path::PathBuf>,
}
impl Drop for Request {
    fn drop(&mut self) {
        self.url.zeroize();
    }
}
impl fmt::Debug for Request {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HeartbeatRequest")
            .field("url", &"[redacted]")
            .field("deadline_ns", &self.deadline_ns)
            .finish_non_exhaustive()
    }
}
impl Request {
    /// Construct with an absolute Linux monotonic deadline.
    /// # Errors
    /// Rejects invalid HTTPS URLs and deadlines more than 30 seconds away.
    pub fn new(url: &str, deadline_ns: u64) -> Result<Self, Failure> {
        Url::new(url).map_err(|_| Failure::Internal)?;
        let now = monotonic_ns();
        if deadline_ns > now.saturating_add(30_000_000_000) {
            return Err(Failure::Internal);
        }
        Ok(Self {
            url: url.into(),
            deadline_ns,
            #[cfg(feature = "testing")]
            test_hold: None,
        })
    }
    /// Parse a bounded stdin message. No parser diagnostics escape this boundary.
    /// # Errors
    /// Rejects oversized, malformed, unknown-field or invalid URL input.
    pub fn read(input: impl Read) -> Result<Self, Failure> {
        let mut bytes = Zeroizing::new(Vec::new());
        input
            .take(8193)
            .read_to_end(&mut bytes)
            .map_err(|_| Failure::Internal)?;
        if bytes.len() > 8192 {
            return Err(Failure::Internal);
        }
        let request: Self = serde_json::from_slice(&bytes).map_err(|_| Failure::Internal)?;
        Self::new(&request.url, request.deadline_ns)?;
        Ok(request)
    }
    /// Serialize secret bytes for stdin only.
    /// # Errors
    /// Returns a value-free protocol error.
    pub fn encode(&self) -> Result<Zeroizing<Vec<u8>>, Failure> {
        serde_json::to_vec(self)
            .map(Zeroizing::new)
            .map_err(|_| Failure::Internal)
    }
    fn deadline(&self) -> Result<Instant, Failure> {
        let remaining = self
            .deadline_ns
            .checked_sub(monotonic_ns())
            .filter(|n| *n > 0)
            .ok_or(Failure::Deadline)?;
        // Use a fresh monotonic reading after capturing Instant, conservatively.
        let now = Instant::now();
        let remaining = remaining.min(self.deadline_ns.saturating_sub(monotonic_ns()));
        if remaining == 0 {
            return Err(Failure::Deadline);
        }
        Ok(now + Duration::from_nanos(remaining))
    }
}

/// Absolute `CLOCK_MONOTONIC` nanoseconds, shared by parent and child across exec.
/// Assumes the same time namespace; this clock excludes system suspend (§13).
#[must_use]
pub fn monotonic_ns() -> u64 {
    let time = rustix::time::clock_gettime(rustix::time::ClockId::Monotonic);
    u64::try_from(time.tv_sec)
        .unwrap_or(0)
        .saturating_mul(1_000_000_000)
        .saturating_add(u64::try_from(time.tv_nsec).unwrap_or(0))
}

/// Reads stdin and performs exactly one HTTPS GET, as a nonroot exec child.
/// # Errors
/// All failures are closed, value-free categories.
pub fn child(input: impl Read) -> Result<(), Failure> {
    if rustix::process::geteuid().is_root() || rustix::process::getegid().is_root() {
        return Err(Failure::Account);
    }
    rustix::process::setrlimit(
        rustix::process::Resource::Core,
        rustix::process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(|_| Failure::Internal)?;
    rustix::thread::set_no_new_privs(true).map_err(|_| Failure::Internal)?;
    rustix::process::set_dumpable_behavior(rustix::process::DumpableBehavior::NotDumpable)
        .map_err(|_| Failure::Internal)?;
    let request = Request::read(input)?;
    let deadline = request.deadline()?;
    let credentials = std::fs::read_to_string("/proc/self/status").map_err(|_| Failure::Account)?;
    verify_credentials(&credentials)?;
    arm_deadline_kill(deadline)?;
    deliver(&request)
}
// This timer belongs to the exec child, independent of the daemon. Process exit
// closes its SO_LINGER(0) sockets even if resolver/TLS/HTTP work is blocked.
fn arm_deadline_kill(deadline: Instant) -> Result<(), Failure> {
    std::thread::Builder::new()
        .name("heartbeat-deadline".into())
        .spawn(move || {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()));
            let _ = rustix::process::kill_process(
                rustix::process::getpid(),
                rustix::process::Signal::KILL,
            );
        })
        .map(|_| ())
        .map_err(|_| Failure::Internal)
}
fn verify_credentials(status: &str) -> Result<(), Failure> {
    let field = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .ok_or(Failure::Account)
    };
    for key in ["Uid:", "Gid:"] {
        let ids = field(key)?
            .split_whitespace()
            .map(str::parse::<u32>)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| Failure::Account)?;
        if ids.len() != 4 || ids.iter().any(|id| *id == 0 || *id == u32::MAX) {
            return Err(Failure::Account);
        }
    }
    if !field("Groups:")?.trim().is_empty() || field("NoNewPrivs:")?.trim() != "1" {
        return Err(Failure::Account);
    }
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        if u64::from_str_radix(field(key)?.trim(), 16).map_err(|_| Failure::Account)? != 0 {
            return Err(Failure::Account);
        }
    }
    Ok(())
}
fn deliver(request: &Request) -> Result<(), Failure> {
    let deadline = request.deadline()?;
    let target = Url::new(&request.url).map_err(|_| Failure::Internal)?;
    let target = target.target().map_err(|_| Failure::Internal)?;
    // Bound NSS/DNS independently of the parent: an orphan exits at its own
    // deadline even if the host resolver blocks. Returning from the executable
    // terminates any outstanding resolver thread along with the process.
    let host = target.host().to_owned();
    let address = resolve_before(deadline, move || {
        dns_lookup::lookup_host(&host)
            .map_err(|_| Failure::Transport)?
            .find_map(|ip| match ip {
                std::net::IpAddr::V4(ip) => Some(ip),
                std::net::IpAddr::V6(_) => None,
            })
            .ok_or(Failure::Transport)
    })?;
    request.deadline()?; // before connect, including DNS/exec delays
    let socket = deadline_socket(deadline)?;
    let before_request = || {
        #[cfg(feature = "testing")]
        if let Some(path) = &request.test_hold {
            std::fs::write(path, b"handshake complete")
                .map_err(|_| crate::verdict::ProbeError::Timeout)?;
            while path.exists() {
                probe::remaining(deadline)?;
                std::thread::sleep(Duration::from_millis(10));
            }
        }
        Ok(())
    };
    let bytes =
        probe::linux::exchange_status_socket(socket, &target, address, deadline, &before_request)
            .map_err(|error| transport_failure(&error))?;
    status(&bytes)
}
fn transport_failure(error: &crate::verdict::ProbeError) -> Failure {
    match error {
        crate::verdict::ProbeError::Timeout => Failure::Deadline,
        crate::verdict::ProbeError::Tls => Failure::Tls,
        crate::verdict::ProbeError::Certificate => Failure::Certificate,
        crate::verdict::ProbeError::RtoRead => Failure::RtoRead,
        crate::verdict::ProbeError::WriteRefused => Failure::WriteRefused,
        crate::verdict::ProbeError::ConnectionReset => Failure::Reset,
        _ => Failure::Transport,
    }
}
fn deadline_socket(deadline: Instant) -> Result<socket2::Socket, Failure> {
    use socket2::{Domain, Protocol, Socket, Type};
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|time| time.as_millis() > 0)
        .ok_or(Failure::Deadline)?;
    let remaining =
        Duration::from_millis(u64::try_from(remaining.as_millis()).map_err(|_| Failure::Internal)?);
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(|_| Failure::Internal)?;
    socket
        .set_linger(Some(Duration::ZERO))
        .map_err(|_| Failure::Internal)?;
    socket
        .set_tcp_user_timeout(Some(remaining))
        .map_err(|_| Failure::Internal)?;
    Ok(socket)
}
fn resolve_before<T: Send + 'static>(
    deadline: Instant,
    resolve: impl FnOnce() -> Result<T, Failure> + Send + 'static,
) -> Result<T, Failure> {
    if Instant::now() >= deadline {
        return Err(Failure::Deadline);
    }
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("heartbeat-resolve".into())
        .spawn(move || {
            let result = if Instant::now() >= deadline {
                Err(Failure::Deadline)
            } else {
                resolve()
            };
            let _ = send.send(result);
        })
        .map_err(|_| Failure::Internal)?;
    receive
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| match error {
            std::sync::mpsc::RecvTimeoutError::Timeout => Failure::Deadline,
            std::sync::mpsc::RecvTimeoutError::Disconnected => Failure::Internal,
        })?
}

fn status(bytes: &[u8]) -> Result<(), Failure> {
    let line = bytes.split(|b| *b == b'\r').next().ok_or(Failure::Http)?;
    if line.len() < 12
        || !matches!(&line[..9], b"HTTP/1.1 " | b"HTTP/1.0 ")
        || !line[9..12].iter().all(u8::is_ascii_digit)
        || (line.len() > 12 && line[12] != b' ')
    {
        return Err(Failure::Http);
    }
    if line[9] == b'2' {
        Ok(())
    } else {
        Err(Failure::Http)
    }
}

/// Resolve the dedicated local account without NSS or network access.
/// # Errors
/// Rejects missing, shared, root or mismatched account entries.
pub fn account(passwd: &str, group: &str) -> Result<ProbeIdentity, Failure> {
    ProbeIdentity::parse_named(passwd, group, "scupper-alert").map_err(|_| Failure::Account)
}

/// Resolve a confined root-owned 0600 URL reference, and append a pure suffix.
/// # Errors
/// Missing or unsafe files and non-HTTPS/invalid URLs fail without exposing values.
pub fn resolve(
    root: &Path,
    reference: &SecretName,
    suffix: &str,
    owner: u32,
) -> Result<SecretUrl, Failure> {
    let secret =
        SecretFile::open_with_owner(root, reference, owner).map_err(|_| Failure::Secret)?;
    let url = std::str::from_utf8(secret.expose()).map_err(|_| Failure::Secret)?;
    Url::new(url).map_err(|_| Failure::Secret)?;
    if !suffix.is_empty() && !matches!(suffix, "/0" | "/1" | "/2" | "/3" | "/4") {
        return Err(Failure::Internal);
    }
    let (base, query) = url
        .split_once('?')
        .map_or((url, None), |(base, query)| (base, Some(query)));
    let base = if suffix.is_empty() {
        base
    } else {
        base.trim_end_matches('/')
    };
    let mut result = Zeroizing::new(format!("{base}{suffix}"));
    if let Some(query) = query {
        result.push('?');
        result.push_str(query);
    }
    Ok(SecretUrl(result))
}

/// One bounded host-namespace child attempt; all child stdout/stderr are discarded.
/// # Errors
/// Returns only value-free failures, never process or parser error text.
pub fn attempt(binary: &Path, request: &Request, identity: ProbeIdentity) -> Result<(), Failure> {
    use std::os::unix::process::CommandExt;
    if [identity.uid, identity.gid]
        .iter()
        .any(|id| *id == 0 || *id == u32::MAX)
    {
        return Err(Failure::Account);
    }
    let mut command = std::process::Command::new(binary);
    command
        .args(["deliver", "heartbeat"])
        .uid(identity.uid)
        .gid(identity.gid);
    let input = request.encode()?;
    let timeout = request
        .deadline()?
        .saturating_duration_since(Instant::now());
    let output = crate::system::execute_input_command(command, &input, timeout).map_err(
        |error| match error {
            crate::system::ExecError::Timeout { .. } => Failure::Deadline,
            crate::system::ExecError::Spawn(_) => Failure::Exec,
            _ => Failure::Internal,
        },
    )?;
    if output.status.is_none() && monotonic_ns() >= request.deadline_ns {
        return Err(Failure::Deadline);
    }
    child_status(output.status)
}
fn child_status(status: Option<i32>) -> Result<(), Failure> {
    match status {
        Some(0) => Ok(()),
        Some(20) => Err(Failure::Http),
        Some(21) => Err(Failure::Deadline),
        Some(23) => Err(Failure::Account),
        Some(24) => Err(Failure::Tls),
        Some(25) => Err(Failure::Transport),
        Some(26) => Err(Failure::Exec),
        Some(27) => Err(Failure::Secret),
        Some(28) => Err(Failure::RtoRead),
        Some(29) => Err(Failure::WriteRefused),
        Some(30) => Err(Failure::Reset),
        Some(31) => Err(Failure::Certificate),
        _ => Err(Failure::Internal),
    }
}

/// Retry at most once, without moving the original verdict deadline.
/// # Errors
/// Returns the final value-free reason after up to two attempts.
pub fn retry(request: &Request, send: impl FnMut() -> Result<(), Failure>) -> Result<(), Failure> {
    retry_deadline(request.deadline_ns, send)
}

/// Retry one complete resolution/delivery job, preserving its absolute deadline.
/// # Errors
/// Returns the final reason; no attempt begins after the verdict deadline.
pub fn retry_deadline(
    deadline_ns: u64,
    mut send: impl FnMut() -> Result<(), Failure>,
) -> Result<(), Failure> {
    if monotonic_ns() >= deadline_ns {
        return Err(Failure::Deadline);
    }
    match send() {
        Ok(()) => Ok(()),
        Err(first) => {
            if monotonic_ns() >= deadline_ns {
                Err(first)
            } else {
                send()
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn distinct_failures_survive_child_exit_and_remain_value_free() {
        for failure in [
            Failure::Http,
            Failure::Deadline,
            Failure::Internal,
            Failure::Account,
            Failure::Tls,
            Failure::Transport,
            Failure::Exec,
            Failure::Secret,
            Failure::RtoRead,
            Failure::WriteRefused,
            Failure::Reset,
            Failure::Certificate,
        ] {
            assert_eq!(
                child_status(Some(i32::from(failure.exit_code()))),
                Err(failure)
            );
            assert!(!failure.to_string().contains("private"));
        }
        assert_eq!(
            transport_failure(&crate::verdict::ProbeError::Tls),
            Failure::Tls
        );
        assert_eq!(
            transport_failure(&crate::verdict::ProbeError::io("private")),
            Failure::Transport
        );
        assert_eq!(
            transport_failure(&crate::verdict::ProbeError::Timeout),
            Failure::Deadline
        );
    }
    #[test]
    fn transport_causes_survive_delivery_mapping() {
        for (error, failure) in [
            (crate::verdict::ProbeError::RtoRead, Failure::RtoRead),
            (
                crate::verdict::ProbeError::WriteRefused,
                Failure::WriteRefused,
            ),
            (crate::verdict::ProbeError::ConnectionReset, Failure::Reset),
            (
                crate::verdict::ProbeError::Certificate,
                Failure::Certificate,
            ),
        ] {
            assert_eq!(transport_failure(&error), failure);
        }
    }
    #[test]
    #[ignore = "isolated process changes irreversible hardening settings"]
    fn hardened_stdin_fixture() {
        struct InspectInput(bool);
        impl Read for InspectInput {
            fn read(&mut self, _: &mut [u8]) -> std::io::Result<usize> {
                let limits = rustix::process::getrlimit(rustix::process::Resource::Core);
                assert_eq!(limits.current, Some(0));
                assert_eq!(limits.maximum, Some(0));
                assert_eq!(
                    rustix::process::dumpable_behavior().unwrap(),
                    rustix::process::DumpableBehavior::NotDumpable
                );
                assert!(rustix::thread::no_new_privs().unwrap());
                self.0 = true;
                Err(std::io::ErrorKind::UnexpectedEof.into())
            }
        }
        if rustix::process::geteuid().is_root() || rustix::process::getegid().is_root() {
            return; // Root delivery is rejected before any input is read.
        }
        let mut input = InspectInput(false);
        assert_eq!(child(&mut input), Err(Failure::Internal));
        assert!(input.0);
    }
    #[test]
    fn delivery_hardens_before_first_secret_input_read() {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "heartbeat::tests::hardened_stdin_fixture",
            ])
            .status()
            .unwrap();
        assert!(status.success());
    }
    #[test]
    fn missing_executable_is_an_exec_failure() {
        let request = Request::new(
            "https://heartbeat.invalid/private",
            monotonic_ns() + 5_000_000_000,
        )
        .unwrap();
        assert_eq!(
            attempt(
                Path::new("/nonexistent-scupper-delivery"),
                &request,
                ProbeIdentity {
                    uid: 65534,
                    gid: 65534
                }
            ),
            Err(Failure::Exec)
        );
    }
    #[test]
    #[ignore = "subprocess fixture kills itself"]
    fn deadline_kill_fixture() {
        arm_deadline_kill(Instant::now() + Duration::from_millis(50)).unwrap();
        loop {
            std::thread::park();
        }
    }
    #[test]
    fn child_timer_kills_without_parent_supervision() {
        use std::os::unix::process::ExitStatusExt;
        let before = Instant::now();
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--ignored",
                "--exact",
                "heartbeat::tests::deadline_kill_fixture",
            ])
            .stdout(std::process::Stdio::null())
            .status()
            .unwrap();
        assert_eq!(status.signal(), Some(9));
        assert!(before.elapsed() < Duration::from_secs(2));
    }
    #[test]
    fn child_checks_all_ids_groups_and_live_capabilities() {
        let status = "Uid: 99 99 99 99\nGid: 98 98 98 98\nGroups:\nCapInh: 0\nCapPrm: 0\nCapEff: 0\nCapAmb: 0\nNoNewPrivs: 1\n";
        assert_eq!(verify_credentials(status), Ok(()));
        for bad in [
            status.replace("99 99 99 99", "99 99 0 99"),
            status.replace("98 98 98 98", "0 98 98 98"),
            status.replace("Groups:", "Groups: 98"),
            status.replace("CapAmb: 0", "CapAmb: 1"),
            status.replace("NoNewPrivs: 1", "NoNewPrivs: 0"),
        ] {
            assert_eq!(verify_credentials(&bad), Err(Failure::Account));
        }
    }
    #[test]
    fn socket_discards_queued_bytes_and_bounds_unacknowledged_data() {
        let deadline = Instant::now() + Duration::from_secs(5);
        let socket = deadline_socket(deadline).unwrap();
        assert_eq!(socket.linger().unwrap(), Some(Duration::ZERO));
        let timeout = socket.tcp_user_timeout().unwrap().unwrap();
        assert!(timeout > Duration::ZERO && timeout <= Duration::from_secs(5));
        assert!(deadline_socket(Instant::now()).is_err());
    }
    #[test]
    fn blocked_resolver_cannot_hold_child_past_deadline() {
        let started = Instant::now();
        let result = resolve_before(started + Duration::from_millis(20), || {
            std::thread::sleep(Duration::from_millis(200));
            Ok(())
        });
        assert_eq!(result, Err(Failure::Deadline));
        assert!(started.elapsed() < Duration::from_millis(150));
        assert_eq!(
            resolve_before(Instant::now(), || Ok(())),
            Err(Failure::Deadline)
        );
        assert_eq!(
            resolve_before(Instant::now() + Duration::from_secs(1), || Ok(42)),
            Ok(42)
        );
    }
    #[test]
    fn classifies_only_valid_2xx_statuses() {
        for code in [200, 201, 204, 299] {
            assert_eq!(
                status(format!("HTTP/1.1 {code} OK\r\n\r\n").as_bytes()),
                Ok(())
            );
        }
        for code in [301, 400, 429, 500] {
            assert_eq!(
                status(format!("HTTP/1.0 {code} failure\r\n\r\n").as_bytes()),
                Err(Failure::Http)
            );
        }
        for bytes in [
            b"HTTP/1.1 2000".as_slice(),
            b"HTTP/2 200",
            b"private-path",
            b"HTTP/1.1 2xx",
        ] {
            assert_eq!(status(bytes), Err(Failure::Http));
        }
    }
}
