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
    /// Malformed protocol, URL, transport, or execution failure.
    #[error("heartbeat internal or transport failure")]
    Internal,
    /// Missing, unreadable, unsafe or invalid URL secret file.
    #[error("heartbeat URL reference missing, unreadable, unsafe or invalid")]
    Secret,
    /// Dedicated nonroot local account unavailable or invalid.
    #[error("heartbeat scupper-alert account unavailable or invalid")]
    Account,
}
impl Failure {
    /// Stable child status: 0 is delivered; 20/21/22 classify failures.
    #[must_use]
    pub fn exit_code(self) -> u8 {
        match self {
            Self::Http => 20,
            Self::Deadline => 21,
            _ => 22,
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
            .finish()
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
        Self::new(&request.url, request.deadline_ns)
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
    deliver(&request)
}
fn deliver(request: &Request) -> Result<(), Failure> {
    use socket2::{Domain, Protocol, Socket, Type};
    let deadline = request.deadline()?;
    let target = Url::new(&request.url).map_err(|_| Failure::Internal)?;
    let target = target.target().map_err(|_| Failure::Internal)?;
    // Bound NSS/DNS independently of the parent: an orphan exits at its own
    // deadline even if the host resolver blocks. Returning from the executable
    // terminates any outstanding resolver thread along with the process.
    let host = target.host().to_owned();
    let address = resolve_before(deadline, move || {
        dns_lookup::lookup_host(&host)
            .map_err(|_| Failure::Internal)?
            .find_map(|ip| match ip {
                std::net::IpAddr::V4(ip) => Some(ip),
                std::net::IpAddr::V6(_) => None,
            })
            .ok_or(Failure::Internal)
    })?;
    request.deadline()?; // before connect, including DNS/exec delays
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
        .map_err(|_| Failure::Internal)?;
    let bytes = probe::linux::exchange_status_socket(socket, &target, address, deadline).map_err(
        |error| {
            if matches!(error, crate::verdict::ProbeError::Timeout) {
                Failure::Deadline
            } else {
                Failure::Internal
            }
        },
    )?;
    status(&bytes)
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
    let line = bytes
        .split(|b| *b == b'\r')
        .next()
        .ok_or(Failure::Internal)?;
    if line.len() < 12
        || !matches!(&line[..9], b"HTTP/1.1 " | b"HTTP/1.0 ")
        || !line[9..12].iter().all(u8::is_ascii_digit)
        || (line.len() > 12 && line[12] != b' ')
    {
        return Err(Failure::Internal);
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
    let timeout = request
        .deadline()?
        .saturating_duration_since(Instant::now())
        .min(Duration::from_secs(8));
    let mut command = std::process::Command::new(binary);
    command
        .args(["deliver", "heartbeat"])
        .uid(identity.uid)
        .gid(identity.gid);
    let input = request.encode()?;
    let output = crate::system::execute_input_command(command, &input, timeout).map_err(|e| {
        if matches!(e, crate::system::ExecError::Timeout { .. }) {
            Failure::Deadline
        } else {
            Failure::Internal
        }
    })?;
    match output.status {
        Some(0) => Ok(()),
        Some(20) => Err(Failure::Http),
        Some(21) => Err(Failure::Deadline),
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
            assert_eq!(status(bytes), Err(Failure::Internal));
        }
    }
}
