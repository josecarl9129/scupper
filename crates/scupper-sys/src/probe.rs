//! HTTPS exit observations through a device-bound IPv4 TCP socket.
//!
//! In M1, DNS uses the host resolver over the uplink, revealing only the probe
//! host name, as in v1. Resolving through the exit is deferred to M2 (ADR 0020).
//! A bound probe proves tunnel traffic, so the route stage must run first.

use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    sync::{Arc, mpsc},
    thread,
    time::{Duration, Instant},
};

use thiserror::Error;

use crate::{
    check::ExitProbe,
    rules::{IfName, V1Config},
    verdict::{Probe, ProbeError},
};

/// Shared deadline for DNS, all targets, connects, TLS and HTTP reads.
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(8);
/// Maximum complete HTTP response, including headers and chunk framing.
pub const MAX_RESPONSE_BYTES: usize = 16 * 1024;

/// A verified HTTPS host and origin-form path; the port is always 443.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Target {
    host: String,
    path: String,
}

impl Target {
    /// Creates a target without allowing request-line or header injection.
    ///
    /// # Errors
    /// Returns a setup error for an invalid DNS name or origin-form path.
    pub fn new(host: &str, path: &str) -> Probe<Self> {
        if host.is_empty()
            || host.len() > 253
            || host.split('.').any(|label| {
                label.is_empty()
                    || label.len() > 63
                    || label.starts_with('-')
                    || label.ends_with('-')
                    || !label
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            })
            || !path.starts_with('/')
            || path.len() > 2048
            || !path
                .bytes()
                .all(|byte| byte.is_ascii_graphic() && byte != b'#')
        {
            return Err(ProbeError::setup("invalid HTTPS probe target"));
        }
        Ok(Self {
            host: host.into(),
            path: path.into(),
        })
    }

    /// Target host used for DNS, certificate verification, SNI and HTTP Host.
    #[must_use]
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Exact HTTP/1.1 request bytes, with no redirect following or proxy support.
    #[must_use]
    pub fn request_bytes(&self) -> Vec<u8> {
        format!(
            "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: scupper/{}\r\nAccept: text/plain\r\nConnection: close\r\n\r\n",
            self.path, self.host, env!("CARGO_PKG_VERSION")
        )
        .into_bytes()
    }
}

/// Default targets in failover order.
#[must_use]
pub fn default_targets() -> Vec<Target> {
    [("ifconfig.me", "/ip"), ("icanhazip.com", "/")]
        .into_iter()
        .map(|(host, path)| Target {
            host: host.into(),
            path: path.into(),
        })
        .collect()
}

/// Injectable network boundary. Implementations must not use an unbound fallback.
///
/// Calls run on helper threads. A stalled resolver or connector cannot extend the
/// caller's deadline; a stuck system resolver may outlive this observation.
#[doc(hidden)]
pub trait Connector: Send + Sync + 'static {
    /// Resolves only IPv4 addresses, using the same overall deadline.
    ///
    /// # Errors
    /// Returns a path resolution failure. Local worker failures may use Setup.
    fn resolve(&self, target: &Target, deadline: Instant) -> Probe<Vec<Ipv4Addr>>;

    /// Fetches one HTTPS response through the exit device at one IPv4 address.
    ///
    /// # Errors
    /// Returns local socket setup errors or path failures, preserving their class.
    fn exchange(
        &self,
        iface: &IfName,
        target: &Target,
        address: Ipv4Addr,
        deadline: Instant,
    ) -> Probe<Vec<u8>>;
}

/// HTTPS probe with ordered fallback and one deadline across all operations.
pub struct BoundHttpsProbe {
    targets: Vec<Target>,
    connector: Arc<dyn Connector>,
}

impl BoundHttpsProbe {
    /// Configures the target order, with the fixed eight-second budget.
    #[must_use]
    pub fn new(targets: Vec<Target>) -> Self {
        Self {
            targets,
            connector: Arc::new(SystemConnector),
        }
    }

    /// Replaces the network boundary, for deterministic tests without networking.
    #[cfg(feature = "testing")]
    #[must_use]
    pub fn with_connector(mut self, connector: Arc<dyn Connector>) -> Self {
        self.connector = connector;
        self
    }

    /// Runs the target loop on any platform with an injected connector and budget.
    ///
    /// # Errors
    /// Returns setup or path failures with the same history as the production probe.
    #[cfg(feature = "testing")]
    pub fn probe_with_budget(&self, cfg: &V1Config, budget: Duration) -> Probe<IpAddr> {
        self.run(&cfg.exit_iface, budget)
    }

    fn run(&self, iface: &IfName, budget: Duration) -> Probe<IpAddr> {
        let deadline = Instant::now() + budget;
        let mut failures = Failures::default();
        let mut last = ProbeError::io("no HTTPS probe targets");
        for target in &self.targets {
            if remaining(deadline).is_err() {
                failures.push(target.host(), &ProbeError::Timeout, true);
                return Err(failures.finish(ProbeError::Timeout));
            }
            match self.try_target(iface, target, deadline, &mut failures) {
                Ok(ip) => return Ok(ip),
                Err(error) => {
                    let expired = remaining(deadline).is_err();
                    failures.push(target.host(), &error, expired);
                    if matches!(error, ProbeError::Setup(_)) || expired {
                        return Err(failures.finish(error));
                    }
                    last = error;
                }
            }
        }
        Err(failures.finish(last))
    }

    fn try_target(
        &self,
        iface: &IfName,
        target: &Target,
        deadline: Instant,
        failures: &mut Failures,
    ) -> Probe<IpAddr> {
        let connector = Arc::clone(&self.connector);
        let owned_target = target.clone();
        let addresses =
            before_deadline(deadline, move || connector.resolve(&owned_target, deadline))?;
        let mut addresses = addresses.into_iter().peekable();
        while let Some(address) = addresses.next() {
            let connector = Arc::clone(&self.connector);
            let owned_target = target.clone();
            let iface = iface.clone();
            let response = before_deadline(deadline, move || {
                connector.exchange(&iface, &owned_target, address, deadline)
            });
            match response.and_then(|bytes| {
                let ip = parse_ip_response(&bytes)
                    .map_err(|error| ProbeError::io(&error.to_string()))?
                    .to_canonical();
                match ip {
                    IpAddr::V4(_) => Ok(ip),
                    IpAddr::V6(_) => Err(ProbeError::io(
                        "probe answered with IPv6 over an IPv4 connection",
                    )),
                }
            }) {
                Ok(ip) => return Ok(ip),
                Err(error) => {
                    if matches!(error, ProbeError::Setup(_))
                        || remaining(deadline).is_err()
                        || addresses.peek().is_none()
                    {
                        return Err(error);
                    }
                    failures.push(target.host(), &error, false);
                }
            }
        }
        Err(ProbeError::io("DNS returned no IPv4 addresses"))
    }
}

impl ExitProbe for BoundHttpsProbe {
    fn probe(&self, cfg: &V1Config) -> Probe<IpAddr> {
        if cfg!(target_os = "linux") {
            self.run(&cfg.exit_iface, PROBE_TIMEOUT)
        } else {
            Err(ProbeError::setup("exit probe needs Linux"))
        }
    }
}

pub(crate) fn remaining(deadline: Instant) -> Probe<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(ProbeError::Timeout)
}

fn before_deadline<T: Send + 'static>(
    deadline: Instant,
    operation: impl FnOnce() -> Probe<T> + Send + 'static,
) -> Probe<T> {
    remaining(deadline)?;
    let (tx, rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name("exit-probe".into())
        .spawn(move || {
            let result = remaining(deadline).and_then(|_| operation());
            let _ = tx.send(result);
        })
        .map_err(|error| ProbeError::setup(&format!("probe worker: {error}")))?;
    let result = rx
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|error| match error {
            mpsc::RecvTimeoutError::Timeout => ProbeError::Timeout,
            mpsc::RecvTimeoutError::Disconnected => ProbeError::io("probe worker stopped"),
        })?;
    // Preserve an observed failure, especially Setup, even if the deadline has
    // just expired. A successful result still has to arrive within the budget.
    if result.is_ok() {
        remaining(deadline)?;
    }
    result
}

#[derive(Default)]
struct Failures {
    text: String,
}

impl Failures {
    fn push(&mut self, host: &str, error: &ProbeError, expired: bool) {
        // Reserve space for each default target, including its diagnostic. With
        // custom lists the newest failures replace the oldest, never exceeding
        // ProbeError's 200-character diagnostic bound.
        let host: String = host.chars().take(30).collect();
        let diagnostic: String = error.to_string().chars().take(60).collect();
        let suffix = if expired { " (deadline reached)" } else { "" };
        let entry = format!("{host}: {diagnostic}{suffix}");
        if !self.text.is_empty() {
            self.text.push_str("; ");
        }
        self.text.push_str(&entry);
        if self.text.chars().count() > 200 {
            self.text = self
                .text
                .chars()
                .rev()
                .take(197)
                .collect::<String>()
                .chars()
                .rev()
                .collect();
            self.text.insert_str(0, "...");
        }
    }

    fn finish(self, last: ProbeError) -> ProbeError {
        if self.text.is_empty() {
            return last;
        }
        // Timeout is a unit variant, so retain its diagnostic and path class in
        // Io when attaching history. Setup stops the loop and retains its class.
        if matches!(last, ProbeError::Setup(_)) {
            ProbeError::setup(&self.text)
        } else {
            ProbeError::io(&self.text)
        }
    }
}

/// Context needed to distinguish local setup errors from path errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoOperation {
    /// Creating a socket is always local setup.
    Socket,
    /// Binding the exit device; permission and missing-device errors are local.
    BindDevice,
    /// Resolving a host; all resolver failures are path errors, even `NotFound`.
    Resolve,
    /// Connect, TLS, HTTP and other path operations.
    Path,
}

/// Pure classification of operating-system failures, independent of error text.
///
/// Raw bind errno values are Linux values because device binding is Linux-only.
/// Resolver errors cannot reliably distinguish local configuration from the path.
#[must_use]
pub fn is_setup_error(operation: IoOperation, kind: io::ErrorKind, raw: Option<i32>) -> bool {
    match operation {
        IoOperation::Socket => true,
        IoOperation::BindDevice => {
            matches!(raw, Some(1 | 13 | 19))
                || matches!(
                    kind,
                    io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                )
        }
        IoOperation::Resolve | IoOperation::Path => false,
    }
}

/// Maps local socket failures to Setup, timeouts to Timeout, and other failures
/// to Io with their diagnostic. Resolving always uses the path classification.
#[cfg(target_os = "linux")]
pub(crate) fn io_failure(operation: IoOperation, error: &io::Error) -> ProbeError {
    if is_setup_error(operation, error.kind(), error.raw_os_error()) {
        ProbeError::setup(&error.to_string())
    } else if matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    ) {
        ProbeError::Timeout
    } else {
        ProbeError::io(&error.to_string())
    }
}

struct SystemConnector;

#[cfg(not(target_os = "linux"))]
impl Connector for SystemConnector {
    fn resolve(&self, _target: &Target, _deadline: Instant) -> Probe<Vec<Ipv4Addr>> {
        Err(ProbeError::setup("exit probe needs Linux"))
    }

    fn exchange(
        &self,
        _iface: &IfName,
        _target: &Target,
        _address: Ipv4Addr,
        _deadline: Instant,
    ) -> Probe<Vec<u8>> {
        Err(ProbeError::setup("exit probe needs Linux"))
    }
}

#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use std::{
        io::{Read, Write},
        net::{SocketAddr, TcpStream},
    };

    use dns_lookup::{AddrFamily, AddrInfoHints, SockType, getaddrinfo};
    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName,
    };
    use socket2::{Domain, Protocol, Socket, Type};

    use super::{
        Arc, Connector, IfName, Instant, IoOperation, Ipv4Addr, MAX_RESPONSE_BYTES, Probe,
        ProbeError, SystemConnector, Target, io, io_failure, remaining,
    };

    impl Connector for SystemConnector {
        fn resolve(&self, target: &Target, deadline: Instant) -> Probe<Vec<Ipv4Addr>> {
            remaining(deadline)?;
            let hints = AddrInfoHints {
                address: AddrFamily::Inet.into(),
                socktype: SockType::Stream.into(),
                ..AddrInfoHints::default()
            };
            let addresses = getaddrinfo(Some(target.host()), Some("443"), Some(hints))
                .map_err(|error| io_failure(IoOperation::Resolve, &io::Error::from(error)))?;
            remaining(deadline)?;
            addresses
                .filter_map(|address| match address {
                    Ok(address) => match address.sockaddr {
                        SocketAddr::V4(address) => Some(Ok(*address.ip())),
                        SocketAddr::V6(_) => None,
                    },
                    Err(error) => Some(Err(io_failure(IoOperation::Resolve, &error))),
                })
                .collect()
        }

        fn exchange(
            &self,
            iface: &IfName,
            target: &Target,
            address: Ipv4Addr,
            deadline: Instant,
        ) -> Probe<Vec<u8>> {
            remaining(deadline)?;
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
                .map_err(|error| io_failure(IoOperation::Socket, &error))?;
            socket
                .bind_device(Some(iface.as_str().as_bytes()))
                .map_err(|error| io_failure(IoOperation::BindDevice, &error))?;
            exchange_socket(socket, target, address, deadline)
        }
    }

    // Shared by the M1 connector and the namespace child. The child supplies an
    // unconnected socket created before its permanent privilege drop.
    pub(crate) fn exchange_socket(
        socket: Socket,
        target: &Target,
        address: Ipv4Addr,
        deadline: Instant,
    ) -> Probe<Vec<u8>> {
        socket
            .connect_timeout(
                &SocketAddr::from((address, 443)).into(),
                remaining(deadline)?,
            )
            .map_err(|error| io_failure(IoOperation::Path, &error))?;
        let stream = DeadlineStream {
            stream: socket.into(),
            deadline,
        };
        stream
            .set_timeouts()
            .map_err(|error| io_failure(IoOperation::Path, &error))?;
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        let config =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[&rustls::version::TLS13, &rustls::version::TLS12])
                .map_err(|error| ProbeError::setup(&error.to_string()))?
                .with_root_certificates(roots)
                .with_no_client_auth();
        let name = ServerName::try_from(target.host.clone())
            .map_err(|error| ProbeError::setup(&error.to_string()))?;
        let connection = ClientConnection::new(Arc::new(config), name)
            .map_err(|error| ProbeError::io(&error.to_string()))?;
        let mut tls = StreamOwned::new(connection, stream);
        tls.write_all(&target.request_bytes())
            .and_then(|()| tls.flush())
            .map_err(|error| io_failure(IoOperation::Path, &error))?;
        let mut bytes = Vec::new();
        let mut buffer = [0; 2048];
        loop {
            remaining(deadline)?;
            // Read at most 16 KiB. A response exactly at the cap is rejected
            // conservatively if framing cannot prove it is complete.
            let available = (MAX_RESPONSE_BYTES - bytes.len()).min(buffer.len());
            if available == 0 {
                return Err(ProbeError::io("HTTP response too large"));
            }
            let count = tls
                .read(&mut buffer[..available])
                .map_err(|error| io_failure(IoOperation::Path, &error))?;
            if count == 0 {
                return Ok(bytes);
            }
            bytes.extend_from_slice(&buffer[..count]);
            // Framed responses need not wait for the peer to close TLS.
            if parse_complete(&bytes) {
                return Ok(bytes);
            }
        }
    }

    fn parse_complete(bytes: &[u8]) -> bool {
        super::response_body(bytes).is_ok_and(|(_, framed)| framed)
    }

    // rustls can perform several socket operations per read or handshake. Refresh
    // the timeout at every underlying syscall to prevent a slow peer extending it.
    struct DeadlineStream {
        stream: TcpStream,
        deadline: Instant,
    }

    impl DeadlineStream {
        fn set_timeouts(&self) -> io::Result<()> {
            let timeout =
                remaining(self.deadline).map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            self.stream.set_read_timeout(Some(timeout))?;
            self.stream.set_write_timeout(Some(timeout))
        }
    }

    impl Read for DeadlineStream {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.set_timeouts()?;
            self.stream.read(buffer)
        }
    }

    impl Write for DeadlineStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.set_timeouts()?;
            self.stream.write(buffer)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.set_timeouts()?;
            self.stream.flush()
        }
    }
}

/// Invalid, incomplete or oversized HTTP response; never a local setup failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Error)]
pub enum ResponseError {
    /// The entire response exceeded the 16 KiB limit.
    #[error("HTTP response too large")]
    Oversize,
    /// Status is not HTTP/1.0 or HTTP/1.1 200.
    #[error("HTTP status is not HTTP/1.0 or HTTP/1.1 200")]
    Status,
    /// Headers or body framing are malformed, ambiguous or incomplete.
    #[error("invalid or incomplete HTTP framing")]
    Framing,
    /// Decoded body does not contain exactly one IP address.
    #[error("HTTP body is not one IP address")]
    Body,
}

/// Parses a bounded HTTP response without I/O or clock access.
///
/// Duplicate framing headers, conflicting length and chunking, unsupported
/// transfer/content encodings, malformed chunks and trailing bytes are rejected.
/// Chunk extensions and trailers are deliberately unsupported in this probe.
///
/// # Errors
/// Returns a status, framing, size or IP-body error.
pub fn parse_ip_response(bytes: &[u8]) -> Result<IpAddr, ResponseError> {
    let (body, _) = response_body(bytes)?;
    let body = body.trim_ascii();
    std::str::from_utf8(body)
        .map_err(|_| ResponseError::Body)?
        .parse()
        .map_err(|_| ResponseError::Body)
}

fn response_body(bytes: &[u8]) -> Result<(Vec<u8>, bool), ResponseError> {
    if bytes.len() > MAX_RESPONSE_BYTES {
        return Err(ResponseError::Oversize);
    }
    let split = bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(ResponseError::Framing)?;
    let headers = std::str::from_utf8(&bytes[..split]).map_err(|_| ResponseError::Framing)?;
    let mut lines = headers.split("\r\n");
    let status = lines.next().ok_or(ResponseError::Status)?;
    let code = status.get(..12).ok_or(ResponseError::Status)?;
    if !matches!(code, "HTTP/1.1 200" | "HTTP/1.0 200")
        || (!status[12..].is_empty() && !status[12..].starts_with(' '))
        || !status
            .bytes()
            .all(|byte| byte == b' ' || byte.is_ascii_graphic())
    {
        return Err(ResponseError::Status);
    }
    let mut length = None;
    let mut chunked = false;
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(ResponseError::Framing)?;
        if name.is_empty()
            || !name.bytes().all(header_token)
            || !value
                .bytes()
                .all(|byte| byte == b'\t' || (b' '..=b'~').contains(&byte))
        {
            return Err(ResponseError::Framing);
        }
        let value = value.trim_matches([' ', '\t']);
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some()
                || value.is_empty()
                || !value.bytes().all(|byte| byte.is_ascii_digit())
            {
                return Err(ResponseError::Framing);
            }
            let count = value.parse::<usize>().map_err(|_| ResponseError::Framing)?;
            if count > MAX_RESPONSE_BYTES {
                return Err(ResponseError::Oversize);
            }
            length = Some(count);
        } else if name.eq_ignore_ascii_case("transfer-encoding") {
            if chunked || !value.eq_ignore_ascii_case("chunked") {
                return Err(ResponseError::Framing);
            }
            chunked = true;
        } else if name.eq_ignore_ascii_case("content-encoding")
            && !value.eq_ignore_ascii_case("identity")
        {
            return Err(ResponseError::Framing);
        }
    }
    let body = &bytes[split + 4..];
    match (length, chunked) {
        (Some(_), true) => Err(ResponseError::Framing),
        (Some(length), false) if length != body.len() => Err(ResponseError::Framing),
        (_, true) => decode_chunks(body).map(|body| (body, true)),
        (length, false) => Ok((body.to_vec(), length.is_some())),
    }
}

fn header_token(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn decode_chunks(mut bytes: &[u8]) -> Result<Vec<u8>, ResponseError> {
    let mut body = Vec::new();
    loop {
        let end = bytes
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(ResponseError::Framing)?;
        let digits = &bytes[..end];
        if digits.is_empty() || !digits.iter().all(u8::is_ascii_hexdigit) {
            return Err(ResponseError::Framing);
        }
        let count = usize::from_str_radix(
            std::str::from_utf8(digits).map_err(|_| ResponseError::Framing)?,
            16,
        )
        .map_err(|_| ResponseError::Framing)?;
        bytes = &bytes[end + 2..];
        if count == 0 {
            return if bytes == b"\r\n" {
                Ok(body)
            } else {
                Err(ResponseError::Framing)
            };
        }
        if count > MAX_RESPONSE_BYTES - body.len() {
            return Err(ResponseError::Oversize);
        }
        let chunk = bytes.get(..count).ok_or(ResponseError::Framing)?;
        if bytes.get(count..count + 2) != Some(b"\r\n") {
            return Err(ResponseError::Framing);
        }
        body.extend_from_slice(chunk);
        bytes = &bytes[count + 2..];
    }
}
