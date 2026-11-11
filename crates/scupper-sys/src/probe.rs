//! HTTPS response parsing and TLS transport for the namespace probe child.

use std::{
    io,
    net::{IpAddr, Ipv4Addr},
    sync::Arc,
    time::{Duration, Instant},
};

use thiserror::Error;

use crate::verdict::{Probe, ProbeError};

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

pub(crate) fn remaining(deadline: Instant) -> Probe<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .filter(|duration| !duration.is_zero())
        .ok_or(ProbeError::Timeout)
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

#[cfg(target_os = "linux")]
mod tcp_info;

#[cfg(target_os = "linux")]
pub(crate) mod linux {
    use std::{
        io::{Read, Write},
        net::{SocketAddr, TcpStream},
    };

    use rustls::{
        ClientConfig, ClientConnection, RootCertStore, StreamOwned, pki_types::ServerName,
    };
    use socket2::Socket;

    use super::{
        Arc, Instant, IoOperation, Ipv4Addr, MAX_RESPONSE_BYTES, Probe, ProbeError, Target, io,
        io_failure, remaining,
    };

    // The namespace child supplies an unconnected socket before privilege drop.
    pub(crate) fn exchange_socket(
        socket: Socket,
        target: &Target,
        address: Ipv4Addr,
        deadline: Instant,
    ) -> Probe<Vec<u8>> {
        exchange(socket, target, address, deadline, false, &|| Ok(()))
    }

    // Heartbeats need only the status line/headers, not an IP response body.
    pub(crate) fn exchange_status_socket(
        socket: Socket,
        target: &Target,
        address: Ipv4Addr,
        deadline: Instant,
        before_request: &dyn Fn() -> Probe<()>,
    ) -> Probe<Vec<u8>> {
        exchange(socket, target, address, deadline, true, before_request)
    }

    fn exchange(
        socket: Socket,
        target: &Target,
        address: Ipv4Addr,
        deadline: Instant,
        status_only: bool,
        before_request: &dyn Fn() -> Probe<()>,
    ) -> Probe<Vec<u8>> {
        remaining(deadline)?;
        socket
            .connect_timeout(
                &SocketAddr::from((address, 443)).into(),
                remaining(deadline)?,
            )
            .map_err(|error| io_failure(IoOperation::Path, &error))?;
        let stream = DeadlineStream {
            stream: socket.into(),
            deadline,
            abort_at_deadline: status_only,
        };
        stream
            .set_timeouts()
            .map_err(|error| io_failure(IoOperation::Path, &error))?;
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        #[cfg(feature = "testing")]
        let roots = {
            let mut roots = roots;
            if let Ok(hex) = std::env::var("SCUPPER_TEST_CA_DER") {
                if hex.len() > 16384 || !hex.len().is_multiple_of(2) || !hex.is_ascii() {
                    return Err(ProbeError::setup("invalid test CA encoding"));
                }
                let der = (0..hex.len())
                    .step_by(2)
                    .map(|at| u8::from_str_radix(&hex[at..at + 2], 16))
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(|e| ProbeError::setup(&e.to_string()))?;
                roots
                    .add(rustls::pki_types::CertificateDer::from(der))
                    .map_err(|e| ProbeError::setup(&e.to_string()))?;
            }
            roots
        };
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
        // Finish the handshake before accepting application bytes. In particular,
        // a handshake delayed beyond the verdict deadline must never queue a GET.
        while tls.conn.is_handshaking() {
            remaining(deadline)?;
            tls.conn
                .complete_io(&mut tls.sock)
                .map_err(|error| tls_failure(&error))?;
        }
        before_request()?;
        write_request(&mut tls, target, deadline)?;
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
            if (status_only && bytes.windows(4).any(|w| w == b"\r\n\r\n")) || parse_complete(&bytes)
            {
                return Ok(bytes);
            }
        }
    }

    fn tls_failure(error: &io::Error) -> ProbeError {
        if matches!(
            error.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ) {
            ProbeError::Timeout
        } else {
            ProbeError::Tls
        }
    }

    fn write_request(writer: &mut impl Write, target: &Target, deadline: Instant) -> Probe<()> {
        remaining(deadline)?;
        writer
            .write_all(&target.request_bytes())
            .and_then(|()| writer.flush())
            .map_err(|error| io_failure(IoOperation::Path, &error))
    }

    fn parse_complete(bytes: &[u8]) -> bool {
        super::response_body(bytes).is_ok_and(|(_, framed)| framed)
    }

    // rustls can perform several socket operations per read or handshake. Refresh
    // the timeout at every underlying syscall to prevent a slow peer extending it.
    struct DeadlineStream {
        stream: TcpStream,
        deadline: Instant,
        abort_at_deadline: bool,
    }

    impl DeadlineStream {
        fn set_timeouts(&self) -> io::Result<()> {
            let timeout =
                remaining(self.deadline).map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?;
            if self.abort_at_deadline {
                // Refresh before every syscall, including each TLS flight: the
                // kernel timeout must shrink with the verdict's remaining life.
                let millis = u64::try_from(timeout.as_millis()).unwrap_or(u64::MAX);
                if millis == 0 {
                    return Err(io::Error::from(io::ErrorKind::TimedOut));
                }
                socket2::SockRef::from(&self.stream)
                    .set_tcp_user_timeout(Some(std::time::Duration::from_millis(millis)))?;
            }
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

    // TCP_USER_TIMEOUT cannot advance the first retransmission or tail-loss
    // probe. Leave room for the current RTO plus scheduling/measurement margin.
    fn write_allowed(left: std::time::Duration, rto: std::time::Duration) -> bool {
        left >= std::time::Duration::from_secs(2)
            && left > rto.saturating_add(std::time::Duration::from_secs(1))
    }
    impl Write for DeadlineStream {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            if self.abort_at_deadline {
                let rto = super::tcp_info::rto(&self.stream)?;
                let left = self.deadline.saturating_duration_since(Instant::now());
                if !write_allowed(left, rto) {
                    return Err(io::Error::from(io::ErrorKind::TimedOut));
                }
            }
            self.set_timeouts()?;
            self.stream.write(buffer)
        }

        fn flush(&mut self) -> io::Result<()> {
            self.set_timeouts()?;
            self.stream.flush()
        }
    }
    #[cfg(test)]
    mod deadline_tests {
        use super::*;
        use socket2::{Domain, Protocol, Type};
        use std::time::Duration;
        #[test]
        fn tls_handshake_errors_are_distinct_from_deadlines() {
            for kind in [
                io::ErrorKind::InvalidData,
                io::ErrorKind::UnexpectedEof,
                io::ErrorKind::ConnectionReset,
            ] {
                assert_eq!(tls_failure(&io::Error::from(kind)), ProbeError::Tls);
            }
            for kind in [io::ErrorKind::TimedOut, io::ErrorKind::WouldBlock] {
                assert_eq!(tls_failure(&io::Error::from(kind)), ProbeError::Timeout);
            }
        }
        #[test]
        fn refuses_writes_without_rto_margin_or_two_seconds() {
            for (left, rto, allowed) in [
                (1999, 100, false),
                (2000, 100, true),
                (2000, 1000, false),
                (6000, 5000, false),
                (6001, 5000, true),
                (0, 0, false),
            ] {
                assert_eq!(
                    write_allowed(Duration::from_millis(left), Duration::from_millis(rto)),
                    allowed
                );
            }
        }
        #[test]
        fn refused_write_never_reaches_peer() {
            let listener = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
            let stream = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
            let (mut peer, _) = listener.accept().unwrap();
            let mut stream = DeadlineStream {
                stream,
                deadline: Instant::now() + Duration::from_millis(1999),
                abort_at_deadline: true,
            };
            assert_eq!(
                stream
                    .write(b"GET /private HTTP/1.1\r\n")
                    .unwrap_err()
                    .kind(),
                io::ErrorKind::TimedOut
            );
            peer.set_nonblocking(true).unwrap();
            assert_eq!(
                peer.read(&mut [0; 64]).unwrap_err().kind(),
                io::ErrorKind::WouldBlock
            );
        }
        #[test]
        fn expired_before_connect_never_uses_socket() {
            let target = Target::new("heartbeat.invalid", "/secret-path").unwrap();
            let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP)).unwrap();
            let result = exchange_status_socket(
                socket,
                &target,
                Ipv4Addr::LOCALHOST,
                Instant::now().checked_sub(Duration::from_secs(1)).unwrap(),
                &|| Ok(()),
            );
            assert!(matches!(result, Err(ProbeError::Timeout)));
        }
        #[test]
        fn handshake_finishing_after_deadline_never_writes_request() {
            let target = Target::new("heartbeat.invalid", "/secret-path").unwrap();
            let mut bytes = Vec::new();
            let deadline = Instant::now();
            std::thread::sleep(Duration::from_millis(2));
            assert!(matches!(
                write_request(&mut bytes, &target, deadline),
                Err(ProbeError::Timeout)
            ));
            assert_eq!(bytes, [] as [u8; 0]);
            write_request(&mut bytes, &target, Instant::now() + Duration::from_secs(1)).unwrap();
            assert!(bytes.starts_with(b"GET /secret-path HTTP/1.1\r\n"));
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
