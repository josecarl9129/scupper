//! Bounded continuous canaries, including a persistent bidirectional TCP flow.
use super::{Result, fail};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

// Stop between records: default SIGTERM can interrupt Display's individual
// writes and leave an otherwise successfully reaped flow with truncated JSON.
struct FlowStop {
    requested: Arc<AtomicBool>,
    registration: signal_hook::SigId,
}
impl FlowStop {
    fn new() -> std::io::Result<Self> {
        let requested = Arc::new(AtomicBool::new(false));
        let registration =
            signal_hook::flag::register(signal_hook::consts::SIGTERM, Arc::clone(&requested))?;
        Ok(Self {
            requested,
            registration,
        })
    }
    fn requested(&self) -> bool {
        self.requested.load(Ordering::Relaxed)
    }
}
impl Drop for FlowStop {
    fn drop(&mut self) {
        signal_hook::low_level::unregister(self.registration);
    }
}

/// Run a lab stream for the requested seconds; log actual transmitted/received
/// bytes so each fault case can prove that its established-flow control worked.
///
/// # Errors
/// Returns invalid mode, setup, or evidence-write errors.
pub fn flow(mode: &str, address: SocketAddr, marker: &str, log: &Path, seconds: u64) -> Result<()> {
    let stop = FlowStop::new()?;
    let mut log = OpenOptions::new().create(true).append(true).open(log)?;
    if mode == "connect" {
        return connect_canary(address, marker, &mut log, seconds, &stop);
    }
    if mode == "heartbeat-sink" {
        return heartbeat_sink(address, &mut log, seconds, &stop);
    }
    let start = Instant::now();
    let payload = format!("{marker}\n");
    let mut tcp = match mode {
        "server" => {
            let listener = TcpListener::bind(address)?;
            listener.set_nonblocking(true)?;
            let mut accepted = None;
            while start.elapsed() < Duration::from_secs(10) {
                if stop.requested() {
                    return Ok(());
                }
                if let Ok((stream, _)) = listener.accept() {
                    accepted = Some(stream);
                    break;
                }
                thread::sleep(Duration::from_millis(20));
            }
            Some(accepted.ok_or("stream accept timed out")?)
        }
        "client" => Some(TcpStream::connect_timeout(
            &address,
            Duration::from_secs(3),
        )?),
        "udp" => None,
        _ => return fail("unknown stream mode"),
    };
    let udp = if tcp.is_none() {
        let socket = UdpSocket::bind("0.0.0.0:0")?;
        socket.connect(address)?;
        socket.set_nonblocking(true)?;
        Some(socket)
    } else {
        None
    };
    if let Some(stream) = &tcp {
        stream.set_nonblocking(true)?;
    }
    let local = udp.as_ref().map(UdpSocket::local_addr).transpose()?;
    let mut buffer = [0; 1024];
    while !stop.requested() && start.elapsed() < Duration::from_secs(seconds) {
        let (sent, received) = if let Some(stream) = &mut tcp {
            (
                stream.write(payload.as_bytes()).unwrap_or(0),
                stream.read(&mut buffer).unwrap_or(0),
            )
        } else if let Some(socket) = &udp {
            (
                socket.send(payload.trim_end().as_bytes()).unwrap_or(0),
                socket.recv(&mut buffer).unwrap_or(0),
            )
        } else {
            return fail("stream socket missing");
        };
        writeln!(
            log,
            "{}",
            serde_json::json!({"elapsed_ms":start.elapsed().as_millis(),"sent":sent,"received":received,"local":local})
        )?;
        log.flush()?;
        thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}

// Repeated connection attempts let an outage canary run without requiring an
// already healthy TCP session. Successful connects send the marker in plaintext.
fn connect_canary(
    address: SocketAddr,
    marker: &str,
    log: &mut std::fs::File,
    seconds: u64,
    stop: &FlowStop,
) -> Result<()> {
    let start = Instant::now();
    // Each attempt is bounded by 250 ms timeouts, so a stop request ends the
    // loop well inside the supervising timeout's kill-after window.
    while !stop.requested() && start.elapsed() < Duration::from_secs(seconds) {
        let mut sent = 0;
        let mut received = 0;
        if let Ok(mut stream) = TcpStream::connect_timeout(&address, Duration::from_millis(250)) {
            stream.set_write_timeout(Some(Duration::from_millis(250)))?;
            stream.set_read_timeout(Some(Duration::from_millis(250)))?;
            sent = stream.write(marker.as_bytes()).unwrap_or(0);
            received = stream.read(&mut [0; 1024]).unwrap_or(0);
        }
        writeln!(
            log,
            "{}",
            serde_json::json!({"elapsed_ms":start.elapsed().as_millis(),"attempted":1,"sent":sent,"received":received})
        )?;
        log.flush()?;
        thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}

// A TCP observer only: records ClientHello receipt, never terminates TLS or
// decrypts a request, and needs no lab certificate in the delivery binary.
fn heartbeat_sink(
    address: SocketAddr,
    log: &mut std::fs::File,
    seconds: u64,
    stop: &FlowStop,
) -> Result<()> {
    let listener = TcpListener::bind(address)?;
    listener.set_nonblocking(true)?;
    let start = Instant::now();
    while !stop.requested() && start.elapsed() < Duration::from_secs(seconds) {
        if let Ok((mut stream, peer)) = listener.accept() {
            stream.set_read_timeout(Some(Duration::from_millis(250)))?;
            let mut bytes = [0; 4096];
            let count = stream.read(&mut bytes).unwrap_or(0);
            let hello = count >= 6 && bytes[0] == 22 && bytes[1] == 3 && bytes[5] == 1;
            writeln!(
                log,
                "{}",
                serde_json::json!({"hello":hello, "peer":peer, "bytes":count})
            )?;
            log.flush()?;
        }
        thread::sleep(Duration::from_millis(10));
    }
    Ok(())
}
