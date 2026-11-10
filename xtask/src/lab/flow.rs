//! Bounded continuous canaries, including a persistent bidirectional TCP flow.
use super::{Result, fail};
use std::{
    fs::OpenOptions,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::Path,
    thread,
    time::{Duration, Instant},
};

/// Run a lab stream for the requested seconds; log actual transmitted/received
/// bytes so each fault case can prove that its established-flow control worked.
///
/// # Errors
/// Returns invalid mode, setup, or evidence-write errors.
pub fn flow(mode: &str, address: SocketAddr, marker: &str, log: &Path, seconds: u64) -> Result<()> {
    let mut log = OpenOptions::new().create(true).append(true).open(log)?;
    let start = Instant::now();
    let payload = format!("{marker}\n");
    let mut tcp = match mode {
        "server" => {
            let listener = TcpListener::bind(address)?;
            listener.set_nonblocking(true)?;
            let mut accepted = None;
            while start.elapsed() < Duration::from_secs(10) {
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
    let mut buffer = [0; 1024];
    while start.elapsed() < Duration::from_secs(seconds) {
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
            serde_json::json!({"elapsed_ms":start.elapsed().as_millis(),"sent":sent,"received":received})
        )?;
        log.flush()?;
        thread::sleep(Duration::from_millis(25));
    }
    Ok(())
}
