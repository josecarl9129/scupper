//! Bounded systemd notification without a client library.
use crate::reconcile::TickReport;
use std::{
    ffi::OsStr,
    io,
    os::{
        linux::net::SocketAddrExt,
        unix::{
            ffi::OsStrExt,
            net::{SocketAddr, UnixDatagram},
        },
    },
};

/// A process-local systemd notification endpoint; absence is valid outside systemd.
pub struct Notify {
    socket: Option<(UnixDatagram, SocketAddr)>,
    ready: bool,
}
impl Notify {
    /// Disabled endpoint used when service-manager configuration is invalid.
    #[must_use]
    pub fn disabled() -> Self {
        Self {
            socket: None,
            ready: false,
        }
    }
    /// Parse a filesystem or `@` abstract socket address.
    ///
    /// # Errors
    /// Returns invalid address or socket setup errors.
    pub fn new(address: Option<&OsStr>) -> io::Result<Self> {
        let socket = address
            .map(|name| {
                let address = if let Some(name) = name.as_bytes().strip_prefix(b"@") {
                    SocketAddr::from_abstract_name(name)?
                } else {
                    SocketAddr::from_pathname(name)?
                };
                let socket = UnixDatagram::unbound()?;
                socket.set_nonblocking(true)?;
                Ok::<_, io::Error>((socket, address))
            })
            .transpose()?;
        Ok(Self {
            socket,
            ready: false,
        })
    }
    /// Announce entry into the main loop, independently of kernel health.
    ///
    /// # Errors
    /// Returns a nonblocking socket error; the next iteration retries.
    pub fn started(&mut self) -> io::Result<()> {
        if !self.ready {
            self.send(b"READY=1")?;
            self.ready = true;
        }
        Ok(())
    }
    /// Notify completion of bounded loop work, including degraded work.
    ///
    /// # Errors
    /// Returns a nonblocking send error.
    pub fn iteration(&mut self, complete: bool, status: &str) -> io::Result<()> {
        self.started()?;
        self.send(format!("STATUS={status}").as_bytes())?;
        if complete {
            self.send(b"WATCHDOG=1")?;
        }
        Ok(())
    }
    /// Notify after a reconciler tick; rebuild decisions belong to the loop.
    ///
    /// # Errors
    /// Returns a nonblocking send error.
    pub fn completed(&mut self, report: &TickReport) -> io::Result<()> {
        self.started()?;
        if report.complete {
            self.send(b"WATCHDOG=1")?;
        }
        Ok(())
    }
    /// Extend a bounded full apply and keep its service watchdog alive.
    /// # Errors
    /// Returns a nonblocking socket error.
    pub fn extend_apply(&self) -> io::Result<()> {
        self.send(b"EXTEND_TIMEOUT_USEC=30000000")?;
        self.send(b"WATCHDOG=1")
    }
    /// Publish startup progress without arming the watchdog.
    /// # Errors
    /// Returns a nonblocking socket error.
    pub fn status(&self, status: &str) -> io::Result<()> {
        self.send(format!("STATUS={status}").as_bytes())
    }
    fn send(&self, message: &[u8]) -> io::Result<()> {
        if let Some((socket, address)) = &self.socket {
            socket.send_to_addr(message, address)?;
        }
        Ok(())
    }
}

/// Notification lifetime for an explicit apply on the tick owner.
pub(crate) struct ApplyKeepalive {
    stop: std::sync::mpsc::Sender<()>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl ApplyKeepalive {
    pub(crate) fn start() -> Self {
        let notify = Notify::new(std::env::var_os("NOTIFY_SOCKET").as_deref())
            .unwrap_or_else(|_| Notify::disabled());
        Self::start_with(
            notify,
            std::time::Duration::from_secs(120),
            std::time::Duration::from_secs(5),
        )
    }
    fn start_with(
        notify: Notify,
        budget: std::time::Duration,
        interval: std::time::Duration,
    ) -> Self {
        let (stop, receive) = std::sync::mpsc::channel();
        let deadline = std::time::Instant::now() + budget;
        let worker = std::thread::spawn(move || {
            while std::time::Instant::now() < deadline {
                let _ = notify.extend_apply();
                if receive
                    .recv_timeout(
                        interval.min(deadline.saturating_duration_since(std::time::Instant::now())),
                    )
                    .is_ok()
                {
                    break;
                }
            }
        });
        Self {
            stop,
            worker: Some(worker),
        }
    }
}
impl Drop for ApplyKeepalive {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn apply_extends_service_timeout_and_feeds_watchdog() {
        let name = format!("scupper-apply-notify-{}", std::process::id());
        let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
        let socket = UnixDatagram::bind_addr(&address).unwrap();
        socket
            .set_read_timeout(Some(std::time::Duration::from_secs(1)))
            .unwrap();
        let notify = Notify::new(Some(OsStr::new(&format!("@{name}")))).unwrap();
        notify.extend_apply().unwrap();
        let mut buffer = [0; 128];
        let len = socket.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..len], b"EXTEND_TIMEOUT_USEC=30000000");
        let len = socket.recv(&mut buffer).unwrap();
        assert_eq!(&buffer[..len], b"WATCHDOG=1");
    }
}

#[cfg(test)]
#[test]
#[allow(clippy::unwrap_used)]
fn apply_keepalive_stops_at_budget() {
    use std::time::Duration;
    let name = format!("scupper-apply-budget-{}", std::process::id());
    let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let socket = UnixDatagram::bind_addr(&address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(500)))
        .unwrap();
    let notify = Notify::new(Some(OsStr::new(&format!("@{name}")))).unwrap();
    let mut feeder =
        ApplyKeepalive::start_with(notify, Duration::from_millis(80), Duration::from_millis(10));
    let mut bytes = [0; 128];
    assert!(socket.recv(&mut bytes).is_ok());
    // Joining proves that a hung owner need not drop the guard for feeding to end.
    feeder.worker.take().unwrap().join().unwrap();
    socket.set_nonblocking(true).unwrap();
    let mut watchdogs = 0;
    while let Ok(len) = socket.recv(&mut bytes) {
        watchdogs += usize::from(&bytes[..len] == b"WATCHDOG=1");
    }
    assert!(watchdogs > 0);
    std::thread::sleep(Duration::from_millis(30));
    assert!(socket.recv(&mut bytes).is_err());
}
