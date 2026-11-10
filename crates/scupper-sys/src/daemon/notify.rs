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
        let (stop, receive) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            let notify = Notify::new(std::env::var_os("NOTIFY_SOCKET").as_deref())
                .unwrap_or_else(|_| Notify::disabled());
            loop {
                let _ = notify.extend_apply();
                if receive
                    .recv_timeout(std::time::Duration::from_secs(5))
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
