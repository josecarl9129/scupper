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
    fn send(&self, message: &[u8]) -> io::Result<()> {
        if let Some((socket, address)) = &self.socket {
            socket.send_to_addr(message, address)?;
        }
        Ok(())
    }
}
