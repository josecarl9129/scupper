//! Bounded systemd notification without a client library.
use crate::reconcile::{Escalation, TickReport};
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
    /// Notify only after a complete iteration without a pending rebuild.
    /// READY is retried until successfully sent, then emitted exactly once.
    ///
    /// # Errors
    /// Returns a nonblocking send error; the next eligible tick retries.
    pub fn completed(&mut self, report: &TickReport) -> io::Result<()> {
        if !report.complete || report.escalations.contains(&Escalation::RebuildRequired) {
            return Ok(());
        }
        if !self.ready {
            self.send(b"READY=1")?;
            self.ready = true;
        }
        self.send(b"WATCHDOG=1")
    }
    fn send(&self, message: &[u8]) -> io::Result<()> {
        if let Some((socket, address)) = &self.socket {
            socket.send_to_addr(message, address)?;
        }
        Ok(())
    }
}
