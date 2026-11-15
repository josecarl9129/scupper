//! Independent fixed-cadence session observation; no reconciler writer lock.
use super::{
    SAMPLE_INTERVAL, activate, checkpoint_recovered, checkpoint_stop_until, configured_keys,
    invalidate_at,
};
use crate::{
    lock::WriterLock,
    netns::NetnsHandle,
    system::{RealSystem, System},
};
use scupper_core::config::{GatewayId, ValidatedSite};
use std::{
    io,
    path::PathBuf,
    sync::{Arc, mpsc},
    thread,
    time::Instant,
};

struct Attachment {
    held: Arc<NetnsHandle>,
    identity: String,
    iface: String,
    keys: Vec<[u8; 32]>,
}
impl Attachment {
    fn new(held: Arc<NetnsHandle>, site: &ValidatedSite, gateway: &GatewayId) -> io::Result<Self> {
        held.verify(held.identity()).map_err(io::Error::other)?;
        let gw = site
            .gateway(gateway)
            .ok_or_else(|| io::Error::other("unknown gateway"))?;
        Ok(Self {
            held,
            identity: gw.client_tunnel().identity().public_key.as_str().to_owned(),
            iface: gw.client_tunnel().ifname().as_str().to_owned(),
            keys: configured_keys(site, gateway),
        })
    }
}
enum Control {
    Attach(Attachment),
    Stop,
    Finish(Instant, mpsc::Sender<io::Result<()>>),
}
/// Owned sampler. Dropping it requests stop without joining blocked storage I/O.
/// A single worker serializes commits, so late writes cannot reorder samples.
pub struct Sampler {
    control: mpsc::Sender<Control>,
}
impl Sampler {
    /// Consume EMPTY durably, then sample the held device every five seconds.
    /// The child has a three-second deadline; freshness permits ten seconds of
    /// collection/commit/scheduling slack. Missed slots are observation gaps.
    /// # Errors
    /// Rejects invalid namespaces, failed EMPTY consumption or worker startup.
    pub fn start(
        root: PathBuf,
        run: PathBuf,
        held: Arc<NetnsHandle>,
        binary: PathBuf,
        site: &ValidatedSite,
        gateway: &GatewayId,
    ) -> io::Result<Self> {
        let attachment = Attachment::new(held, site, gateway)?;
        let system = RealSystem::default().with_canon_paths(binary, run.clone());
        Self::start_worker(root, run, attachment, system)
    }
    fn start_worker(
        root: PathBuf,
        run: PathBuf,
        mut attachment: Attachment,
        system: impl System + Send + 'static,
    ) -> io::Result<Self> {
        let capability = WriterLock::try_acquire(run.join("client-sampler-owner"))?;
        activate(
            &root,
            &run,
            &attachment.identity,
            system.now_unix_secs(),
            &capability,
        )?;
        let (control, receive) = mpsc::channel();
        thread::Builder::new()
            .name("scupper-client-sampler".into())
            .spawn(move || {
                let finish = |attachment: &Attachment, deadline| {
                    checkpoint_stop_until(
                        &system,
                        &attachment.held,
                        &attachment.iface,
                        &root,
                        &run,
                        &attachment.identity,
                        &capability,
                        &attachment.keys,
                        deadline,
                    )
                };
                let mut next = Instant::now();
                loop {
                    for command in receive.try_iter() {
                        match command {
                            Control::Attach(new) => attachment = new,
                            Control::Stop => return,
                            Control::Finish(deadline, done) => {
                                let _ = done.send(finish(&attachment, deadline));
                                return;
                            }
                        }
                    }
                    if let Err(error) = checkpoint_recovered(
                        &system,
                        &attachment.held,
                        &attachment.iface,
                        &root,
                        &run,
                        &attachment.identity,
                        &capability,
                        &attachment.keys,
                    ) {
                        eprintln!("client sampler: {error}");
                    }
                    next += SAMPLE_INTERVAL;
                    let now = Instant::now();
                    // Never backfill missed samples or make a late commit fresh.
                    if now > next {
                        let wall_now = system.now_unix_secs();
                        invalidate_at(
                            &root,
                            &run,
                            &attachment.identity,
                            wall_now,
                            wall_now.saturating_sub(now.saturating_duration_since(next).as_secs()),
                        );
                        next = now + SAMPLE_INTERVAL;
                    }
                    loop {
                        match receive.recv_timeout(next.saturating_duration_since(Instant::now())) {
                            Ok(Control::Attach(new)) => attachment = new,
                            Ok(Control::Finish(deadline, done)) => {
                                let _ = done.send(finish(&attachment, deadline));
                                return;
                            }
                            Err(mpsc::RecvTimeoutError::Timeout) => break,
                            _ => return,
                        }
                    }
                }
            })?;
        Ok(Self { control })
    }
    /// Sample the last partial interval before a daemon-only stop. The worker
    /// retains its owner capability and uses the ordinary lifecycle/commit fences.
    /// Waiting is bounded even if storage I/O stalls; no clean-stop seal is made.
    /// # Errors
    /// Returns incomplete telemetry, persistence failure or a stopped/stalled worker.
    pub fn stop(self) -> io::Result<()> {
        let deadline = Instant::now() + SAMPLE_INTERVAL;
        let (done, completion) = mpsc::channel();
        self.control
            .send(Control::Finish(deadline, done))
            .map_err(|_| io::Error::other("session sampler stopped"))?;
        completion
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .map_err(|error| {
                io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!("final client sample: {error}"),
                )
            })?
    }
    #[cfg(all(test, feature = "testing"))]
    pub(super) fn start_test(
        root: PathBuf,
        identity: String,
        system: impl System + Send + 'static,
    ) -> io::Result<Self> {
        let held = Arc::new(crate::netns::testing::handle().map_err(io::Error::other)?);
        Self::start_worker(
            root.clone(),
            root,
            Attachment {
                held,
                identity,
                iface: "wg0".into(),
                keys: vec![[3; 32]],
            },
            system,
        )
    }
    /// Update the verified attachment without restarting cadence or its writer.
    /// # Errors
    /// Rejects invalid namespaces or a worker that has exited.
    pub fn attach(
        &self,
        held: Arc<NetnsHandle>,
        site: &ValidatedSite,
        gateway: &GatewayId,
    ) -> io::Result<()> {
        self.control
            .send(Control::Attach(Attachment::new(held, site, gateway)?))
            .map_err(|_| io::Error::other("session sampler stopped"))
    }
}
impl Drop for Sampler {
    fn drop(&mut self) {
        let _ = self.control.send(Control::Stop);
    }
}
