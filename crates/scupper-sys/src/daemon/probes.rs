//! At most one outstanding round per cadence, with child waits outside the tick.
use crate::{
    netns::NetnsHandle,
    probe_child::{self, ProbeExec, ProbeKind, ProbeRequest, ProbeResult},
    system::{ExecError, ExecOutput},
};
use scupper_core::config::ExitId;
use std::{
    collections::BTreeMap,
    fs::File,
    path::PathBuf,
    sync::{
        Arc,
        mpsc::{self, Receiver},
    },
    time::{Duration, Instant},
};

/// Explicit probe executable: the daemon never executes itself as a probe child.
pub struct ProbeCommand(pub PathBuf);
impl ProbeExec for ProbeCommand {
    #[cfg(any(test, feature = "testing"))]
    fn accepts_test_namespace(&self) -> bool {
        true
    }

    fn execute_probe(
        &self,
        json: &str,
        namespace: File,
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        let mut command = std::process::Command::new(&self.0);
        command.args(["probe", json]);
        crate::system::execute_file_command(command, namespace, timeout)
    }
}
/// Completed round, delivered atomically to its owner.
#[derive(Debug)]
pub struct Round {
    /// Path results only; Setup and unobserved outcomes are omitted.
    pub paths: BTreeMap<ExitId, bool>,
    /// Exit-IP observations completed successfully.
    pub exit_ok: Option<bool>,
}
/// Monotonic scheduler. Standby work is deliberately absent in M2.
pub struct Probes {
    binary: PathBuf,
    path_at: Instant,
    exit_at: Instant,
    path: Option<Receiver<Round>>,
    exit: Option<Receiver<Round>>,
}
impl Probes {
    /// Start both active observations immediately on the first eligible tick.
    #[must_use]
    pub fn new(binary: PathBuf, now: Instant) -> Self {
        Self {
            binary,
            path_at: now,
            exit_at: now,
            path: None,
            exit: None,
        }
    }
    /// Drain complete rounds without waiting; never split a round across ticks.
    pub fn collect(&mut self) -> Vec<Round> {
        let mut rounds = Vec::new();
        for pending in [&mut self.path, &mut self.exit] {
            if let Some(receive) = pending {
                match receive.try_recv() {
                    Ok(round) => {
                        rounds.push(round);
                        *pending = None;
                    }
                    Err(mpsc::TryRecvError::Disconnected) => *pending = None,
                    Err(mpsc::TryRecvError::Empty) => {}
                }
            }
        }
        rounds
    }
    /// Schedule the active path (10 s / 2 s Suspect) and exit IP (60 s).
    ///
    /// # Errors
    /// Returns worker creation failure; no tick waits for a child.
    pub fn schedule(
        &mut self,
        now: Instant,
        suspect: bool,
        exit: &ExitId,
        mut request: ProbeRequest,
        held: &Arc<NetnsHandle>,
    ) -> std::io::Result<()> {
        let interval = Duration::from_secs(if suspect { 2 } else { 10 });
        // A transition into Suspect shortens the outstanding deadline as well.
        self.path_at = self.path_at.min(now + interval);
        if now >= self.path_at && self.path.is_none() {
            request.kind = ProbeKind::Path;
            self.path = Some(spawn(
                self.binary.clone(),
                held.clone(),
                vec![(exit.clone(), request.clone())],
            )?);
            self.path_at = now + interval;
        }
        if now >= self.exit_at && self.exit.is_none() {
            request.kind = ProbeKind::ExitIp;
            self.exit = Some(spawn(
                self.binary.clone(),
                held.clone(),
                vec![(exit.clone(), request)],
            )?);
            self.exit_at = now + Duration::from_secs(60);
        }
        Ok(())
    }
}
fn spawn(
    binary: PathBuf,
    held: Arc<NetnsHandle>,
    requests: Vec<(ExitId, ProbeRequest)>,
) -> std::io::Result<Receiver<Round>> {
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("scupper-probe-wait".into())
        .spawn(move || {
            let exec = ProbeCommand(binary);
            let mut round = Round {
                paths: BTreeMap::new(),
                exit_ok: None,
            };
            for (exit, request) in requests {
                let result =
                    probe_child::run_probe(&exec, &held, &request).map(|outcome| outcome.result);
                if request.kind == ProbeKind::ExitIp {
                    round.exit_ok = Some(matches!(result, Ok(ProbeResult::Success { .. })));
                } else {
                    match result {
                        Ok(ProbeResult::Success { .. }) => {
                            round.paths.insert(exit, true);
                        }
                        Ok(ProbeResult::Path { .. } | ProbeResult::Timeout)
                        | Err(crate::verdict::ProbeError::Timeout) => {
                            round.paths.insert(exit, false);
                        }
                        _ => {} // Local setup failures cannot condemn an exit.
                    }
                }
            }
            let _ = send.send(round);
        })?;
    Ok(receive)
}

#[cfg(all(test, feature = "testing"))]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::probe_child::{ProbeCredentials, ProbeOutcome, Url};
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicUsize, Ordering},
    };
    fn script(contents: &str) -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../target/daemon-probe-workers")
            .join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        fs::create_dir_all(&path).unwrap();
        let script = path.join("probe");
        fs::write(&script, contents).unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o700)).unwrap();
        script
    }
    fn request(held: &NetnsHandle) -> ProbeRequest {
        ProbeRequest {
            kind: ProbeKind::Path,
            bind: None,
            expected_netns: held.identity(),
            dns: "10.2.0.1".parse().unwrap(),
            targets: vec![Url::new("https://example.com/").unwrap()],
            deadline_ms: 10,
            identity: None,
        }
    }
    #[test]
    fn round_is_delivered_once_after_every_child_completes() {
        let outcome = ProbeOutcome {
            result: ProbeResult::Success { ip: None },
            credentials: Some(ProbeCredentials {
                uids: [99; 4],
                gids: [98; 4],
                no_new_privs: true,
                cap_bnd: 0,
            }),
            threads_before_setns: Some(1),
        };
        let binary = script(&format!(
            "#!/bin/sh\nsleep 0.05\nprintf '%s' '{}'\n",
            serde_json::to_string(&outcome).unwrap()
        ));
        let held = Arc::new(crate::netns::testing::handle().unwrap());
        let req = request(&held);
        let receiver = spawn(
            binary.clone(),
            held,
            vec![
                (ExitId("one".into()), req.clone()),
                (ExitId("two".into()), req),
            ],
        )
        .unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        let round = receiver.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(
            round.paths,
            BTreeMap::from([(ExitId("one".into()), true), (ExitId("two".into()), true)])
        );
        assert!(receiver.try_recv().is_err());
        fs::remove_dir_all(binary.parent().unwrap()).unwrap();
    }
    #[test]
    fn hanging_child_is_killed_without_blocking_scheduler_or_tick_owner() {
        let binary = script("#!/bin/sh\nsleep 2\ntouch \"$0.survived\"\n");
        let held = Arc::new(crate::netns::testing::handle().unwrap());
        let started = Instant::now();
        let receiver = spawn(
            binary.clone(),
            held.clone(),
            vec![(ExitId("one".into()), request(&held))],
        )
        .unwrap();
        let mut iterations = 0;
        let round = loop {
            // This represents work on the tick thread while the child is hung.
            iterations += 1;
            match receiver.try_recv() {
                Ok(round) => break round,
                Err(mpsc::TryRecvError::Empty) => std::thread::sleep(Duration::from_millis(20)),
                Err(e) => {
                    assert_eq!(e, mpsc::TryRecvError::Empty, "worker vanished");
                }
            }
            assert!(started.elapsed() < Duration::from_secs(3));
        };
        assert!(iterations > 10);
        assert_eq!(round.paths, BTreeMap::from([(ExitId("one".into()), false)]));
        assert!(started.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(1100));
        assert!(!binary.with_extension("survived").exists());
        fs::remove_dir_all(binary.parent().unwrap()).unwrap();
    }
}
