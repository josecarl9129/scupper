//! At most one outstanding round per cadence, with child waits outside the tick.
use crate::{
    netns::NetnsHandle,
    probe_child::{self, ProbeExec, ProbeKind, ProbeRequest, ProbeResult},
    system::{ExecError, ExecOutput},
};
use scupper_core::{config::ExitId, failover::ProbeOutcome};
use std::{
    collections::BTreeMap,
    fs::File,
    net::IpAddr,
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
/// Exit IP results keep an observed leak distinct from ordinary probe failure.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitIpOutcome {
    /// A non-uplink exit address was observed.
    Ok,
    /// No usable exit address was obtained.
    ProbeFailed,
    /// The exit address equals a host uplink address.
    UplinkAddress,
}
/// Completed round, delivered atomically to its owner.
#[derive(Debug)]
pub struct Round {
    /// Path results, including failed child setup.
    pub paths: BTreeMap<ExitId, ProbeOutcome>,
    /// Exit-IP observations completed successfully.
    pub exit_ok: Option<ExitIpOutcome>,
    /// Number of child setup failures in this round.
    pub setup_failures: u64,
}
/// Monotonic scheduler. Standby work is deliberately absent in M2.
pub struct Probes {
    binary: PathBuf,
    uplink: Vec<IpAddr>,
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
            uplink: Vec::new(),
            path_at: now,
            exit_at: now,
            path: None,
            exit: None,
        }
    }
    /// Addresses which an exit-IP response must never report.
    #[must_use]
    pub fn with_uplink(mut self, uplink: Vec<IpAddr>) -> Self {
        self.uplink = uplink;
        self
    }
    fn launch(
        &mut self,
        held: &Arc<NetnsHandle>,
        exit: &ExitId,
        request: &ProbeRequest,
    ) -> Receiver<Round> {
        match spawn(
            self.binary.clone(),
            held.clone(),
            vec![(exit.clone(), request.clone())],
            self.uplink.clone(),
        ) {
            Ok(receiver) => receiver,
            Err(error) => {
                eprintln!("scupperd: probe worker setup: {error}");
                let (send, receiver) = mpsc::sync_channel(1);
                let _ = send.send(failed_round(exit, request.kind));
                receiver
            }
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
    /// Reserved for scheduler errors. Worker creation failure is delivered as a
    /// failed round so that health and audit observations are never lost.
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
            self.path = Some(self.launch(held, exit, &request));
            self.path_at = now + interval;
        }
        if now >= self.exit_at && self.exit.is_none() {
            request.kind = ProbeKind::ExitIp;
            self.exit = Some(self.launch(held, exit, &request));
            self.exit_at = now + Duration::from_secs(60);
        }
        Ok(())
    }
}
fn failed_round(exit: &ExitId, kind: ProbeKind) -> Round {
    Round {
        paths: BTreeMap::from([(exit.clone(), ProbeOutcome::Inconclusive)]),
        exit_ok: (kind == ProbeKind::ExitIp).then_some(ExitIpOutcome::ProbeFailed),
        setup_failures: 1,
    }
}
fn spawn(
    binary: PathBuf,
    held: Arc<NetnsHandle>,
    requests: Vec<(ExitId, ProbeRequest)>,
    uplink: Vec<IpAddr>,
) -> std::io::Result<Receiver<Round>> {
    spawn_with(ProbeCommand(binary), held, requests, uplink)
}
fn spawn_with(
    exec: impl ProbeExec + Send + 'static,
    held: Arc<NetnsHandle>,
    requests: Vec<(ExitId, ProbeRequest)>,
    uplink: Vec<IpAddr>,
) -> std::io::Result<Receiver<Round>> {
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("scupper-probe-wait".into())
        .spawn(move || {
            let mut round = Round {
                paths: BTreeMap::new(),
                exit_ok: None,
                setup_failures: 0,
            };
            for (exit, request) in requests {
                let result =
                    probe_child::run_probe(&exec, &held, &request).map(|outcome| outcome.result);
                let setup = matches!(&result, Ok(ProbeResult::Setup { .. }) | Err(_))
                    && !matches!(&result, Err(crate::verdict::ProbeError::Timeout));
                round.setup_failures += u64::from(setup);
                if setup || (request.kind == ProbeKind::ExitIp && uplink.is_empty()) {
                    round.paths.insert(exit, ProbeOutcome::Inconclusive);
                    if !setup {
                        round.setup_failures += 1;
                    }
                } else if request.kind == ProbeKind::ExitIp {
                    round.exit_ok = Some(match result {
                        Ok(ProbeResult::Success { ip: Some(ip) }) if uplink.contains(&ip) => {
                            ExitIpOutcome::UplinkAddress
                        }
                        Ok(ProbeResult::Success { ip: Some(_) }) => ExitIpOutcome::Ok,
                        _ => ExitIpOutcome::ProbeFailed,
                    });
                } else {
                    round.paths.insert(
                        exit,
                        matches!(result, Ok(ProbeResult::Success { .. })).into(),
                    );
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
    use crate::probe_child::{ProbeCredentials, ProbeOutcome as ChildOutcome, Url};
    use std::{
        fs,
        os::unix::fs::PermissionsExt,
        sync::atomic::{AtomicUsize, Ordering},
    };
    // Interpret fixtures explicitly: concurrently forked children can briefly
    // inherit an executable script's write fd and make direct exec fail ETXTBSY.
    struct ShellProbe(PathBuf);
    impl ProbeExec for ShellProbe {
        fn accepts_test_namespace(&self) -> bool {
            true
        }
        fn execute_probe(
            &self,
            json: &str,
            namespace: File,
            timeout: Duration,
        ) -> Result<ExecOutput, ExecError> {
            let mut command = std::process::Command::new("/bin/sh");
            command.arg(&self.0).args(["probe", json]);
            crate::system::execute_file_command(command, namespace, timeout)
        }
    }
    fn spawn(
        binary: PathBuf,
        held: Arc<NetnsHandle>,
        requests: Vec<(ExitId, ProbeRequest)>,
        uplink: Vec<IpAddr>,
    ) -> std::io::Result<Receiver<Round>> {
        super::spawn_with(ShellProbe(binary), held, requests, uplink)
    }
    fn script(contents: &str) -> PathBuf {
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let path = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || {
                    std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/tmp"
                    ))
                },
                std::path::PathBuf::from,
            )
            .join("daemon-probe-workers")
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
        let outcome = ChildOutcome {
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
            Vec::new(),
        )
        .unwrap();
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::TryRecvError::Empty)
        ));
        let round = receiver.recv_timeout(Duration::from_secs(3)).unwrap();
        assert_eq!(
            round.paths,
            BTreeMap::from([
                (ExitId("one".into()), ProbeOutcome::Success),
                (ExitId("two".into()), ProbeOutcome::Success)
            ])
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
            Vec::new(),
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
        assert_eq!(
            round.paths,
            BTreeMap::from([(ExitId("one".into()), ProbeOutcome::Failure)])
        );
        assert!(started.elapsed() < Duration::from_secs(2));
        std::thread::sleep(Duration::from_millis(1100));
        assert!(!binary.with_extension("survived").exists());
        fs::remove_dir_all(binary.parent().unwrap()).unwrap();
    }
    #[test]
    fn setup_failures_are_delivered_for_both_probe_kinds() {
        let held = Arc::new(crate::netns::testing::handle().unwrap());
        for kind in [ProbeKind::Path, ProbeKind::ExitIp] {
            let mut req = request(&held);
            req.kind = kind;
            let round = spawn(
                PathBuf::from("/nonexistent/scupper-probe"),
                held.clone(),
                vec![(ExitId("one".into()), req)],
                Vec::new(),
            )
            .unwrap()
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
            assert_eq!(round.setup_failures, 1);
            assert_eq!(
                round.paths.get(&ExitId("one".into())),
                Some(&ProbeOutcome::Inconclusive)
            );
        }
        let fallback = failed_round(&ExitId("one".into()), ProbeKind::Path);
        assert_eq!(
            fallback.paths.get(&ExitId("one".into())),
            Some(&ProbeOutcome::Inconclusive)
        );
        assert_eq!(fallback.setup_failures, 1);
    }
    #[test]
    fn exit_ip_must_differ_from_real_uplink_addresses() {
        let held = Arc::new(crate::netns::testing::handle().unwrap());
        for (observed, expected) in [
            ("192.0.2.1", ExitIpOutcome::UplinkAddress),
            ("198.51.100.1", ExitIpOutcome::Ok),
        ] {
            let outcome = ChildOutcome {
                result: ProbeResult::Success {
                    ip: Some(observed.parse().unwrap()),
                },
                credentials: Some(ProbeCredentials {
                    uids: [99; 4],
                    gids: [98; 4],
                    no_new_privs: true,
                    cap_bnd: 0,
                }),
                threads_before_setns: Some(1),
            };
            let binary = script(&format!(
                "#!/bin/sh\nprintf '%s' '{}'\n",
                serde_json::to_string(&outcome).unwrap()
            ));
            let mut req = request(&held);
            req.kind = ProbeKind::ExitIp;
            let round = spawn(
                binary.clone(),
                held.clone(),
                vec![(ExitId("one".into()), req)],
                vec!["192.0.2.1".parse().unwrap()],
            )
            .unwrap()
            .recv_timeout(Duration::from_secs(3))
            .unwrap();
            assert_eq!(round.exit_ok, Some(expected));
            assert_eq!(round.setup_failures, 0);
            fs::remove_dir_all(binary.parent().unwrap()).unwrap();
        }
    }
}
