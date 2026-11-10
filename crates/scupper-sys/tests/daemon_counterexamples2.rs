//! Second-round regressions for state deadlines, replay and startup continuity.
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used)]
#[path = "support/v2.rs"]
mod support;
use scupper_core::config::GatewayId;
use scupper_proto::{Actor, EventKind, UnixSeconds};
use scupper_sys::{
    events::{EventLog, read_since},
    reconcile::StateStore,
    state::StateFile,
};
use std::{
    fs,
    io::Write,
    path::PathBuf,
    time::{Duration, Instant},
};

fn root(name: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/daemon-fix-counterexamples")
        .join(format!("{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}

#[test]
fn fx1_applied_snapshot_timeout_must_not_truncate_phase_b_state_read() {
    let root = root("fx1");
    let fifo = root.join("state.json");
    assert!(
        std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success()
    );
    let store = StateFile::open(&root, None).unwrap();
    assert!(
        StateStore::applied_snapshot_until(&store, Instant::now() + Duration::from_millis(25))
            .is_none(),
        "control: the snapshot read is still blocked"
    );
    let writer_path = fifo.clone();
    let writer = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(200));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .open(&writer_path)
            .unwrap();
        file.write_all(b"{}").unwrap();
    });
    let started = Instant::now();
    let result = StateStore::read_until(&store, Instant::now() + Duration::from_secs(3));
    let waited = started.elapsed();
    writer.join().unwrap();
    let _ = fs::remove_dir_all(&root);
    assert!(
        waited >= Duration::from_millis(150),
        "phase B gave up after {waited:?} with {result:?} although its deadline was 3 s; \
         the 25 ms snapshot left its worker pending, so the next read only polled it"
    );
}

#[test]
fn fx2_replay_must_not_leave_an_unexplained_disk_sequence_hole() {
    let root = root("fx2");
    let memory = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(2)).unwrap();
    for _ in 0..5 {
        memory
            .handle
            .emit(EventKind::Flapping {}, Actor::Daemon, None)
            .unwrap();
    }
    let disk = EventLog::open(&root, GatewayId("gw1".into()), || UnixSeconds(3)).unwrap();
    memory.handle.replay_into(&disk.handle).unwrap();
    disk.handle.flush_blocking(Duration::from_secs(5)).unwrap();
    let mut seqs: Vec<u64> = read_since(&root, 0, None)
        .filter_map(Result::ok)
        .filter(|e| !matches!(e.kind, EventKind::EventGap { .. }))
        .map(|e| e.seq)
        .collect();
    seqs.sort_unstable();
    drop(disk);
    let _ = fs::remove_dir_all(&root);
    let first = *seqs.first().unwrap();
    assert!(
        first <= 1 && seqs.windows(2).all(|w| w[1] == w[0] + 1),
        "disk seqs {seqs:?} start at {first} or have holes with no EventGap covering them"
    );
}

use scupper_core::{
    failover::MonoTime,
    planner::{Desired, Known, Step},
    render::{RouteTarget, VersionStamp},
    verdict::v2::Selection,
};
use scupper_sys::{
    canon::{self, CanonCache},
    daemon::{DaemonDeps, Iteration, run_with},
    lock::WriterGuard,
    netns::NetnsHandle,
    reconcile::{Config, Kernel, Observation, Reconciler, StepError, TickReport, fake::FakeKernel},
    state::State,
    system::{ExecError, ExecOutput, ExecTarget, Program, System},
};
use std::{
    cell::RefCell,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};

struct CacheSystem {
    cache: RefCell<CanonCache>,
    root: PathBuf,
    calls: Arc<AtomicUsize>,
    live: String,
}
const RULES: &str = r#"{"nftables":[{"table":{"family":"inet","name":"scupper"}}]}"#;
impl System for CacheSystem {
    fn canon_cache(&self) -> Option<(&RefCell<CanonCache>, &Path)> {
        Some((&self.cache, &self.root))
    }
    fn canon_run_root(&self) -> &Path {
        &self.root
    }
    fn canon_worker(&self) -> Option<Box<dyn System + Send>> {
        Some(Box::new(Self {
            cache: RefCell::default(),
            root: self.root.clone(),
            calls: self.calls.clone(),
            live: self.live.clone(),
        }))
    }
    fn run(&self, program: Program, _: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        if program == Program::Unshare {
            std::thread::sleep(Duration::from_millis(200));
        }
        Ok(ExecOutput {
            status: Some(0),
            stdout: if program == Program::Unshare {
                RULES.into()
            } else {
                "nft v1".into()
            },
            stderr: String::new(),
        })
    }
    fn run_in(
        &self,
        _: ExecTarget<'_>,
        _: Program,
        _: &[String],
        _: Duration,
    ) -> Result<ExecOutput, ExecError> {
        Ok(ExecOutput {
            status: Some(0),
            stdout: self.live.clone(),
            stderr: String::new(),
        })
    }
    fn now_unix_secs(&self) -> u64 {
        100
    }
}
struct CacheKernel<'a> {
    fake: FakeKernel,
    system: &'a CacheSystem,
}
impl Kernel for CacheKernel<'_> {
    fn observe(&self, held: &NetnsHandle) -> Observation {
        let mut observed = self.fake.observe(held);
        if !canon::netns_rulesets_safety(self.system, held, "rendered")
            .is_ok_and(|(want, live)| want == live)
        {
            observed.model.ruleset = Known::Unknown;
            observed.safety_complete = false;
        }
        observed
    }
    fn observe_rest(
        &self,
        held: &NetnsHandle,
        safety: Observation,
        deadline: Instant,
    ) -> Observation {
        self.fake.observe_rest(held, safety, deadline)
    }
    fn execute(&self, step: &Step) -> Result<(), StepError> {
        self.fake.execute(step)
    }
    fn restore_name(&self, held: &NetnsHandle, guard: &WriterGuard) -> Result<(), StepError> {
        self.fake.restore_name(held, guard)
    }
}
fn now() -> (MonoTime, u64) {
    (MonoTime(Duration::from_secs(100)), 100)
}
type StartupMachine<'a> = Reconciler<CacheKernel<'a>, StateFile, fn() -> (MonoTime, u64)>;
struct StartupDaemon<'a> {
    machine: StartupMachine<'a>,
    system: &'a CacheSystem,
    held: Arc<NetnsHandle>,
    root: &'a Path,
    stop: &'a AtomicBool,
    ticks: usize,
    slow: bool,
    writer: Option<std::thread::JoinHandle<()>>,
    time: Instant,
    ready: bool,
}
impl DaemonDeps for StartupDaemon<'_> {
    fn initialize(&mut self) {
        // Same ordering as production: bounded cold canonicalization, handoff, READY.
        assert_eq!(self.system.calls.load(Ordering::Relaxed), 0);
        let started = Instant::now();
        canon::prepare_netns_ruleset(
            self.system,
            &self.held,
            "rendered",
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        assert!(started.elapsed() >= Duration::from_millis(150));
        self.machine.resume_existing();
        if self.slow {
            let fifo = self.root.join("state.json");
            fs::remove_file(&fifo).unwrap();
            assert!(
                std::process::Command::new("mkfifo")
                    .arg(&fifo)
                    .status()
                    .unwrap()
                    .success()
            );
            self.writer = Some(std::thread::spawn(move || {
                std::thread::sleep(Duration::from_millis(200));
                let mut file = fs::OpenOptions::new().write(true).open(fifo).unwrap();
                file.write_all(
                    &serde_json::to_vec(&State {
                        applied_version: Some(1),
                        ..State::default()
                    })
                    .unwrap(),
                )
                .unwrap();
            }));
        }
    }
    fn now(&self) -> Instant {
        self.time
    }
    fn sleep(&mut self, duration: Duration) {
        self.time += duration;
    }
    fn started(&mut self) {
        self.ready = true;
    }
    fn tick(&mut self, _: &AtomicBool) -> Option<TickReport> {
        assert!(self.ready);
        self.ticks += 1;
        let started = Instant::now();
        let report = self.machine.tick();
        if let Some(writer) = self.writer.take() {
            writer.join().unwrap();
            assert!(started.elapsed() >= Duration::from_millis(150));
            fs::remove_file(self.root.join("state.json")).unwrap();
            fs::write(
                self.root.join("state.json"),
                serde_json::to_vec(&State {
                    applied_version: Some(1),
                    ..State::default()
                })
                .unwrap(),
            )
            .unwrap();
        }
        assert!(report.complete, "{report:?}");
        if self.ticks == 8 {
            self.stop.store(true, Ordering::Relaxed);
        }
        Some(report)
    }
    fn close_only(&mut self) {
        assert!(self.ticks == usize::MAX, "unexpected startup close");
    }
    fn abandon_probes(&mut self) {}
    fn rebuild(&mut self) {
        assert!(self.ticks == usize::MAX, "unexpected rebuild");
    }
    fn run_root(&self) -> &Path {
        self.root
    }
    fn boot_time(&self) -> Duration {
        Duration::from_secs(100)
    }
    fn budget_error(&mut self, error: &std::io::Error) {
        assert!(self.ticks == usize::MAX, "{error}");
    }
    fn maintenance(&mut self) {}
    fn notify(&mut self, iteration: &Iteration) {
        assert!(iteration.complete);
    }
    fn shutdown(&mut self) {}
}

#[test]
fn healthy_daemon_start_and_restart_never_close_with_cold_cache_and_slow_state() {
    for slow in [false, true] {
        let root = root(if slow { "startup-slow" } else { "startup" });
        let site = support::site("ubuntu-24.04");
        let gateway = GatewayId("gw1".into());
        let stamp = VersionStamp {
            version: 1,
            sha256: [1; 32],
        };
        let desired = Desired::new(
            &site,
            &gateway,
            &stamp,
            [7; 32],
            &RouteTarget::Exit(site.gateway(&gateway).unwrap().exits()[0].ifname().clone()),
            &Selection::Auto,
        )
        .unwrap();
        let kernel = FakeKernel::new(desired);
        let log = EventLog::memory_only(gateway.clone(), || UnixSeconds(100)).unwrap();
        fs::write(
            root.join("state.json"),
            serde_json::to_vec(&State {
                applied_version: Some(1),
                ..State::default()
            })
            .unwrap(),
        )
        .unwrap();
        for _ in 0..2 {
            let system = CacheSystem {
                cache: RefCell::default(),
                root: root.clone(),
                calls: Arc::default(),
                live: RULES.into(),
            };
            let held = Arc::new(scupper_sys::netns::testing::handle().unwrap());
            let machine = Reconciler::new(
                CacheKernel {
                    fake: kernel.clone(),
                    system: &system,
                },
                StateFile::open(&root, None).unwrap(),
                log.handle.clone(),
                Config {
                    site: site.clone(),
                    gateway: gateway.clone(),
                    stamp,
                    fingerprint: [7; 32],
                    run_root: root.clone(),
                    lock_wait: Duration::from_millis(100),
                },
                held.clone(),
                now as fn() -> (MonoTime, u64),
            )
            .unwrap();
            let stop = AtomicBool::new(false);
            let mut daemon = StartupDaemon {
                machine,
                system: &system,
                held,
                root: &root,
                stop: &stop,
                ticks: 0,
                slow,
                writer: None,
                time: Instant::now(),
                ready: false,
            };
            run_with(&mut daemon, &stop);
            assert_eq!(daemon.ticks, 8);
            assert!(
                !kernel.history().iter().any(|(step, _)| matches!(
                    step,
                    Step::ForwardingOff | Step::RouteReplace { .. } | Step::FlushConntrack
                )),
                "{:?}",
                kernel.history()
            );
        }
        fs::remove_dir_all(root).unwrap();
    }
}

#[test]
fn safety_cache_misses_and_confirmations_never_wait_on_worker_io() {
    let root = root("pending-cache");
    let mut system = CacheSystem {
        cache: RefCell::default(),
        root: root.clone(),
        calls: Arc::default(),
        live: RULES.into(),
    };
    let held = scupper_sys::netns::testing::handle().unwrap();
    let started = Instant::now();
    assert!(matches!(
        canon::prepare_netns_ruleset(
            &system,
            &held,
            "rendered",
            Instant::now() + Duration::from_millis(5)
        ),
        Err(scupper_sys::verdict::ProbeError::Timeout)
    ));
    assert!(canon::netns_rulesets_safety(&system, &held, "rendered").is_err());
    assert!(started.elapsed() < Duration::from_millis(100));
    std::thread::sleep(Duration::from_millis(250));
    assert!(canon::netns_rulesets_safety(&system, &held, "rendered").is_ok());
    // A changed live JSON cannot inherit a previously verified observation.
    system.live = r#"{"nftables":[]}"#.into();
    let started = Instant::now();
    assert!(canon::netns_rulesets_safety(&system, &held, "rendered").is_err());
    assert!(started.elapsed() < Duration::from_millis(100));
    // Returning to the verified live JSON keeps traffic while confirmation is pending.
    system.live = RULES.into();
    assert!(canon::netns_rulesets_safety(&system, &held, "rendered").is_ok());
    // Different render inputs cannot use that verified result while pending.
    assert!(canon::netns_rulesets_safety(&system, &held, "other render").is_err());
    std::thread::sleep(Duration::from_millis(250));
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn startup_handoff_does_not_adopt_unknown_rules_or_an_unhealthy_exit() {
    use scupper_core::config::ExitId;
    use scupper_sys::reconcile::fake::MemoryStore;
    for drift in 0..4 {
        let root = root(&format!("refuse-startup-{drift}"));
        let site = support::site("ubuntu-24.04");
        let gateway = GatewayId("gw1".into());
        let stamp = VersionStamp {
            version: 1,
            sha256: [1; 32],
        };
        let target = RouteTarget::Exit(site.gateway(&gateway).unwrap().exits()[0].ifname().clone());
        let desired =
            Desired::new(&site, &gateway, &stamp, [7; 32], &target, &Selection::Auto).unwrap();
        let kernel = FakeKernel::new(desired);
        match drift {
            0 => kernel.mutate(|model| model.ruleset = Known::Unknown),
            1 => kernel.handshake(ExitId("ch1".into()), None),
            2 => kernel.mutate(|model| {
                model.default_v4 =
                    Known::Value(scupper_core::verdict::v2::DefaultRouteObs::Unreachable);
            }),
            _ => kernel
                .mutate(|model| model.links.get_mut("ex-ch1").unwrap().tc_hooks = Known::Unknown),
        }
        let log = EventLog::memory_only(gateway.clone(), || UnixSeconds(100)).unwrap();
        let mut machine = Reconciler::new(
            kernel.clone(),
            MemoryStore::new(State {
                applied_version: Some(1),
                ..State::default()
            }),
            log.handle.clone(),
            Config {
                site,
                gateway,
                stamp,
                fingerprint: [7; 32],
                run_root: root.clone(),
                lock_wait: Duration::from_millis(100),
            },
            Arc::new(scupper_sys::netns::testing::handle().unwrap()),
            now,
        )
        .unwrap();
        machine.resume_existing();
        assert!(
            machine
                .desired()
                .unwrap()
                .routes()
                .iter()
                .all(|(_, route)| *route == RouteTarget::Unreachable)
        );
        assert_eq!(kernel.history(), []);
        fs::remove_dir_all(root).unwrap();
    }
}
