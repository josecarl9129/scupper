//! Review counterexamples: replay identity, boot publication and warm-cache I/O.
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used)]
#[path = "support/v2.rs"]
mod support;
use scupper_core::{
    config::GatewayId,
    failover::MonoTime,
    planner::{Desired, Known, Step},
    render::{RouteTarget, VersionStamp},
    verdict::v2::Selection,
};
use scupper_proto::{Actor, EventKind, UnixSeconds};
use scupper_sys::{
    canon::CanonCache,
    events::{EventLog, read_since},
    lock::WriterGuard,
    netns::NetnsHandle,
    reconcile::{
        Config, Kernel, Observation, Reconciler, StepError,
        fake::{FakeKernel, MemoryStore},
    },
    state::State,
    system::{ExecError, ExecOutput, ExecTarget, Program, System},
};
use std::{
    cell::{Cell, RefCell},
    fs,
    path::{Path, PathBuf},
    rc::Rc,
    sync::Arc,
    time::{Duration, Instant},
};

fn root(name: &str) -> PathBuf {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/daemon-counterexamples")
        .join(format!("{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    root
}
#[test]
fn replay_gap_must_not_name_committed_disk_seqs_or_count_replayed_events_as_dropped() {
    let root = root("ce1");
    {
        let opened = EventLog::open(&root, GatewayId("gw1".into()), || UnixSeconds(1)).unwrap();
        for _ in 0..20 {
            opened
                .handle
                .emit(EventKind::Flapping {}, Actor::Daemon, None)
                .unwrap();
        }
        opened
            .handle
            .flush_blocking(Duration::from_secs(5))
            .unwrap();
    }
    let committed: Vec<u64> = read_since(&root, 0, None)
        .filter_map(Result::ok)
        .map(|e| e.seq)
        .collect();
    assert!(committed.len() >= 20);
    let memory = EventLog::memory_only(GatewayId("gw1".into()), || UnixSeconds(2)).unwrap();
    let mut local_last = 0;
    for _ in 0..3 {
        local_last = memory
            .handle
            .emit(EventKind::Flapping {}, Actor::Daemon, None)
            .unwrap();
    }
    let disk = EventLog::open(&root, GatewayId("gw1".into()), || UnixSeconds(3)).unwrap();
    memory.handle.replay_into(&disk.handle).unwrap();
    disk.handle.flush_blocking(Duration::from_secs(5)).unwrap();
    let events: Vec<_> = read_since(&root, 0, None).filter_map(Result::ok).collect();
    // API change: a memory replay names a local interval, never a disk gap.
    let (dropped, first, last, replayed) = events
        .iter()
        .find_map(|e| match e.kind {
            EventKind::MemoryReplay {
                dropped,
                local_first,
                local_last,
                replayed,
            } => Some((dropped, local_first, local_last, replayed)),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        (dropped, first, last, replayed),
        (0, 1, local_last, local_last)
    );
    assert!(!events.iter().any(|e| matches!(e.kind, EventKind::EventGap { first_seq, last_seq, .. } if committed.iter().any(|s| (first_seq..=last_seq).contains(s)))));
    let replay: Vec<_> = events
        .iter()
        .filter(|e| e.seq > *committed.last().unwrap() && matches!(e.kind, EventKind::Flapping {}))
        .collect();
    assert_eq!(replay.len(), 3);
    assert!(replay.iter().all(|e| e.at == UnixSeconds(2)));
    drop(disk);
    fs::remove_dir_all(root).unwrap();
}

struct Rig {
    root: PathBuf,
    kernel: FakeKernel,
    store: MemoryStore,
    held: Arc<NetnsHandle>,
    config: Config,
    log: scupper_sys::events::OpenedLog,
}
impl Rig {
    fn new(name: &str) -> Self {
        let root = root(name);
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
            &RouteTarget::Unreachable,
            &Selection::Auto,
        )
        .unwrap();
        Self {
            config: Config {
                site,
                gateway: gateway.clone(),
                stamp,
                fingerprint: [7; 32],
                run_root: root.clone(),
                lock_wait: Duration::from_millis(100),
            },
            root,
            kernel: FakeKernel::new(desired),
            store: MemoryStore::new(State {
                applied_version: Some(1),
                ..State::default()
            }),
            held: Arc::new(scupper_sys::netns::testing::handle().unwrap()),
            log: EventLog::memory_only(gateway, || UnixSeconds(1000)).unwrap(),
        }
    }
}
struct Publishing {
    inner: FakeKernel,
    fail: Rc<Cell<bool>>,
}
impl Kernel for Publishing {
    fn checkpoint_owned(&self, _: &WriterGuard) -> Result<(), StepError> {
        if self.fail.get() {
            Err(StepError("boot identity write failed"))
        } else {
            Ok(())
        }
    }
    fn observe(&self, held: &NetnsHandle) -> Observation {
        self.inner.observe(held)
    }
    fn observe_rest(
        &self,
        held: &NetnsHandle,
        safety: Observation,
        deadline: Instant,
    ) -> Observation {
        self.inner.observe_rest(held, safety, deadline)
    }
    fn restore_name(&self, held: &NetnsHandle, guard: &WriterGuard) -> Result<(), StepError> {
        self.inner.restore_name(held, guard)
    }
    fn execute(&self, step: &Step) -> Result<(), StepError> {
        self.inner.execute(step)
    }
    fn hold_latch(&self, latch: Option<&scupper_core::planner::Latch>) {
        self.inner.hold_latch(latch);
    }
}
#[test]
fn publication_failure_alone_keeps_ticks_complete() {
    let rig = Rig::new("ce2");
    let fail = Rc::new(Cell::new(false));
    let mut machine = Reconciler::new(
        Publishing {
            inner: rig.kernel.clone(),
            fail: fail.clone(),
        },
        rig.store.clone(),
        rig.log.handle.clone(),
        rig.config,
        rig.held.clone(),
        || (MonoTime(Duration::from_secs(100)), 1000),
    )
    .unwrap();
    let mut last = machine.tick();
    for _ in 0..5 {
        last = machine.tick();
    }
    assert!(
        last.complete,
        "control: healthy rig must reach complete ticks: {last:?}"
    );
    fail.set(true);
    for _ in 0..3 {
        let report = machine.tick();
        assert!(
            report.complete,
            "persistence-only failure starved the watchdog: {report:?}"
        );
        assert!(report.events.iter().any(|e| matches!(
            e,
            EventKind::PersistenceFailed {
                reason: scupper_proto::Reason::BootWrite
            }
        )));
    }
    rig.kernel.mutate(|model| {
        model.links.remove("ex-ch1");
    });
    let mut moved = false;
    let mut raised = false;
    for _ in 0..5 {
        let report = machine.tick();
        moved |= report.steps.iter().any(|step| {
            matches!(
                step,
                Step::LinkCreate {
                    phase: scupper_core::planner::LinkPhase::Move,
                    ..
                }
            )
        });
        raised |= report.steps.iter().any(|step| {
            matches!(
                step,
                Step::LinkCreate {
                    phase: scupper_core::planner::LinkPhase::Up,
                    ..
                }
            )
        });
        assert!(!report.failures.iter().any(|(step, _)| matches!(
            step,
            Step::LinkCreate {
                phase: scupper_core::planner::LinkPhase::Move,
                ..
            }
        )));
    }
    assert!(
        moved && raised,
        "boot publication skipped the rest of a successful link sequence"
    );
    fs::remove_dir_all(rig.root).unwrap();
}
struct Cached {
    cache: RefCell<CanonCache>,
    binary: PathBuf,
    temp: PathBuf,
    live: String,
    infra_calls: Cell<usize>,
}
impl System for Cached {
    fn canon_cache(&self) -> Option<(&RefCell<CanonCache>, &Path)> {
        Some((&self.cache, &self.binary))
    }
    fn canon_run_root(&self) -> &Path {
        &self.temp
    }
    fn run(&self, program: Program, args: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
        let stdout = match program {
            Program::Nft if args == ["--version"] => {
                self.infra_calls.set(self.infra_calls.get() + 1);
                "nft v1".into()
            }
            Program::Nft => self.live.clone(),
            Program::Unshare => {
                self.infra_calls.set(self.infra_calls.get() + 1);
                self.live.clone()
            }
            _ => return Err(ExecError::spawn("unexpected program")),
        };
        Ok(ExecOutput {
            status: Some(0),
            stdout,
            stderr: String::new(),
        })
    }
    fn run_in(
        &self,
        _: ExecTarget<'_>,
        p: Program,
        a: &[String],
        t: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.run(p, a, t)
    }
    fn now_unix_secs(&self) -> u64 {
        0
    }
}
struct CacheObserving<'a> {
    inner: FakeKernel,
    sys: &'a Cached,
}
impl Kernel for CacheObserving<'_> {
    fn restore_name(&self, held: &NetnsHandle, guard: &WriterGuard) -> Result<(), StepError> {
        self.inner.restore_name(held, guard)
    }
    fn observe(&self, held: &NetnsHandle) -> Observation {
        let mut observation = self.inner.observe(held);
        if scupper_sys::canon::netns_rulesets(self.sys, held, "rendered").is_err() {
            observation.model.ruleset = Known::Unknown;
        }
        observation
    }
    fn observe_rest(
        &self,
        held: &NetnsHandle,
        safety: Observation,
        deadline: Instant,
    ) -> Observation {
        self.inner.observe_rest(held, safety, deadline)
    }
    fn execute(&self, step: &Step) -> Result<(), StepError> {
        self.inner.execute(step)
    }
}
#[test]
fn warm_cache_observation_must_not_need_a_temp_file() {
    // Explicit runtime path replaces TMPDIR: the miss loader now uses /run/scupper.
    let rig = Rig::new("ce3");
    let tmp = rig.root.join("run");
    fs::create_dir(&tmp).unwrap();
    let binary = rig.root.join("nft");
    fs::write(&binary, "fixture").unwrap();
    let sys = Cached {
        cache: RefCell::default(),
        binary,
        temp: tmp.clone(),
        live: r#"{"nftables":[{"table":{"family":"inet","name":"scupper"}}]}"#.into(),
        infra_calls: Cell::new(0),
    };
    let (want, live) = scupper_sys::canon::netns_rulesets(&sys, &rig.held, "rendered").unwrap();
    assert_eq!(want, live);
    let time = Cell::new(100_u64);
    let mut machine = Reconciler::new(
        CacheObserving {
            inner: rig.kernel.clone(),
            sys: &sys,
        },
        rig.store.clone(),
        rig.log.handle.clone(),
        rig.config,
        rig.held.clone(),
        || {
            let t = time.get();
            time.set(t + 2);
            (MonoTime(Duration::from_secs(t)), 1000 + t)
        },
    )
    .unwrap();
    for _ in 0..6 {
        machine.submit_probe_round(std::collections::BTreeMap::from([(
            scupper_core::config::ExitId("ch1".into()),
            true,
        )]));
        machine.tick();
    }
    assert_eq!(rig.kernel.model().forwarding_v4, Known::Value(1));
    rig.kernel.clear_history();
    let calls = sys.infra_calls.get();
    fs::remove_dir_all(&tmp).unwrap();
    fs::remove_file(&sys.binary).unwrap();
    let again = scupper_sys::canon::netns_rulesets(&sys, &rig.held, "rendered");
    assert!(
        again.is_ok(),
        "warm-cache safety observation failed on temp-dir I/O: {again:?}"
    );
    assert_eq!(
        sys.infra_calls.get(),
        calls,
        "a cache hit executed tool discovery or a canon child"
    );
    let report = machine.tick();
    assert!(report.complete);
    assert_eq!(rig.kernel.model().forwarding_v4, Known::Value(1));
    assert!(
        !rig.kernel
            .history()
            .iter()
            .any(|(step, _)| matches!(step, Step::ForwardingOff))
    );
    fs::write(&sys.binary, "fixture").unwrap();
    // A failed miss closes observation, but leaves an old, usable hit intact.
    assert!(scupper_sys::canon::netns_rulesets(&sys, &rig.held, "changed").is_err());
    fs::create_dir(&tmp).unwrap();
    assert!(scupper_sys::canon::netns_rulesets(&sys, &rig.held, "rendered").is_ok());
    fs::remove_dir_all(rig.root).unwrap();
}
