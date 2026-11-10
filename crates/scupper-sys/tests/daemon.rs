//! Daemon persistence recovery and canonical-cache boundaries.
#![allow(clippy::unwrap_used)]
use scupper_core::config::GatewayId;
use scupper_proto::{Actor, EventKind};
use scupper_sys::{
    canon::{CacheKey, CanonCache},
    daemon::{Audit, notify::Notify},
    events::read_since,
};
use std::{
    fs, io,
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
    time::{Duration, Instant},
};
fn root() -> PathBuf {
    static NEXT: AtomicUsize = AtomicUsize::new(0);
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../target/daemon-tests")
        .join(format!(
            "{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
    fs::create_dir_all(&root).unwrap();
    root
}
#[test]
fn audit_open_failure_recovers_ring_with_fresh_sequences() {
    let root = root();
    fs::write(root.join("blocked"), b"not a directory").unwrap();
    let disk_root = root.join("blocked");
    let now = Instant::now();
    let mut audit = Audit::open(&disk_root, GatewayId("gw1".into()), now).unwrap();
    assert!(!audit.handle().is_persistent());
    let old = audit
        .handle()
        .emit(EventKind::Flapping {}, Actor::Daemon, Some(1))
        .unwrap();
    fs::remove_file(&disk_root).unwrap();
    fs::create_dir(&disk_root).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    while !audit.poll(now + Duration::from_secs(61)) {
        assert!(Instant::now() < until);
        std::thread::sleep(Duration::from_millis(10));
    }
    audit.shutdown().unwrap();
    drop(audit);
    let events = read_since(&disk_root, 0, None)
        .collect::<io::Result<Vec<_>>>()
        .unwrap();
    assert!(events.windows(2).all(|v| v[0].seq < v[1].seq));
    assert!(events.iter().any(
        |e| matches!(e.kind, EventKind::MemoryReplay { local_last, .. } if local_last == old)
    ));
    let replay = events
        .iter()
        .find(|e| matches!(e.kind, EventKind::Flapping {}))
        .unwrap();
    assert!(replay.seq > old);
    assert_eq!(replay.config_version, Some(1));
    assert!(disk_root.join("events/clean").exists());
    fs::remove_dir_all(root).unwrap();
}
#[test]
fn cache_key_changes_and_fresh_confirmation_replace_stale_values() {
    let key = CacheKey {
        rendered: [1; 32],
        nft_version: "nft v1".into(),
        nft_identity: (1, 2, 3, 4),
        kernel_release: "6.8".into(),
    };
    let mut cache = CanonCache::default();
    let count = std::cell::Cell::new(0);
    let load = || {
        count.set(count.get() + 1);
        Ok(serde_json::json!({"nftables": []}))
    };
    cache.get_or_try(key.clone(), false, load).unwrap();
    cache.get_or_try(key.clone(), false, load).unwrap();
    assert_eq!(count.get(), 1);
    // A mismatch with the cached value cannot be reported without a fresh load.
    let fresh = cache
        .get_or_try(key.clone(), true, || {
            count.set(count.get() + 1);
            Ok(serde_json::json!({"nftables": [1]}))
        })
        .unwrap();
    assert_eq!(count.get(), 2);
    assert_eq!(cache.get_or_try(key.clone(), false, load).unwrap(), fresh);
    for changed in [
        CacheKey {
            rendered: [2; 32],
            ..key.clone()
        },
        CacheKey {
            nft_version: "v2".into(),
            ..key.clone()
        },
        CacheKey {
            nft_identity: (1, 3, 3, 4),
            ..key.clone()
        },
        CacheKey {
            nft_identity: (1, 2, 4, 4),
            ..key.clone()
        },
        CacheKey {
            kernel_release: "6.9".into(),
            ..key.clone()
        },
    ] {
        let before = count.get();
        cache.get_or_try(changed, false, load).unwrap();
        assert_eq!(count.get(), before + 1);
    }
}
#[test]
fn abstract_notify_socket() {
    use std::os::{
        linux::net::SocketAddrExt,
        unix::net::{SocketAddr, UnixDatagram},
    };
    let name = format!("scupper-test-{}", std::process::id());
    let address = SocketAddr::from_abstract_name(name.as_bytes()).unwrap();
    let socket = UnixDatagram::bind_addr(&address).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(1)))
        .unwrap();
    let mut notify = Notify::new(Some(std::ffi::OsStr::new(&format!("@{name}")))).unwrap();
    notify
        .completed(&scupper_sys::reconcile::TickReport {
            complete: true,
            ..Default::default()
        })
        .unwrap();
    let mut bytes = [0; 64];
    let len = socket.recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..len], b"READY=1");
    let len = socket.recv(&mut bytes).unwrap();
    assert_eq!(&bytes[..len], b"WATCHDOG=1");
}

#[cfg(feature = "testing")]
#[test]
fn a_cached_difference_must_survive_a_fresh_kernel_canonicalization() {
    use scupper_sys::system::{ExecError, ExecOutput, ExecTarget, Program, System};
    use std::{
        cell::{Cell, RefCell},
        collections::VecDeque,
        path::Path,
    };
    struct Cached {
        cache: RefCell<CanonCache>,
        binary: PathBuf,
        live: RefCell<String>,
        wants: RefCell<VecDeque<String>>,
        calls: Cell<usize>,
    }
    impl System for Cached {
        fn canon_run_root(&self) -> &Path {
            self.binary.parent().unwrap()
        }
        fn canon_cache(&self) -> Option<(&RefCell<CanonCache>, &Path)> {
            Some((&self.cache, &self.binary))
        }
        fn run(
            &self,
            program: Program,
            args: &[String],
            _: Duration,
        ) -> Result<ExecOutput, ExecError> {
            let stdout = match program {
                Program::Nft if args == ["--version"] => "nft v1".into(),
                Program::Nft => self.live.borrow().clone(),
                Program::Unshare => {
                    self.calls.set(self.calls.get() + 1);
                    self.wants
                        .borrow_mut()
                        .pop_front()
                        .ok_or_else(|| ExecError::spawn("fresh canonicalization failed"))?
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
            program: Program,
            args: &[String],
            timeout: Duration,
        ) -> Result<ExecOutput, ExecError> {
            self.run(program, args, timeout)
        }
        fn now_unix_secs(&self) -> u64 {
            0
        }
    }
    let root = root();
    let binary = root.join("nft");
    fs::write(&binary, "fixture").unwrap();
    let a = r#"{"nftables":[{"table":{"family":"inet","name":"scupper"}}]}"#;
    let b = r#"{"nftables":[{"table":{"family":"inet","name":"scupper"}},{"chain":{"name":"b"}}]}"#;
    let sys = Cached {
        cache: RefCell::default(),
        binary,
        live: RefCell::new(a.into()),
        wants: RefCell::new(VecDeque::from([a.into(), b.into(), b.into()])),
        calls: Cell::new(0),
    };
    let held = scupper_sys::netns::testing::handle().unwrap();
    let first = scupper_sys::canon::netns_rulesets(&sys, &held, "rendered").unwrap();
    assert_eq!(first.0, first.1);
    *sys.live.borrow_mut() = b.into();
    let refreshed = scupper_sys::canon::netns_rulesets(&sys, &held, "rendered").unwrap();
    assert_eq!(refreshed.0, refreshed.1); // Cached A would have been a false violation.
    assert_eq!(sys.calls.get(), 2);
    *sys.live.borrow_mut() = a.into();
    let differs = scupper_sys::canon::netns_rulesets(&sys, &held, "rendered").unwrap();
    assert_ne!(differs.0, differs.1);
    assert_eq!(sys.calls.get(), 3); // Real difference was freshly confirmed.
    assert!(scupper_sys::canon::netns_rulesets(&sys, &held, "rendered").is_err());
    fs::remove_dir_all(root).unwrap();
}

#[test]
fn ordinary_audit_restart_waits_for_previous_writer_without_failure_event() {
    use scupper_proto::UnixSeconds;
    use scupper_sys::events::EventLog;
    let root = root();
    let previous = EventLog::open(&root, GatewayId("gw1".into()), || UnixSeconds(100)).unwrap();
    previous
        .handle
        .emit(EventKind::Flapping {}, Actor::Daemon, None)
        .unwrap();
    let (send, receive) = std::sync::mpsc::sync_channel(1);
    let open_root = root.clone();
    let opening = std::thread::spawn(move || {
        send.send(EventLog::open(&open_root, GatewayId("gw1".into()), || {
            UnixSeconds(101)
        }))
        .unwrap();
    });
    assert!(matches!(
        receive.recv_timeout(Duration::from_millis(100)),
        Err(std::sync::mpsc::RecvTimeoutError::Timeout)
    ));
    previous
        .handle
        .flush_blocking(Duration::from_secs(5))
        .unwrap();
    drop(previous);
    let successor = receive
        .recv_timeout(Duration::from_secs(5))
        .unwrap()
        .unwrap();
    opening.join().unwrap();
    successor
        .handle
        .flush_blocking(Duration::from_secs(5))
        .unwrap();
    drop(successor);

    let now = Instant::now();
    let mut audit = Audit::open(&root, GatewayId("gw1".into()), now).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    while !audit.poll(now) {
        assert!(Instant::now() < until);
        std::thread::yield_now();
    }
    audit.shutdown().unwrap();
    drop(audit);
    let events = read_since(&root, 0, None)
        .collect::<io::Result<Vec<_>>>()
        .unwrap();
    assert!(
        !events
            .iter()
            .any(|e| matches!(e.kind, EventKind::PersistenceFailed { .. }))
    );
    fs::remove_dir_all(root).unwrap();
}
