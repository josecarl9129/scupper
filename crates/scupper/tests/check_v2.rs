#![cfg(target_os = "linux")]
//! CLI routing, non-TTY output and schema checks through the real M2 driver.
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used)]
#[path = "../../scupper-sys/tests/support/v2.rs"]
mod support;
use scupper::cli::{self, Dependencies, NamespaceReader, Privilege, Prompt};
use scupper_sys::{
    netns::{NetnsHandle, testing},
    system::Program,
};
use std::{
    io,
    path::{Path, PathBuf},
};
use support::{Root, Script, fixture, fresh};

struct Host;
impl NamespaceReader for Host {
    fn gateway_marker(&self) -> io::Result<bool> {
        Ok(false)
    }
    fn read_namespace(&self, _: &Path) -> io::Result<PathBuf> {
        unreachable!()
    }
    fn open_gateway(&self) -> Result<Option<NetnsHandle>, String> {
        Ok(Some(testing::handle().unwrap()))
    }
}
impl Privilege for Host {
    fn is_root(&self) -> bool {
        true
    }
}
impl Prompt for Host {
    fn is_terminal(&self) -> bool {
        false
    }
    fn confirm(&self, _: &str, _: Option<&str>) -> io::Result<bool> {
        unreachable!()
    }
}
fn run(sys: &Script, root: &Root, args: &[&str]) -> (u8, String, String) {
    let mut out = Vec::new();
    let mut err = Vec::new();
    let code = cli::run_with(
        std::iter::once("scupper").chain(args.iter().copied()),
        &Dependencies {
            system: sys,
            namespaces: &Host,
            privilege: &Host,
            prompt: &Host,

            probe_exec: sys,
            writer_root: &root.path,
            state_root: &root.path,
            config_root: &root.path,
        },
        &mut out,
        &mut err,
    );
    (
        code,
        String::from_utf8(out).unwrap(),
        String::from_utf8(err).unwrap(),
    )
}
#[test]
fn m2_check_codes_and_json_work_without_a_tty() {
    let sys = Script::new("ubuntu-24.04");
    fresh(&sys);
    let root = Root::new(&sys.runner, &testing::handle().unwrap());
    let (code, out, err) = run(&sys, &root, &["check"]);
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.starts_with("protected:"));
    assert!(!out.contains('\u{1b}'));
    let (code, out, _) = run(&sys, &root, &["--json", "check"]);
    assert_eq!(code, 0);
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["schema"], 1);
    assert_eq!(report["config_version"], 1);
    assert_eq!(report["verdict"]["Protected"]["exit"], "ch1");
    let (code, out, _) = run(&sys, &root, &["status", "--json"]);
    assert_eq!(code, 0);
    let status: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(status["schema"], 1);
    assert!(
        !status["observations"]["topology"]
            .as_str()
            .unwrap()
            .contains("endpoint: Some")
    );
    let (_, text_status, _) = run(&sys, &root, &["status"]);
    assert!(!text_status.contains("endpoint: Some"));
    assert_eq!(status["observations"]["supervisor"], "Some(NotRequired)");
    for (filename, value, code) in [
        (
            "scupper-nft-ruleset.json",
            r#"{"nftables":[]}"#.to_string(),
            2,
        ),
        ("scupper--4-route.json", "[]".to_string(), 3),
        (
            "scupper-wg-ex-ch1-latest-handshakes.txt",
            format!(
                "{}\t1\n",
                fixture(&sys.runner, "scupper-wg-ex-ch1-peers.txt").trim()
            ),
            4,
        ),
    ] {
        sys.replace(filename, &value);
        assert_eq!(run(&sys, &root, &["check"]).0, code);
        assert_eq!(run(&sys, &root, &["status"]).0, 0);
        sys.replacements.borrow_mut().remove(filename);
    }
    std::fs::remove_file(root.path.join("boot.json")).unwrap();
    let (code, out, _) = run(&sys, &root, &["check", "--json"]);
    assert_eq!(code, 1);
    let error: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(error["schema"], 1);
    assert_eq!(error["error"]["stage"], "Topology");
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("boot.json")
    );
    let (code, out, _) = run(&sys, &root, &["status"]);
    assert_eq!(code, 0);
    assert!(out.contains("boot.json"));
    assert!(
        !sys.calls
            .borrow()
            .iter()
            .any(|(ns, p, _)| !ns && *p == Program::Nft)
    );
}

#[test]
fn corrupt_m2_head_never_falls_back_to_m1() {
    let sys = Script::new("ubuntu-22.04");
    let root = Root::new(&sys.runner, &testing::handle().unwrap());
    std::fs::write(root.path.join("config/head"), "invalid").unwrap();
    assert_eq!(run(&sys, &root, &["check"]).0, 1);
    let (code, out, _) = run(&sys, &root, &["check", "--json"]);
    assert_eq!(code, 1);
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["schema"], 1);
    assert!(report["error"]["stage"].is_null());
    assert!(
        report["error"]["message"]
            .as_str()
            .unwrap()
            .contains("invalid head")
    );
    let (code, out, _) = run(&sys, &root, &["status"]);
    assert_eq!(code, 0);
    assert!(out.contains("invalid head"));
    assert!(sys.calls.borrow().is_empty());
}

#[test]
fn required_daemon_fallback_verdict_table() {
    let sys = Script::new("ubuntu-24.04");
    fresh(&sys);
    let root = Root::new(&sys.runner, &testing::handle().unwrap());
    let writer = scupper_sys::lock::WriterLock::acquire(root.path.join("writer")).unwrap();
    let store = scupper_sys::store::VersionStore::open(&root.path, Some(&writer)).unwrap();
    store
        .commit(
            &writer,
            Some(1),
            &support::site_text(&sys.runner)
                .replace("require_daemon = false", "require_daemon = true"),
            scupper_sys::store::MetaInput {
                actor: "test".into(),
                at: 1000,
                reason: "require supervisor".into(),
            },
        )
        .unwrap();
    let (code, out, err) = run(&sys, &root, &["check", "--json"]);
    assert_eq!(code, 5, "{out} {err}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["config_version"], 2);
    assert_eq!(report["verdict"]["Unsupervised"]["why"], "Dead");
    assert_eq!(run(&sys, &root, &["status"]).0, 0);
    for (filename, value, expected) in [
        ("scupper-nft-ruleset.json", r#"{"nftables":[]}"#, 2),
        ("scupper--4-route.json", "[]", 3),
    ] {
        sys.replace(filename, value);
        assert_eq!(run(&sys, &root, &["check"]).0, expected);
        sys.replacements.borrow_mut().remove(filename);
    }
    *sys.file_error.borrow_mut() = true;
    assert_eq!(run(&sys, &root, &["check"]).0, 1);
}

#[test]
fn each_m2_marker_without_head_refuses_m1_fallback() {
    struct NamespaceMarker;
    impl NamespaceReader for NamespaceMarker {
        fn read_namespace(&self, _: &Path) -> io::Result<PathBuf> {
            unreachable!()
        }
        fn gateway_marker(&self) -> io::Result<bool> {
            Ok(true)
        }
    }
    for marker in [
        "store",
        "boot.json",
        "state.json",
        "gateway-id",
        "namespace",
    ] {
        let sys = Script::new("ubuntu-24.04");
        let root = Root::new(&sys.runner, &testing::handle().unwrap());
        let state = root.path.join("partial-state");
        let config = root.path.join("partial-config");
        match marker {
            "store" => std::fs::create_dir(&state).unwrap(),
            "boot.json" | "state.json" => {
                std::fs::create_dir(&state).unwrap();
                std::fs::write(state.join(marker), "{}").unwrap();
            }
            "gateway-id" => {
                std::fs::create_dir(&config).unwrap();
                std::fs::write(config.join(marker), "gw1\n").unwrap();
            }
            _ => {}
        }
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = cli::run_with(
            ["scupper", "check", "--json"],
            &Dependencies {
                system: &sys,
                namespaces: if marker == "namespace" {
                    &NamespaceMarker
                } else {
                    &Host
                },
                privilege: &Host,
                prompt: &Host,

                probe_exec: &sys,
                writer_root: &root.path,
                state_root: &state,
                config_root: &config,
            },
            &mut out,
            &mut err,
        );
        assert_eq!(code, 1, "{marker}");
        assert!(
            String::from_utf8(out)
                .unwrap()
                .contains("M2 layout without an applied head"),
            "{marker}"
        );
        assert!(sys.calls.borrow().is_empty(), "{marker}: M1 collector ran");
    }
}

#[test]
fn check_reports_the_applied_version_when_the_head_is_pending() {
    use scupper_sys::{
        lock::WriterLock,
        state::StateFile,
        store::{MetaInput, VersionStore},
    };
    let sys = Script::new("ubuntu-24.04");
    fresh(&sys);
    let root = Root::new(&sys.runner, &testing::handle().unwrap());
    let writer = WriterLock::acquire(root.path.join("writer")).unwrap();
    StateFile::open(&root.path, Some(&writer))
        .unwrap()
        .update(&writer, |state| state.applied_version = Some(1))
        .unwrap();
    let store = VersionStore::open(&root.path, Some(&writer)).unwrap();
    let candidate = support::site_text(&sys.runner).replace("1420", "1380");
    store
        .commit(
            &writer,
            Some(1),
            &candidate,
            MetaInput {
                actor: "test".into(),
                at: 2,
                reason: "pending candidate".into(),
            },
        )
        .unwrap();
    drop(writer);
    let (code, out, err) = run(&sys, &root, &["check", "--json"]);
    assert_eq!(code, 0, "{out} {err}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["config_version"], 1);
}

#[test]
fn local_mutation_refuses_another_writer_before_loading_or_changing_intent() {
    let sys = Script::new("ubuntu-24.04");
    fresh(&sys);
    let root = Root::new(&sys.runner, &testing::handle().unwrap());
    let before = std::fs::read(root.path.join("state.json")).unwrap();
    let guard = scupper_sys::lock::WriterLock::acquire(&root.path).unwrap();
    let started = std::time::Instant::now();
    let (code, out, err) = run(&sys, &root, &["disconnect"]);
    assert_eq!(code, 1);
    assert!(err.contains("writer lock"), "{err}");
    assert!(!out.contains("traffic is now blocked"));
    assert!(started.elapsed() < std::time::Duration::from_secs(3));
    assert_eq!(before, std::fs::read(root.path.join("state.json")).unwrap());
    drop(guard);
}

#[test]
fn stage_eight_socket_age_table_uses_the_strict_thirty_second_boundary() {
    use scupper_proto::{OpResult, Response, Schema};
    use std::{io::Write, os::unix::net::UnixListener};
    let sys = Script::new("ubuntu-24.04");
    fresh(&sys);
    let held = testing::handle().unwrap();
    let root = Root::new(&sys.runner, &held);
    let site = scupper_core::config::validate(
        scupper_core::config::parse_site(
            &support::site_text(&sys.runner)
                .replace("require_daemon = false", "require_daemon = true"),
        )
        .unwrap(),
    )
    .unwrap();
    let (device, inode) = held.identity();
    for (age, wrong_inode, expected) in [
        (Some(29), false, 0),
        (Some(30), false, 5),
        (None, false, 5),
        (Some(1), true, 2),
    ] {
        let path = root.path.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let worker = std::thread::spawn(move || {
            let mut stream = accept_fixture(&listener);
            let request = scupper_sys::daemon::control::read_request(&stream).unwrap();
            serde_json::to_writer(
                &mut stream,
                &Response {
                    request_id: request.request_id,
                    schema: Schema,
                    replayed: false,
                    observed_at: None,
                    result: Ok(OpResult::Ping {
                        netns: scupper_core::verdict::v2::NetnsIdentity {
                            device,
                            inode: inode + u64::from(wrong_inode),
                        },
                        last_complete_iteration_age: age,
                        current_iteration_age: None,
                        operation: None,
                        version: 1,
                        quarantined: false,
                        selection: scupper_core::verdict::v2::Selection::Auto,
                    }),
                },
            )
            .unwrap();
            stream.write_all(b"\n").unwrap();
        });
        let report = scupper_sys::check_v2::run_check_v2(
            &scupper_sys::check_v2::Dependencies {
                system: &sys,
                probe_exec: &sys,
                handle: Some(&held),
                run_root: &root.path,
                state_root: &root.path,
            },
            &scupper_sys::check_v2::Config {
                site: &site,
                gateway: &scupper_core::config::GatewayId("gw1".into()),
                stamp: root.stamp,
            },
        )
        .unwrap();
        assert_eq!(report.verdict.exit_code(), expected);
        worker.join().unwrap();
        std::fs::remove_file(path).unwrap();
    }
}

#[test]
fn live_supervisor_lease_refuses_fallback_without_changing_state() {
    let sys = Script::new("ubuntu-24.04");
    fresh(&sys);
    let root = Root::new(&sys.runner, &testing::handle().unwrap());
    let before = std::fs::read(root.path.join("state.json")).unwrap();
    let _lease = scupper_sys::lock::SupervisorLease::try_acquire(&root.path).unwrap();
    let (code, out, err) = run(&sys, &root, &["disconnect"]);
    assert_eq!(code, 1);
    assert!(
        err.contains("control socket unavailable") && err.contains("systemctl stop scupperd"),
        "{err}"
    );
    assert!(!out.contains("traffic is now blocked"));
    assert_eq!(before, std::fs::read(root.path.join("state.json")).unwrap());
}

#[test]
fn local_dry_run_includes_hardening_repair_preview() {
    let sys = Script::new("ubuntu-24.04");
    fresh(&sys);
    let root = Root::new(&sys.runner, &testing::handle().unwrap());
    let site = scupper_core::config::parse_site(&support::site_text(&sys.runner)).unwrap();
    for reference in site.identities.values().map(|i| &i.private_key_ref).chain(
        site.gateways
            .values()
            .flat_map(|g| &g.exits)
            .map(|e| &e.private_key_ref),
    ) {
        scupper_sys::secrets::SecretFile::write_new(
            &root.path,
            reference,
            b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
        )
        .unwrap();
    }
    let file = scupper_sys::state::StateFile::open(&root.path, None).unwrap();
    let scupper_sys::state::StateRead::Present(mut state) = file.read().unwrap() else {
        unreachable!()
    };
    state.applied_version = Some(1);
    let guard = scupper_sys::lock::WriterLock::acquire(&root.path).unwrap();
    file.write(&guard, &state).unwrap();
    drop(guard);
    sys.replace(
        "scupper-sysctl-net.ipv4.conf.all.accept_redirects.txt",
        "1\n",
    );
    for family in ["ipv4", "ipv6"] {
        for link in ["lo", "wg0", "ex-ch1"] {
            sys.replace(
                &format!("scupper-sysctl-net.{family}.conf.{link}.forwarding.txt"),
                "1\n",
            );
        }
    }
    let before = std::fs::read(root.path.join("state.json")).unwrap();
    let (code, out, err) = run(&sys, &root, &["apply", "--dry-run"]);
    assert_eq!(code, 0, "{out}: {err}");
    assert!(out.contains("Repair preview:"), "{out}: {err}");
    assert!(
        out.lines()
            .any(|line| line.starts_with("Repair preview:") && line.contains("WriteSysctl")),
        "{out}: {err}"
    );
    assert!(out.contains("Target boot:"), "{out}: {err}");
    assert!(out.contains("Preflight: passed"));
    let reference = &site.gateways.values().next().unwrap().exits[0].private_key_ref;
    std::fs::remove_file(root.path.join("secrets/wg").join(reference.name())).unwrap();
    let calls = sys.calls.borrow().clone();
    let (code, out, err) = run(&sys, &root, &["apply", "--dry-run"]);
    assert_eq!(code, 1);
    assert!(
        out.contains("InvalidRequest") && out.contains(reference.name()),
        "{out}: {err}"
    );
    assert_eq!(*sys.calls.borrow(), calls);
    assert_eq!(before, std::fs::read(root.path.join("state.json")).unwrap());
}
#[test]
fn stale_ping_skips_socket_check_and_preserves_stale_supervision() {
    use scupper_proto::OpResult;
    use std::os::unix::net::UnixListener;
    for age in [None, Some(30), Some(100)] {
        let sys = Script::new("ubuntu-24.04");
        fresh(&sys);
        let held = testing::handle().unwrap();
        let text = support::site_text(&sys.runner)
            .replace("require_daemon = false", "require_daemon = true");
        let root = Root::with_text(&text, &held);
        let listener = UnixListener::bind(root.path.join("control.sock")).unwrap();
        let (device, inode) = held.identity();
        let worker = serve_sequence(
            listener,
            vec![Ok(OpResult::Ping {
                last_complete_iteration_age: age,
                current_iteration_age: None,
                operation: None,
                netns: scupper_core::verdict::v2::NetnsIdentity { device, inode },
                version: 1,
                quarantined: false,
                selection: scupper_core::verdict::v2::Selection::Auto,
            })],
        );
        let (code, out, err) = run(&sys, &root, &["check", "--json"]);
        assert_eq!(code, 5, "{out}: {err}");
        assert!(err.contains("transport: local observations"));
        let report: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(report["verdict"]["Unsupervised"]["why"], "Stale");
        worker.join().unwrap();
    }
}
#[test]
fn timed_out_ping_with_live_lease_never_runs_local_mutation() {
    use std::os::unix::net::UnixListener;
    let sys = Script::new("ubuntu-24.04");
    fresh(&sys);
    let root = Root::new(&sys.runner, &testing::handle().unwrap());
    let before = std::fs::read(root.path.join("state.json")).unwrap();
    let _lease = scupper_sys::lock::SupervisorLease::try_acquire(&root.path).unwrap();
    let listener = UnixListener::bind(root.path.join("control.sock")).unwrap();
    let worker = std::thread::spawn(move || {
        let stream = accept_fixture(&listener);
        scupper_sys::daemon::control::read_request(&stream).unwrap();
        std::thread::sleep(std::time::Duration::from_millis(2200));
    });
    let (code, out, err) = run(&sys, &root, &["disconnect"]);
    assert_eq!(code, 1, "{out}: {err}");
    assert!(err.contains("scupperd is alive but unresponsive"));
    assert!(!out.contains("traffic is now blocked"));
    assert_eq!(before, std::fs::read(root.path.join("state.json")).unwrap());
    worker.join().unwrap();
}
#[test]
fn status_with_responsive_uninitialized_socket_keeps_local_schema() {
    use std::os::unix::net::UnixListener;
    let sys = Script::new("ubuntu-24.04");
    fresh(&sys);
    let root = Root::new(&sys.runner, &testing::handle().unwrap());
    let _listener = UnixListener::bind(root.path.join("control.sock")).unwrap();
    let (code, out, _) = run(&sys, &root, &["status", "--json"]);
    assert_eq!(code, 0);
    let value: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(value.get("observations").is_some());
    assert!(value.get("request_id").is_none());
}

#[test]
fn socket_check_error_uses_local_observations() {
    use scupper_proto::{ApiError, ApiErrorCode, OpResult, Response, Schema};
    use std::{io::Write, os::unix::net::UnixListener};
    for error in [
        ApiErrorCode::Timeout,
        ApiErrorCode::SupervisorUnavailable,
        ApiErrorCode::Internal,
    ] {
        let sys = Script::new("ubuntu-24.04");
        fresh(&sys);
        let held = testing::handle().unwrap();
        let text = support::site_text(&sys.runner)
            .replace("require_daemon = false", "require_daemon = true");
        let root = Root::with_text(&text, &held);
        let listener = UnixListener::bind(root.path.join("control.sock")).unwrap();
        let (device, inode) = held.identity();
        let worker = std::thread::spawn(move || {
            for result in [
                Ok(OpResult::Ping {
                    last_complete_iteration_age: Some(0),
                    current_iteration_age: None,
                    operation: None,
                    netns: scupper_core::verdict::v2::NetnsIdentity { device, inode },
                    version: 1,
                    quarantined: false,
                    selection: scupper_core::verdict::v2::Selection::Auto,
                }),
                Err(ApiError {
                    code: error,
                    observation: None,
                }),
            ] {
                let mut stream = accept_fixture(&listener);
                let request = scupper_sys::daemon::control::read_request(&stream).unwrap();
                serde_json::to_writer(
                    &mut stream,
                    &Response {
                        request_id: request.request_id,
                        schema: Schema,
                        replayed: false,
                        observed_at: None,
                        result,
                    },
                )
                .unwrap();
                stream.write_all(b"\n").unwrap();
            }
        });
        let (code, out, err) = run(&sys, &root, &["check", "--json"]);
        assert_eq!(code, 5, "{out}: {err}");
        assert!(err.contains("transport: local observations"));
        worker.join().unwrap();
    }
}

fn accept_fixture(listener: &std::os::unix::net::UnixListener) -> std::os::unix::net::UnixStream {
    use std::time::{Duration, Instant};
    listener.set_nonblocking(true).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false).unwrap();
                stream
                    .set_read_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                stream
                    .set_write_timeout(Some(Duration::from_secs(15)))
                    .unwrap();
                return stream;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                assert!(Instant::now() < deadline, "fixture accept timed out");
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(error) => unreachable!("fixture accept failed: {error}"),
        }
    }
}

fn fixture_reply(
    stream: &mut std::os::unix::net::UnixStream,
    result: Result<scupper_proto::OpResult, scupper_proto::ApiError>,
) -> scupper_proto::Op {
    use std::io::Write;
    let request = scupper_sys::daemon::control::read_request(&*stream).unwrap();
    serde_json::to_writer(
        &mut *stream,
        &scupper_proto::Response {
            request_id: request.request_id,
            schema: scupper_proto::Schema,
            replayed: false,
            observed_at: None,
            result,
        },
    )
    .unwrap();
    stream.write_all(b"\n").unwrap();
    request.op
}

fn serve_sequence(
    listener: std::os::unix::net::UnixListener,
    results: Vec<Result<scupper_proto::OpResult, scupper_proto::ApiError>>,
) -> std::thread::JoinHandle<()> {
    use std::io::Write;
    std::thread::spawn(move || {
        for result in results {
            let mut stream = accept_fixture(&listener);
            let request = scupper_sys::daemon::control::read_request(&stream).unwrap();
            serde_json::to_writer(
                &mut stream,
                &scupper_proto::Response {
                    request_id: request.request_id,
                    schema: scupper_proto::Schema,
                    replayed: false,
                    observed_at: None,
                    result,
                },
            )
            .unwrap();
            stream.write_all(b"\n").unwrap();
        }
    })
}

#[test]
fn check_retries_once_after_apply_invalidates_worker() {
    use scupper_proto::{ApiError, ApiErrorCode, OpResult};
    use std::os::unix::net::UnixListener;
    let sys = Script::new("ubuntu-24.04");
    fresh(&sys);
    let held = testing::handle().unwrap();
    let text =
        support::site_text(&sys.runner).replace("require_daemon = false", "require_daemon = true");
    let root = Root::with_text(&text, &held);
    let site =
        scupper_core::config::validate(scupper_core::config::parse_site(&text).unwrap()).unwrap();
    let report = scupper_sys::check_v2::run_supervised(
        &scupper_sys::check_v2::Dependencies {
            system: &sys,
            probe_exec: &sys,
            handle: Some(&held),
            run_root: &root.path,
            state_root: &root.path,
        },
        &scupper_sys::check_v2::Config {
            site: &site,
            gateway: &scupper_core::config::GatewayId("gw1".into()),
            stamp: root.stamp,
        },
        Some(0),
    )
    .unwrap();
    let (device, inode) = held.identity();
    let ping = || {
        Ok(OpResult::Ping {
            last_complete_iteration_age: Some(0),
            current_iteration_age: None,
            operation: None,
            netns: scupper_core::verdict::v2::NetnsIdentity { device, inode },
            version: 1,
            quarantined: false,
            selection: scupper_core::verdict::v2::Selection::Auto,
        })
    };
    let listener = UnixListener::bind(root.path.join("control.sock")).unwrap();
    let worker = serve_sequence(
        listener,
        vec![
            ping(),
            Err(ApiError {
                code: ApiErrorCode::SupervisorUnavailable,
                observation: None,
            }),
            ping(),
            Ok(OpResult::Check {
                health: (&report).into(),
                report: serde_json::to_value(report).unwrap(),
            }),
        ],
    );
    let (code, out, err) = run(&sys, &root, &["check", "--json"]);
    assert_eq!(code, 0, "{out}: {err}");
    assert!(err.contains("transport: local socket"));
    assert!(
        serde_json::from_str::<serde_json::Value>(&out).unwrap()["verdict"]
            .get("Protected")
            .is_some()
    );
    worker.join().unwrap();
}

#[test]
fn hung_socket_check_falls_back_with_real_ping_age_within_six_seconds() {
    for (age, busy, expected) in [(0, None, 0), (29, None, 5), (2, Some(6), 0)] {
        timed_out_check_case(age, busy, false, false, expected);
    }
}

#[test]
fn timed_out_check_preserves_real_ruleset_violation() {
    timed_out_check_case(0, None, true, false, 2);
}

#[test]
fn hung_check_during_rebuild_reports_operation_in_progress() {
    timed_out_check_case(0, None, true, true, 3);
}

fn serve_hung_check_fixture(
    listener: std::os::unix::net::UnixListener,
    identity: (u64, u64),
    age: u64,
    busy: Option<u64>,
    violation: bool,
    rebuilding: bool,
    fallback_finished: std::sync::mpsc::Receiver<()>,
) -> std::thread::JoinHandle<Option<(std::time::Instant, std::time::Instant)>> {
    use scupper_proto::{ApiError, ApiErrorCode, Op, OpResult, OperationKind, OperationProgress};
    use std::{
        io::Read,
        time::{Duration, Instant},
    };
    let (device, inode) = identity;
    std::thread::spawn(move || {
        let ping = |age, busy, operation| {
            Ok(OpResult::Ping {
                last_complete_iteration_age: Some(age),
                current_iteration_age: busy,
                operation,
                netns: scupper_core::verdict::v2::NetnsIdentity { device, inode },
                version: 1,
                quarantined: false,
                selection: scupper_core::verdict::v2::Selection::Auto,
            })
        };
        let mut stream = accept_fixture(&listener);
        assert_eq!(
            fixture_reply(&mut stream, ping(age, busy, None)),
            Op::Ping {}
        );
        let check_phase = if busy.is_none() {
            let mut stream = accept_fixture(&listener);
            let request = scupper_sys::daemon::control::read_request(&stream).unwrap();
            assert!(matches!(request.op, Op::Check {}));
            let started = Instant::now();
            // Stay hung until the client's own deadline closes its peer.
            // A fixed sleep could race a late receive timeout and simulate EOF.
            assert_eq!(stream.read(&mut [0]).unwrap(), 0);
            Some((started, Instant::now()))
        } else {
            assert!(listener.accept().is_err());
            None
        };
        if violation {
            let mut stream = accept_fixture(&listener);
            let operation = rebuilding.then_some(OperationProgress {
                kind: OperationKind::Rebuild,
                from: 1,
                to: 1,
                age: 1,
            });
            assert_eq!(
                fixture_reply(&mut stream, ping(0, None, operation)),
                Op::Ping {}
            );
        }
        fallback_finished
            .recv_timeout(Duration::from_secs(15))
            .unwrap();
        // Measure the same local stages with a live supervisor, including
        // stage 8. A missing listener would take the cheaper Dead path.
        let error = |code| {
            Err(ApiError {
                code,
                observation: None,
            })
        };
        let mut baseline = vec![
            ping(0, None, None),
            error(ApiErrorCode::SupervisorUnavailable),
            ping(0, None, None),
            error(ApiErrorCode::Internal),
            ping(0, None, None),
        ];
        if violation {
            baseline.push(ping(0, None, None));
        }
        serve_sequence(listener, baseline).join().unwrap();
        check_phase
    })
}

fn timed_out_check_case(
    age: u64,
    busy: Option<u64>,
    violation: bool,
    rebuilding: bool,
    expected: u8,
) {
    use std::{
        os::unix::net::UnixListener,
        time::{Duration, Instant},
    };
    let sys = Script::new("ubuntu-24.04");
    fresh(&sys);
    if violation {
        sys.replace("scupper-nft-ruleset.json", r#"{"nftables":[]}"#);
    }
    let held = testing::handle().unwrap();
    let text =
        support::site_text(&sys.runner).replace("require_daemon = false", "require_daemon = true");
    let root = Root::with_text(&text, &held);
    // A read-only fallback must work while both writer capabilities are held.
    let _lease = scupper_sys::lock::SupervisorLease::try_acquire(&root.path).unwrap();
    let _writer = scupper_sys::lock::WriterLock::try_acquire(&root.path).unwrap();
    let listener = UnixListener::bind(root.path.join("control.sock")).unwrap();
    let (device, inode) = held.identity();
    let (finished, fallback_finished) = std::sync::mpsc::channel();
    let worker = serve_hung_check_fixture(
        listener,
        (device, inode),
        age,
        busy,
        violation,
        rebuilding,
        fallback_finished,
    );
    let start = Instant::now();
    let (code, out, err) = run(&sys, &root, &["check", "--json"]);
    let elapsed = start.elapsed();
    assert_eq!(code, expected, "{out}: {err}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["schema"], 1);
    if rebuilding {
        assert!(out.contains("OperationInProgress"), "{out}");
        assert!(err.contains("rebuild in progress"), "{err}");
    } else if violation {
        assert!(out.contains("Ruleset"), "{out}");
    } else if age == 29 {
        assert_eq!(report["verdict"]["Unsupervised"]["why"], "Stale");
    } else {
        assert!(report["verdict"].get("Protected").is_some(), "{out}");
    }
    assert!(err.contains("local observations"));
    finished.send(()).unwrap();
    let local_start = Instant::now();
    let (local_code, local_out, local_err) = run(&sys, &root, &["check", "--json"]);
    let local = local_start.elapsed();
    assert_eq!(
        local_code,
        if violation { 2 } else { 0 },
        "{local_out}: {local_err}"
    );
    assert!(local_err.contains("local observations"));
    if !violation {
        assert!(
            local_out.contains("Protected"),
            "live baseline: {local_out}"
        );
    }
    let check_phase = worker.join().unwrap();
    let check_offsets =
        check_phase.map(|(begin, end)| (begin.duration_since(start), end.duration_since(start)));
    let check_deadline_margin =
        check_offsets.map(|(_, end)| Duration::from_secs(5).as_secs_f64() - end.as_secs_f64());
    let bound = Duration::from_secs(5) + local + Duration::from_secs(1);
    let fallback_margin = bound.as_secs_f64() - elapsed.as_secs_f64();
    if std::env::var_os("SCUPPER_TEST_CHECK_TIMINGS").is_some() {
        eprintln!(
            "age={age} busy={busy:?} code={code} total={elapsed:?} live_local={local:?} \
             check_phase={check_phase:?} check_offsets={check_offsets:?} \
             check_deadline_margin_s={check_deadline_margin:?} fallback_margin_s={fallback_margin:.6}"
        );
    }
    assert!(
        elapsed < bound,
        "fallback took {elapsed:?}, live local check {local:?}, bound={bound:?}, \
         age={age} busy={busy:?} code={code} start={start:?}, \
         check_phase={check_phase:?} check_offsets={check_offsets:?}, \
         check_deadline_margin_s={check_deadline_margin:?} fallback_margin_s={fallback_margin:.6}: {err}"
    );
}

#[test]
fn boot_under_held_lease_requires_initialized_ping() {
    use scupper_proto::OpResult;
    use std::os::unix::net::UnixListener;
    for wrong_inode in [false, true] {
        let sys = Script::new("ubuntu-24.04");
        fresh(&sys);
        let held = testing::handle().unwrap();
        let root = Root::new(&sys.runner, &held);
        let _lease = scupper_sys::lock::SupervisorLease::try_acquire(&root.path).unwrap();
        let listener = UnixListener::bind(root.path.join("control.sock")).unwrap();
        let (device, inode) = held.identity();
        let worker = serve_sequence(
            listener,
            vec![Ok(OpResult::Ping {
                last_complete_iteration_age: Some(0),
                current_iteration_age: None,
                operation: None,
                netns: scupper_core::verdict::v2::NetnsIdentity {
                    device,
                    inode: inode + u64::from(wrong_inode),
                },
                version: 1,
                quarantined: false,
                selection: scupper_core::verdict::v2::Selection::Auto,
            })],
        );
        let calls = sys.calls.borrow().len();
        let (code, out, err) = run(&sys, &root, &["boot"]);
        assert_eq!(code, u8::from(wrong_inode), "{out} {err}");
        assert!(err.contains(if wrong_inode {
            "stop scupperd, then rerun"
        } else {
            "scupperd owns the namespace"
        }));
        assert_eq!(sys.calls.borrow().len(), calls);
        worker.join().unwrap();
    }
}

#[test]
fn applying_ping_never_compares_kernel_with_unreached_state_version() {
    use scupper_proto::{OpResult, OperationKind, OperationProgress};
    use std::os::unix::net::UnixListener;
    for operation in [
        Some(OperationProgress {
            kind: OperationKind::Apply,
            from: 1,
            to: 2,
            age: 6,
        }),
        None,
    ] {
        let sys = Script::new("ubuntu-24.04");
        fresh(&sys);
        let held = testing::handle().unwrap();
        let root = Root::new(&sys.runner, &held);
        let path = root.path.join("state.json");
        let mut state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        state["applied_version"] = 2.into();
        std::fs::write(path, serde_json::to_vec(&state).unwrap()).unwrap();
        let (device, inode) = held.identity();
        let listener = UnixListener::bind(root.path.join("control.sock")).unwrap();
        // Keep the listener alive but never dispatch Check. An older snapshot
        // without the operation flag also must not compare state version 2.
        let ping_listener = listener.try_clone().unwrap();
        let worker = serve_sequence(
            ping_listener,
            vec![Ok(OpResult::Ping {
                last_complete_iteration_age: Some(0),
                current_iteration_age: None,
                operation,
                netns: scupper_core::verdict::v2::NetnsIdentity { device, inode },
                version: 1,
                quarantined: false,
                selection: scupper_core::verdict::v2::Selection::Auto,
            })],
        );
        let (code, out, err) = run(&sys, &root, &["check", "--json"]);
        assert_eq!(code, 3, "{out}: {err}");
        assert!(err.contains("apply in progress (from 1 to 2"));
        let report: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(report["config_version"], 1);
        assert!(
            report["verdict"]["Degraded"]
                .get("OperationInProgress")
                .is_some()
        );
        worker.join().unwrap();
        drop(listener);
    }
}

#[test]
fn ping_followed_by_connection_refused_is_unsupervised() {
    use scupper_proto::OpResult;
    use std::{io::Write, os::unix::net::UnixListener};
    let sys = Script::new("ubuntu-24.04");
    fresh(&sys);
    let held = testing::handle().unwrap();
    let text =
        support::site_text(&sys.runner).replace("require_daemon = false", "require_daemon = true");
    let root = Root::with_text(&text, &held);
    let (device, inode) = held.identity();
    let listener = UnixListener::bind(root.path.join("control.sock")).unwrap();
    let worker = std::thread::spawn(move || {
        let mut stream = accept_fixture(&listener);
        let request = scupper_sys::daemon::control::read_request(&stream).unwrap();
        drop(listener); // The next connect gets ECONNREFUSED before any request.
        serde_json::to_writer(
            &mut stream,
            &scupper_proto::Response {
                request_id: request.request_id,
                schema: scupper_proto::Schema,
                replayed: false,
                observed_at: None,
                result: Ok(OpResult::Ping {
                    last_complete_iteration_age: Some(0),
                    current_iteration_age: None,
                    operation: None,
                    netns: scupper_core::verdict::v2::NetnsIdentity { device, inode },
                    version: 1,
                    quarantined: false,
                    selection: scupper_core::verdict::v2::Selection::Auto,
                }),
            },
        )
        .unwrap();
        stream.write_all(b"\n").unwrap();
    });
    let (code, out, err) = run(&sys, &root, &["check", "--json"]);
    assert_eq!(code, 5, "{out}: {err}");
    worker.join().unwrap();
}

#[test]
fn failed_check_keeps_real_ruleset_violations_and_retries_rebuilt_namespaces() {
    use scupper_core::verdict::v2::{NetnsIdentity, Selection};
    use scupper_proto::{ApiError, ApiErrorCode, OpResult, OperationKind, OperationProgress};
    use std::os::unix::net::UnixListener;

    // Stable snapshots must preserve a real alarm. An operation may explain a
    // transitional ruleset; a completed rebuild instead requires fresh checks.
    for (device_changed, inode_changed, violation, operation, expected) in [
        (false, false, true, false, 2),
        (false, false, true, true, 3),
        (false, true, false, false, 0),
        (true, false, false, false, 0),
        (false, true, true, false, 2),
    ] {
        let sys = Script::new("ubuntu-24.04");
        fresh(&sys);
        let held = testing::handle().unwrap();
        let text = support::site_text(&sys.runner)
            .replace("require_daemon = false", "require_daemon = true");
        let root = Root::with_text(&text, &held);
        // Make state and all Pings explicitly agree on the applied version.
        let state_path = root.path.join("state.json");
        let mut state: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state_path).unwrap()).unwrap();
        state["applied_version"] = 1.into();
        std::fs::write(state_path, serde_json::to_vec(&state).unwrap()).unwrap();
        if violation {
            sys.replace("scupper-nft-ruleset.json", r#"{"nftables":[]}"#);
        }
        let (device, inode) = held.identity();
        let listener = UnixListener::bind(root.path.join("control.sock")).unwrap();
        let ping = |netns, operation| {
            Ok(OpResult::Ping {
                last_complete_iteration_age: Some(0),
                current_iteration_age: None,
                operation,
                netns,
                version: 1,
                quarantined: false,
                selection: Selection::Auto,
            })
        };
        let initial_netns = NetnsIdentity {
            device: device + u64::from(device_changed),
            inode: inode + u64::from(inode_changed),
        };
        let final_netns = NetnsIdentity { device, inode };
        let final_operation = operation.then_some(OperationProgress {
            kind: OperationKind::Rebuild,
            from: 1,
            to: 1,
            age: 1,
        });
        // A failed Check leaves time to refresh supervision both before
        // local observations and after a possible namespace transition.
        let mut results = vec![
            ping(initial_netns, None),
            Err(ApiError {
                code: ApiErrorCode::Internal,
                observation: None,
            }),
            ping(initial_netns, None),
            ping(final_netns, final_operation),
        ];
        if (device_changed || inode_changed) && violation {
            results.push(ping(final_netns, None));
        }
        let worker = serve_sequence(listener, results);
        let (code, out, err) = run(&sys, &root, &["check", "--json"]);
        assert_eq!(code, expected, "{out}: {err}");
        let report: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(report["config_version"], 1);
        if expected == 2 {
            assert!(out.contains("Ruleset"), "{out}");
        }
        if expected == 3 {
            assert!(out.contains("OperationInProgress"), "{out}");
        }
        // A retry writes only its final report.
        assert_eq!(out.lines().count(), 1);
        worker.join().unwrap();
    }
}
