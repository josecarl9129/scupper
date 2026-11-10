//! CLI routing, non-TTY output and schema checks through the real M2 driver.
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
    for (age, expected) in [(Some(29), 0), (Some(30), 5), (None, 5)] {
        let path = root.path.join("control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = scupper_sys::daemon::control::read_request(&stream).unwrap();
            serde_json::to_writer(
                &mut stream,
                &Response {
                    request_id: request.request_id,
                    schema: Schema,
                    result: Ok(OpResult::Ping {
                        last_complete_iteration_age: age,
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
