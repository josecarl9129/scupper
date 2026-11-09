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
            sleeper: &cli::ThreadSleeper,
            fs: &scupper::apply::RealFs,
            topology: &cli::UnimplementedTopology,
            exit_probe: &cli::UnimplementedExitProbe,
            probe_exec: sys,
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
fn required_future_daemon_uses_code_five_only_after_data_path_passes() {
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
                sleeper: &cli::ThreadSleeper,
                fs: &scupper::apply::RealFs,
                topology: &cli::UnimplementedTopology,
                exit_probe: &cli::UnimplementedExitProbe,
                probe_exec: &sys,
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
