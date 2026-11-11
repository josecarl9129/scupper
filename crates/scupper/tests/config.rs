//! Configuration transactions and namespace rule previews, without host mutations.
#![cfg(feature = "testing")]
#![allow(clippy::unwrap_used)]
#[path = "../../scupper-sys/tests/support/v2.rs"]
mod support;
use scupper::cli::{self, Dependencies, NamespaceReader, Privilege, Prompt};
use scupper_core::{
    config::{GatewayId, parse_site, validate},
    render::render_netns,
};
use scupper_sys::{
    netns::{NetnsHandle, testing},
    store::VersionStore,
};
use std::{
    cell::Cell,
    fs, io,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

struct Harness {
    path: PathBuf,
    system: support::Script,
    root: bool,
    tty: bool,
    answer: Option<bool>,
    prompts: Cell<usize>,
}
impl Harness {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "scupper-config-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::create_dir(path.join("etc")).unwrap();
        fs::write(path.join("etc/gateway-id"), "gw1\n").unwrap();
        fs::write(path.join("input.toml"), support::site_text("ubuntu-24.04")).unwrap();
        Self {
            path,
            system: support::Script::new("ubuntu-24.04"),
            root: true,
            tty: false,
            answer: Some(true),
            prompts: Cell::new(0),
        }
    }
    fn store(&self) -> VersionStore {
        VersionStore::read_only(&self.path.join("state"), &self.path.join("etc"))
    }
    fn input(&self) -> String {
        self.path.join("input.toml").to_str().unwrap().into()
    }
    fn text(&self, text: &str) {
        fs::write(self.input(), text).unwrap();
    }
    fn run(&self, args: &[&str]) -> (u8, String, String) {
        self.run_prompt(args, self)
    }
    fn run_prompt(&self, args: &[&str], prompt: &dyn Prompt) -> (u8, String, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = cli::run_with(
            std::iter::once("scupper").chain(args.iter().copied()),
            &Dependencies {
                state_root: &self.path.join("state"),
                config_root: &self.path.join("etc"),
                writer_root: &self.path.join("run"),
                probe_exec: &self.system,
                system: &self.system,
                namespaces: self,
                privilege: self,
                prompt,
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
    fn load(&self) {
        let (code, out, err) = self.run(&["config", "load", &self.input(), "--yes"]);
        assert_eq!(code, 0, "{out} {err}");
    }
    fn snapshot(&self) -> Vec<(PathBuf, Vec<u8>)> {
        fn walk(path: &Path, files: &mut Vec<(PathBuf, Vec<u8>)>) {
            for entry in fs::read_dir(path).unwrap() {
                let path = entry.unwrap().path();
                if path.is_dir() {
                    walk(&path, files);
                } else {
                    files.push((path.clone(), fs::read(path).unwrap()));
                }
            }
        }
        let mut files = Vec::new();
        walk(&self.path, &mut files);
        files.sort();
        files
    }
}
impl Drop for Harness {
    fn drop(&mut self) {
        fs::remove_dir_all(&self.path).unwrap();
    }
}
impl Privilege for Harness {
    fn is_root(&self) -> bool {
        self.root
    }
    fn user_name(&self) -> io::Result<String> {
        Ok("local-operator".into())
    }
}
impl NamespaceReader for Harness {
    fn read_namespace(&self, _: &Path) -> io::Result<PathBuf> {
        unreachable!()
    }
    fn gateway_marker(&self) -> io::Result<bool> {
        Ok(false)
    }
    fn open_gateway(&self) -> Result<Option<NetnsHandle>, String> {
        Ok(Some(testing::handle().unwrap()))
    }
}
impl Prompt for Harness {
    fn is_terminal(&self) -> bool {
        self.tty
    }
    fn confirm(&self, _: &str, _: Option<&str>) -> io::Result<bool> {
        assert!(self.tty);
        self.prompts.set(self.prompts.get() + 1);
        self.answer.ok_or_else(|| io::Error::other("prompt failed"))
    }
}

#[test]
fn load_show_validate_history_diff_and_linear_rollback() {
    let h = Harness::new();
    let original = fs::read_to_string(h.input()).unwrap();
    let (code, out, err) = h.run(&["config", "validate", &h.input()]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("valid"));
    assert!(!h.path.join("state").exists());
    let (code, out, err) = h.run(&[
        "config",
        "load",
        &h.input(),
        "--reason",
        "initial import",
        "--yes",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("--- head\n+++ proposed\n@@ -0,0 +"));
    assert!(out.ends_with("version 1 stored, not yet applied\n"));
    assert_eq!(h.run(&["config", "show"]).1, original);
    let (_, meta) = h.store().read(1).unwrap();
    assert_eq!(meta.parent, None);
    assert_eq!(meta.actor, "local-operator");
    assert_eq!(meta.reason, "initial import");
    assert_eq!(
        h.run(&["config", "history"]).1,
        format!(
            "version\tparent\tat\tactor\treason\tsha256\n1\t-\t{}\t\"local-operator\"\t\"initial import\"\t{}\n",
            meta.at,
            &meta.sha256[..12]
        )
    );
    let changed = original.replace("name = \"namespace lab\"", "name = \"Changed lab\"");
    assert_ne!(changed, original);
    h.text(&changed);
    h.load();
    assert_eq!(h.run(&["config", "show", "--version", "1"]).1, original);
    assert_eq!(h.run(&["config", "show"]).1, changed);
    let (code, diff, err) = h.run(&["config", "diff"]);
    assert_eq!(code, 0, "{err}");
    assert!(diff.starts_with("--- config/000001.toml\n+++ config/000002.toml\n@@ -"));
    assert!(diff.contains("+name = \"Changed lab\""));
    assert_eq!(h.run(&["config", "diff", "1", "2"]).1, diff);
    assert_eq!(h.run(&["config", "diff", "1"]).1, diff);
    assert_eq!(h.run(&["config", "diff", "2", "2"]).1, "");
    let (code, out, err) = h.run(&["config", "rollback", "1", "--yes"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.ends_with("version 3 stored, not yet applied\n"));
    assert_eq!(h.store().head().unwrap(), Some(3));
    let (text, meta) = h.store().read(3).unwrap();
    assert_eq!(text, original);
    assert_eq!(meta.parent, Some(2));
    assert_eq!(meta.reason, "rollback to version 1");
    assert_eq!(
        fs::read_to_string(h.path.join("etc/scupper.toml")).unwrap(),
        original
    );
    assert_eq!(
        fs::metadata(h.path.join("etc/scupper.toml"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o444
    );
    for n in 1..=3 {
        assert!(h.path.join(format!("state/rendered/{n:06}.nft")).is_file());
    }
    let rendered = fs::read_to_string(h.path.join("state/rendered/000003.nft")).unwrap();
    assert!(rendered.contains(&format!("version 3 (sha256 {})", meta.sha256)));
    assert!(!h.path.join("state/state.json").exists());
    assert!(h.system.calls.borrow().is_empty());
    assert_eq!(h.prompts.get(), 0);
}

#[test]
fn invalid_input_reports_every_semantic_path_and_never_writes() {
    let h = Harness::new();
    for (text, errors) in [
        ("schema = [".into(), vec!["InvalidToml"]),
        (
            support::site_text("ubuntu-24.04")
                .replace("name = \"namespace lab\"", "name = \"\"")
                .replace("netns = \"scupper\"", "netns = \"wrong\""),
            vec!["site.name:", "gateways.gw1.netns:"],
        ),
    ] {
        h.text(&text);
        let before = h.snapshot();
        for command in ["validate", "load"] {
            let mut args = vec!["config", command];
            let input = h.input();
            args.push(&input);
            if command == "load" {
                args.push("--yes");
            }
            let (code, _, err) = h.run(&args);
            assert_eq!(code, 1);
            for error in &errors {
                assert!(err.contains(error), "{err}");
            }
            assert_eq!(h.snapshot(), before);
        }
        assert!(!h.path.join("state").exists());
        assert!(!h.path.join("run").exists());
    }
    assert!(h.system.calls.borrow().is_empty());
}

#[test]
fn non_tty_writes_require_yes_and_root() {
    let mut h = Harness::new();
    let before = h.snapshot();
    let (code, _, err) = h.run(&["config", "load", &h.input()]);
    assert_eq!(code, 1);
    assert!(err.contains("--yes without a TTY"));
    assert_eq!(h.snapshot(), before);
    assert!(!h.path.join("state").exists());
    assert!(!h.path.join("run").exists());
    h.load();
    let before = h.snapshot();
    let (code, _, err) = h.run(&["config", "rollback", "1"]);
    assert_eq!(code, 1);
    assert!(err.contains("--yes without a TTY"));
    assert_eq!(h.snapshot(), before);
    h.root = false;
    let input = h.input();
    for args in [
        vec!["config", "load", &input, "--yes"],
        vec!["config", "rollback", "1", "--yes"],
    ] {
        let (code, _, err) = h.run(&args);
        assert_eq!(code, 1);
        assert!(err.contains("must run as root"));
        assert_eq!(h.snapshot(), before);
    }
    assert_eq!(h.prompts.get(), 0);
}

#[test]
fn tty_accept_cancel_and_prompt_error() {
    let mut h = Harness::new();
    h.tty = true;
    h.answer = Some(false);
    let before = h.snapshot();
    assert_eq!(h.run(&["config", "load", &h.input()]).0, 1);
    assert_eq!(h.snapshot(), before);
    h.answer = None;
    assert_eq!(h.run(&["config", "load", &h.input()]).0, 1);
    assert_eq!(h.snapshot(), before);
    h.answer = Some(true);
    assert_eq!(h.run(&["config", "load", &h.input()]).0, 0);
    assert_eq!(h.run(&["config", "rollback", "1"]).0, 0);
    assert_eq!(h.store().head().unwrap(), Some(2));
    assert_eq!(h.prompts.get(), 4);
}

#[test]
fn two_loads_reviewing_the_same_head_report_the_new_head_on_conflict() {
    struct RacingPrompt<'a>(&'a Harness);
    impl Prompt for RacingPrompt<'_> {
        fn is_terminal(&self) -> bool {
            true
        }
        fn confirm(&self, _: &str, _: Option<&str>) -> io::Result<bool> {
            self.0.load();
            Ok(true)
        }
    }
    let h = Harness::new();
    h.load();
    let (code, out, err) = h.run_prompt(&["config", "load", &h.input()], &RacingPrompt(&h));
    assert_eq!(code, 1, "{out}");
    assert!(err.contains("conflict; head is Some(2)"), "{err}");
    assert_eq!(h.store().head().unwrap(), Some(2));
    assert_eq!(h.store().history().unwrap().len(), 2);
    assert!(!h.path.join("state/config/versions/000003.toml").exists());
    assert!(!h.path.join("state/rendered/000003.nft").exists());
    assert!(h.system.calls.borrow().is_empty());
}

#[test]
fn rollback_refuses_an_integrity_valid_version_invalid_under_todays_schema() {
    let h = Harness::new();
    h.load();
    h.load();
    // Simulate an older schema accepted by a prior binary, with an honest digest.
    let path = h.path.join("state/config/versions/000001.meta.json");
    let mut meta: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&path).unwrap()).unwrap();
    meta["sha256"] =
        serde_json::json!("3f5e49076bd140f8bfd93635af79bb045ca92e38d05f6c0ece06d99ae29a8154");
    fs::write(path, serde_json::to_string(&meta).unwrap()).unwrap();
    fs::write(
        h.path.join("state/config/versions/000001.toml"),
        "schema = 2\n",
    )
    .unwrap();
    let before = h.snapshot();
    let (code, _, err) = h.run(&["config", "rollback", "1", "--yes"]);
    assert_eq!(code, 1);
    assert!(
        err.contains("cannot rollback version 1: invalid site configuration"),
        "{err}"
    );
    assert_eq!(h.snapshot(), before);
    assert_eq!(h.store().head().unwrap(), Some(2));
    assert_eq!(h.prompts.get(), 0);
}

#[test]
fn missing_versions_files_and_ill_formed_arguments_return_one() {
    let h = Harness::new();
    for args in [
        vec!["config", "show"],
        vec!["config", "show", "--version", "0"],
        vec!["config", "diff"],
        vec!["config", "validate", "absent-file"],
        vec!["config", "load", "absent-file", "--yes"],
        vec!["config", "show", "--version", "bad"],
        vec!["config", "rollback", "1", "--yes"],
        vec!["config", "validate"],
        vec!["config", "diff", "1", "2", "3"],
    ] {
        assert_eq!(h.run(&args).0, 1, "{args:?}");
    }
    let (code, out, _) = h.run(&["config", "history"]);
    assert_eq!(code, 0);
    assert_eq!(out.lines().count(), 1);
    assert!(!h.path.join("state").exists());
    h.load();
    assert_eq!(h.run(&["config", "show", "--version", "2"]).0, 1);
    assert_eq!(h.run(&["config", "diff"]).0, 1);
}

#[test]
fn rules_prints_head_and_canonical_diff_ignores_runtime_metadata() {
    let h = Harness::new();
    h.load();
    let (text, meta) = h.store().read(1).unwrap();
    let site = validate(parse_site(&text).unwrap()).unwrap();
    let mut digest = [0; 32];
    for (i, byte) in digest.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&meta.sha256[i * 2..i * 2 + 2], 16).unwrap();
    }
    let expected = render_netns(
        &site,
        &GatewayId("gw1".into()),
        &scupper_core::render::VersionStamp {
            version: 1,
            sha256: digest,
        },
    )
    .unwrap();
    let (code, out, err) = h.run(&["rules"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, expected);
    assert!(h.system.calls.borrow().is_empty());
    let (code, out, err) = h.run(&["rules", "--diff"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "no differences\n");
    h.system
        .replace("scupper-nft-ruleset.json", r#"{"nftables":[]}"#);
    let (code, out, err) = h.run(&["rules", "--diff"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.starts_with("--- live scupper namespace\n+++ rendered head\n@@ -"));
    assert!(out.contains("scupper"));
    assert!(!out.contains("no differences"));
    assert!(h.system.calls.borrow().iter().all(|(ns, p, a)| match p {
        scupper_sys::system::Program::Nft => *ns && a == &["-j", "list", "ruleset"],
        scupper_sys::system::Program::Unshare => !ns && a.iter().any(|a| a == "--gateway-netns"),
        _ => false,
    }));
}

#[test]
fn ordinary_rules_difference_is_confirmed_and_observation_errors_return_one() {
    let h = Harness::new();
    assert_eq!(h.run(&["rules"]).0, 1);
    h.load();
    let mut live: serde_json::Value = serde_json::from_str(&support::fixture(
        "ubuntu-24.04",
        "scupper-nft-ruleset.json",
    ))
    .unwrap();
    live["nftables"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"table": {"family":"inet", "name":"foreign"}}));
    h.system
        .replace("scupper-nft-ruleset.json", &live.to_string());
    let (code, out, err) = h.run(&["rules", "--diff"]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("foreign"));
    assert_eq!(h.system.calls.borrow().len(), 4);
    h.system.replace("scupper-nft-ruleset.json", "invalid JSON");
    assert_eq!(h.run(&["rules", "--diff"]).0, 1);
    assert!(!h.path.join("state/state.json").exists());
}

#[test]
fn machine_output_never_prompts_for_config_writes() {
    let mut h = Harness::new();
    h.tty = true;
    let before = h.snapshot();
    let (code, out, _) = h.run(&["--json", "config", "load", &h.input()]);
    assert_eq!(code, 1);
    let error: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert!(
        error["error"]["message"]
            .as_str()
            .unwrap()
            .contains("--json")
    );
    assert_eq!(h.prompts.get(), 0);
    assert_eq!(h.snapshot(), before);
    assert!(!h.path.join("state").exists());
}

#[test]
fn boot_is_hidden_root_only_and_reports_input_failure_without_kernel_writes() {
    let mut h = Harness::new();
    let (code, help, _) = h.run(&["--help"]);
    assert_eq!(code, 0);
    assert!(!help.contains("boot"));
    h.root = false;
    let (code, out, err) = h.run(&["boot"]);
    assert_eq!(code, 1);
    assert_eq!(out, "");
    assert!(err.contains("boot must run as root"));
    assert!(!h.path.join("run").exists());
    h.root = true;
    let (code, out, err) = h.run(&["boot"]);
    assert_eq!(code, 1, "{out} {err}");
    let report: serde_json::Value = serde_json::from_str(&out).unwrap();
    assert_eq!(report["steps"].as_array().unwrap().len(), 2);
    assert_eq!(report["steps"][1]["step"], "Inputs");
    assert_eq!(report["steps"][1]["error"], "no configuration");
    assert!(h.system.calls.borrow().is_empty());
}

#[test]
fn boot_refuses_unresponsive_lease_holder_before_kernel_calls() {
    let h = Harness::new();
    let _lease = scupper_sys::lock::SupervisorLease::try_acquire(h.path.join("run")).unwrap();
    let (code, output, error) = h.run(&["boot"]);
    assert_eq!(code, 1, "{output} {error}");
    assert!(error.contains("holder is not an initialized, responsive scupperd"));
    assert!(error.contains("pid"));
    assert!(h.system.calls.borrow().is_empty());
    assert!(!h.path.join("state").exists());
}

#[test]
fn alerts_list_redacts_reference_and_test_requires_sink_without_tty() {
    let h = Harness::new();
    let original = fs::read_to_string(h.input()).unwrap();
    h.text(&format!(
        r#"{original}
[alerts.sinks.primary]
kind = "webhook"
preset = "telegram"
min_severity = "critical"
url_ref = "private-reference"
"#
    ));
    h.load();
    let (code, out, err) = h.run(&["alerts", "list", "--json"]);
    assert_eq!(code, 0, "{err}");
    let value: serde_json::Value = serde_json::from_str(&out).unwrap();
    let row = value["sinks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|r| r["sink"] == "primary")
        .unwrap();
    assert_eq!(row["sink"], "primary");
    assert_eq!(row["preset"], "telegram");
    assert_eq!(row["cursor"], 0);
    for forbidden in ["private-reference", "url_ref", "https://"] {
        assert!(!out.contains(forbidden));
    }
    let (code, _, err) = h.run(&["alerts", "test"]);
    assert_eq!(code, 1);
    assert!(err.contains("requires SINK"));
    let (code, _, err) = h.run(&["alerts", "test", "missing"]);
    assert_eq!(code, 1);
    assert!(err.contains("unknown alert sink"));
    let (code, _, err) = h.run(&["alerts", "test", "primary"]);
    assert_eq!(code, 1);
    assert!(err.contains("running scupperd"));
}

#[test]
#[allow(clippy::too_many_lines)] // Exercise the real command with correlated daemon and worker receipts.
fn alerts_test_waits_for_individual_receipt_and_returns_the_real_failure() {
    use scupper_proto::{OpResult, Response, Schema};
    use std::{
        io::Write,
        os::{fd::AsRawFd, unix::net::UnixListener},
        time::{Duration, Instant},
    };
    for (outcome, expected) in [
        ("delivered", 0),
        ("permanent", 1),
        ("transient", 1),
        ("rate_limited", 1),
    ] {
        let h = Harness::new();
        let original = fs::read_to_string(h.input()).unwrap();
        h.text(&format!("{original}\n[alerts.sinks.primary]\nkind = \"ntfy\"\nurl_ref = \"private-reference\"\nmin_severity = \"critical\"\n"));
        h.load();
        fs::create_dir_all(h.path.join("run")).unwrap();
        let directory = fs::File::open(h.path.join("run")).unwrap();
        let listener = UnixListener::bind(format!(
            "/proc/self/fd/{}/control.sock",
            directory.as_raw_fd()
        ))
        .unwrap();
        let tests = h.path.join("state/sinks/primary.tests");
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = scupper_sys::daemon::control::read_request(&stream).unwrap();
            serde_json::to_writer(
                &mut stream,
                &Response {
                    schema: Schema,
                    request_id: request.request_id,
                    replayed: false,
                    observed_at: None,
                    result: Ok(OpResult::Ping {
                        netns: scupper_core::verdict::v2::NetnsIdentity {
                            device: 1,
                            inode: 1,
                        },
                        last_complete_iteration_age: Some(0),
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
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                if let Some(request) = fs::read_dir(&tests)
                    .ok()
                    .into_iter()
                    .flatten()
                    .filter_map(Result::ok)
                    .find(|e| e.path().extension().is_some_and(|s| s == "request"))
                {
                    fs::write(request.path().with_extension("outcome"), outcome).unwrap();
                    break;
                }
                assert!(Instant::now() < deadline);
                std::thread::sleep(Duration::from_millis(10));
            }
        });
        let (code, out, err) = h.run(&["alerts", "test", "primary", "--json"]);
        worker.join().unwrap();
        assert_eq!(code, expected, "{out} {err}");
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&out).unwrap()["outcome"],
            outcome
        );
        assert!(!out.contains("private-reference"));
    }
}

#[test]
fn alerts_list_marks_corrupt_row_and_keeps_other_sinks_visible() {
    let h = Harness::new();
    let original = fs::read_to_string(h.input()).unwrap();
    h.text(&format!("{original}\n[alerts.sinks.broken]\nkind = \"ntfy\"\nurl_ref = \"private-reference\"\nmin_severity = \"critical\"\n[alerts.sinks.healthy]\nkind = \"ntfy\"\nurl_ref = \"private-reference\"\nmin_severity = \"critical\"\n"));
    h.load();
    fs::create_dir_all(h.path.join("state/sinks")).unwrap();
    fs::write(h.path.join("state/sinks/broken.cursor"), "broken").unwrap();
    let (code, out, err) = h.run(&["alerts", "list", "--json"]);
    assert_eq!(code, 0, "{err}");
    let rows = serde_json::from_str::<serde_json::Value>(&out).unwrap();
    assert_eq!(rows["sinks"][0]["unavailable"], true);
    assert_eq!(rows["sinks"][1]["unavailable"], false);
}
