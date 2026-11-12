#![cfg(target_os = "linux")]
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
    os::unix::fs::{MetadataExt, PermissionsExt},
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
        let site = parse_site(&fs::read_to_string(path.join("input.toml")).unwrap()).unwrap();
        for key in site.identities.values().map(|i| &i.private_key_ref).chain(
            site.gateways
                .values()
                .flat_map(|g| &g.exits)
                .map(|e| &e.private_key_ref),
        ) {
            scupper_sys::secrets::SecretFile::write_new(
                &path.join("etc"),
                key,
                b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            )
            .unwrap();
        }
        fs::create_dir(path.join("etc/secrets/url")).unwrap();
        fs::set_permissions(
            path.join("etc/secrets/url"),
            fs::Permissions::from_mode(0o700),
        )
        .unwrap();
        fs::write(
            path.join("etc/secrets/url/private-reference"),
            "https://sink.example.net/test",
        )
        .unwrap();
        fs::set_permissions(
            path.join("etc/secrets/url/private-reference"),
            fs::Permissions::from_mode(0o600),
        )
        .unwrap();
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
                system: &ProviderSystem(&self.system),
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

// The import command exercises the real filesystem and store, with only public
// key derivation substituted. Command recording deliberately excludes stdin.
struct ProviderSystem<'a>(&'a support::Script);
impl scupper_sys::system::System for ProviderSystem<'_> {
    fn canon_run_root(&self) -> &Path {
        self.0.canon_run_root()
    }
    fn wireguard_socket_dirs(&self) -> Vec<PathBuf> {
        self.0.wireguard_socket_dirs()
    }
    fn read_host_udp(&self, ipv6: bool) -> io::Result<String> {
        self.0.read_host_udp(ipv6)
    }
    fn run_in(
        &self,
        target: scupper_sys::system::ExecTarget<'_>,
        p: scupper_sys::system::Program,
        a: &[String],
        t: std::time::Duration,
    ) -> Result<scupper_sys::system::ExecOutput, scupper_sys::system::ExecError> {
        self.0.run_in(target, p, a, t)
    }
    fn run(
        &self,
        p: scupper_sys::system::Program,
        a: &[String],
        t: std::time::Duration,
    ) -> Result<scupper_sys::system::ExecOutput, scupper_sys::system::ExecError> {
        self.0.run(p, a, t)
    }
    fn run_with_stdin(
        &self,
        _: scupper_sys::system::ExecTarget<'_>,
        p: scupper_sys::system::Program,
        a: &[String],
        stdin: &[u8],
        _: std::time::Duration,
    ) -> Result<scupper_sys::system::ExecOutput, scupper_sys::system::ExecError> {
        assert_eq!(p, scupper_sys::system::Program::Wg);
        assert_eq!(a, &["pubkey"]);
        self.0.calls.borrow_mut().push((false, p, a.to_vec()));
        Ok(scupper_sys::system::ExecOutput {
            status: Some(0),
            stdout: if stdin.starts_with(b"BAQE") {
                IMPORT_PUBLIC
            } else {
                "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
            }
            .into(),
            stderr: String::new(),
        })
    }
    fn now_unix_secs(&self) -> u64 {
        1000
    }
}
const IMPORT_PRIVATE: &str = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=";
const IMPORT_PUBLIC: &str = "BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=";
const IMPORT_PEER: &str = "BgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgYGBgY=";
struct ProviderFile(PathBuf);
impl ProviderFile {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "provider-source-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, format!("# CH#1234\n# NetShield = 2\n[Interface]\nPrivateKey = {IMPORT_PRIVATE}\nAddress = 192.0.2.22/32\nDNS = 192.0.2.53\nMTU = 1420\n[Peer]\nPublicKey = {IMPORT_PEER}\nEndpoint = 203.0.113.22:51820\nAllowedIPs = 0.0.0.0/0\nPersistentKeepalive = 25\n")).unwrap();
        Self(path)
    }
    fn path(&self) -> &str {
        self.0.to_str().unwrap()
    }
}
impl Drop for ProviderFile {
    fn drop(&mut self) {
        fs::remove_file(&self.0).unwrap();
    }
}
#[test]
fn import_replaces_and_remove_is_refused_without_exposing_secrets() {
    let h = Harness::new();
    h.load();
    let source = ProviderFile::new();
    let (code, out, err) = h.run(&["exit", "import", source.path(), "--yes"]);
    assert_eq!(code, 0, "{out} {err}");
    for shown in [
        "public key BQUF…BQU=",
        "203.0.113.22:51820",
        "NetShield 2",
        "IPv4",
        "Delete",
        "private key",
    ] {
        assert!(out.contains(shown), "{out}");
    }
    let key_path = h.path.join("etc/secrets/wg/exit-ch-1234-v2");
    assert_eq!(fs::read(&key_path).unwrap(), IMPORT_PRIVATE.as_bytes());
    assert_eq!(
        fs::metadata(&key_path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert_eq!(
        fs::metadata(&key_path).unwrap().uid(),
        rustix::process::geteuid().as_raw()
    );
    let (text, meta) = h.store().read(2).unwrap();
    assert_eq!(meta.parent, Some(1));
    let site = parse_site(&text).unwrap();
    let exit = &site.gateways[&GatewayId("gw1".into())].exits[0];
    assert_eq!(exit.id.as_str(), "ch-1234");
    assert_eq!(exit.name.as_str(), "Switzerland");
    assert_eq!(exit.private_key_ref.name(), "exit-ch-1234-v2");
    for (path, bytes) in h.snapshot() {
        if path != key_path {
            assert!(
                !bytes
                    .windows(IMPORT_PRIVATE.len())
                    .any(|b| b == IMPORT_PRIVATE.as_bytes()),
                "{}",
                path.display()
            );
        }
    }
    assert!(!format!("{:?}", h.system.calls.borrow()).contains(IMPORT_PRIVATE));
    assert!(!out.contains(IMPORT_PRIVATE));
    assert!(!err.contains(IMPORT_PRIVATE));
    let before = h.snapshot();
    let (code, _, err) = h.run(&["exit", "remove", "switzerland", "--yes"]);
    assert_eq!(code, 1);
    assert!(err.contains("use exit import to replace"), "{err}");
    assert_eq!(h.snapshot(), before);
    assert!(key_path.exists());
    assert_eq!(h.store().head().unwrap(), Some(2));
}
#[test]
fn import_confirmation_duplicates_size_and_no_replacement() {
    let mut h = Harness::new();
    h.load();
    let source = ProviderFile::new();
    let before = h.snapshot();
    let (code, _, err) = h.run(&["exit", "import", source.path()]);
    assert_eq!(code, 1);
    assert!(err.contains("--yes without a TTY"));
    assert_eq!(h.snapshot(), before);
    h.tty = true;
    h.answer = Some(false);
    assert_eq!(h.run(&["exit", "import", source.path()]).0, 1);
    assert_eq!(h.snapshot(), before);
    h.root = false;
    assert!(
        h.run(&["exit", "import", source.path(), "--yes"])
            .2
            .contains("root")
    );
    assert_eq!(h.snapshot(), before);
    h.root = true;
    for id in ["../escape", "/absolute", "-bad", "BAD"] {
        assert_eq!(
            h.run(&[
                "exit",
                "import",
                source.path(),
                &format!("--id={id}"),
                "--yes"
            ])
            .0,
            1
        );
        assert_eq!(h.snapshot(), before);
    }
    let original = fs::read_to_string(&source.0).unwrap();
    fs::write(&source.0, "x".repeat(16 * 1024 + 1)).unwrap();
    assert!(
        h.run(&["exit", "import", source.path(), "--yes"])
            .2
            .contains("16 KiB")
    );
    assert_eq!(h.snapshot(), before);
    fs::write(&source.0, &original).unwrap();

    for path in ["etc/secrets", "etc/secrets/wg"] {
        fs::set_permissions(h.path.join(path), fs::Permissions::from_mode(0o700)).unwrap();
    }
    let config = parse_site(&h.store().read(1).unwrap().0).unwrap();
    let reference = &config.gateways[&GatewayId("gw1".into())].exits[0].private_key_ref;
    fs::write(
        h.path.join("etc/secrets/wg").join(reference.name()),
        IMPORT_PRIVATE,
    )
    .unwrap();
    fs::set_permissions(
        h.path.join("etc/secrets/wg").join(reference.name()),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    let (code, _, err) = h.run(&["exit", "import", source.path(), "--yes"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(h.store().head().unwrap(), Some(2));
}
#[test]
fn failed_local_socket_commit_rolls_back_key_and_sends_only_references() {
    use std::{
        io::Write,
        os::{fd::AsRawFd, unix::net::UnixListener},
    };
    let h = Harness::new();
    h.load();
    let selection = scupper_sys::state::Selection::Pin(scupper_core::config::ExitId("ch1".into()));
    h.save_state(1, selection.clone());
    let source = ProviderFile::new();
    let directory = fs::File::open(h.path.join("run")).unwrap();
    let listener = UnixListener::bind(format!(
        "/proc/self/fd/{}/control.sock",
        directory.as_raw_fd()
    ))
    .unwrap();
    let key = h.path.join("etc/secrets/wg/exit-ch-1234-v2");
    let observed_key = key.clone();
    let worker = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = scupper_sys::daemon::control::read_request(&stream).unwrap();
        assert!(observed_key.is_file());
        let json = serde_json::to_string(&request).unwrap();
        assert!(!json.contains(IMPORT_PRIVATE));
        let scupper_proto::Op::Commit { parent, toml, .. } = &request.op else {
            panic!("expected commit")
        };
        assert_eq!(*parent, Some(1));
        assert!(toml.contains("exit-ch-1234-v2"));
        serde_json::to_writer(
            &mut stream,
            &scupper_proto::Response {
                schema: scupper_proto::Schema,
                request_id: request.request_id,
                replayed: false,
                observed_at: None,
                result: Err(scupper_proto::ApiError {
                    code: scupper_proto::ApiErrorCode::Conflict,
                    observation: None,
                }),
            },
        )
        .unwrap();
        stream.write_all(b"\n").unwrap();
    });
    let (code, _, err) = h.run(&["exit", "import", source.path(), "--yes"]);
    worker.join().unwrap();
    assert_eq!(code, 1);
    assert!(err.contains("Conflict"), "{err}");
    assert!(!key.exists());
    let scupper_sys::state::StateRead::Present(saved) =
        scupper_sys::state::StateFile::open(h.path.join("state"), None)
            .unwrap()
            .read()
            .unwrap()
    else {
        panic!("missing state")
    };
    assert_eq!(saved.selection, selection);
    assert_eq!(h.store().head().unwrap(), Some(1));
    assert_eq!(
        fs::read_dir(h.path.join("etc/secrets/wg")).unwrap().count(),
        2
    );
}
#[test]
fn config_bundle_cli_export_and_verify() {
    let h = Harness::new();
    h.load();
    fs::write(
        h.path.join("state/state.json"),
        serde_json::to_vec(&scupper_sys::state::State::default()).unwrap(),
    )
    .unwrap();
    let output = h.path.join("bundle.tar");
    let path = output.to_str().unwrap();
    let (code, _, err) = h.run(&["config", "bundle", "-o", path]);
    assert_eq!(code, 0, "{err}");
    let (code, out, err) = h.run(&["config", "bundle", "--verify", path]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(out, "bundle is valid\n");
    fs::write(&output, b"invalid").unwrap();
    assert_eq!(h.run(&["config", "bundle", "--verify", path]).0, 1);
}

#[test]
fn preshared_key_lifecycle_and_last_exit_removal() {
    let h = Harness::new();
    h.load();
    h.boot_keys();
    h.save_state(1, scupper_sys::state::Selection::Auto);
    let source = ProviderFile::new();
    let psk = "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
    let text = fs::read_to_string(&source.0).unwrap() + &format!("PresharedKey = {psk}\n");
    fs::write(&source.0, &text).unwrap();
    let (code, out, err) = h.run(&["exit", "import", source.path(), "--yes"]);
    assert_eq!(code, 0, "{out} {err}");
    assert!(!out.contains(psk));
    let path = h.path.join("etc/secrets/wg/exit-ch-1234-v2-psk");
    assert_eq!(fs::read(&path).unwrap(), psk.as_bytes());
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    assert!(h.store().read(2).unwrap().0.contains("preshared_key_ref"));
    h.assert_boot_inputs(1);
    h.save_state(2, scupper_sys::state::Selection::Auto);
    h.assert_boot_inputs(2);
    let before = h.snapshot();
    let (code, _, err) = h.run(&["exit", "remove", "ch-1234", "--yes"]);
    assert_eq!(code, 1);
    assert!(err.contains("use exit import to replace"), "{err}");
    assert_eq!(h.snapshot(), before);
    assert!(path.exists());
}

#[test]
fn racing_import_confirmation_refuses_before_writing_a_key() {
    struct Race<'a>(&'a Harness);
    impl Prompt for Race<'_> {
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
    let source = ProviderFile::new();
    let (code, _, error) = h.run_prompt(&["exit", "import", source.path()], &Race(&h));
    assert_eq!(code, 1);
    assert!(error.contains("409"), "{error}");
    assert_eq!(h.store().head().unwrap(), Some(2));
    assert!(!h.path.join("etc/secrets/wg/exit-ch-1234-v2").exists());
}

#[test]
fn uncertain_or_published_socket_commits_retain_the_key() {
    use std::{
        io::Write,
        os::{fd::AsRawFd, unix::net::UnixListener},
    };
    for published in [false, true] {
        let h = Harness::new();
        h.load();
        let source = ProviderFile::new();
        let directory = fs::File::open(h.path.join("run")).unwrap();
        let listener = UnixListener::bind(format!(
            "/proc/self/fd/{}/control.sock",
            directory.as_raw_fd()
        ))
        .unwrap();
        let state = h.path.join("state");
        let config = h.path.join("etc");
        let run = h.path.join("run");
        let worker = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = scupper_sys::daemon::control::read_request(&stream).unwrap();
            let scupper_proto::Op::Commit { parent, toml, .. } = &request.op else {
                panic!("expected commit")
            };
            assert!(!toml.contains(IMPORT_PRIVATE));
            if published {
                let guard = scupper_sys::lock::WriterLock::acquire(&run).unwrap();
                let store =
                    VersionStore::open_with_mirror_root(&state, &config, Some(&guard)).unwrap();
                store
                    .commit(
                        &guard,
                        *parent,
                        toml,
                        scupper_sys::store::MetaInput {
                            actor: "socket-fixture".into(),
                            at: 0,
                            reason: "published before error".into(),
                        },
                    )
                    .unwrap();
                serde_json::to_writer(
                    &mut stream,
                    &scupper_proto::Response {
                        schema: scupper_proto::Schema,
                        request_id: request.request_id,
                        replayed: false,
                        observed_at: None,
                        result: Err(scupper_proto::ApiError {
                            code: scupper_proto::ApiErrorCode::Internal,
                            observation: None,
                        }),
                    },
                )
                .unwrap();
                stream.write_all(b"\n").unwrap();
            }
        });
        let (code, _, error) = h.run(&["exit", "import", source.path(), "--yes"]);
        worker.join().unwrap();
        assert_eq!(code, 1, "{error}");
        assert!(h.path.join("etc/secrets/wg/exit-ch-1234-v2").is_file());
        assert_eq!(
            h.store().head().unwrap(),
            Some(if published { 2 } else { 1 })
        );
        if !published {
            assert!(error.contains("keys retained"));
        }
    }
}

#[test]
fn unsafe_sweep_entry_names_fix_and_keeps_all_keys_and_selection() {
    let h = Harness::new();
    h.load();
    h.save_state(
        1,
        scupper_sys::state::Selection::Pin(scupper_core::config::ExitId("ch1".into())),
    );
    let source = ProviderFile::new();
    let root = h.path.join("etc");
    for name in ["exit-orphan-v1", "exit-unsafe-v1"] {
        let reference =
            scupper_core::config::SecretName::new(scupper_core::config::SecretKind::Wg, name)
                .unwrap();
        scupper_sys::secrets::SecretFile::write_new(&root, &reference, IMPORT_PRIVATE.as_bytes())
            .unwrap();
    }
    fs::set_permissions(
        root.join("secrets/wg/exit-unsafe-v1"),
        fs::Permissions::from_mode(0o400),
    )
    .unwrap();
    drop(scupper_sys::lock::WriterLock::acquire(h.path.join("run/exit-import")).unwrap());
    let before = h.snapshot();
    let (code, _, error) = h.run(&["exit", "import", source.path(), "--yes"]);
    assert_eq!(code, 1);
    assert!(
        error.contains("exit-unsafe-v1") && error.contains("0600"),
        "{error}"
    );
    assert_eq!(h.snapshot(), before);
}

impl Harness {
    fn save_state(&self, version: u64, selection: scupper_sys::state::Selection) {
        let writer = scupper_sys::lock::WriterLock::acquire(self.path.join("run")).unwrap();
        scupper_sys::state::StateFile::open(self.path.join("state"), Some(&writer))
            .unwrap()
            .write(
                &writer,
                &scupper_sys::state::State {
                    applied_version: Some(version),
                    selection,
                    ..Default::default()
                },
            )
            .unwrap();
    }
    fn boot_keys(&self) {
        let site = parse_site(&self.store().read(1).unwrap().0).unwrap();
        for key in site.identities.values().map(|i| &i.private_key_ref).chain(
            site.gateways
                .values()
                .flat_map(|g| &g.exits)
                .map(|e| &e.private_key_ref),
        ) {
            if self.path.join("etc/secrets/wg").join(key.name()).exists() {
                continue;
            }
            scupper_sys::secrets::SecretFile::write_new(
                &self.path.join("etc"),
                key,
                b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
            )
            .unwrap();
        }
    }
    fn assert_boot_inputs(&self, version: u64) {
        use scupper_core::verdict::v2::{HealthConfigV2, NetnsIdentity};
        let site = validate(parse_site(&self.store().read(version).unwrap().0).unwrap()).unwrap();
        HealthConfigV2::new(
            &site,
            &GatewayId("gw1".into()),
            NetnsIdentity {
                device: 1,
                inode: 1,
            },
            vec!["203.0.113.100".parse().unwrap()],
            version,
        )
        .unwrap();
        scupper_sys::boot::testing::inputs(&scupper_sys::boot::BootDeps {
            system: &ProviderSystem(&self.system),
            namespace: &scupper_sys::boot::GatewayNamespace,
            state_root: &self.path.join("state"),
            config_root: &self.path.join("etc"),
            run_root: &self.path.join("run"),
            hook: None,
            secret_owner: rustix::process::geteuid().as_raw(),
        })
        .unwrap();
    }
}

#[test]
fn replacement_keeps_applied_keys_and_resets_pin_and_prefer() {
    use scupper_sys::state::{Selection, StateFile, StateRead};
    for prefer in [false, true] {
        let h = Harness::new();
        h.load();
        h.boot_keys();
        let initial = parse_site(&h.store().read(1).unwrap().0).unwrap();
        let old = &initial.gateways[&GatewayId("gw1".into())].exits[0];
        h.save_state(
            1,
            if prefer {
                Selection::Prefer(old.id.clone())
            } else {
                Selection::Pin(old.id.clone())
            },
        );
        let source = ProviderFile::new();
        let (code, out, err) = h.run(&["exit", "import", source.path(), "--yes"]);
        assert_eq!(code, 0, "{out} {err}");
        assert!(out.contains(&format!(
            "Replace {} [{}] with Switzerland [ch-1234]",
            old.name, old.id
        )));
        let StateRead::Present(saved) = StateFile::open(h.path.join("state"), None)
            .unwrap()
            .read()
            .unwrap()
        else {
            panic!("missing state")
        };
        assert_eq!(saved.selection, Selection::Auto);
        assert!(out.contains("reset Pin/Prefer selection to Auto after commit"));
        let events: Vec<scupper_proto::Event> = h
            .snapshot()
            .into_iter()
            .filter(|(path, _)| path.extension().is_some_and(|e| e == "jsonl"))
            .flat_map(|(_, bytes)| {
                String::from_utf8(bytes)
                    .unwrap()
                    .lines()
                    .map(|line| serde_json::from_str(line).unwrap())
                    .collect::<Vec<_>>()
            })
            .collect();
        assert!(
            events
                .iter()
                .any(|e| e.actor == scupper_proto::Actor::Local { uid: 0 }
                    && matches!(
                        e.kind,
                        scupper_proto::EventKind::AdminAction {
                            command: scupper_proto::Command::ResetSelection,
                            ..
                        }
                    ))
        );
        assert_eq!(saved.applied_version, Some(1));
        // The running/applied version and the newly committed version both
        // resolve all keys through boot's actual input loader.
        h.assert_boot_inputs(1);
        h.save_state(2, Selection::Auto);
        h.assert_boot_inputs(2);
        assert!(
            h.path
                .join("etc/secrets/wg")
                .join(old.private_key_ref.name())
                .exists()
        );
        // Advance applied, then import again: the next sweep collects only the
        // obsolete initial key and retains v2's key while v2 remains applied.
        fs::write(
            &source.0,
            fs::read_to_string(&source.0)
                .unwrap()
                .replace(
                    IMPORT_PRIVATE,
                    "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=",
                )
                .replace(IMPORT_PEER, "CQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCQk="),
        )
        .unwrap();
        let (code, out, err) = h.run(&["exit", "import", source.path(), "--id", "second", "--yes"]);
        assert_eq!(code, 0, "{out} {err}");
        assert!(
            !h.path
                .join("etc/secrets/wg")
                .join(old.private_key_ref.name())
                .exists()
        );
        assert!(h.path.join("etc/secrets/wg/exit-ch-1234-v2").exists());
        h.assert_boot_inputs(2);
        h.save_state(3, Selection::Auto);
        h.assert_boot_inputs(3);
    }
}

#[test]
fn same_server_key_rotation_in_one_import_retains_applied_generation() {
    use scupper_sys::state::Selection;
    let h = Harness::new();
    h.load();
    h.save_state(1, Selection::Auto);
    let source = ProviderFile::new();
    assert_eq!(h.run(&["exit", "import", source.path(), "--yes"]).0, 0);
    let pinned = Selection::Pin(scupper_core::config::ExitId("ch-1234".into()));
    h.save_state(2, pinned.clone());
    let rotated = fs::read_to_string(&source.0).unwrap().replace(
        IMPORT_PRIVATE,
        "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=",
    );
    fs::write(&source.0, rotated).unwrap();
    let (code, out, err) = h.run(&["exit", "import", source.path(), "--yes"]);
    assert_eq!(code, 0, "{out} {err}");
    let key_dir = h.path.join("etc/secrets/wg");
    assert_eq!(
        fs::read(key_dir.join("exit-ch-1234-v2")).unwrap(),
        IMPORT_PRIVATE.as_bytes()
    );
    assert_eq!(
        fs::read(key_dir.join("exit-ch-1234-v3")).unwrap(),
        b"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg="
    );
    let scupper_sys::state::StateRead::Present(saved) =
        scupper_sys::state::StateFile::open(h.path.join("state"), None)
            .unwrap()
            .read()
            .unwrap()
    else {
        panic!("missing state")
    };
    assert_eq!(saved.selection, pinned);
    h.assert_boot_inputs(2);
    h.save_state(3, pinned);
    h.assert_boot_inputs(3);
    assert_eq!(h.run(&["exit", "import", source.path(), "--yes"]).0, 0);
    assert!(!key_dir.join("exit-ch-1234-v2").exists());
    assert!(key_dir.join("exit-ch-1234-v3").exists());
    assert_eq!(h.run(&["exit", "import", source.path(), "--yes"]).0, 0);
    assert!(!key_dir.join("exit-ch-1234-v2").exists());
}

#[test]
fn orphan_recovery_retains_staged_identity_and_unrelated_exit_names() {
    use scupper_core::config::{SecretKind, SecretName};
    use scupper_sys::secrets::SecretFile;
    let h = Harness::new();
    h.load();
    let source = ProviderFile::new();
    let key = SecretName::new(SecretKind::Wg, "exit-ch-1234-v2").unwrap();
    SecretFile::write_new(
        &h.path.join("etc"),
        &key,
        b"CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=",
    )
    .unwrap();
    for name in ["wg0-2", "exit-unrelated"] {
        let key = SecretName::new(SecretKind::Wg, name).unwrap();
        SecretFile::write_new(&h.path.join("etc"), &key, IMPORT_PRIVATE.as_bytes()).unwrap();
    }
    let stale = h.path.join("etc/secrets/wg/.scupper-old-0.tmp");
    fs::write(&stale, IMPORT_PRIVATE).unwrap();
    fs::set_permissions(&stale, fs::Permissions::from_mode(0o600)).unwrap();
    fs::File::open(&stale)
        .unwrap()
        .set_modified(std::time::UNIX_EPOCH)
        .unwrap();
    let (code, out, err) = h.run(&[
        "exit",
        "import",
        source.path(),
        "--yes",
        "--replace-leftover-key",
    ]);
    assert_eq!(code, 0, "{out} {err}");
    assert!(!stale.exists());
    assert_eq!(
        fs::read(h.path.join("etc/secrets/wg/exit-ch-1234-v2")).unwrap(),
        IMPORT_PRIVATE.as_bytes()
    );
    assert!(h.path.join("etc/secrets/wg/wg0-2").exists());
    assert!(h.path.join("etc/secrets/wg/exit-unrelated").exists());
}

#[test]
fn ipv6_provider_fields_are_dropped_and_verbose_shows_public_key() {
    for verbose in [false, true] {
        let h = Harness::new();
        h.load();
        let source = ProviderFile::new();
        fs::write(
            &source.0,
            fs::read_to_string(&source.0)
                .unwrap()
                .replace("192.0.2.22/32", "192.0.2.22/32, 2001:db8::22/128")
                .replace("192.0.2.53", "192.0.2.53, 2001:db8::53")
                .replace("0.0.0.0/0", "0.0.0.0/0, ::/0"),
        )
        .unwrap();
        let mut args = vec!["exit", "import", source.path(), "--yes"];
        if verbose {
            args.push("--verbose");
        }
        let (code, out, err) = h.run(&args);
        assert_eq!(code, 0, "{out} {err}");
        assert!(out.contains("IPv6 not used: client IPv6 fails closed"));
        assert_eq!(out.contains(IMPORT_PUBLIC), verbose);
        assert!(out.contains(if verbose {
            IMPORT_PUBLIC
        } else {
            "BQUF…BQU="
        }));
        assert!(!out.contains("SHA-256"));
        let saved = parse_site(&h.store().read(2).unwrap().0).unwrap();
        let exit = &saved.gateways[&GatewayId("gw1".into())].exits[0];
        assert!(exit.address6.is_none());
        assert_eq!(exit.dns, ["192.0.2.53"]);
    }
}

#[test]
fn unchanged_exit_id_preserves_pin_and_prefer_and_confirmation_names_both() {
    use scupper_sys::state::{Selection, StateFile, StateRead};
    struct Confirmation<'a> {
        old: &'a str,
        id: &'a str,
    }
    impl Prompt for Confirmation<'_> {
        fn is_terminal(&self) -> bool {
            true
        }
        fn confirm(&self, message: &str, _: Option<&str>) -> io::Result<bool> {
            assert!(
                message.contains(&format!(
                    "Replace {} [{}] with Switzerland [{}]",
                    self.old, self.id, self.id
                )),
                "{message}"
            );
            Ok(true)
        }
    }
    for prefer in [false, true] {
        let h = Harness::new();
        h.load();
        h.boot_keys();
        let site = parse_site(&h.store().read(1).unwrap().0).unwrap();
        let old = &site.gateways[&GatewayId("gw1".into())].exits[0];
        let selection = if prefer {
            Selection::Prefer(old.id.clone())
        } else {
            Selection::Pin(old.id.clone())
        };
        h.save_state(1, selection.clone());
        let source = ProviderFile::new();
        let (code, out, err) = h.run_prompt(
            &["exit", "import", source.path(), "--id", old.id.as_str()],
            &Confirmation {
                old: old.name.as_str(),
                id: old.id.as_str(),
            },
        );
        assert_eq!(code, 0, "{out} {err}");
        let StateRead::Present(saved) = StateFile::open(h.path.join("state"), None)
            .unwrap()
            .read()
            .unwrap()
        else {
            panic!("missing state")
        };
        assert_eq!(saved.selection, selection);
        h.assert_boot_inputs(1);
        h.save_state(2, selection);
        h.assert_boot_inputs(2);
    }
}

#[path = "../../scupper-sys/tests/support/boot_kernel.rs"]
mod boot_kernel;

#[test]
#[allow(clippy::too_many_lines)] // Keep the complete live transaction and its safety assertions together.
fn import_replacement_applies_over_existing_namespace_in_place() {
    use scupper_sys::boot::{self, BootDeps};
    use scupper_sys::{daemon::admin, events::EventLog, state::Selection};
    let h = Harness::new();
    h.load();
    h.save_state(1, Selection::Auto);
    let kernel = boot_kernel::Kernel::new();
    let state_root = h.path.join("state");
    let config_root = h.path.join("etc");
    let run_root = h.path.join("run");
    let deps = BootDeps {
        system: &kernel,
        namespace: &kernel,
        state_root: &state_root,
        config_root: &config_root,
        run_root: &run_root,
        hook: None,
        secret_owner: rustix::process::geteuid().as_raw(),
    };
    assert!(boot::boot(&deps).succeeded());
    let before = parse_site(&h.store().read(1).unwrap().0).unwrap();
    let old = &before.gateways[&GatewayId("gw1".into())].exits[0];
    let source = ProviderFile::new();
    let (code, out, err) = h.run(&["exit", "import", source.path(), "--yes"]);
    assert_eq!(code, 0, "{out} {err}");
    let after = parse_site(&h.store().read(2).unwrap().0).unwrap();
    let new = &after.gateways[&GatewayId("gw1".into())].exits[0];
    assert_eq!(new.ifname, old.ifname);
    kernel.verified_this_run.set(false);
    kernel.gates_closed.set(false);
    kernel.began_live.set(true);
    let log = EventLog::memory_only(GatewayId("gw1".into()), || scupper_proto::UnixSeconds(1000))
        .unwrap();
    // An operator may still select the old exit against the applied v1 after
    // the import has published head v2. Both apply modes must refuse untouched.
    for selection in [
        Selection::Pin(old.id.clone()),
        Selection::Prefer(old.id.clone()),
    ] {
        h.save_state(1, selection);
        let state_before = fs::read(state_root.join("state.json")).unwrap();
        let calls_before = kernel.calls.borrow().clone();
        let values_before = kernel.values.borrow().clone();
        for dry_run in [true, false] {
            let error = admin::apply(&deps, &log.handle, None, dry_run, 0).unwrap_err();
            assert_eq!(error.code, scupper_proto::ApiErrorCode::InvalidRequest);
            assert!(error.to_string().contains(old.id.as_str()));
            assert!(error.to_string().contains("scupper connect"));
            assert_eq!(
                fs::read(state_root.join("state.json")).unwrap(),
                state_before
            );
            assert_eq!(*kernel.calls.borrow(), calls_before);
            assert_eq!(*kernel.values.borrow(), values_before);
        }
    }
    h.save_state(1, Selection::Auto);
    // Fail v2 at Routes after the new key and peer have reached the same link.
    let fail_once = Cell::new(true);
    let hook = |point| {
        if point == boot::BootPoint::After(boot::BootStep::Routes) && fail_once.replace(false) {
            Err("injected Routes failure".into())
        } else {
            Ok(())
        }
    };
    let failing = BootDeps {
        hook: Some(&hook),
        ..deps
    };
    let error = admin::apply(&failing, &log.handle, None, false, 0).unwrap_err();
    assert_eq!(error.code, scupper_proto::ApiErrorCode::Internal);
    assert_eq!(error.observation.unwrap()["rollback"]["verified"], true);
    assert_eq!(
        kernel.ns.borrow()[&old.ifname].public_key,
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
    );
    assert!(
        kernel.ns.borrow()[&old.ifname]
            .peers
            .contains_key(old.peer_public_key.as_str())
    );
    assert!(
        !kernel.ns.borrow()[&old.ifname]
            .peers
            .contains_key(IMPORT_PEER)
    );
    assert_eq!(kernel.values.borrow()["net.ipv4.ip_forward"], "1");
    let saved = scupper_sys::state::StateFile::open(&state_root, None)
        .unwrap()
        .read()
        .unwrap();
    assert!(
        matches!(saved, scupper_sys::state::StateRead::Present(state) if state.applied_version == Some(1))
    );
    kernel.verified_this_run.set(false);
    kernel.gates_closed.set(false);
    admin::apply(&deps, &log.handle, None, false, 0).unwrap();
    let links = kernel.ns.borrow();
    assert_eq!(
        links.keys().map(String::as_str).collect::<Vec<_>>(),
        ["ex-ch1", "lo", "wg0"]
    );
    let exit = &links[&old.ifname];
    assert!(!exit.peers.contains_key(old.peer_public_key.as_str()));
    assert!(exit.peers.contains_key(IMPORT_PEER));
    assert_eq!(
        exit.public_key,
        "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="
    );
    assert!(kernel.calls.borrow().iter().any(|call| call
        == &format!(
            "netns Wg set {} peer {} remove",
            old.ifname,
            old.peer_public_key.as_str()
        )));
    assert!(
        kernel
            .calls
            .borrow()
            .iter()
            .any(|call| call.starts_with(&format!("netns Wg set {} private-key", old.ifname)))
    );
    drop(links);
    // Rotate the same server with the same default ID, then apply in place again.
    h.save_state(2, Selection::Pin(new.id.clone()));
    fs::write(
        &source.0,
        fs::read_to_string(&source.0).unwrap().replace(
            IMPORT_PRIVATE,
            "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=",
        ),
    )
    .unwrap();
    let (code, out, err) = h.run(&["exit", "import", source.path(), "--yes"]);
    assert_eq!(code, 0, "{out} {err}");
    kernel.verified_this_run.set(false);
    kernel.gates_closed.set(false);
    admin::apply(&deps, &log.handle, None, false, 0).unwrap();
    assert_eq!(
        kernel.ns.borrow()[&old.ifname].public_key,
        "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI="
    );
    assert!(config_root.join("secrets/wg/exit-ch-1234-v2").exists());
    assert!(config_root.join("secrets/wg/exit-ch-1234-v3").exists());
}

#[test]
fn load_and_rollback_refuse_missing_secrets_by_name_without_publication() {
    let h = Harness::new();
    h.load();
    let original = fs::read_to_string(h.input()).unwrap();
    let mut site = parse_site(&original).unwrap();
    site.gateways
        .get_mut(&GatewayId("gw1".into()))
        .unwrap()
        .exits[0]
        .private_key_ref = scupper_core::config::SecretName::new(
        scupper_core::config::SecretKind::Wg,
        "missing-exit-v2",
    )
    .unwrap();
    h.text(&toml::to_string(&site).unwrap());
    let (code, _, error) = h.run(&["config", "load", &h.input(), "--yes"]);
    assert_eq!(code, 1);
    assert!(error.contains("missing-exit-v2"), "{error}");
    assert_eq!(h.store().head().unwrap(), Some(1));
    let key =
        &parse_site(&original).unwrap().gateways[&GatewayId("gw1".into())].exits[0].private_key_ref;
    fs::remove_file(h.path.join("etc/secrets/wg").join(key.name())).unwrap();
    let before = h.snapshot();
    let (code, _, error) = h.run(&["config", "rollback", "1", "--yes"]);
    assert_eq!(code, 1);
    assert!(error.contains(key.name()), "{error}");
    assert_eq!(h.snapshot(), before);
    assert_eq!(h.store().head().unwrap(), Some(1));
}

#[test]
fn import_id_length_reserves_space_for_maximum_generation_and_psk() {
    use scupper_core::config::{SecretKind, SecretName};
    let h = Harness::new();
    h.load();
    let source = ProviderFile::new();
    let id = "a".repeat(32);
    assert!(SecretName::new(SecretKind::Wg, &format!("exit-{id}-v{}-psk", u64::MAX)).is_ok());
    let (code, out, error) = h.run(&["exit", "import", source.path(), "--id", &id, "--yes"]);
    assert_eq!(code, 0, "{out} {error}");
    let before = h.snapshot();
    let (code, _, error) = h.run(&[
        "exit",
        "import",
        source.path(),
        "--id",
        &"a".repeat(33),
        "--yes",
    ]);
    assert_eq!(code, 1);
    assert!(error.contains("32"));
    assert_eq!(h.snapshot(), before);
}

#[test]
fn initial_import_library_publishes_first_exit_and_keys_in_an_empty_store() {
    use scupper_sys::{lock::WriterLock, provider, store::MetaInput};
    let h = Harness::new();
    let mut site = parse_site(&fs::read_to_string(h.input()).unwrap()).unwrap();
    site.gateways
        .get_mut(&GatewayId("gw1".into()))
        .unwrap()
        .exits
        .clear();
    site.policy.exits.clear();
    let source = ProviderFile::new();
    let psk = "AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=";
    fs::write(
        &source.0,
        fs::read_to_string(&source.0).unwrap() + &format!("PresharedKey = {psk}\n"),
    )
    .unwrap();
    let guard = WriterLock::acquire(h.path.join("run")).unwrap();
    let store =
        VersionStore::open_with_mirror_root(h.path.join("state"), h.path.join("etc"), Some(&guard))
            .unwrap();
    let import = |site| {
        provider::import_initial(
            &store,
            &guard,
            &h.path.join("etc"),
            site,
            &GatewayId("gw1".into()),
            &source.0,
            MetaInput {
                actor: "test".into(),
                at: 1000,
                reason: "initial import".into(),
            },
        )
    };
    assert_eq!(import(site.clone()).unwrap(), 1);
    let (text, meta) = store.read(1).unwrap();
    assert_eq!(meta.parent, None);
    let imported = parse_site(&text).unwrap();
    let exit = &imported.gateways[&GatewayId("gw1".into())].exits[0];
    assert_eq!(exit.ifname, "ex-0");
    assert_eq!(exit.id.as_str(), "ch-1234");
    assert_eq!(exit.peer_public_key.as_str(), IMPORT_PEER);
    assert_eq!(
        fs::read(
            h.path
                .join("etc/secrets/wg")
                .join(exit.private_key_ref.name())
        )
        .unwrap(),
        IMPORT_PRIVATE.as_bytes()
    );
    assert_eq!(
        fs::read(
            h.path
                .join("etc/secrets/wg")
                .join(exit.preshared_key_ref.as_ref().unwrap().name())
        )
        .unwrap(),
        psk.as_bytes()
    );
    assert!(!text.contains(psk));
    assert!(!text.contains(IMPORT_PRIVATE));
    assert!(h.path.join("state/rendered/000001.nft").is_file());
    assert!(
        import(site)
            .unwrap_err()
            .contains("empty configuration store")
    );
}

#[test]
fn existing_next_generation_requires_dedicated_flag_before_replacement() {
    let mut h = Harness::new();
    h.tty = true;
    h.load();
    let source = ProviderFile::new();
    let key = h.path.join("etc/secrets/wg/exit-ch-1234-v2");
    fs::write(&key, "CAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg=").unwrap();
    fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
    drop(scupper_sys::lock::WriterLock::acquire(h.path.join("run/exit-import")).unwrap());
    let before = h.snapshot();
    let (code, out, err) = h.run_prompt(&["exit", "import", source.path()], &h);
    assert_eq!(code, 1);
    assert!(out.contains("unreferenced"), "{out}");
    assert!(err.contains("--replace-leftover-key"), "{err}");
    assert_eq!(h.snapshot(), before);
    let (code, _, err) = h.run(&["exit", "import", source.path(), "--yes"]);
    assert_eq!(code, 1);
    assert!(err.contains("--replace-leftover-key"));
    assert_eq!(h.snapshot(), before);
    let (code, out, err) = h.run(&[
        "exit",
        "import",
        source.path(),
        "--yes",
        "--replace-leftover-key",
    ]);
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("unreferenced"));
    assert_eq!(fs::read(key).unwrap(), IMPORT_PRIVATE.as_bytes());
}

#[test]
#[allow(clippy::too_many_lines)] // Keep both socket requests and their interleaved disconnect in one regression.
fn socket_import_reset_preserves_disconnect_and_reports_post_commit_failure() {
    use scupper_sys::{
        daemon::{admin, control},
        state::{Selection, StateFile, StateRead},
    };
    use std::{
        io::Write,
        os::{fd::AsRawFd, unix::net::UnixListener},
    };
    for fail in [false, true] {
        let h = Harness::new();
        h.load();
        h.save_state(
            1,
            Selection::Pin(scupper_core::config::ExitId("ch1".into())),
        );
        let source = ProviderFile::new();
        let directory = fs::File::open(h.path.join("run")).unwrap();
        let listener = UnixListener::bind(format!(
            "/proc/self/fd/{}/control.sock",
            directory.as_raw_fd()
        ))
        .unwrap();
        let state = h.path.join("state");
        let config = h.path.join("etc");
        let run = h.path.join("run");
        let worker = std::thread::spawn(move || {
            let kernel = boot_kernel::Kernel::new();
            let log = scupper_sys::events::EventLog::memory_only(GatewayId("gw1".into()), || {
                scupper_proto::UnixSeconds(1000)
            })
            .unwrap();
            for committed in [false, true] {
                let (mut stream, _) = listener.accept().unwrap();
                let request = control::read_request(&stream).unwrap();
                let result = if committed {
                    let scupper_proto::Op::ResetSelection { replaced } = request.op else {
                        panic!("expected reset")
                    };
                    assert_eq!(String::from(replaced.clone()), "ch1");
                    let guard = scupper_sys::lock::WriterLock::acquire(&run).unwrap();
                    StateFile::open(&state, None)
                        .unwrap()
                        .update(&guard, |s| s.selection = Selection::Disconnected)
                        .unwrap();
                    drop(guard);
                    if fail {
                        Err(scupper_proto::ApiError {
                            code: scupper_proto::ApiErrorCode::PersistenceUnavailable,
                            observation: None,
                        })
                    } else {
                        admin::reset_selection(
                            &scupper_sys::boot::BootDeps {
                                system: &kernel,
                                namespace: &kernel,
                                state_root: &state,
                                config_root: &config,
                                run_root: &run,
                                hook: None,
                                secret_owner: rustix::process::geteuid().as_raw(),
                            },
                            &log.handle,
                            &replaced,
                            0,
                        )
                    }
                } else {
                    let scupper_proto::Op::Commit { parent, toml, .. } = request.op else {
                        panic!("expected commit")
                    };
                    let guard = scupper_sys::lock::WriterLock::acquire(&run).unwrap();
                    let store =
                        VersionStore::open_with_mirror_root(&state, &config, Some(&guard)).unwrap();
                    let version = store
                        .commit(
                            &guard,
                            parent,
                            &toml,
                            scupper_sys::store::MetaInput {
                                actor: "test".into(),
                                at: 1000,
                                reason: "import".into(),
                            },
                        )
                        .unwrap();
                    Ok(scupper_proto::OpResult::Commit { version })
                };
                serde_json::to_writer(
                    &mut stream,
                    &scupper_proto::Response {
                        schema: scupper_proto::Schema,
                        request_id: request.request_id,
                        replayed: false,
                        observed_at: None,
                        result,
                    },
                )
                .unwrap();
                stream.write_all(b"\n").unwrap();
            }
        });
        let (code, out, err) = h.run(&["exit", "import", source.path(), "--yes"]);
        worker.join().unwrap();
        assert_eq!(code, u8::from(fail), "{out} {err}");
        assert!(out.contains(&format!(
            "Delete {}: it holds a private key.",
            source.path()
        )));
        if fail {
            assert!(
                err.contains("version 2 committed; selection reset"),
                "{err}"
            );
        }
        assert_eq!(h.store().head().unwrap(), Some(2));
        let StateRead::Present(saved) = StateFile::open(h.path.join("state"), None)
            .unwrap()
            .read()
            .unwrap()
        else {
            panic!("missing state")
        };
        assert_eq!(saved.selection, Selection::Disconnected);
    }
}
