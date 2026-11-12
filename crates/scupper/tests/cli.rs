#![cfg(target_os = "linux")]
//! CLI parsing, isolated-canon safety guards, and interaction contracts.
#![allow(clippy::unwrap_used)]
use scupper::{
    cli::{self, Dependencies, NamespaceReader, Privilege, Prompt},
    system::{ExecError, ExecOutput, Program, System},
};
use std::{
    cell::RefCell,
    collections::VecDeque,
    io,
    os::fd::AsRawFd,
    path::{Path, PathBuf},
    time::Duration,
};
struct Call {
    program: Program,
    args: Vec<String>,
}
struct Harness {
    responses: RefCell<VecDeque<Result<ExecOutput, ExecError>>>,
    calls: RefCell<Vec<Call>>,
    self_netns: Option<&'static str>,
    pid1_netns: Option<&'static str>,
}
impl Default for Harness {
    fn default() -> Self {
        Self {
            responses: RefCell::default(),
            calls: RefCell::default(),
            self_netns: Some("net:[123]"),
            pid1_netns: Some("net:[456]"),
        }
    }
}
impl System for Harness {
    fn run(&self, program: Program, args: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
        self.calls.borrow_mut().push(Call {
            program,
            args: args.into(),
        });
        self.responses
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Err(ExecError::spawn("unexpected command")))
    }
    fn now_unix_secs(&self) -> u64 {
        1000
    }
}
impl NamespaceReader for Harness {
    fn read_namespace(&self, path: &Path) -> io::Result<PathBuf> {
        let value = if path == Path::new("/proc/self/ns/net") {
            self.self_netns
        } else {
            self.pid1_netns
        };
        value
            .map(PathBuf::from)
            .ok_or_else(|| io::ErrorKind::PermissionDenied.into())
    }
    fn gateway_marker(&self) -> io::Result<bool> {
        Ok(false)
    }
}
impl Privilege for Harness {
    fn is_root(&self) -> bool {
        true
    }
}
impl Prompt for Harness {
    fn is_terminal(&self) -> bool {
        false
    }
    fn confirm(&self, _: &str, _: Option<&str>) -> io::Result<bool> {
        unreachable!()
    }
}
impl Harness {
    fn output(&self, stdout: &str) {
        self.responses.borrow_mut().push_back(Ok(ExecOutput {
            status: Some(0),
            stdout: stdout.into(),
            stderr: String::new(),
        }));
    }
    fn run(&self, args: &[&str]) -> (u8, String, String) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        static NEXT: AtomicUsize = AtomicUsize::new(0);
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || PathBuf::from(concat!(env!("CARGO_MANIFEST_DIR"), "/../../target/tmp")),
                PathBuf::from,
            )
            .join(format!(
                "cli-harness-{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
        std::fs::create_dir_all(&root).unwrap();
        let directory = std::fs::File::open(&root).unwrap();
        let socket_root = PathBuf::from(format!("/proc/self/fd/{}/.", directory.as_raw_fd()));
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = cli::run_with(
            std::iter::once("scupper").chain(args.iter().copied()),
            &Dependencies {
                state_root: &root.join("missing-store"),
                config_root: &root.join("missing-config"),
                writer_root: &socket_root.join("unused-writer"),
                probe_exec: &scupper::system::RealSystem::default(),
                system: self,
                namespaces: self,
                privilege: self,
                prompt: self,
            },
            &mut out,
            &mut err,
        );
        std::fs::remove_dir_all(root).unwrap();
        (
            code,
            String::from_utf8(out).unwrap(),
            String::from_utf8(err).unwrap(),
        )
    }
}
#[test]
fn confirmation_parsing_defaults_to_no() {
    for answer in ["y", "yes", "Y", "YES", " YeS ", "  y\n"] {
        assert!(cli::parse_confirmation(answer), "{answer:?}");
    }
    // read_line returns an empty string on EOF.
    for answer in [
        "",
        "\n",
        " \t\n",
        "no",
        "n",
        "yeah",
        "yes please",
        "true",
        "1",
    ] {
        assert!(!cli::parse_confirmation(answer), "{answer:?}");
    }
}

#[test]
fn canon_is_hidden_and_requires_one_path() {
    let h = Harness::default();
    let (code, out, err) = h.run(&["--help"]);
    assert_eq!(code, 0);
    assert!(!out.contains("canon"));
    assert_eq!(err, "");
    for args in [
        vec!["canon"],
        vec!["canon", "one"],
        vec!["canon", "--outer-netns", "net:[789]", "one", "two"],
    ] {
        let (code, out, err) = h.run(&args);
        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert_ne!(err, "");
    }
    assert!(h.calls.borrow().is_empty());
}

#[test]
fn canon_namespace_guards_run_before_any_system_calls() {
    for (current, pid1) in [
        (Some("net:[789]"), Some("net:[456]")),
        (None, Some("net:[456]")),
        (Some("net:[123]"), Some("net:[123]")),
    ] {
        let h = Harness {
            self_netns: current,
            pid1_netns: pid1,
            ..Harness::default()
        };
        let (code, out, err) = h.run(&[
            "canon",
            "--outer-netns",
            "net:[789]",
            "/private/ruleset.nft",
        ]);
        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.contains("canon:"));
        assert!(h.calls.borrow().is_empty());
    }
}

#[test]
fn canon_unreadable_pid1_is_optional_and_empty_ruleset_precedes_load() {
    let h = Harness {
        pid1_netns: None,
        ..Harness::default()
    };
    h.output(r#"{"nftables":[{"metainfo":{"version":"1"}}]}"#);
    h.output("");
    h.output(r#"{"nftables":[{"table":{"name":"scupper","family":"inet"}}]}"#);
    let (code, out, err) = h.run(&[
        "canon",
        "--outer-netns",
        "net:[789]",
        "/private/ruleset.nft",
    ]);
    assert_eq!(code, 0, "{err}");
    assert!(out.contains("scupper"));
    let calls = h.calls.borrow();
    assert_eq!(calls.len(), 3);
    assert!(calls.iter().all(|call| call.program == Program::Nft));
    assert_eq!(calls[0].args, ["-j", "list", "ruleset"]);
    assert_eq!(calls[1].args, ["-f", "/private/ruleset.nft"]);
    assert_eq!(calls[2].args, calls[0].args);
}

#[test]
fn canon_refuses_nonempty_or_unreadable_preload_ruleset() {
    for before in [
        r#"{"nftables":[{"table":{"family":"inet","name":"foreign"}}]}"#,
        r#"{"nftables":[{"metainfo":{},"table":{}}]}"#,
        r#"{"nftables":[null]}"#,
        r#"{"nftables":[{"metainfo":null}]}"#,
        "{}",
        "invalid JSON",
    ] {
        let h = Harness::default();
        h.output(before);
        let (code, out, err) = h.run(&[
            "canon",
            "--outer-netns",
            "net:[789]",
            "/private/ruleset.nft",
        ]);
        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.contains("canon:"));
        let calls = h.calls.borrow();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].args, ["-j", "list", "ruleset"]);
    }
}

#[test]
fn canon_rejects_malformed_outer_namespace_before_system_calls() {
    for outer in [
        "net:[]",
        "net:[12a]",
        "mnt:[1]",
        "",
        "net:[1]/",
        "net:[１２]",
        "net:[+1]",
        " net:[1]",
    ] {
        let h = Harness::default();
        let (code, out, err) = h.run(&["canon", "--outer-netns", outer, "/private/ruleset.nft"]);
        assert_eq!(code, 1, "{outer:?}");
        assert_eq!(out, "");
        assert_ne!(err, "");
        // Clap rejects an empty PathBuf before the canon guard runs.
        if !outer.is_empty() {
            assert!(err.contains("outer network namespace must be"), "{err}");
        }
        assert!(h.calls.borrow().is_empty());
    }
}

#[test]
fn no_m2_gateway_is_an_error_and_retired_commands_are_unknown() {
    let h = Harness::default();
    for command in ["check", "status"] {
        let (code, _, err) = h.run(&[command]);
        assert_eq!(code, 1);
        assert!(err.contains("not an M2 gateway (no /var/lib/scupper store)"));
    }
    for command in ["connect", "disconnect", "apply"] {
        assert_eq!(h.run(&[command]).0, 1);
    }
    assert!(h.calls.borrow().is_empty());
}

#[test]
fn exit_codes_contract() {
    let h = Harness::default();
    for args in [
        vec!["bogus"],
        vec!["check", "--bad"],
        vec!["--nft-path", "/bin/true"],
        vec![],
    ] {
        let (code, out, err) = h.run(&args);
        assert_eq!(code, 1);
        assert_eq!(out, "");
        assert!(err.starts_with("scupper:"));
    }
    for args in [vec!["--help"], vec!["--version"], vec!["config", "--help"]] {
        let (code, out, err) = h.run(&args);
        assert_eq!(code, 0);
        assert!(out.contains("scupper"));
        assert_eq!(err, "");
    }
    assert!(h.calls.borrow().is_empty());
}
