//! Isolated canonicalization loader safety and error contracts.
use scupper_sys::{
    canon::run_isolated,
    system::{EXEC_TIMEOUT, ExecError, ExecOutput, Program, System},
};
use std::{
    cell::RefCell,
    collections::VecDeque,
    error::Error,
    io,
    path::{Path, PathBuf},
    time::Duration,
};
fn output(stdout: &str) -> ExecOutput {
    ExecOutput {
        status: Some(0),
        stdout: stdout.into(),
        stderr: String::new(),
    }
}
fn failure(stderr: &str) -> ExecOutput {
    ExecOutput {
        status: Some(1),
        stdout: String::new(),
        stderr: stderr.into(),
    }
}
const NFT_LIVE: &str = include_str!("fixtures/ubuntu-24.04/nft-live.json");
struct FakeSystem {
    live_results: RefCell<VecDeque<Result<ExecOutput, ExecError>>>,
    scripts: RefCell<VecDeque<Result<ExecOutput, ExecError>>>,
    calls: RefCell<Vec<(Program, Vec<String>, Duration)>>,
}
impl FakeSystem {
    fn new() -> Self {
        Self {
            live_results: RefCell::default(),
            scripts: RefCell::default(),
            calls: RefCell::default(),
        }
    }
    fn push(&self, _: Program, _: &[&str], response: Result<ExecOutput, ExecError>) {
        self.scripts.borrow_mut().push_back(response);
    }
    fn set(&self, p: Program, a: &[&str], text: &str) {
        self.push(p, a, Ok(output(text)));
    }
}
impl System for FakeSystem {
    fn run_in(
        &self,
        _: scupper_sys::system::ExecTarget<'_>,
        p: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.run(p, args, timeout)
    }
    fn canon_run_root(&self) -> &Path {
        Path::new(env!("CARGO_TARGET_TMPDIR"))
    }
    fn run(&self, p: Program, a: &[String], t: Duration) -> Result<ExecOutput, ExecError> {
        self.calls.borrow_mut().push((p, a.into(), t));
        if a == ["-j", "list", "ruleset"] {
            return self
                .live_results
                .borrow_mut()
                .pop_front()
                .unwrap_or_else(|| Ok(output(NFT_LIVE)));
        }
        self.scripts
            .borrow_mut()
            .pop_front()
            .unwrap_or_else(|| Err(ExecError::spawn("unexpected command")))
    }
    fn now_unix_secs(&self) -> u64 {
        0
    }
}
#[test]
fn namespace_guard_aborts_without_nft() {
    for unreadable in [None, Some("/proc/self/ns/net"), Some("/proc/1/ns/net")] {
        let sys = FakeSystem::new();
        let mut stdout = Vec::new();
        let mut stderr = Vec::new();
        let code = run_isolated(
            &sys,
            Path::new("/ignored/ruleset.nft"),
            Path::new("net:[4026531840]"),
            |path| {
                if unreadable.is_some_and(|bad| path == Path::new(bad)) {
                    Err(io::ErrorKind::PermissionDenied.into())
                } else {
                    Ok(PathBuf::from("net:[4026531840]"))
                }
            },
            &mut stdout,
            &mut stderr,
        );
        assert_eq!(code, 1);
        assert_eq!(stdout, Vec::<u8>::new());
        assert_ne!(stderr, Vec::<u8>::new());
        assert!(sys.calls.borrow().is_empty());
    }
}

fn isolated_run(sys: &FakeSystem) -> (u8, Vec<u8>, Vec<u8>) {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    let code = run_isolated(
        sys,
        Path::new("/private/ruleset.nft"),
        Path::new("net:[789]"),
        |path| {
            Ok(PathBuf::from(if path == Path::new("/proc/self/ns/net") {
                "net:[123]"
            } else {
                "net:[456]"
            }))
        },
        &mut stdout,
        &mut stderr,
    );
    (code, stdout, stderr)
}

#[test]
fn isolated_canon_loads_then_lists_and_reports_failures() -> Result<(), Box<dyn Error>> {
    let sys = FakeSystem::new();
    sys.live_results
        .borrow_mut()
        .push_back(Ok(output(r#"{"nftables":[]}"#)));
    sys.set(Program::Nft, &["-f", "/private/ruleset.nft"], "");
    let (code, stdout, stderr) = isolated_run(&sys);
    assert_eq!(code, 0);
    assert_eq!(String::from_utf8(stdout)?, NFT_LIVE);
    assert_eq!(stderr, Vec::<u8>::new());
    assert_eq!(
        *sys.calls.borrow(),
        [
            (
                Program::Nft,
                vec!["-j".into(), "list".into(), "ruleset".into()],
                EXEC_TIMEOUT
            ),
            (
                Program::Nft,
                vec!["-f".into(), "/private/ruleset.nft".into()],
                EXEC_TIMEOUT
            ),
            (
                Program::Nft,
                vec!["-j".into(), "list".into(), "ruleset".into()],
                EXEC_TIMEOUT
            ),
        ]
    );
    for error in [
        Ok(failure("invalid ruleset")),
        Err(ExecError::Timeout {
            after: EXEC_TIMEOUT,
        }),
        Err(ExecError::spawn("nft unavailable")),
    ] {
        let sys = FakeSystem::new();
        sys.live_results
            .borrow_mut()
            .push_back(Ok(output(r#"{"nftables":[]}"#)));
        sys.push(Program::Nft, &["-f", "/private/ruleset.nft"], error);
        let (code, stdout, stderr) = isolated_run(&sys);
        assert_eq!(code, 1);
        assert_eq!(stdout, Vec::<u8>::new());
        assert_ne!(stderr, Vec::<u8>::new());
        assert_eq!(sys.calls.borrow().len(), 2);
    }
    let sys = FakeSystem::new();
    sys.live_results
        .borrow_mut()
        .push_back(Ok(output(r#"{"nftables":[]}"#)));
    sys.set(Program::Nft, &["-f", "/private/ruleset.nft"], "");
    sys.live_results
        .borrow_mut()
        .push_back(Ok(failure("cannot list ruleset")));
    let (code, stdout, stderr) = isolated_run(&sys);
    assert_eq!(code, 1);
    assert_eq!(stdout, Vec::<u8>::new());
    assert_ne!(stderr, Vec::<u8>::new());
    Ok(())
}

#[cfg(feature = "testing")]
#[test]
fn relative_tmpdir_does_not_affect_canonicalization() -> Result<(), Box<dyn Error>> {
    let output = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--ignored",
            "--exact",
            "relative_temp_dir_fixture",
            "--nocapture",
        ])
        .env("TMPDIR", "relative-canon-temp")
        .output()?;
    assert!(
        output.status.success(),
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[cfg(feature = "testing")]
#[test]
#[ignore = "subprocess fixture"]
fn relative_temp_dir_fixture() -> Result<(), Box<dyn Error>> {
    assert!(!std::env::temp_dir().is_absolute());
    let sys = FakeSystem::new();
    sys.live_results
        .borrow_mut()
        .push_back(Ok(output(r#"{"nftables":[]}"#)));
    sys.push(Program::Unshare, &[], Ok(output(r#"{"nftables":[]}"#)));
    let (want, live) = scupper_sys::canon::netns_rulesets(
        &sys,
        &scupper_sys::netns::testing::handle()?,
        "flush ruleset",
    )?;
    assert_eq!(want, live);
    assert!(
        sys.calls
            .borrow()
            .iter()
            .any(|call| call.0 == Program::Unshare)
    );
    assert!(!Path::new("relative-canon-temp").exists());
    Ok(())
}
