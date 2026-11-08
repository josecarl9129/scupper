//! Apply sequencing, durability, cleanup, and interactive preview using fakes.

use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    io::{self, Write},
    path::{Path, PathBuf},
    rc::Rc,
    time::Duration,
};

use scupper::{
    apply::{self, Fs, RULESET_PATH, TempFile},
    cli::{
        self, Dependencies, Privilege, Prompt, Sleeper, UnimplementedExitProbe,
        UnimplementedTopology,
    },
    system::{ExecError, ExecOutput, Program, System},
};

const TEMP: &str = "/etc/.fake.tmp";
const NEW: &str = "new rules\n";

#[derive(Default)]
struct State {
    log: RefCell<Vec<String>>,
    files: RefCell<BTreeMap<PathBuf, Vec<u8>>>,
    fail: RefCell<Option<&'static str>>,
    mode: Cell<u32>,
    tty: Cell<bool>,
    confirmed: Cell<bool>,
    preview: RefCell<Option<String>>,
    question: RefCell<String>,
}

impl State {
    fn step(&self, name: &str) -> io::Result<()> {
        self.log.borrow_mut().push(name.into());
        if self
            .fail
            .borrow()
            .as_ref()
            .is_some_and(|fail| *fail == name)
        {
            self.fail.borrow_mut().take();
            return Err(io::Error::other(format!("injected {name}")));
        }
        Ok(())
    }
}

#[derive(Default)]
struct Harness(Rc<State>);

struct FakeFile(Rc<State>);

impl Write for FakeFile {
    fn write(&mut self, data: &[u8]) -> io::Result<usize> {
        self.0.step("write temp")?;
        self.0
            .files
            .borrow_mut()
            .entry(TEMP.into())
            .or_default()
            .extend_from_slice(data);
        Ok(data.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl TempFile for FakeFile {
    fn sync_all(&self) -> io::Result<()> {
        self.0.step("sync temp")
    }
}

impl Fs for Harness {
    fn read(&self, path: &Path) -> io::Result<String> {
        self.0.step("read")?;
        self.0
            .files
            .borrow()
            .get(path)
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
            .ok_or_else(|| io::ErrorKind::NotFound.into())
    }
    fn create_temp(&self, directory: &Path) -> io::Result<(PathBuf, Box<dyn TempFile>)> {
        assert_eq!(directory, Path::new("/etc"));
        self.0.step("create temp")?;
        self.0.mode.set(0o600);
        self.0.files.borrow_mut().insert(TEMP.into(), Vec::new());
        Ok((TEMP.into(), Box::new(FakeFile(self.0.clone()))))
    }
    fn rename(&self, source: &Path, destination: &Path) -> io::Result<()> {
        assert_eq!(source, Path::new(TEMP));
        assert_eq!(destination, Path::new(RULESET_PATH));
        assert_eq!(self.0.mode.get(), 0o600);
        self.0.step("rename")?;
        let content = self
            .0
            .files
            .borrow_mut()
            .remove(source)
            .ok_or_else(|| io::Error::other("missing temp"))?;
        self.0
            .files
            .borrow_mut()
            .insert(destination.into(), content);
        Ok(())
    }
    fn set_mode(&self, path: &Path, mode: u32) -> io::Result<()> {
        assert_eq!(path, Path::new(RULESET_PATH));
        assert_eq!(mode, 0o644);
        self.0.step("mode")?;
        self.0.mode.set(mode);
        Ok(())
    }
    fn sync_dir(&self, directory: &Path) -> io::Result<()> {
        assert_eq!(directory, Path::new("/etc"));
        self.0.step("sync directory")
    }
    fn remove(&self, path: &Path) -> io::Result<()> {
        assert_eq!(path, Path::new(TEMP));
        self.0.step("remove temp")?;
        self.0.files.borrow_mut().remove(path);
        Ok(())
    }
}

impl System for Harness {
    fn run(&self, program: Program, args: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
        assert_eq!(program, Program::Nft);
        let validate = args.first().is_some_and(|arg| arg == "-c");
        let step = if validate { "nft validate" } else { "nft load" };
        if validate {
            assert_eq!(args, ["-c", "-f", TEMP]);
            assert!(self.0.files.borrow().contains_key(Path::new(TEMP)));
        } else {
            assert_eq!(args, ["-f", RULESET_PATH]);
        }
        self.0
            .step(&format!("{step} exec"))
            .map_err(|error| ExecError::spawn(&error.to_string()))?;
        let failed = self.0.step(step).is_err();
        Ok(ExecOutput {
            status: Some(i32::from(failed)),
            stdout: String::new(),
            stderr: if failed {
                "first nft error\nsecond nft error\n".into()
            } else {
                String::new()
            },
        })
    }
    fn now_unix_secs(&self) -> u64 {
        1_000
    }
}
impl Privilege for Harness {
    fn is_root(&self) -> bool {
        true
    }
}
impl Prompt for Harness {
    fn is_terminal(&self) -> bool {
        self.0.tty.get()
    }
    fn confirm(&self, question: &str, preview: Option<&str>) -> io::Result<bool> {
        self.0.step("prompt")?;
        *self.0.question.borrow_mut() = question.into();
        *self.0.preview.borrow_mut() = preview.map(str::to_owned);
        Ok(self.0.confirmed.get())
    }
}
impl Sleeper for Harness {
    fn sleep(&self, _: Duration) {}
}

impl Harness {
    fn fail(&self, step: &'static str) {
        *self.0.fail.borrow_mut() = Some(step);
    }
    fn old(&self) {
        self.0
            .files
            .borrow_mut()
            .insert(RULESET_PATH.into(), b"old rules\n".to_vec());
    }
    fn run(&self, args: &[&str]) -> (u8, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = cli::run_with(
            std::iter::once("scupper").chain(args.iter().copied()),
            &Dependencies {
                system: self,
                fs: self,
                privilege: self,
                prompt: self,
                sleeper: self,
                topology: &UnimplementedTopology,
                exit_probe: &UnimplementedExitProbe,
            },
            &mut out,
            &mut err,
        );
        (code, String::from_utf8_lossy(&err).into_owned())
    }
    fn assert_no_temp(&self) {
        assert!(!self.0.files.borrow().contains_key(Path::new(TEMP)));
    }
    fn disk(&self) -> Option<String> {
        self.0
            .files
            .borrow()
            .get(Path::new(RULESET_PATH))
            .map(|bytes| String::from_utf8_lossy(bytes).into_owned())
    }
}

#[test]
fn apply_validates_before_rename() -> Result<(), String> {
    let h = Harness::default();
    h.old();
    apply::apply(&h, &h, NEW)?;
    assert_eq!(
        *h.0.log.borrow(),
        [
            "create temp",
            "write temp",
            "sync temp",
            "nft validate exec",
            "nft validate",
            "rename",
            "mode",
            "sync directory",
            "nft load exec",
            "nft load",
        ]
    );
    assert_eq!(h.disk().as_deref(), Some(NEW));
    assert_eq!(h.0.mode.get(), 0o644);
    h.assert_no_temp();
    Ok(())
}

#[test]
fn apply_invalid_never_renamed() {
    let h = Harness::default();
    h.old();
    h.fail("nft validate");
    let (code, err) = h.run(&["apply", "--yes"]);
    assert_eq!(code, 1);
    assert!(err.starts_with("scupper:"));
    assert!(err.contains("first nft error"));
    assert!(!err.contains("second nft error"));
    assert!(!h.0.log.borrow().iter().any(|entry| entry == "rename"));
    assert_eq!(h.disk().as_deref(), Some("old rules\n"));
    h.assert_no_temp();
}

#[test]
fn apply_load_failure_reported() {
    let h = Harness::default();
    h.old();
    h.fail("nft load");
    let (code, err) = h.run(&["apply", "--yes"]);
    assert_eq!(code, 1);
    assert!(err.contains("first nft error\nsecond nft error"));
    assert!(err.contains("file on disk at /etc/nftables.conf is the new, validated version"));
    assert_eq!(
        h.disk().as_deref(),
        Some(include_str!("golden/ruleset.golden"))
    );
    h.assert_no_temp();
}

#[test]
fn apply_temp_cleanup_on_every_error() {
    struct FailingValidation<'a>(&'a Harness);
    impl System for FailingValidation<'_> {
        fn run(&self, _: Program, _: &[String], _: Duration) -> Result<ExecOutput, ExecError> {
            self.0.fail("remove temp");
            Err(ExecError::spawn("validation spawn failed"))
        }
        fn now_unix_secs(&self) -> u64 {
            1_000
        }
    }
    for step in [
        "create temp",
        "write temp",
        "sync temp",
        "nft validate exec",
        "nft validate",
        "rename",
        "mode",
        "sync directory",
        "nft load exec",
        "nft load",
    ] {
        let h = Harness::default();
        h.old();
        h.fail(step);
        let (code, err) = h.run(&["apply", "--yes"]);
        assert_eq!(code, 1, "{step}: {err}");
        h.assert_no_temp();
        if ["mode", "sync directory", "nft load exec", "nft load"].contains(&step) {
            assert!(err.contains("validated version"), "{step}: {err}");
        } else {
            assert_eq!(h.disk().as_deref(), Some("old rules\n"), "{step}");
        }
    }
    // A transient removal failure is reported and retried by the guard.
    let h = Harness::default();
    let result = apply::apply(&FailingValidation(&h), &h, NEW);
    assert!(result.is_err());
    h.assert_no_temp();
    assert_eq!(
        h.0.log
            .borrow()
            .iter()
            .filter(|entry| *entry == "remove temp")
            .count(),
        2
    );
}

#[test]
fn apply_diff_shown_on_tty() {
    let h = Harness::default();
    h.old();
    h.0.tty.set(true);
    h.0.confirmed.set(true);
    let (code, err) = h.run(&["apply"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(
        *h.0.question.borrow(),
        "Replace /etc/nftables.conf and load it? [y/N]"
    );
    let preview = h.0.preview.borrow();
    let diff = preview.as_deref().unwrap_or_default();
    assert!(
        diff.starts_with("--- /etc/nftables.conf\n+++ /etc/nftables.conf (generated)\n@@ -1 +1,")
    );
    assert!(diff.contains("-old rules\n"));
    assert!(diff.contains("+# Generated by scupper"));
    let log = h.0.log.borrow();
    assert_eq!(&log[..3], ["read", "prompt", "create temp"]);
}

#[test]
fn preview_read_error_prevents_writes() {
    let h = Harness::default();
    h.0.tty.set(true);
    h.fail("read");
    assert_eq!(h.run(&["apply"]).0, 1);
    assert_eq!(*h.0.log.borrow(), ["read"]);
    h.assert_no_temp();
}

#[test]
fn apply_without_old_file_can_be_confirmed() {
    let h = Harness::default();
    h.0.tty.set(true);
    h.0.confirmed.set(true);
    assert_eq!(h.run(&["apply"]).0, 0);
    assert!(h.0.preview.borrow().is_none());
}

#[test]
fn diff_handles_empty_files_and_missing_newlines() {
    assert_eq!(apply::ruleset_diff("same\n", "same\n"), "");
    assert_eq!(
        apply::ruleset_diff("", "new\n"),
        "--- /etc/nftables.conf\n+++ /etc/nftables.conf (generated)\n@@ -0,0 +1 @@\n+new\n"
    );
    let diff = apply::ruleset_diff("old", "");
    assert!(diff.contains("@@ -1 +0,0 @@\n-old\n\\ No newline at end of file\n"));
}
