//! Apply sequencing, durability, cleanup, and interactive preview using fakes.

use std::{
    cell::{Cell, RefCell},
    collections::BTreeMap,
    io::{self, Write},
    path::{Path, PathBuf},
    rc::Rc,
    time::{Duration, Instant},
};

use scupper::{
    apply::{self, Fs, RULESET_PATH, TempFile},
    cli::{
        self, Dependencies, NamespaceReader, Privilege, Prompt, Sleeper, UnimplementedExitProbe,
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
    stdout: RefCell<String>,
    nft_response: RefCell<Option<(&'static str, Result<ExecOutput, ExecError>)>>,
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
    fn set_mode(&self, mode: u32) -> io::Result<()> {
        assert_eq!(mode, 0o644);
        self.0.step("mode")?;
        self.0.mode.set(mode);
        Ok(())
    }

    fn sync_all(&self) -> io::Result<()> {
        self.0.step(if self.0.mode.get() == 0o600 {
            "sync temp"
        } else {
            "sync mode"
        })
    }
}

impl Fs for Harness {
    fn check_target(&self, _: &Path) -> io::Result<()> {
        self.0.step("check target")
    }
    fn cleanup_stale(&self, _: &Path) -> io::Result<()> {
        self.0.step("cleanup stale")
    }

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
        assert_eq!(self.0.mode.get(), 0o644);
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
            assert_eq!(&args[..2], ["-c", "-f"]);
            if args[2] == TEMP {
                assert!(self.0.files.borrow().contains_key(Path::new(TEMP)));
            }
        } else {
            assert_eq!(args, ["-f", RULESET_PATH]);
        }
        self.0
            .step(&format!("{step} exec"))
            .map_err(|error| ExecError::spawn(&error.to_string()))?;
        if self
            .0
            .nft_response
            .borrow()
            .as_ref()
            .is_some_and(|(name, _)| *name == step)
        {
            return self
                .0
                .nft_response
                .borrow_mut()
                .take()
                .map(|(_, response)| response)
                .ok_or_else(|| ExecError::spawn("missing injected response"))?;
        }
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
    fn now(&self) -> Instant {
        Instant::now()
    }

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
        self.run_fs(args, self)
    }
    fn run_fs(&self, args: &[&str], fs: &dyn Fs) -> (u8, String) {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let code = cli::run_with(
            std::iter::once("scupper").chain(args.iter().copied()),
            &Dependencies {
                state_root: Path::new("target/m1-without-head"),
                config_root: Path::new("target/m1-without-head"),
                probe_exec: &scupper::system::RealSystem::default(),
                system: self,
                fs,
                privilege: self,
                prompt: self,
                sleeper: self,
                topology: &UnimplementedTopology,
                exit_probe: &UnimplementedExitProbe,
                namespaces: &NoNamespaces,
            },
            &mut out,
            &mut err,
        );
        *self.0.stdout.borrow_mut() = String::from_utf8_lossy(&out).into_owned();
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
            "cleanup stale",
            "check target",
            "read",
            "create temp",
            "write temp",
            "sync temp",
            "nft validate exec",
            "nft validate",
            "mode",
            "sync mode",
            "rename",
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
    assert!(err.contains("live ruleset was not changed by this run"));
    assert_eq!(
        h.disk().as_deref(),
        Some(include_str!(
            "../../scupper-core/tests/golden/ruleset.golden"
        ))
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
        "cleanup stale",
        "check target",
        "read",
        "create temp",
        "write temp",
        "sync temp",
        "nft validate exec",
        "nft validate",
        "rename",
        "mode",
        "sync mode",
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
        if ["sync directory", "nft load exec", "nft load"].contains(&step) {
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
    assert_eq!(
        &log[..4],
        ["check target", "read", "prompt", "cleanup stale"]
    );
}

#[test]
fn preview_read_error_prevents_writes() {
    let h = Harness::default();
    h.0.tty.set(true);
    h.fail("read");
    assert_eq!(h.run(&["apply"]).0, 1);
    assert_eq!(*h.0.log.borrow(), ["check target", "read"]);
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

#[test]
fn apply_signal_and_timeout_failures_preserve_the_correct_disk_version() {
    for step in ["nft validate", "nft load"] {
        for response in [
            Ok(ExecOutput {
                status: None,
                stdout: String::new(),
                stderr: "terminated".into(),
            }),
            Err(ExecError::Timeout {
                after: Duration::from_secs(3),
            }),
        ] {
            let h = Harness::default();
            h.old();
            *h.0.nft_response.borrow_mut() = Some((step, response));
            let (code, err) = h.run(&["apply", "--yes"]);
            assert_eq!(code, 1, "{step}: {err}");
            assert!(h.0.stdout.borrow().is_empty());
            h.assert_no_temp();
            let renames =
                h.0.log
                    .borrow()
                    .iter()
                    .filter(|entry| *entry == "rename")
                    .count();
            if step == "nft validate" {
                assert_eq!(renames, 0);
                assert_eq!(h.disk().as_deref(), Some("old rules\n"));
                assert!(
                    !h.0.log
                        .borrow()
                        .iter()
                        .any(|entry| entry == "nft load exec")
                );
            } else {
                // The final load follows the single validated rename; no rollback rename.
                assert_eq!(renames, 1);
                assert_eq!(
                    h.disk().as_deref(),
                    Some(include_str!(
                        "../../scupper-core/tests/golden/ruleset.golden"
                    ))
                );
                assert!(err.contains("new, validated version"));
                assert!(err.contains("live ruleset was not changed by this run"));
            }
        }
    }
}

#[test]
fn apply_messages_and_unchanged_reload() {
    let h = Harness::default();
    let (code, err) = h.run(&["apply", "--yes"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(*h.0.stdout.borrow(), "ruleset written and loaded\n");
    h.0.log.borrow_mut().clear();
    // No TTY and no --yes: unchanged contents do not require confirmation.
    let (code, err) = h.run(&["apply"]);
    assert_eq!(code, 0, "{err}");
    assert_eq!(*h.0.stdout.borrow(), "ruleset unchanged; reloading\n");
    assert_eq!(
        *h.0.log.borrow(),
        [
            "check target",
            "read",
            "cleanup stale",
            "check target",
            "read",
            "nft validate exec",
            "nft validate",
            "nft load exec",
            "nft load"
        ]
    );
}

// Redirect only the filesystem boundary; production sequencing and RealFs
// operations run unchanged in an isolated directory, without touching /etc.
struct DiskFs {
    directory: PathBuf,
    log: Rc<RefCell<Vec<&'static str>>>,
}

impl DiskFs {
    fn new() -> io::Result<Self> {
        use std::sync::atomic::{AtomicU64, Ordering};
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = std::env::temp_dir().join(format!(
            "scupper-apply-test-{}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(io::Error::other)?
                .as_nanos(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&directory)?;
        Ok(Self {
            directory,
            log: Rc::default(),
        })
    }

    fn path(&self, path: &Path) -> PathBuf {
        path.strip_prefix("/etc")
            .map_or_else(|_| path.to_owned(), |name| self.directory.join(name))
    }
}

impl Drop for DiskFs {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.directory);
    }
}

struct DiskFile {
    file: Box<dyn TempFile>,
    path: PathBuf,
    log: Rc<RefCell<Vec<&'static str>>>,
}

fn mode(path: &Path) -> io::Result<u32> {
    use std::os::unix::fs::PermissionsExt;
    Ok(std::fs::metadata(path)?.permissions().mode() & 0o777)
}

impl Write for DiskFile {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        assert_eq!(mode(&self.path)?, 0o600);
        let count = self.file.write(bytes)?;
        self.log.borrow_mut().push("write 0600");
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

impl TempFile for DiskFile {
    fn sync_all(&self) -> io::Result<()> {
        self.file.sync_all()?;
        self.log.borrow_mut().push(if mode(&self.path)? == 0o600 {
            "sync content"
        } else {
            "sync mode"
        });
        Ok(())
    }
    fn set_mode(&self, mode: u32) -> io::Result<()> {
        self.file.set_mode(mode)?;
        self.log.borrow_mut().push("fchmod");
        Ok(())
    }
}

impl Fs for DiskFs {
    fn check_target(&self, path: &Path) -> io::Result<()> {
        apply::RealFs.check_target(&self.path(path))
    }
    fn cleanup_stale(&self, directory: &Path) -> io::Result<()> {
        apply::RealFs.cleanup_stale(&self.path(directory))?;
        self.log.borrow_mut().push("cleanup stale");
        Ok(())
    }
    fn read(&self, path: &Path) -> io::Result<String> {
        apply::RealFs.read(&self.path(path))
    }
    fn create_temp(&self, directory: &Path) -> io::Result<(PathBuf, Box<dyn TempFile>)> {
        let (path, file) = apply::RealFs.create_temp(&self.path(directory))?;
        assert_eq!(mode(&path)?, 0o600);
        self.log.borrow_mut().push("create 0600");
        Ok((
            path.clone(),
            Box::new(DiskFile {
                file,
                path,
                log: self.log.clone(),
            }),
        ))
    }
    fn rename(&self, source: &Path, destination: &Path) -> io::Result<()> {
        assert_eq!(
            mode(source)?,
            0o644,
            "permissions must be final before rename"
        );
        assert_eq!(self.log.borrow().last(), Some(&"sync mode"));
        apply::RealFs.rename(source, &self.path(destination))?;
        self.log.borrow_mut().push("rename 0644");
        Ok(())
    }
    fn sync_dir(&self, directory: &Path) -> io::Result<()> {
        apply::RealFs.sync_dir(&self.path(directory))?;
        self.log.borrow_mut().push("sync directory");
        Ok(())
    }
    fn remove(&self, path: &Path) -> io::Result<()> {
        apply::RealFs.remove(path)
    }
}

#[test]
fn real_fs_apply_permissions_and_durability() -> io::Result<()> {
    let disk = DiskFs::new()?;
    let h = Harness::default();
    let (code, err) = h.run_fs(&["apply", "--yes"], &disk);
    assert_eq!(code, 0, "{err}");
    let destination = disk.directory.join("nftables.conf");
    assert_eq!(
        std::fs::read_to_string(&destination)?,
        include_str!("../../scupper-core/tests/golden/ruleset.golden")
    );
    assert_eq!(mode(&destination)?, 0o644);
    assert_eq!(
        *disk.log.borrow(),
        [
            "cleanup stale",
            "create 0600",
            "write 0600",
            "sync content",
            "fchmod",
            "sync mode",
            "rename 0644",
            "sync directory"
        ]
    );
    assert_eq!(std::fs::read_dir(&disk.directory)?.count(), 1);
    disk.log.borrow_mut().clear();
    let (code, err) = h.run_fs(&["apply"], &disk);
    assert_eq!(code, 0, "{err}");
    assert_eq!(*h.0.stdout.borrow(), "ruleset unchanged; reloading\n");
    assert_eq!(*disk.log.borrow(), ["cleanup stale"]);
    Ok(())
}

#[test]
fn real_fs_refuses_symlinked_target_without_following_or_replacing_it() -> io::Result<()> {
    use std::os::unix::fs::symlink;
    for dangling in [false, true] {
        let disk = DiskFs::new()?;
        let victim = disk.directory.join("victim");
        if !dangling {
            std::fs::write(&victim, "keep this file")?;
        }
        let destination = disk.directory.join("nftables.conf");
        symlink(&victim, &destination)?;
        assert!(apply::RealFs.read(&destination).is_err());
        for args in [vec!["apply", "--yes"], vec!["apply"]] {
            let h = Harness::default();
            let (code, err) = h.run_fs(&args, &disk);
            assert_eq!(code, 1, "{err}");
            assert!(err.contains("refusing symlinked boot ruleset"));
            assert!(h.0.stdout.borrow().is_empty());
            assert!(h.0.log.borrow().is_empty());
            assert!(disk.log.borrow().is_empty());
        }
        // Check the real rename boundary too, including a link introduced
        // after the preview/validation checks.
        let (source, file) = apply::RealFs.create_temp(&disk.directory)?;
        drop(file);
        assert!(apply::RealFs.rename(&source, &destination).is_err());
        assert!(source.exists());
        assert_eq!(std::fs::read_link(&destination)?, victim);
        if dangling {
            assert!(!victim.exists());
        } else {
            assert_eq!(std::fs::read_to_string(&victim)?, "keep this file");
        }
    }
    Ok(())
}

#[test]
fn real_fs_apply_cleans_only_matching_regular_stale_files() -> io::Result<()> {
    use std::os::unix::fs::symlink;
    let disk = DiskFs::new()?;
    for name in [".scupper-123-0.tmp", ".scupper-456-987.tmp"] {
        std::fs::write(disk.directory.join(name), "stale")?;
    }
    let preserved = [
        "other.tmp",
        ".scupper-.tmp",
        ".scupper-1.tmp",
        ".scupper-1-.tmp",
        ".scupper--2.tmp",
        ".scupper-one-2.tmp",
        ".scupper-1-2.tmp.bak",
        ".scupper-1-2-3.tmp",
    ];
    for name in preserved {
        std::fs::write(disk.directory.join(name), "keep")?;
    }
    let subdir = disk.directory.join(".scupper-789-0.tmp");
    std::fs::create_dir(&subdir)?;
    let link = disk.directory.join(".scupper-789-1.tmp");
    symlink(disk.directory.join("other.tmp"), &link)?;
    let h = Harness::default();
    let (code, err) = h.run_fs(&["apply", "--yes"], &disk);
    assert_eq!(code, 0, "{err}");
    assert!(!disk.directory.join(".scupper-123-0.tmp").exists());
    assert!(!disk.directory.join(".scupper-456-987.tmp").exists());
    for name in preserved {
        assert_eq!(std::fs::read_to_string(disk.directory.join(name))?, "keep");
    }
    assert!(subdir.is_dir());
    assert!(std::fs::symlink_metadata(link)?.is_symlink());
    assert_eq!(disk.log.borrow().first(), Some(&"cleanup stale"));
    Ok(())
}

/// `apply` never runs `canon`, so namespace reads must not happen.
struct NoNamespaces;

impl NamespaceReader for NoNamespaces {
    fn read_namespace(&self, _path: &Path) -> io::Result<PathBuf> {
        Err(io::Error::other("namespace read in an apply test"))
    }
}
