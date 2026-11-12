//! Real stdin, safe summaries and confined writes through the injected CLI boundary.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]
use scupper::{
    cli::{self, Dependencies, Privilege, ProcNamespaces, TerminalPrompt},
    system::RealSystem,
};
use scupper_core::config::{SecretKind, SecretName};
use scupper_sys::{
    lock::WriterLock,
    secrets::SecretFile,
    store::{MetaInput, VersionStore},
};
use std::{
    fs,
    io::Write,
    os::unix::fs::{MetadataExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::{Command, Stdio},
    sync::atomic::{AtomicU64, Ordering},
};

const STDIN_NOTICE: &str =
    "reading the secret from stdin (not a terminal); over SSH use `ssh -t` for a hidden prompt\n";

struct Disk(PathBuf);
impl Disk {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let path = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "secret-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&path).unwrap();
        fs::create_dir(path.join("etc")).unwrap();
        Self(path)
    }
    fn target(&self) -> PathBuf {
        self.0.join("etc/secrets/url/fake-ref")
    }
    fn spawn(&self, command: &str) -> std::process::Child {
        Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "secret_child", "--nocapture", "--quiet"])
            .env_clear()
            .env("SCUPPER_SECRET_TEST_ROOT", &self.0)
            .env("SCUPPER_SECRET_TEST_COMMAND", command)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap()
    }
    fn run(&self, command: &str, input: &[u8]) -> (i32, String, String) {
        let mut child = self.spawn(command);
        let args = fs::read(format!("/proc/{}/cmdline", child.id())).unwrap();
        if input.len() >= 16 {
            assert!(!args.windows(input.len()).any(|w| w == input));
        }
        let mut pipe = child.stdin.take().unwrap();
        // Keep the pipe open while sampling argv after handing over the value.
        // No helper process is spawned by the secret command.
        if let Err(error) = pipe.write_all(input) {
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        }
        if let Ok(args) = fs::read(format!("/proc/{}/cmdline", child.id())) {
            let value = input.strip_suffix(b"\n").unwrap_or(input);
            if value.len() >= 16 {
                assert!(!args.windows(value.len()).any(|w| w == value));
            }
        }
        drop(pipe);
        let result = child.wait_with_output().unwrap();
        (
            result.status.code().unwrap(),
            String::from_utf8(result.stdout).unwrap(),
            String::from_utf8(result.stderr).unwrap(),
        )
    }
    fn commit(&self, parent: Option<u64>, extras: &str) {
        let guard = WriterLock::acquire(self.0.join("run")).unwrap();
        let store = VersionStore::open_with_mirror_root(
            self.0.join("state"),
            self.0.join("etc"),
            Some(&guard),
        )
        .unwrap();
        let text = include_str!("../../../xtask/lab/site-lab.toml")
            .replace("https://sink.lab.test/", "https://example.com/")
            + extras;
        store
            .commit(
                &guard,
                parent,
                &text,
                MetaInput {
                    actor: "test".into(),
                    at: 0,
                    reason: "fake config".into(),
                },
            )
            .unwrap();
    }
}
impl Drop for Disk {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

struct Root;
impl Privilege for Root {
    fn is_root(&self) -> bool {
        true
    }
}

// Spawn the integration test itself so stdin is a real pipe while privilege is
// injected, as in other CLI tests. Production always uses EffectiveUid.
#[test]
fn secret_child() {
    let Some(path) = std::env::var_os("SCUPPER_SECRET_TEST_ROOT") else {
        return;
    };
    let path = PathBuf::from(path);
    let command = std::env::var("SCUPPER_SECRET_TEST_COMMAND").unwrap();
    let system = RealSystem::default();
    let code = cli::run_with(
        std::iter::once("scupper").chain(command.split_whitespace()),
        &Dependencies {
            config_root: &path.join("etc"),
            state_root: &path.join("state"),
            writer_root: &path.join("run"),
            system: &system,
            probe_exec: &system,
            privilege: &Root,
            namespaces: &ProcNamespaces,
            prompt: &TerminalPrompt,
        },
        &mut std::io::stdout(),
        &mut std::io::stderr(),
    );
    if code == 0 && command.starts_with("secret set ") {
        let limits = rustix::process::getrlimit(rustix::process::Resource::Core);
        assert_eq!(limits.current, Some(0));
        assert_eq!(limits.maximum, Some(0));
        assert_eq!(
            rustix::process::dumpable_behavior().unwrap(),
            rustix::process::DumpableBehavior::NotDumpable
        );
    }
    std::process::exit(i32::from(code));
}

fn no_other_values(path: &Path, target: &Path, value: &[u8]) {
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            no_other_values(&path, target, value);
        } else if path != target {
            assert!(
                !fs::read(path)
                    .unwrap()
                    .windows(value.len())
                    .any(|w| w == value)
            );
        }
    }
}

#[test]
fn stdin_permissions_replacement_and_only_target_persists() {
    let disk = Disk::new();
    let value = b"https://hc-ping.example/FAKE_PRIVATE_PATH?key=FAKE_QUERY";
    let (code, out, err) = disk.run("secret set url fake-ref", value);
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("fake-ref: https://hc-ping.example/…"));
    assert!(!out.contains("FAKE_PRIVATE") && !out.contains("FAKE_QUERY"));
    assert_eq!(err, STDIN_NOTICE);
    assert_eq!(fs::read(disk.target()).unwrap(), value);
    for (path, mode) in [
        (disk.0.join("etc/secrets"), 0o700),
        (disk.0.join("etc/secrets/url"), 0o700),
        (disk.target(), 0o600),
    ] {
        let stat = fs::metadata(path).unwrap();
        assert_eq!(stat.permissions().mode() & 0o7777, mode);
        assert_eq!(stat.uid(), rustix::process::geteuid().as_raw());
    }
    no_other_values(&disk.0, &disk.target(), value);
    let next = b"https://example.com/FAKE_REPLACEMENT?key=FAKE_NEW_QUERY\n";
    let (code, _, err) = disk.run("secret set url fake-ref", next);
    assert_eq!(code, 1);
    assert!(err.contains("use --replace"));
    assert_eq!(fs::read(disk.target()).unwrap(), value);
    no_other_values(&disk.0, &disk.target(), &next[..next.len() - 1]);
    let (code, out, err) = disk.run("secret set url fake-ref --replace", next);
    assert_eq!(code, 0, "{out} {err}");
    assert_eq!(fs::read(disk.target()).unwrap(), &next[..next.len() - 1]);
    no_other_values(&disk.0, &disk.target(), &next[..next.len() - 1]);
    assert_eq!(
        fs::read_dir(disk.0.join("etc/secrets/url"))
            .unwrap()
            .count(),
        1
    );
    let (code, out, err) = disk.run("secret check fake-ref", b"");
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains(&format!("url fake-ref: ok length={}", next.len() - 1)));
    assert!(!out.contains("FAKE_"));
    let (code, out, err) = disk.run("secret list", b"");
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("url fake-ref 0600 referenced=false"));
}

#[test]
fn telegram_two_lines_and_refusals_are_value_free() {
    let disk = Disk::new();
    let token = "00000000:FAKE_TOKEN_for_tests_only_00000000000";
    let (code, out, err) = disk.run(
        "secret set telegram fake-ref",
        format!("{token}\n@fake_channel\n").as_bytes(),
    );
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("fake-ref: telegram bot 0000… chat @fake_channel"));
    assert!(!out.contains(token) && !err.contains(token));
    assert_eq!(
        fs::read_to_string(disk.target()).unwrap(),
        format!("https://api.telegram.org/bot{token}/sendMessage?chat_id=@fake_channel")
    );
    no_other_values(&disk.0, &disk.target(), token.as_bytes());
    for (command, input) in [
        (
            "secret set url fake-ref --replace",
            "http://example.com/FAKE_PATH?key=FAKE_QUERY".to_owned(),
        ),
        (
            "secret set url fake-ref --replace",
            "https://example.com/FAKE_PATH\nextra".to_owned(),
        ),
        (
            "secret set url fake-ref --replace",
            format!("https://example.com/{}", "x".repeat(4096)),
        ),
        (
            "secret set telegram fake-ref --replace",
            format!("{token}\nbad?FAKE_QUERY\n"),
        ),
        (
            "secret set telegram fake-ref --replace",
            "bad:FAKE_TOKEN\n@fake_channel\n".to_owned(),
        ),
        (
            "secret set url ../bad",
            "https://example.com/FAKE_PATH".to_owned(),
        ),
    ] {
        let (code, out, err) = disk.run(command, input.as_bytes());
        assert_eq!(code, 1);
        for forbidden in ["FAKE_PATH", "FAKE_QUERY", token, "bad:FAKE_TOKEN"] {
            assert!(!out.contains(forbidden) && !err.contains(forbidden));
        }
    }
}

#[test]
fn list_and_check_cover_both_kinds_and_unsafe_metadata() {
    let disk = Disk::new();
    let wg = SecretName::new(SecretKind::Wg, "fake-ref").unwrap();
    SecretFile::write_new(
        &disk.0.join("etc"),
        &wg,
        b"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
    )
    .unwrap();
    assert_eq!(
        disk.run("secret set url fake-ref", b"https://example.com/FAKE_PATH")
            .0,
        0
    );
    let (code, out, err) = disk.run("secret check fake-ref", b"");
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("wg fake-ref: ok length=44") && out.contains("url fake-ref: ok length="));
    fs::set_permissions(disk.target(), fs::Permissions::from_mode(0o644)).unwrap();
    assert!(disk.run("secret list", b"").1.contains("url fake-ref 0644"));
    assert_eq!(disk.run("secret check fake-ref", b"").0, 1);
    assert_eq!(
        disk.run(
            "secret set url fake-ref --replace",
            b"https://example.com/FAKE_NEW"
        )
        .0,
        1
    );
    fs::remove_file(disk.target()).unwrap();
    symlink(disk.0.join("victim"), disk.target()).unwrap();
    assert_eq!(
        disk.run(
            "secret set url fake-ref --replace",
            b"https://example.com/FAKE_NEW"
        )
        .0,
        1
    );
    assert!(!disk.0.join("victim").exists());
    assert_eq!(disk.run("secret check fake-ref", b"").0, 1);
}

#[test]
fn set_hints_use_only_head_and_list_preserves_historical_information() {
    let disk = Disk::new();
    let refs = "\n[alerts.sinks.fake-sink]\nkind = 'ntfy'\nmin_severity = 'warning'\nurl_ref = 'fake-ref'\n[heartbeat]\nkind = 'healthchecks'\nurl_ref = 'fake-ref'\n";
    disk.commit(None, refs);
    let (code, out, err) = disk.run("secret set url fake-ref", b"https://example.com/FAKE_PATH");
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("Next: scupper alerts test fake-sink"));
    assert!(out.contains("heartbeat uses this ref at the next interval"));
    assert!(
        disk.run("secret list", b"")
            .1
            .contains("url fake-ref 0600 referenced=true")
    );
    disk.commit(Some(1), "");
    let (code, out, err) = disk.run(
        "secret set url fake-ref --replace",
        b"https://example.com/FAKE_NEW",
    );
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("No current config references"));
    assert!(!out.contains("alerts test"));
    assert!(
        disk.run("secret list", b"")
            .1
            .contains("url fake-ref 0600 referenced=true")
    );
    let empty = Disk::new();
    assert!(
        empty
            .run("secret set url fake-ref", b"https://example.com/FAKE_PATH")
            .1
            .contains("No current config references this ref; use scupper config edit")
    );
}

#[test]
fn delivery_rejections_fail_set_write_and_check_without_values() {
    let disk = Disk::new();
    let name = SecretName::new(SecretKind::Url, "fake-ref").unwrap();
    let invalid = [
        "https://example.com:8443/FAKE_PATH".to_owned(),
        "https://[2001:db8::1]/FAKE_PATH".to_owned(),
        "https://example.com/FAKE_PATH#fragment".to_owned(),
        "https://example.com/FAKE_PATH/é".to_owned(),
        "https://example.com/FAKE_PATH?é".to_owned(),
        format!("https://example.com/{}", "x".repeat(2048)),
    ];
    for value in invalid {
        let (code, out, err) = disk.run("secret set url fake-ref --replace", value.as_bytes());
        assert_eq!(code, 1);
        assert!(!out.contains("ok") && !out.contains("FAKE_PATH") && !err.contains("FAKE_PATH"));
        assert!(SecretFile::write_url(&disk.0.join("etc"), &name, value.as_bytes(), true).is_err());
        // Simulate a credential installed by hand or an older binary.
        fs::write(disk.target(), value).unwrap();
        fs::set_permissions(disk.target(), fs::Permissions::from_mode(0o600)).unwrap();
        let (code, out, err) = disk.run("secret check fake-ref", b"");
        assert_eq!(code, 1);
        assert!(!out.contains("ok length") && !err.contains("FAKE_PATH"));
    }
    let token = format!("00000000:{}", "x".repeat(2048));
    assert_eq!(
        disk.run(
            "secret set telegram fake-ref --replace",
            format!("{token}\n@fake_channel\n").as_bytes()
        )
        .0,
        1
    );
}

#[test]
fn stray_entries_are_reported_and_only_stale_url_writer_temps_are_removed() {
    use std::time::{Duration, SystemTime};
    let disk = Disk::new();
    assert_eq!(
        disk.run("secret set url fake-ref", b"https://example.com/FAKE_PATH")
            .0,
        0
    );
    fs::create_dir(disk.0.join("etc/secrets/wg")).unwrap();
    fs::set_permissions(
        disk.0.join("etc/secrets/wg"),
        fs::Permissions::from_mode(0o700),
    )
    .unwrap();
    let old = SystemTime::now() - Duration::from_secs(60);
    for (kind, name) in [
        ("wg", ".scupper-1-0.tmp"),
        ("url", ".scupper-1-0.tmp"),
        ("url", ".scupper-other.tmp"),
        ("url", ".scupper-2-0.tmp"),
        ("url", "README"),
    ] {
        let file = fs::File::create(disk.0.join(format!("etc/secrets/{kind}/{name}"))).unwrap();
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .unwrap();
        file.set_modified(if name == ".scupper-2-0.tmp" {
            SystemTime::now() + Duration::from_secs(3600)
        } else {
            old
        })
        .unwrap();
    }
    symlink(
        disk.0.join("victim"),
        disk.0.join("etc/secrets/url/.scupper-3-0.tmp"),
    )
    .unwrap();
    let (code, out, err) = disk.run("secret list", b"");
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("stray entry; inspect and move it out"));
    assert!(out.contains(".scupper-1-0.tmp") && out.contains("README"));
    assert_eq!(disk.run("secret check fake-ref", b"").0, 0);
    assert_eq!(
        disk.run(
            "secret set url fake-ref --replace",
            b"https://example.com/FAKE_NEW"
        )
        .0,
        0
    );
    assert!(!disk.0.join("etc/secrets/url/.scupper-1-0.tmp").exists());
    for path in [
        "wg/.scupper-1-0.tmp",
        "url/.scupper-other.tmp",
        "url/.scupper-2-0.tmp",
        "url/README",
        "url/.scupper-3-0.tmp",
    ] {
        assert!(fs::symlink_metadata(disk.0.join("etc/secrets").join(path)).is_ok());
    }
}

fn invalidate_version(disk: &Disk, version: u64) {
    use sha2::{Digest, Sha256};
    let dir = disk.0.join("state/config/versions");
    let text = "not valid config";
    fs::write(dir.join(format!("{version:06}.toml")), text).unwrap();
    let path = dir.join(format!("{version:06}.meta.json"));
    let mut meta: serde_json::Value = serde_json::from_slice(&fs::read(&path).unwrap()).unwrap();
    meta["sha256"] = format!("{:x}", Sha256::digest(text)).into();
    fs::write(path, serde_json::to_vec(&meta).unwrap()).unwrap();
}

#[test]
fn bad_old_config_never_blocks_set_and_bad_head_only_loses_hint() {
    let disk = Disk::new();
    disk.commit(None, "");
    disk.commit(
        Some(1),
        "\n[heartbeat]\nkind = 'healthchecks'\nurl_ref = 'fake-ref'\n",
    );
    invalidate_version(&disk, 1);
    let (code, out, err) = disk.run("secret set url fake-ref", b"https://example.com/FAKE_PATH");
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("heartbeat uses this ref"));
    let (code, out, err) = disk.run("secret list", b"");
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("referenced=?"));
    invalidate_version(&disk, 2);
    let (code, out, err) = disk.run(
        "secret set url fake-ref --replace",
        b"https://example.com/FAKE_NEW",
    );
    assert_eq!(code, 0, "{out} {err}");
    assert!(out.contains("next-step hint unavailable"));
    assert_eq!(
        fs::read(disk.target()).unwrap(),
        b"https://example.com/FAKE_NEW"
    );
}

#[test]
fn writer_lock_is_free_during_input_and_destination_is_rechecked() {
    for change in ["none", "created", "unsafe", "replace"] {
        let disk = Disk::new();
        let replace = change == "replace";
        if replace {
            assert_eq!(
                disk.run("secret set url fake-ref", b"https://example.com/FAKE_OLD")
                    .0,
                0
            );
        }
        let mut child = disk.spawn(if replace {
            "secret set url fake-ref --replace"
        } else {
            "secret set url fake-ref"
        });
        let mut stderr = child.stderr.take().unwrap();
        let mut notice = vec![0; STDIN_NOTICE.len()];
        read_bounded(&mut stderr, &mut notice);
        assert_eq!(notice, STDIN_NOTICE.as_bytes());
        assert!(child.try_wait().unwrap().is_none());
        // The child has passed its prechecks and is blocked on our open pipe.
        // A separate descriptor must acquire the global lock immediately.
        let writer = WriterLock::try_acquire(disk.0.join("run")).unwrap();
        if change == "created" {
            let name = SecretName::new(SecretKind::Url, "fake-ref").unwrap();
            SecretFile::write_url(
                &disk.0.join("etc"),
                &name,
                b"https://example.com/FAKE_OTHER",
                false,
            )
            .unwrap();
        } else if change == "unsafe" || replace {
            if replace {
                fs::remove_file(disk.target()).unwrap();
            }
            symlink("missing", disk.target()).unwrap();
        }
        let mut stdin = child.stdin.take().unwrap();
        stdin.write_all(b"https://example.com/FAKE_NEW\n").unwrap();
        drop(stdin);
        drop(writer);
        assert_eq!(
            wait_bounded(&mut child).code(),
            Some(i32::from(change != "none"))
        );
        let output = child.wait_with_output().unwrap();
        let mut error = String::new();
        std::io::Read::read_to_string(&mut stderr, &mut error).unwrap();
        assert!(!error.contains("FAKE_"));
        if change == "created" {
            assert!(error.contains("use --replace"));
            assert_eq!(
                fs::read(disk.target()).unwrap(),
                b"https://example.com/FAKE_OTHER"
            );
        } else if change == "none" {
            assert!(output.status.success());
            assert_eq!(
                fs::read(disk.target()).unwrap(),
                b"https://example.com/FAKE_NEW"
            );
        } else {
            assert!(
                fs::symlink_metadata(disk.target())
                    .unwrap()
                    .file_type()
                    .is_symlink()
            );
        }
    }
}

#[test]
fn writer_reacquisition_times_out_after_input() {
    let disk = Disk::new();
    let mut child = disk.spawn("secret set url fake-ref");
    let mut stderr = child.stderr.take().unwrap();
    let mut notice = vec![0; STDIN_NOTICE.len()];
    read_bounded(&mut stderr, &mut notice);
    assert_eq!(notice, STDIN_NOTICE.as_bytes());
    let _writer = WriterLock::try_acquire(disk.0.join("run")).unwrap();
    let started = std::time::Instant::now();
    child
        .stdin
        .take()
        .unwrap()
        .write_all(b"https://example.com/FAKE_NEW\n")
        .unwrap();
    let status = wait_bounded_for(&mut child, std::time::Duration::from_secs(7));
    assert_eq!(status.code(), Some(1));
    assert!(started.elapsed() >= std::time::Duration::from_secs(5));
    assert!(!disk.target().exists());
    let mut error = String::new();
    std::io::Read::read_to_string(&mut stderr, &mut error).unwrap();
    assert!(error.contains("secret writer lock unavailable"));
    assert!(!error.contains("FAKE_"));
}

#[test]
fn stored_target_boundary_allows_every_delivery_suffix() {
    let disk = Disk::new();
    let name = SecretName::new(SecretKind::Url, "fake-ref").unwrap();
    let limit = scupper_sys::probe::MAX_TARGET_BYTES - scupper_sys::heartbeat::MAX_SUFFIX_BYTES;
    for query in ["", "?fake=query"] {
        let value = format!(
            "https://example.com/{}{query}",
            "x".repeat(limit - 1 - query.len())
        );
        let (code, out, err) = disk.run("secret set url fake-ref --replace", value.as_bytes());
        assert_eq!(code, 0, "{out} {err}");
        assert_eq!(disk.run("secret check fake-ref", b"").0, 0);
        for suffix in ["", "/0", "/1", "/2", "/3", "/4"] {
            let resolved = scupper_sys::heartbeat::resolve(
                &disk.0.join("etc"),
                &name,
                suffix,
                rustix::process::geteuid().as_raw(),
            )
            .unwrap();
            assert!(scupper_sys::probe_child::Url::new(resolved.expose()).is_ok());
        }
        let oversized = format!("{value}x");
        assert_eq!(
            disk.run("secret set url fake-ref --replace", oversized.as_bytes())
                .0,
            1
        );
        assert!(
            SecretFile::write_url(&disk.0.join("etc"), &name, oversized.as_bytes(), true).is_err()
        );
        fs::write(disk.target(), oversized).unwrap();
        assert_eq!(disk.run("secret check fake-ref", b"").0, 1);
    }
}

#[test]
fn prechecks_fail_without_reading_stdin_and_backend_check_is_explicit() {
    let disk = Disk::new();
    assert_eq!(
        disk.run("secret set url fake-ref", b"https://example.com/FAKE_PATH")
            .0,
        0
    );
    for command in [
        "secret set url fake-ref",
        "secret set url ../bad",
        "secret check pass://fake/path",
        "secret check op:fake",
    ] {
        let mut child = disk.spawn(command);
        // Keep stdin open: any attempt to read would block until this deadline.
        let status = wait_bounded(&mut child);
        assert_eq!(status.code(), Some(1));
        let output = child.wait_with_output().unwrap();
        let err = String::from_utf8(output.stderr).unwrap();
        assert!(!err.contains(STDIN_NOTICE));
        if command.contains("check") {
            assert!(err.contains("operator-side secret lookup is not implemented in M2"));
            assert!(!err.contains("fake/path"));
        }
    }
}

fn wait_bounded(child: &mut std::process::Child) -> std::process::ExitStatus {
    wait_bounded_for(child, std::time::Duration::from_secs(5))
}

fn wait_bounded_for(
    child: &mut std::process::Child,
    limit: std::time::Duration,
) -> std::process::ExitStatus {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            assert!(
                std::time::Instant::now() < deadline,
                "secret child exceeded its deadline"
            );
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

fn read_bounded(reader: &mut (impl std::io::Read + std::os::fd::AsFd), buffer: &mut [u8]) {
    use rustix::event::{PollFd, PollFlags, Timespec, poll};
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    let mut offset = 0;
    while offset < buffer.len() {
        let remaining = deadline.saturating_duration_since(std::time::Instant::now());
        let timeout = Timespec::try_from(remaining).unwrap();
        assert_ne!(
            poll(&mut [PollFd::new(&*reader, PollFlags::IN)], Some(&timeout)).unwrap(),
            0,
            "terminal read timed out"
        );
        let n = reader.read(&mut buffer[offset..]).unwrap();
        assert_ne!(n, 0, "terminal closed before prompt");
        offset += n;
    }
}

#[test]
fn production_cli_is_root_only_before_reading_input() {
    if rustix::process::geteuid().is_root() {
        return;
    }
    for args in [
        vec!["secret", "set", "url", "fake-ref"],
        vec!["secret", "list"],
        vec!["secret", "check", "fake-ref"],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_scupper"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert!(
            String::from_utf8(output.stderr)
                .unwrap()
                .contains("must run as root")
        );
    }
}

#[test]
fn unsafe_parent_directories_and_special_destinations_fail_closed() {
    for part in ["etc", "etc/secrets", "etc/secrets/url"] {
        let disk = Disk::new();
        assert_eq!(
            disk.run("secret set url fake-ref", b"https://example.com/FAKE_OLD")
                .0,
            0
        );
        let path = disk.0.join(part);
        let original = fs::metadata(&path).unwrap().permissions();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
        assert_eq!(
            disk.run(
                "secret set url fake-ref --replace",
                b"https://example.com/FAKE_NEW"
            )
            .0,
            1
        );
        assert_eq!(disk.run("secret check fake-ref", b"").0, 1);
        assert_eq!(disk.run("secret list", b"").0, 1);
        fs::set_permissions(&path, original).unwrap();
        assert_eq!(
            fs::read(disk.target()).unwrap(),
            b"https://example.com/FAKE_OLD"
        );
        let saved = disk.0.join("saved");
        fs::rename(&path, &saved).unwrap();
        symlink(&saved, &path).unwrap();
        assert_eq!(
            disk.run(
                "secret set url fake-ref --replace",
                b"https://example.com/FAKE_NEW"
            )
            .0,
            1
        );
        assert_eq!(disk.run("secret check fake-ref", b"").0, 1);
        assert_eq!(disk.run("secret list", b"").0, 1);
        fs::remove_file(&path).unwrap();
        fs::rename(saved, path).unwrap();
    }
    let disk = Disk::new();
    assert_eq!(
        disk.run("secret set url fake-ref", b"https://example.com/FAKE_OLD")
            .0,
        0
    );
    fs::remove_file(disk.target()).unwrap();
    rustix::fs::mknodat(
        rustix::fs::CWD,
        disk.target(),
        rustix::fs::FileType::Fifo,
        rustix::fs::Mode::from_raw_mode(0o600),
        0,
    )
    .unwrap();
    assert_eq!(
        disk.run(
            "secret set url fake-ref --replace",
            b"https://example.com/FAKE_NEW"
        )
        .0,
        1
    );
    assert_eq!(disk.run("secret check fake-ref", b"").0, 1);
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(32))]
    #[test]
    fn cli_output_is_exactly_the_allowed_confirmation_or_fixed_error(input in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..5000), telegram in proptest::prelude::any::<bool>()) {
        let disk = Disk::new();
        let expected = scupper_sys::secrets::input::read_stdin(&mut input.as_slice(), telegram);
        let command = if telegram { "secret set telegram fake-ref" } else { "secret set url fake-ref" };
        let (code, out, err) = disk.run(command, &input);
        let harness = "\nrunning 1 test\n";
        match expected {
            Ok(value) => {
                proptest::prop_assert_eq!(code, 0);
                proptest::prop_assert_eq!(err, STDIN_NOTICE);
                proptest::prop_assert_eq!(out, format!("{harness}fake-ref: {}\nNo current config references this ref; use scupper config edit.\n", value.confirmation()));
            }
            Err(error) => {
                proptest::prop_assert_eq!(code, 1);
                proptest::prop_assert_eq!(out, harness);
                proptest::prop_assert_eq!(err, format!("{STDIN_NOTICE}scupper: {error}\n"));
            }
        }
    }
}

fn spawn_tty(disk: &Disk, slave: &fs::File, ignored: Option<i32>) -> std::process::Child {
    let mut command = if let Some(number) = ignored {
        let mut shell = Command::new("sh");
        shell
            .args(["-c", "trap '' \"$1\"; shift; exec \"$@\"", "secret-test"])
            .arg(number.to_string())
            .arg(std::env::current_exe().unwrap());
        shell
    } else {
        Command::new(std::env::current_exe().unwrap())
    };
    command
        .args(["--exact", "secret_child", "--nocapture", "--quiet"])
        .env_clear()
        .env("SCUPPER_SECRET_TEST_ROOT", &disk.0)
        .env(
            "SCUPPER_SECRET_TEST_COMMAND",
            "secret set telegram fake-ref",
        )
        .stdin(slave.try_clone().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap()
}

fn send_ignored_signal(child: &std::process::Child, number: i32) {
    let status = fs::read_to_string(format!("/proc/{}/status", child.id())).unwrap();
    let mask = status
        .lines()
        .find_map(|line| line.strip_prefix("SigIgn:"))
        .unwrap();
    let mask = u64::from_str_radix(mask.trim(), 16).unwrap();
    assert_ne!(mask & (1_u64 << (number - 1)), 0);
    let signal = match number {
        1 => rustix::process::Signal::HUP,
        2 => rustix::process::Signal::INT,
        _ => rustix::process::Signal::TERM,
    };
    rustix::process::kill_process(
        rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap(),
        signal,
    )
    .unwrap();
}

#[test]
fn tty_hides_token_shows_chat_and_restores_echo_on_cancel_and_signals() {
    use rustix::{
        pty::{OpenptFlags, grantpt, ioctl_tiocgptpeer, openpt, unlockpt},
        termios::{LocalModes, tcgetattr},
    };
    use std::{io::Read, os::unix::process::ExitStatusExt};
    for (interruption, ignored) in [
        (0, false),
        (3, false),
        (1, false),
        (2, false),
        (15, false),
        (1, true),
        (2, true),
        (15, true),
    ] {
        let cancel = interruption != 0 && !ignored;
        let disk = Disk::new();
        let master =
            openpt(OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC).unwrap();
        grantpt(&master).unwrap();
        unlockpt(&master).unwrap();
        let slave = std::fs::File::from(
            ioctl_tiocgptpeer(
                &master,
                OpenptFlags::RDWR | OpenptFlags::NOCTTY | OpenptFlags::CLOEXEC,
            )
            .unwrap(),
        );
        let original = tcgetattr(&slave).unwrap();
        let mut child = spawn_tty(&disk, &slave, ignored.then_some(interruption));
        let mut stderr = child.stderr.take().unwrap();
        let mut prompt = [0; 11];
        read_bounded(&mut stderr, &mut prompt);
        assert_eq!(&prompt, b"Bot token: ");
        assert!(
            !tcgetattr(&slave)
                .unwrap()
                .local_modes
                .contains(LocalModes::ECHO)
        );
        let mut terminal = std::fs::File::from(master);
        if ignored {
            send_ignored_signal(&child, interruption);
        }
        if interruption == 3 {
            terminal.write_all(b"FAKE_PARTIAL_TOKEN\x03").unwrap();
        } else if cancel {
            terminal.write_all(b"FAKE_PARTIAL_TOKEN").unwrap();
            let signal = match interruption {
                1 => rustix::process::Signal::HUP,
                2 => rustix::process::Signal::INT,
                _ => rustix::process::Signal::TERM,
            };
            rustix::process::kill_process(
                rustix::process::Pid::from_raw(i32::try_from(child.id()).unwrap()).unwrap(),
                signal,
            )
            .unwrap();
        } else {
            terminal
                .write_all(b"00000000:FAKE_TOKEN_for_tests_only_00000000000\n")
                .unwrap();
            let mut prompt = [0; 10];
            read_bounded(&mut stderr, &mut prompt);
            assert_eq!(&prompt, b"\nChat id: ");
            assert!(
                tcgetattr(&slave)
                    .unwrap()
                    .local_modes
                    .contains(LocalModes::ECHO)
            );
            terminal.write_all(b"@fake_channel\n").unwrap();
        }
        wait_bounded(&mut child);
        let output = child.wait_with_output().unwrap();
        if cancel && interruption != 3 {
            assert_eq!(output.status.signal(), Some(interruption));
        } else {
            assert_eq!(output.status.code(), Some(i32::from(cancel)));
        }
        let final_settings = tcgetattr(&slave).unwrap();
        assert_eq!(final_settings.local_modes, original.local_modes);
        let mut error = String::new();
        stderr.read_to_string(&mut error).unwrap();
        assert!(!error.contains("FAKE_"));
        if interruption == 3 {
            assert!(error.contains("cancelled"));
        } else if !cancel {
            let mut echo = [0; 15];
            read_bounded(&mut terminal, &mut echo);
            assert_eq!(&echo, b"@fake_channel\r\n");
            assert!(
                String::from_utf8(output.stdout)
                    .unwrap()
                    .contains("telegram bot 0000… chat @fake_channel")
            );
        }
    }
}

#[test]
fn mistaken_credential_arguments_are_refused_without_echoing_them() {
    for args in [
        vec![
            "secret",
            "set",
            "url",
            "fake-ref",
            "https://example.com/FAKE_PATH?key=FAKE_QUERY",
        ],
        vec![
            "secret",
            "set",
            "telegram",
            "fake-ref",
            "00000000:FAKE_TOKEN_for_tests_only_00000000000",
        ],
        vec![
            "secret",
            "set",
            "https://example.com/FAKE_PATH?key=FAKE_QUERY",
        ],
    ] {
        let output = Command::new(env!("CARGO_BIN_EXE_scupper"))
            .args(args)
            .stdin(Stdio::null())
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(output.stdout, b"");
        assert_eq!(
            output.stderr,
            b"scupper: invalid secret command; run scupper secret --help\n"
        );
    }
}
