//! Unprivileged filesystem, interruption, confinement, and writer-lock tests.
#![allow(clippy::unwrap_used)] // Fixture failures must fail the test.

use rustix::fs::{CWD, Mode, mkfifoat};
use scupper_core::config::{ExitId, SecretKind, SecretName, parse_site};
use scupper_sys::{
    apply::DurableStep,
    lock::{WriterGuard, WriterLock},
    secrets::{SecretError, SecretFile},
    state::{Quarantine, Selection, State, StateFile, StateRead},
    store::{CommitStep, MetaInput, MirrorStatus, StoreError, VersionStore},
};
use std::{
    cell::Cell,
    fs::{self, OpenOptions},
    io,
    os::unix::fs::{OpenOptionsExt, PermissionsExt, symlink},
    path::{Path, PathBuf},
    process::Command,
    sync::{
        Arc, Barrier,
        atomic::{AtomicU64, Ordering},
    },
};

const SITE: &str = include_str!("../../scupper-core/tests/fixtures/site-m2.toml");
const KEY: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const MARKER: &str = "private-content-marker";
const DURABLE_STEPS: [DurableStep; 6] = [
    DurableStep::Created,
    DurableStep::Written,
    DurableStep::ContentSynced,
    DurableStep::FileSynced,
    DurableStep::Renamed,
    DurableStep::DirectorySynced,
];
fn commit_steps() -> Vec<CommitStep> {
    let mut steps = vec![
        CommitStep::VersionCreated,
        CommitStep::VersionWritten,
        CommitStep::VersionSynced,
        CommitStep::VersionDirectorySynced,
        CommitStep::MetaCreated,
        CommitStep::MetaWritten,
        CommitStep::MetaSynced,
        CommitStep::MetaDirectorySynced,
    ];
    steps.extend(DURABLE_STEPS.map(CommitStep::Head));
    steps.extend(DURABLE_STEPS.map(CommitStep::Mirror));
    steps
}

struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        // All new test artifacts stay inside the current worktree.
        let parent = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/persistence-tests");
        fs::create_dir_all(&parent).unwrap();
        loop {
            let path = parent.join(format!(
                "{}-{}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let result = fs::create_dir(&path);
            if result
                .as_ref()
                .is_err_and(|error| error.kind() == io::ErrorKind::AlreadyExists)
            {
                continue;
            }
            result.unwrap();
            return Self(path);
        }
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn writer(root: &Path) -> WriterGuard {
    WriterLock::acquire(root.join("run")).unwrap()
}
fn meta(reason: &str) -> MetaInput {
    MetaInput {
        actor: "operator".into(),
        at: 1_700_000_000,
        reason: reason.into(),
    }
}
fn changed_site() -> String {
    SITE.replace("name = \"home\"", "name = \"new-home\"")
}
fn closed_state() -> State {
    State {
        applied_version: Some(43),
        selection: Selection::Disconnected,
        quarantine: Some(Quarantine {
            reason: "repair budget exhausted".into(),
            object: "ex-ch1".into(),
            since_unix: 1_700_000_001,
        }),
        ..State::default()
    }
}
fn mode(path: impl AsRef<Path>) -> u32 {
    fs::metadata(path).unwrap().permissions().mode() & 0o7777
}
fn set_mode(path: impl AsRef<Path>, mode: u32) {
    fs::set_permissions(path, fs::Permissions::from_mode(mode)).unwrap();
}

#[test]
fn store_commit_cas_history_rollback_and_rendered() {
    let dir = TempDir::new();
    let etc = dir.0.join("etc");
    let store = VersionStore::open_with_mirror_root(dir.0.join("lib"), &etc, None).unwrap();
    assert_eq!(store.head().unwrap(), None);
    assert_eq!(store.history().unwrap().len(), 0);
    assert!(matches!(store.read(0), Err(StoreError::NotCommitted(0))));
    assert_eq!(
        store
            .commit(&writer(&dir.0), None, SITE, meta("initial"))
            .unwrap(),
        1
    );
    let first = store.read(1).unwrap();
    assert_eq!(first.0, SITE);
    assert_eq!(first.1.parent, None);
    assert_eq!(first.1.actor, "operator");
    assert_eq!(first.1.at, 1_700_000_000);
    assert_eq!(first.1.reason, "initial");
    assert_eq!(first.1.sha256.len(), 64);
    assert!(matches!(
        store.commit(&writer(&dir.0), None, SITE, meta("stale")),
        Err(StoreError::Conflict { head: Some(1) })
    ));
    assert_eq!(
        store
            .commit(&writer(&dir.0), Some(1), &changed_site(), meta("edit"))
            .unwrap(),
        2
    );
    assert_eq!(store.rollback(&writer(&dir.0), 1, meta("undo")).unwrap(), 3);
    assert_eq!(store.head().unwrap(), Some(3));
    assert_eq!(store.read(3).unwrap().0, SITE);
    assert_eq!(store.read(2).unwrap().0, changed_site());
    let history = store.history().unwrap();
    assert_eq!(
        history.iter().map(|m| m.parent).collect::<Vec<_>>(),
        [None, Some(1), Some(2)]
    );
    assert_eq!(history[0].sha256, history[2].sha256);
    assert_ne!(history[0].sha256, history[1].sha256);
    assert_eq!(mode(dir.0.join("lib/config/versions/000001.toml")), 0o640);
    assert_eq!(
        mode(dir.0.join("lib/config/versions/000001.meta.json")),
        0o640
    );
    assert_eq!(mode(etc.join("scupper.toml")), 0o444);
    store
        .write_rendered(&writer(&dir.0), 3, "table inet scupper {}\n")
        .unwrap();
    assert_eq!(
        fs::read_to_string(dir.0.join("lib/rendered/000003.nft")).unwrap(),
        "table inet scupper {}\n"
    );
    assert!(matches!(
        store.write_rendered(&writer(&dir.0), 4, "no"),
        Err(StoreError::NotCommitted(4))
    ));
    assert_eq!(
        VersionStore::open_with_mirror_root(dir.0.join("lib"), &etc, None)
            .unwrap()
            .head()
            .unwrap(),
        Some(3)
    );
}

#[test]
fn invalid_configuration_writes_nothing_and_error_is_value_free() {
    let dir = TempDir::new();
    let store = VersionStore::open(&dir.0, None).unwrap();
    let before = fs::read_dir(dir.0.join("config")).unwrap().count();
    for invalid in [
        MARKER.to_owned(),
        SITE.replace("schema = 1", "schema = 2"),
        SITE.replace("exits = [\"ch1\"]", "exits = []"),
    ] {
        let error = store
            .commit(&writer(&dir.0), None, &invalid, meta("bad"))
            .unwrap_err();
        assert!(matches!(error, StoreError::InvalidConfig));
        assert!(!error.to_string().contains(MARKER));
        assert_eq!(store.head().unwrap(), None);
        assert_eq!(
            fs::read_dir(dir.0.join("config/versions")).unwrap().count(),
            0
        );
        assert_eq!(fs::read_dir(dir.0.join("config")).unwrap().count(), before);
        assert!(!dir.0.join("scupper.toml").exists());
    }
}

#[test]
fn concurrent_store_handles_have_one_cas_winner() {
    let dir = TempDir::new();
    let barrier = Arc::new(Barrier::new(2));
    let threads = (0..2)
        .map(|_| {
            let root = dir.0.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let store = VersionStore::open(&root, None).unwrap();
                barrier.wait();
                store.commit(&writer(&root), None, SITE, meta("race"))
            })
        })
        .collect::<Vec<_>>();
    let results = threads
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|r| matches!(r, Err(StoreError::Conflict { head: Some(1) })))
            .count(),
        1
    );
    assert_eq!(
        VersionStore::open(&dir.0, None)
            .unwrap()
            .history()
            .unwrap()
            .len(),
        1
    );
}

#[test]
fn mirror_detects_changes_and_missing_file() {
    let dir = TempDir::new();
    let store = VersionStore::open(&dir.0, None).unwrap();
    assert_eq!(store.mirror_status().unwrap(), MirrorStatus::Missing);
    store
        .commit(&writer(&dir.0), None, SITE, meta("initial"))
        .unwrap();
    assert_eq!(store.mirror_status().unwrap(), MirrorStatus::InSync);
    let path = dir.0.join("scupper.toml");
    set_mode(&path, 0o600);
    fs::write(&path, MARKER).unwrap();
    assert_eq!(store.mirror_status().unwrap(), MirrorStatus::HandEdited);
    assert_eq!(store.read(1).unwrap().0, SITE);
    let recovered = VersionStore::open(&dir.0, Some(&writer(&dir.0))).unwrap();
    assert_eq!(recovered.mirror_status().unwrap(), MirrorStatus::HandEdited);
    assert_eq!(fs::read_to_string(&path).unwrap(), MARKER);
    store.refresh_mirror(&writer(&dir.0)).unwrap();
    assert_eq!(store.mirror_status().unwrap(), MirrorStatus::InSync);
    fs::remove_file(&path).unwrap();
    assert_eq!(
        store.mirror_status().unwrap(),
        MirrorStatus::Stale {
            mirror_matches: None
        }
    );
    fs::write(&path, [0xff]).unwrap();
    assert_eq!(store.mirror_status().unwrap(), MirrorStatus::HandEdited);
}

#[test]
fn store_refuses_corrupt_head_metadata_and_content() {
    for artifact in ["head", "versions/000001.toml", "versions/000001.meta.json"] {
        let dir = TempDir::new();
        let store = VersionStore::open(&dir.0, None).unwrap();
        store
            .commit(&writer(&dir.0), None, SITE, meta("initial"))
            .unwrap();
        fs::write(dir.0.join("config").join(artifact), MARKER).unwrap();
        let error = VersionStore::open(&dir.0, None).unwrap_err();
        assert!(!error.to_string().contains(MARKER));
    }
}

fn run_crash_child(root: &Path, kind: &str, index: usize) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "crash_child"])
        .env("SCUPPER_PERSISTENCE_TEST_ROOT", root)
        .env("SCUPPER_PERSISTENCE_TEST_KIND", kind)
        .env("SCUPPER_PERSISTENCE_TEST_STEP", index.to_string())
        .output()
        .unwrap();
    assert_eq!(
        output.status.code(),
        Some(73),
        "child did not reach injected crash: {output:?}"
    );
}

#[test]
fn crash_child() {
    let Some(root) = std::env::var_os("SCUPPER_PERSISTENCE_TEST_ROOT") else {
        return;
    };
    let root = PathBuf::from(root);
    let index: usize = std::env::var("SCUPPER_PERSISTENCE_TEST_STEP")
        .unwrap()
        .parse()
        .unwrap();
    match std::env::var("SCUPPER_PERSISTENCE_TEST_KIND")
        .unwrap()
        .as_str()
    {
        "store" => {
            let store = VersionStore::open(&root, None).unwrap();
            store
                .commit_with_hook(
                    &writer(&root),
                    store.head().unwrap(),
                    &changed_site(),
                    meta("interrupted"),
                    &|step| {
                        if step == commit_steps()[index] {
                            std::process::exit(73);
                        }
                        Ok(())
                    },
                )
                .unwrap();
        }
        "state" => {
            StateFile::open(&root, None)
                .unwrap()
                .write_with_hook(&writer(&root), &closed_state(), &|step| {
                    if step == DURABLE_STEPS[index] {
                        std::process::exit(73);
                    }
                    Ok(())
                })
                .unwrap();
        }
        mode => assert_eq!(mode, "store or state", "unknown crash mode"),
    }
}

#[test]
fn every_store_interruption_keeps_old_or_complete_new_head_and_allows_retry() {
    for (index, step) in commit_steps().into_iter().enumerate() {
        let dir = TempDir::new();
        VersionStore::open(&dir.0, None)
            .unwrap()
            .commit(&writer(&dir.0), None, SITE, meta("initial"))
            .unwrap();
        run_crash_child(&dir.0, "store", index);
        let reopened = VersionStore::open(&dir.0, None).unwrap();
        if matches!(
            step,
            CommitStep::Head(DurableStep::Renamed | DurableStep::DirectorySynced)
                | CommitStep::Mirror(_)
        ) {
            assert_eq!(reopened.head().unwrap(), Some(2), "{step:?}");
            assert_eq!(reopened.read(2).unwrap().0, changed_site());
            assert_eq!(reopened.history().unwrap().len(), 2);
            assert_eq!(reopened.interrupted_versions(), [] as [u64; 0]);
            assert_eq!(
                reopened.mirror_status().unwrap(),
                if matches!(
                    step,
                    CommitStep::Mirror(DurableStep::Renamed | DurableStep::DirectorySynced)
                ) {
                    MirrorStatus::InSync
                } else {
                    MirrorStatus::Stale {
                        mirror_matches: Some(1),
                    }
                }
            );
            let recovered = VersionStore::open(&dir.0, Some(&writer(&dir.0))).unwrap();
            assert_eq!(recovered.mirror_status().unwrap(), MirrorStatus::InSync);
        } else {
            assert_eq!(reopened.head().unwrap(), Some(1), "{step:?}");
            assert_eq!(reopened.read(1).unwrap().0, SITE);
            assert_eq!(reopened.interrupted_versions(), [2]);
            assert_eq!(reopened.history().unwrap().len(), 1);
            assert!(matches!(reopened.read(2), Err(StoreError::NotCommitted(2))));
            assert_eq!(
                reopened
                    .commit(&writer(&dir.0), Some(1), SITE, meta("retry"))
                    .unwrap(),
                2
            );
            assert!(dir.0.join("config/interrupted").exists());
        }
        assert_eq!(reopened.mirror_status().unwrap(), MirrorStatus::InSync);
    }
}

#[test]
fn store_hook_observes_the_documented_durability_order() {
    let dir = TempDir::new();
    let seen = std::cell::RefCell::new(Vec::new());
    VersionStore::open(&dir.0, None)
        .unwrap()
        .commit_with_hook(&writer(&dir.0), None, SITE, meta("initial"), &|step| {
            seen.borrow_mut().push(step);
            Ok(())
        })
        .unwrap();
    assert_eq!(*seen.borrow(), commit_steps());
}

#[test]
fn state_round_trip_and_fail_closed_reads() {
    let dir = TempDir::new();
    let file = StateFile::open(&dir.0, None).unwrap();
    assert_eq!(file.read().unwrap(), StateRead::Missing);
    for selection in [
        Selection::Auto,
        Selection::Prefer(ExitId("ch1".into())),
        Selection::Pin(ExitId("ch1".into())),
        Selection::Disconnected,
    ] {
        let state = State {
            selection,
            ..closed_state()
        };
        file.write(&writer(&dir.0), &state).unwrap();
        assert_eq!(file.read().unwrap(), StateRead::Present(state));
    }
    assert_eq!(mode(dir.0.join("state.json")), 0o600);
    for invalid in [
        "not JSON".into(),
        "{}".into(),
        "{\"schema\":1,\"selection\":\"Auto\",\"quarantine\":null}".into(),
        "{\"schema\":1,\"selection\":\"Auto\",\"applied_version\":null}".into(),
        serde_json::to_string(&closed_state())
            .unwrap()
            .replace("\"schema\":1", "\"schema\":2"),
        serde_json::to_string(&closed_state())
            .unwrap()
            .replace("\"schema\":1", "\"schema\":1,\"unexpected\":true"),
        serde_json::to_string(&closed_state())
            .unwrap()
            .replace("\"object\":", "\"unexpected\":true,\"object\":"),
        serde_json::to_string(&closed_state())
            .unwrap()
            .replace("\"schema\":1", "\"schema\":1,\"schema\":1"),
    ] {
        fs::write(dir.0.join("state.json"), invalid).unwrap();
        assert!(file.read().is_err());
    }
    file.write(&writer(&dir.0), &closed_state()).unwrap();
    assert!(
        file.write(
            &writer(&dir.0),
            &State {
                schema: 2,
                ..State::default()
            }
        )
        .is_err()
    );
    assert_eq!(file.read().unwrap(), StateRead::Present(closed_state()));
}

#[test]
fn every_state_interruption_preserves_a_complete_old_or_new_state() {
    for (index, step) in DURABLE_STEPS.into_iter().enumerate() {
        let dir = TempDir::new();
        let file = StateFile::open(&dir.0, None).unwrap();
        file.write(&writer(&dir.0), &State::default()).unwrap();
        run_crash_child(&dir.0, "state", index);
        let expected = if matches!(step, DurableStep::Renamed | DurableStep::DirectorySynced) {
            closed_state()
        } else {
            State::default()
        };
        assert_eq!(
            file.read().unwrap(),
            StateRead::Present(expected),
            "{step:?}"
        );
    }
}

#[test]
fn returned_write_failures_leave_state_atomic_and_clean_temporary_files() {
    for fail in DURABLE_STEPS {
        let dir = TempDir::new();
        let file = StateFile::open(&dir.0, None).unwrap();
        file.write(&writer(&dir.0), &closed_state()).unwrap();
        let seen = Cell::new(false);
        assert!(
            file.write_with_hook(&writer(&dir.0), &State::default(), &|step| {
                if step == fail {
                    seen.set(true);
                    Err(io::Error::other("injected"))
                } else {
                    Ok(())
                }
            })
            .is_err()
        );
        assert!(seen.get());
        let new = matches!(fail, DurableStep::Renamed | DurableStep::DirectorySynced);
        assert_eq!(
            file.read().unwrap(),
            StateRead::Present(if new {
                State::default()
            } else {
                closed_state()
            })
        );
        assert_eq!(fs::read_dir(&dir.0).unwrap().count(), 2);
    }
}

struct SecretFixture {
    dir: TempDir,
    uid: u32,
}
impl SecretFixture {
    fn new() -> Self {
        let dir = TempDir::new();
        for path in ["secrets", "secrets/wg", "secrets/url"] {
            fs::create_dir(dir.0.join(path)).unwrap();
            set_mode(dir.0.join(path), 0o700);
        }
        Self {
            dir,
            uid: rustix::process::geteuid().as_raw(),
        }
    }
    fn put(&self, kind: &str, content: &[u8]) -> PathBuf {
        let path = self.dir.0.join(format!("secrets/{kind}/test"));
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        std::io::Write::write_all(&mut file, content).unwrap();
        set_mode(&path, 0o600);
        path
    }
    fn name(kind: SecretKind) -> SecretName {
        SecretName::new(kind, "test").unwrap()
    }
    fn open(&self, kind: SecretKind) -> Result<scupper_sys::secrets::Secret, SecretError> {
        SecretFile::open_with_owner(&self.dir.0, &Self::name(kind), self.uid)
    }
    fn refused(&self, kind: SecretKind, check: &str, content: &str) {
        let error = self.open(kind).err().unwrap();
        let diagnostic = error.to_string();
        assert!(diagnostic.contains("test"));
        assert!(diagnostic.contains(check), "{diagnostic}");
        assert!(!diagnostic.contains(content));
        assert!(!format!("{error:?}").contains(content));
    }
}

#[test]
fn valid_secrets_preserve_bytes_and_kind() {
    for content in [KEY.to_owned(), format!("{KEY}\n")] {
        let fixture = SecretFixture::new();
        fixture.put("wg", content.as_bytes());
        assert_eq!(
            fixture.open(SecretKind::Wg).ok().unwrap().expose(),
            content.as_bytes()
        );
    }
    let fixture = SecretFixture::new();
    let content = format!("https://example.net/{MARKER}");
    fixture.put("url", content.as_bytes());
    assert_eq!(
        fixture.open(SecretKind::Url).ok().unwrap().expose(),
        content.as_bytes()
    );
    if fixture.uid != 0 {
        assert!(SecretFile::open(&fixture.dir.0, &SecretFixture::name(SecretKind::Url)).is_err());
    }
}

#[test]
fn invalid_reference_names_are_refused_before_open() {
    let fixture = SecretFixture::new();
    for invalid in ["../x", "/absolute", "x/y", ".", "", "X", "-x", KEY] {
        assert!(SecretName::new(SecretKind::Wg, invalid).is_err());
        // Deserialization retains untrusted names for validation. The resolver
        // must independently reject them even when site validation was skipped.
        let cfg = parse_site(&SITE.replace(
            "private_key_ref = \"wg0\"",
            &format!("private_key_ref = \"{invalid}\""),
        ))
        .unwrap();
        let name = &cfg.identities["edge"].private_key_ref;
        let error = SecretFile::open_with_owner(&fixture.dir.0, name, fixture.uid)
            .err()
            .unwrap();
        assert!(error.to_string().contains("invalid reference basename"));
        assert!(!error.to_string().contains(MARKER));
        assert!(
            error
                .to_string()
                .contains(&format!("length {}", invalid.len()))
        );
        assert!(error.to_string().contains("[a-z0-9][a-z0-9-]{0,62}"));
        if invalid == KEY {
            assert!(!error.to_string().contains(KEY));
            assert!(!format!("{error:?}").contains(KEY));
        }
    }
}

#[test]
fn secret_symlinks_and_fifo_are_refused_without_reading() {
    let fixture = SecretFixture::new();
    let outside = fixture.dir.0.join("outside");
    fs::write(&outside, MARKER).unwrap();
    set_mode(&outside, 0o600);
    let reference = fixture.dir.0.join("secrets/wg/test");
    symlink(&outside, &reference).unwrap();
    fixture.refused(SecretKind::Wg, "without symlinks", MARKER);
    fs::remove_file(&reference).unwrap();
    mkfifoat(CWD, &reference, Mode::RUSR | Mode::WUSR).unwrap();
    fixture.refused(SecretKind::Wg, "regular file", MARKER);
    fs::remove_file(&reference).unwrap();
    fs::create_dir(&reference).unwrap();
    fixture.refused(SecretKind::Wg, "regular file", MARKER);
    fs::remove_dir_all(fixture.dir.0.join("secrets/wg")).unwrap();
    symlink(
        fixture.dir.0.join("secrets/url"),
        fixture.dir.0.join("secrets/wg"),
    )
    .unwrap();
    fixture.refused(SecretKind::Wg, "kind directory without symlinks", MARKER);
}

#[test]
fn secret_owner_permissions_and_size_checks_precede_content_checks() {
    let fixture = SecretFixture::new();
    let path = fixture.put("wg", MARKER.as_bytes());
    let error = SecretFile::open_with_owner(
        &fixture.dir.0,
        &SecretFixture::name(SecretKind::Wg),
        fixture.uid.wrapping_add(1),
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("owner"));
    assert!(!error.to_string().contains(MARKER));
    for file_mode in [0o640, 0o644, 0o1600] {
        set_mode(&path, file_mode);
        fixture.refused(SecretKind::Wg, "mode must be 0600", MARKER);
    }
    set_mode(&path, 0o600);
    for directory_mode in [0o755, 0o1700] {
        set_mode(fixture.dir.0.join("secrets/wg"), directory_mode);
        fixture.refused(SecretKind::Wg, "mode must be 0700", MARKER);
    }
    set_mode(fixture.dir.0.join("secrets/wg"), 0o700);
    fs::write(&path, MARKER.repeat(300)).unwrap();
    fixture.refused(SecretKind::Wg, "exceeds 4 KiB", MARKER);
}

#[test]
fn secret_content_validation_is_strict_and_value_free() {
    for (kind, directory, contents) in [
        (
            SecretKind::Wg,
            "wg",
            format!("https://example.net/{MARKER}"),
        ),
        (SecretKind::Wg, "wg", MARKER.into()),
        (SecretKind::Wg, "wg", KEY.trim_end_matches('=').into()),
        (SecretKind::Wg, "wg", format!("_{}", &KEY[1..])),
        (SecretKind::Wg, "wg", format!("-{}", &KEY[1..])),
        (SecretKind::Wg, "wg", format!("{KEY}\n\n")),
        (SecretKind::Wg, "wg", format!("{KEY}\r\n")),
        (
            SecretKind::Wg,
            "wg",
            "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAB=".into(),
        ),
        (SecretKind::Url, "url", KEY.into()),
        (
            SecretKind::Url,
            "url",
            format!("http://example.net/{MARKER}"),
        ),
        (
            SecretKind::Url,
            "url",
            format!("https://user:{MARKER}@example.net/"),
        ),
        (
            SecretKind::Url,
            "url",
            format!("https://example.net/{MARKER}\n"),
        ),
        (
            SecretKind::Url,
            "url",
            format!("https://example.net:0/{MARKER}"),
        ),
    ] {
        let fixture = SecretFixture::new();
        fixture.put(directory, contents.as_bytes());
        fixture.refused(kind, "invalid content", &contents);
        assert!(
            !fixture
                .open(kind)
                .err()
                .unwrap()
                .to_string()
                .contains(MARKER)
        );
    }
    let fixture = SecretFixture::new();
    fixture.put("wg", &[0xff]);
    fixture.refused(SecretKind::Wg, "UTF-8", MARKER);
}

#[test]
fn writer_lock_excludes_independent_descriptors_and_releases_on_drop() {
    let dir = TempDir::new();
    let guard = WriterLock::acquire(&dir.0).unwrap();
    assert_eq!(
        WriterLock::try_acquire(&dir.0).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(guard);
    let guard = WriterLock::try_acquire(&dir.0).unwrap();
    assert_eq!(
        WriterLock::try_acquire(&dir.0).unwrap_err().kind(),
        io::ErrorKind::WouldBlock
    );
    drop(guard);
    assert!(WriterLock::acquire(&dir.0).is_ok());
}

#[test]
fn secret_parent_directories_must_be_trusted() {
    for directory in ["", "secrets"] {
        let fixture = SecretFixture::new();
        fixture.put("wg", KEY.as_bytes());
        set_mode(fixture.dir.0.join(directory), 0o777);
        assert!(fixture.open(SecretKind::Wg).is_err(), "{directory}");
    }
}

#[test]
fn interrupted_head_is_not_a_hand_edit() {
    for initial in [false, true] {
        for step in [DurableStep::Renamed, DurableStep::DirectorySynced] {
            let dir = TempDir::new();
            let store = VersionStore::open(&dir.0, None).unwrap();
            if initial {
                store
                    .commit(&writer(&dir.0), None, SITE, meta("initial"))
                    .unwrap();
            }
            let index = commit_steps()
                .iter()
                .position(|s| *s == CommitStep::Head(step))
                .unwrap();
            run_crash_child(&dir.0, "store", index);
            let reopened = VersionStore::open(&dir.0, None).unwrap();
            assert_eq!(
                reopened.mirror_status().unwrap(),
                MirrorStatus::Stale {
                    mirror_matches: if initial { Some(1) } else { None }
                }
            );
            let recovered = VersionStore::open(&dir.0, Some(&writer(&dir.0))).unwrap();
            assert_eq!(recovered.mirror_status().unwrap(), MirrorStatus::InSync);
        }
    }
}

#[test]
fn missing_state_requires_an_explicit_boot_or_fresh_install_decision() {
    let dir = TempDir::new();
    let guard = writer(&dir.0);
    let file = StateFile::open(&dir.0, Some(&guard)).unwrap();
    let fresh = file.read().unwrap().for_boot(false);
    assert_eq!(fresh.state, State::default());
    assert!(!fresh.missing_state_alert);
    assert!(!dir.0.join("state.json").exists());
    // Only install creates the initial state, explicitly, while still fresh.
    file.write(&guard, &fresh.state).unwrap();
    let store = VersionStore::open(&dir.0, Some(&guard)).unwrap();
    store.commit(&guard, None, SITE, meta("initial")).unwrap();
    file.write(&guard, &closed_state()).unwrap();
    let present = file
        .read()
        .unwrap()
        .for_boot(store.head().unwrap().is_some());
    assert_eq!(present.state, closed_state());
    assert!(!present.missing_state_alert);
    fs::remove_file(dir.0.join("state.json")).unwrap();
    assert_eq!(file.read().unwrap(), StateRead::Missing);
    let boot = file
        .read()
        .unwrap()
        .for_boot(store.head().unwrap().is_some());
    assert_eq!(boot.state.selection, Selection::Disconnected);
    assert!(boot.missing_state_alert);
    assert_eq!(
        file.update(&guard, |_| {}).unwrap_err().kind(),
        io::ErrorKind::NotFound
    );
    assert!(!dir.0.join("state.json").exists());
}

#[test]
fn state_updates_cannot_interleave_or_lose_selection_and_quarantine() {
    let dir = TempDir::new();
    let guard = writer(&dir.0);
    let file = StateFile::open(&dir.0, Some(&guard)).unwrap();
    file.write(&guard, &State::default()).unwrap();
    let (attempted, received) = std::sync::mpsc::channel();
    let root = dir.0.clone();
    let second = std::thread::spawn(move || {
        assert_eq!(
            WriterLock::try_acquire(root.join("run"))
                .unwrap_err()
                .kind(),
            io::ErrorKind::WouldBlock
        );
        attempted.send(()).unwrap();
        let guard =
            WriterLock::acquire_timeout(root.join("run"), std::time::Duration::from_secs(2))
                .unwrap();
        StateFile::open(&root, Some(&guard))
            .unwrap()
            .update(&guard, |state| {
                state.selection = Selection::Disconnected;
            })
            .unwrap();
    });
    file.update(&guard, |state| {
        received
            .recv_timeout(std::time::Duration::from_secs(2))
            .unwrap();
        state.quarantine = closed_state().quarantine;
    })
    .unwrap();
    drop(guard);
    second.join().unwrap();
    let StateRead::Present(final_state) = file.read().unwrap() else {
        unreachable!("state was written");
    };
    assert_eq!(final_state.selection, Selection::Disconnected);
    assert_eq!(final_state.quarantine, closed_state().quarantine);
}

#[test]
fn writer_timeout_is_bounded_and_can_wait_for_release() {
    use std::time::{Duration, Instant};
    let dir = TempDir::new();
    let root = dir.0.join("new-run");
    let guard = WriterLock::acquire(&root).unwrap();
    let start = Instant::now();
    let error = WriterLock::acquire_timeout(&root, Duration::from_millis(30)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(
        error
            .to_string()
            .contains(&format!("pid {}", std::process::id()))
    );
    assert!(start.elapsed() >= Duration::from_millis(30));
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(
        WriterLock::acquire_timeout(&root, Duration::ZERO)
            .unwrap_err()
            .kind(),
        io::ErrorKind::TimedOut
    );
    let release = std::thread::spawn(move || {
        std::thread::sleep(Duration::from_millis(20));
        drop(guard);
    });
    let acquired = WriterLock::acquire_timeout(&root, Duration::from_secs(2)).unwrap();
    release.join().unwrap();
    drop(acquired);
    fs::remove_file(root.join("writer.lock")).unwrap();
    let target = dir.0.join("other");
    fs::write(&target, b"untouched").unwrap();
    symlink(&target, root.join("writer.lock")).unwrap();
    assert!(WriterLock::acquire_timeout(&root, Duration::ZERO).is_err());
    assert_eq!(fs::read(target).unwrap(), b"untouched");
}

fn plant_temps(directory: &Path) {
    fs::create_dir_all(directory).unwrap();
    for name in [
        ".scupper-123-456.tmp",
        ".scupper-x-1.tmp",
        ".scupper-1-.tmp",
        ".scupper-1-2-3.tmp",
        ".scupper-1-2.tmp.extra",
        "unrelated",
    ] {
        fs::write(directory.join(name), b"preserve unless ours").unwrap();
    }
    fs::create_dir(directory.join(".scupper-1-3.tmp")).unwrap();
    symlink("unrelated", directory.join(".scupper-1-4.tmp")).unwrap();
}
fn assert_temps_cleaned(directory: &Path) {
    assert!(!directory.join(".scupper-123-456.tmp").exists());
    for name in [
        ".scupper-x-1.tmp",
        ".scupper-1-.tmp",
        ".scupper-1-2-3.tmp",
        ".scupper-1-2.tmp.extra",
        "unrelated",
        ".scupper-1-3.tmp",
        ".scupper-1-4.tmp",
    ] {
        assert!(directory.join(name).exists(), "{name}");
    }
}

#[test]
fn writer_open_cleans_only_owned_regular_temps_with_exact_names() {
    let dir = TempDir::new();
    let lib = dir.0.join("lib");
    let etc = dir.0.join("etc");
    let state = dir.0.join("state");
    for directory in [
        &lib,
        &lib.join("config"),
        &lib.join("rendered"),
        &etc,
        &state,
    ] {
        plant_temps(directory);
    }
    VersionStore::open_with_mirror_root(&lib, &etc, None).unwrap();
    StateFile::open(&state, None).unwrap();
    assert!(lib.join("config/.scupper-123-456.tmp").exists());
    assert!(state.join(".scupper-123-456.tmp").exists());
    let guard = writer(&dir.0);
    VersionStore::open_with_mirror_root(&lib, &etc, Some(&guard)).unwrap();
    StateFile::open(&state, Some(&guard)).unwrap();
    for directory in [
        &lib,
        &lib.join("config"),
        &lib.join("rendered"),
        &etc,
        &state,
    ] {
        assert_temps_cleaned(directory);
    }
}

#[test]
fn secret_parent_symlinks_and_directory_swap_are_refused() {
    let fixture = SecretFixture::new();
    fixture.put("wg", KEY.as_bytes());
    let secrets = fixture.dir.0.join("secrets");
    fs::rename(secrets.join("wg"), secrets.join("wg-old")).unwrap();
    fs::create_dir(secrets.join("wg")).unwrap();
    set_mode(secrets.join("wg"), 0o700);
    fixture.put("wg", format!("B{}", &KEY[1..]).as_bytes());
    // A writable parent permits swapping two otherwise trusted directories.
    set_mode(&secrets, 0o770);
    fixture.refused(SecretKind::Wg, "secrets directory mode must be 0700", KEY);
    set_mode(&secrets, 0o700);
    fs::rename(&secrets, fixture.dir.0.join("saved-secrets")).unwrap();
    symlink("saved-secrets", &secrets).unwrap();
    fixture.refused(SecretKind::Wg, "open secrets directory", KEY);
    let linked_root = fixture.dir.0.join("linked-root");
    symlink(&fixture.dir.0, &linked_root).unwrap();
    let error = SecretFile::open_with_owner(
        linked_root,
        &SecretFixture::name(SecretKind::Wg),
        fixture.uid,
    )
    .err()
    .unwrap();
    assert!(error.to_string().contains("open root directory"));
}

#[test]
fn mirror_observation_waits_for_an_in_progress_commit() {
    use std::{sync::mpsc, time::Duration};
    let dir = TempDir::new();
    let store = Arc::new(VersionStore::open(&dir.0, None).unwrap());
    store
        .commit(&writer(&dir.0), None, SITE, meta("initial"))
        .unwrap();
    let (renamed, head_ready) = mpsc::channel();
    let (resume, paused) = mpsc::channel();
    let committing = store.clone();
    let root = dir.0.clone();
    let commit = std::thread::spawn(move || {
        committing
            .commit_with_hook(
                &writer(&root),
                Some(1),
                &changed_site(),
                meta("next"),
                &|step| {
                    if step == CommitStep::Head(DurableStep::Renamed) {
                        renamed.send(()).unwrap();
                        paused.recv_timeout(Duration::from_secs(2)).unwrap();
                    }
                    Ok(())
                },
            )
            .unwrap();
    });
    head_ready.recv_timeout(Duration::from_secs(2)).unwrap();
    let (attempted, started) = mpsc::channel();
    let (send_status, result) = mpsc::channel();
    let observing = store.clone();
    let observer = std::thread::spawn(move || {
        attempted.send(()).unwrap();
        send_status
            .send(observing.mirror_status().unwrap())
            .unwrap();
    });
    started.recv_timeout(Duration::from_secs(2)).unwrap();
    assert_eq!(
        result.recv_timeout(Duration::from_millis(30)),
        Err(mpsc::RecvTimeoutError::Timeout)
    );
    resume.send(()).unwrap();
    commit.join().unwrap();
    assert_eq!(
        result.recv_timeout(Duration::from_secs(2)).unwrap(),
        MirrorStatus::InSync
    );
    observer.join().unwrap();
}
