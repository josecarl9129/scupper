//! Real child execution keeps key input out of all process arguments and artifacts.
#![allow(clippy::unwrap_used)]
use scupper_core::config::{SecretKind, SecretName};
use scupper_sys::{
    provider,
    secrets::SecretFile,
    system::{Program, Programs, RealSystem},
};
use std::{fs, os::unix::fs::PermissionsExt, path::PathBuf};
fn walk(path: &std::path::Path, key: &std::path::Path, private: &[u8]) {
    for entry in fs::read_dir(path).unwrap() {
        let path = entry.unwrap().path();
        if path.is_dir() {
            walk(&path, key, private);
        } else if path != key {
            assert!(
                !fs::read(path)
                    .unwrap()
                    .windows(private.len())
                    .any(|w| w == private)
            );
        }
    }
}

#[test]
fn real_derivation_stdin_and_secret_file_are_the_only_key_consumers() {
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("provider-child-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let private = "BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=";
    let program = root.join("wg");
    // Consume stdin in a shell builtin, without a child argument or disk copy.
    fs::write(&program, "#!/bin/sh\nread -r input\nprintf '%s\\n' \"$@\" > \"$0.args\"\nprintf 'BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQU=\\n'\n").unwrap();
    fs::set_permissions(&program, fs::Permissions::from_mode(0o700)).unwrap();
    let programs = Programs::new([(Program::Wg, program)]).unwrap();
    let system = RealSystem::new(programs);
    let public = provider::public_key(&system, private.as_bytes()).unwrap();
    assert!(!public.as_str().contains(private));
    assert_eq!(
        fs::read_to_string(root.join("wg.args")).unwrap(),
        "pubkey\n"
    );
    let name = SecretName::new(SecretKind::Wg, "exit-test").unwrap();
    SecretFile::write_new(&root, &name, private.as_bytes()).unwrap();
    let key = root.join("secrets/wg/exit-test");
    walk(&root, &key, private.as_bytes());
    assert_eq!(fs::read(&key).unwrap(), private.as_bytes());
    assert_eq!(
        fs::metadata(&key).unwrap().permissions().mode() & 0o7777,
        0o600
    );
    SecretFile::remove(&root, &name).unwrap();
    fs::remove_dir_all(&root).unwrap();
}

#[test]
fn sweep_collects_only_unreferenced_keys_and_older_temporary_files() {
    use std::{
        collections::BTreeSet,
        time::{Duration, SystemTime},
    };
    let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("provider-sweep-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let live = SecretName::new(SecretKind::Wg, "exit-live").unwrap();
    let orphan = SecretName::new(SecretKind::Wg, "exit-orphan").unwrap();
    let private = b"BAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQ=";
    for key in [&live, &orphan] {
        SecretFile::write_new(&root, key, private).unwrap();
    }
    let started = SystemTime::now();
    for (name, modified) in [
        (".scupper-old-0.tmp", std::time::UNIX_EPOCH),
        (".scupper-new-0.tmp", started + Duration::from_secs(60)),
    ] {
        let path = root.join("secrets/wg").join(name);
        fs::write(&path, private).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::File::open(&path)
            .unwrap()
            .set_modified(modified)
            .unwrap();
    }
    for name in ["exit-future-v2", "exit-old-v1"] {
        SecretFile::write_new(
            &root,
            &SecretName::new(SecretKind::Wg, name).unwrap(),
            private,
        )
        .unwrap();
    }
    SecretFile::sweep_wg(
        &root,
        &BTreeSet::from([orphan.name().into(), "exit-future-v2".into()]),
        &BTreeSet::from([live.name().into()]),
        1,
        started,
    )
    .unwrap();
    assert_eq!(
        fs::read(root.join("secrets/wg/exit-live")).unwrap(),
        private
    );
    assert!(!root.join("secrets/wg/exit-orphan").exists());
    assert!(!root.join("secrets/wg/exit-old-v1").exists());
    assert!(root.join("secrets/wg/exit-future-v2").exists());
    assert!(!root.join("secrets/wg/.scupper-old-0.tmp").exists());
    assert!(root.join("secrets/wg/.scupper-new-0.tmp").exists());
    fs::remove_dir_all(root).unwrap();
}
