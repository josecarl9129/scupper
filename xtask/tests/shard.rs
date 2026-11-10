//! Listing and invalid selections must never require root or create a topology.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]
use std::process::Command;

#[test]
fn list_cli_matches_catalog_without_creating_artifacts() {
    let root = std::env::var_os("CARGO_TARGET_TMPDIR").map_or_else(
        || std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../target/tmp"),
        std::path::PathBuf::from,
    );
    let absent = root.join(format!("list-does-not-create-{}", std::process::id()));
    for shard in [None, Some("1/4"), Some("4/4"), Some("1/1")] {
        let mut command = Command::new(env!("CARGO_BIN_EXE_xtask"));
        command
            .args(["leaktest", "--list", "--artifacts"])
            .arg(&absent);
        if let Some(shard) = shard {
            command.args(["--shard", shard]);
        }
        let output = command.output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(
            String::from_utf8(output.stdout).unwrap(),
            xtask::lab::list(shard.map(str::parse).transpose().unwrap()).unwrap()
        );
        assert!(!absent.exists());
    }
    let invalid = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["leaktest", "--list", "--shard", "0/4"])
        .output()
        .unwrap();
    assert!(!invalid.status.success());
    assert!(String::from_utf8_lossy(&invalid.stderr).contains("shard must be I/N"));
}

#[test]
fn shared_duration_file_is_used_by_root_free_cli_listing() {
    let root = std::path::PathBuf::from(env!("CARGO_TARGET_TMPDIR"));
    std::fs::create_dir_all(&root).unwrap();
    let durations = root.join(format!("list-durations-{}.tsv", std::process::id()));
    std::fs::write(
        &durations,
        "name\tgot\telapsed_ms\tdetail\ndaemon-L9\tpassed\t800000\tmeasured\n",
    )
    .unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["leaktest", "--list", "--durations"])
        .arg(&durations)
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert_eq!(
        text,
        xtask::lab::list_with_durations(None, Some(&durations)).unwrap()
    );
    assert!(
        text.lines()
            .any(|line| line.starts_with("daemon-L9\t") && line.ends_with("\t1005"))
    );
    std::fs::remove_file(durations).unwrap();
}
