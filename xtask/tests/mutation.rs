//! CLI feature fencing and selector diagnostics without privileged lab execution.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]
#[test]
fn unknown_mutation_is_rejected_before_lab_setup() {
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["leaktest", "--mutation", "unknown"])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&output.stderr).contains("unknown mutation"));
}

#[test]
#[cfg(not(feature = "lab-mutation"))]
fn default_build_cannot_select_a_mutation_even_with_the_environment_set() {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("mutation-gate-{}", std::process::id()));
    assert!(!path.exists());
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .env("SCUPPER_LAB_MUTATION", "M-src")
        .args(["leaktest", "--mutation", "M-src", "--artifacts"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr)
            .contains("requires the testing-only lab-mutation feature")
    );
    assert!(!path.exists());
}

#[test]
#[cfg(feature = "lab-mutation")]
fn stale_mutant_is_refused_before_the_control_runs() {
    let path = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("mutation-stale-{}", std::process::id()));
    std::fs::create_dir_all(path.join("mutant")).unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args(["leaktest", "--mutation", "M-ct", "--artifacts"])
        .arg(&path)
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    assert!(
        String::from_utf8_lossy(&output.stderr).contains("refusing existing mutation artifacts"),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(!path.join("control").exists());
    std::fs::remove_dir_all(path).unwrap();
}
