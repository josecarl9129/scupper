//! Exercise the real hidden executable and secret stdin, including expired jobs.
#![allow(clippy::unwrap_used)]
use std::{
    io::Write,
    process::{Command, Stdio},
};
fn child(input: &[u8]) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_scupper"));
    command
        .args(["deliver", "heartbeat"])
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    if rustix::process::geteuid().is_root() {
        use std::os::unix::process::CommandExt;
        command.uid(65534).gid(65534);
    }
    let mut child = command.spawn().unwrap();
    child.stdin.take().unwrap().write_all(input).unwrap();
    child.wait_with_output().unwrap()
}
#[test]
fn expired_stdin_job_exits_without_resolution_or_output() {
    let input = br#"{"url":"https://heartbeat.invalid/private-check","deadline_ns":0}"#;
    let result = child(input);
    assert_eq!(result.status.code(), Some(21));
    assert_eq!(result.stdout, [] as [u8; 0]);
    assert_eq!(result.stderr, [] as [u8; 0]);
}
#[test]
fn malformed_protocol_is_value_free_and_hidden_from_help() {
    let result = child(br#"{"url":"https://heartbeat.invalid/private-check","deadline_ns":"bad"}"#);
    assert_eq!(result.status.code(), Some(22));
    assert_eq!(result.stdout, [] as [u8; 0]);
    assert_eq!(result.stderr, [] as [u8; 0]);
    let help = Command::new(env!("CARGO_BIN_EXE_scupper"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&help.stdout).contains("deliver"));
}
