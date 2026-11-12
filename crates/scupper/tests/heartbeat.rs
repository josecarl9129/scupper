#![cfg(target_os = "linux")]
//! Exercise the real hidden executable and secret stdin, including expired jobs.
#![allow(clippy::unwrap_used)]
use std::{
    io::Write,
    process::{Command, Stdio},
};
fn child(input: &[u8]) -> std::process::Output {
    delivery(input, "heartbeat")
}
fn delivery(input: &[u8], kind: &str) -> std::process::Output {
    let mut command = Command::new(env!("CARGO_BIN_EXE_scupper"));
    command
        .args(["deliver", kind])
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

#[test]
fn alert_child_rejects_expired_or_injected_requests_without_output() {
    let expired=br#"{"url":"https://fixture.invalid/private-token","deadline_ns":0,"payload":{"content_type":"application/json","headers":{},"body":"{}"}}"#;
    let result = delivery(expired, "alert");
    assert_eq!(result.status.code(), Some(21));
    assert_eq!(result.stdout, [] as [u8; 0]);
    assert_eq!(result.stderr, [] as [u8; 0]);
    let missing = delivery(
        br#"{"url":"https://fixture.invalid/private-token","deadline_ns":0}"#,
        "alert",
    );
    assert_eq!(missing.status.code(), Some(22));
    assert_eq!(missing.stdout, [] as [u8; 0]);
    assert_eq!(missing.stderr, [] as [u8; 0]);
    let injected=br#"{"url":"https://fixture.invalid/private-token","deadline_ns":0,"payload":{"content_type":"application/json","headers":{"Title":"bad\r\nInjected: secret"},"body":"{}"}}"#;
    let result = delivery(injected, "alert");
    assert_eq!(result.status.code(), Some(22));
    assert_eq!(result.stdout, [] as [u8; 0]);
    assert_eq!(result.stderr, [] as [u8; 0]);
}
