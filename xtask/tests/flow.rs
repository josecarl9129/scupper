//! The flow CLI must honor its requested lifetime and record successful writes.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

use std::{
    fs,
    net::UdpSocket,
    path::Path,
    process::{Command, Stdio},
    time::{Duration, Instant},
};

#[test]
fn flow_seconds_bounds_a_live_sender() {
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let log = std::path::Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("flow-duration-{}.jsonl", std::process::id()));
    let output = std::process::Command::new("timeout")
        .args([
            "10",
            env!("CARGO_BIN_EXE_xtask"),
            "flow",
            "--mode",
            "udp",
            "--address",
        ])
        .arg(peer.local_addr().unwrap().to_string())
        .args(["--marker", "scupper-flow-duration", "--log"])
        .arg(&log)
        .args(["--seconds", "1"])
        .output()
        .unwrap();
    assert!(output.status.success(), "{output:?}");
    let text = std::fs::read_to_string(&log).unwrap();
    std::fs::remove_file(log).unwrap();
    let records: Vec<serde_json::Value> = text
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert!(records.iter().any(|v| v["sent"].as_u64().unwrap() > 0));
    assert!(records.last().unwrap()["elapsed_ms"].as_u64().unwrap() >= 500);
    let mut buffer = [0; 128];
    peer.set_nonblocking(true).unwrap();
    let (received, _) = peer.recv_from(&mut buffer).unwrap();
    assert_eq!(&buffer[..received], b"scupper-flow-duration");
}

#[test]
fn sigterm_finishes_flow_records_before_exit() {
    let root = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("flow-shutdown-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    let sink = UdpSocket::bind("127.0.0.1:0").unwrap();
    for attempt in 0..8 {
        let log = root.join(format!("{attempt}.jsonl"));
        let mut child = Command::new(env!("CARGO_BIN_EXE_xtask"))
            .args([
                "flow",
                "--mode",
                "udp",
                "--address",
                &sink.local_addr().unwrap().to_string(),
                "--marker",
                "scupper-canary-shutdown",
                "--seconds",
                "10",
                "--log",
            ])
            .arg(&log)
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let until = Instant::now() + Duration::from_secs(5);
        while !fs::read(&log).is_ok_and(|bytes| bytes.contains(&b'\n')) {
            assert!(
                Instant::now() < until,
                "flow did not produce its first record"
            );
            assert!(
                child.try_wait().unwrap().is_none(),
                "flow exited before measurement"
            );
            std::thread::sleep(Duration::from_millis(1));
        }
        rustix::process::kill_process(
            rustix::process::Pid::from_raw(child.id().cast_signed()).unwrap(),
            rustix::process::Signal::TERM,
        )
        .unwrap();
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < until, "flow ignored graceful shutdown");
            std::thread::sleep(Duration::from_millis(1));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let text = fs::read_to_string(&log).unwrap();
        assert!(text.ends_with('\n'), "unterminated record: {text}");
        for line in text.lines() {
            let record: serde_json::Value = serde_json::from_str(line).unwrap();
            assert!(record["sent"].as_u64().unwrap() > 0);
        }
    }
    fs::remove_dir_all(root).unwrap();
}
