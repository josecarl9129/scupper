//! The flow CLI must honor its requested lifetime and record successful writes.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

#[test]
fn flow_seconds_bounds_a_live_sender() {
    let peer = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let log = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(format!(
        "../target/flow-duration-{}.jsonl",
        std::process::id()
    ));
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
