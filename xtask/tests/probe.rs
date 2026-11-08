//! Probe failures must preserve local socket errors as harness failures.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]

#[test]
fn occupied_udp_source_port_is_a_structured_harness_error() {
    let occupied = std::net::UdpSocket::bind("0.0.0.0:0").unwrap();
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args([
            "probe",
            "--protocol",
            "udp",
            "--target",
            "127.0.0.1",
            "--port",
            "8080",
            "--marker",
            "scupper-canary-0011223344556677",
            "--source-port",
            &occupied.local_addr().unwrap().port().to_string(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(1));
    let attempt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(attempt["outcome"]["HarnessError"]["errno"], 98);
    assert_eq!(attempt["destination"], "127.0.0.1:8080");
}
