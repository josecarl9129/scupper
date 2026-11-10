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

#[test]
fn gateway_dns_probe_sends_a_real_question_and_detects_a_service_response() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(std::time::Duration::from_secs(3)))
        .unwrap();
    let port = socket.local_addr().unwrap().port();
    let receiver = std::thread::spawn(move || {
        let mut bytes = [0; 512];
        let (len, peer) = socket.recv_from(&mut bytes).unwrap();
        assert_eq!(&bytes[4..6], &[0, 1]);
        assert_eq!(&bytes[len - 4..len], &[0, 1, 0, 1]);
        assert!(
            bytes[12..len]
                .windows(b"scupper-canary-0011223344556677".len())
                .any(|part| part == b"scupper-canary-0011223344556677")
        );
        bytes[2] |= 0x80;
        socket.send_to(&bytes[..len], peer).unwrap();
    });
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_xtask"))
        .args([
            "probe",
            "--protocol",
            "dns",
            "--target",
            "127.0.0.1",
            "--port",
            &port.to_string(),
            "--marker",
            "scupper-canary-0011223344556677",
        ])
        .output()
        .unwrap();
    receiver.join().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stdout)
    );
    let attempt: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(attempt["outcome"], "Delivered");
}
