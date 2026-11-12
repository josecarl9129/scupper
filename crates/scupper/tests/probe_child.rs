//! Real CLI process checks that require neither root nor a foreign namespace.
#![cfg(target_os = "linux")]
use scupper_sys::probe_child::{ProbeOutcome, ProbeResult};
use std::{
    error::Error,
    fs::File,
    process::{Command, Stdio},
};

#[test]
fn child_starts_single_threaded_and_refuses_invalid_stdin_with_json_outcome()
-> Result<(), Box<dyn Error>> {
    let json = r#"{"kind":"Path","bind":null,"expected_netns":[0,0],"dns":"10.2.0.1","targets":["https://probe.test/"]}"#;
    let output = Command::new(env!("CARGO_BIN_EXE_scupper"))
        .args(["probe", json])
        .stdin(Stdio::from(File::open("/proc/self/ns/net")?))
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let outcome: ProbeOutcome = serde_json::from_slice(&output.stdout)?;
    assert!(matches!(outcome.result, ProbeResult::Setup { .. }));
    assert_eq!(outcome.threads_before_setns, Some(1));
    assert_eq!(outcome.credentials, None);
    Ok(())
}
#[test]
fn hidden_command_and_invalid_protocol_are_internal_errors() -> Result<(), Box<dyn Error>> {
    let help = Command::new(env!("CARGO_BIN_EXE_scupper"))
        .arg("--help")
        .output()?;
    assert!(!String::from_utf8(help.stdout)?.contains("probe"));
    let output = Command::new(env!("CARGO_BIN_EXE_scupper"))
        .args(["probe", "{} invalid"])
        .output()?;
    assert!(!output.status.success());
    assert_eq!(output.stdout, [] as [u8; 0]);
    Ok(())
}
