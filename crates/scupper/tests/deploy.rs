//! Deploy orchestration with no real SSH connection or host mutation.
#![allow(clippy::unwrap_used)]
use proptest::prelude::*;
use scupper::deploy::{self, Confirmation, DeployArgs, Invocation, Transport};
use scupper_core::release::{self, Members};
use scupper_proto::deploy::{self as wire, DeployOp};
use std::{cell::RefCell, collections::VecDeque, fs, path::PathBuf};

struct Fake {
    calls: RefCell<Vec<Invocation>>,
    responses: RefCell<VecDeque<Result<String, String>>>,
}
impl Transport for Fake {
    fn execute(&self, call: Invocation) -> Result<String, String> {
        self.calls.borrow_mut().push(call);
        self.responses.borrow_mut().pop_front().unwrap()
    }
}
struct Prompt(bool);
impl Confirmation for Prompt {
    fn terminal(&self) -> bool {
        self.0
    }
    fn confirm(&self) -> Result<bool, String> {
        Ok(true)
    }
}
struct Fixture(PathBuf);
impl Fixture {
    fn new(label: &str, fresh: bool) -> (Self, DeployArgs, Fake) {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("deploy-{}-{label}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        let mut members = Members::new();
        for name in [
            "scupper",
            "scupperd",
            "scupper-net.service",
            "scupperd.service",
        ] {
            let data = if matches!(name, "scupper" | "scupperd") {
                let mut elf = vec![0; 64];
                elf[..6].copy_from_slice(b"\x7fELF\x02\x01");
                elf[16] = 2;
                elf[18] = 62;
                elf
            } else {
                name.as_bytes().to_vec()
            };
            members.insert(name.into(), data);
        }
        let archive = release::encode(members).unwrap();
        let name = format!(
            "scupper-{}-x86_64-unknown-linux-musl.tar.gz",
            env!("CARGO_PKG_VERSION")
        );
        let path = root.join(&name);
        fs::write(&path, &archive).unwrap();
        fs::write(
            root.join("SHA256SUMS"),
            format!("{}  {name}\n", release::hash(&archive)),
        )
        .unwrap();
        let args = DeployArgs {
            host: "192.0.2.10".into(),
            archive: Some(path),
            yes: true,
            ssh_option: vec![
                "-i /tmp/example-key".into(),
                "-p 2222".into(),
                "-o StrictHostKeyChecking=yes".into(),
            ],
        };
        let responses = if fresh {
            vec!["x86_64\n", "fresh\n", "", "verified\n"]
        } else {
            vec![
                "x86_64\n",
                "installed\n",
                "",
                "verified\n",
                "install plan\n",
                "switched\n",
                "check healthy\n",
            ]
        };
        (
            Self(root),
            args,
            Fake {
                calls: RefCell::default(),
                responses: RefCell::new(responses.into_iter().map(|r| Ok(r.into())).collect()),
            },
        )
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn every_step_uses_fixed_remote_command_and_typed_stdin() {
    let (_fixture, args, fake) = Fixture::new("all", false);
    let mut output = Vec::new();
    assert_eq!(
        deploy::run(&args, &fake, &Prompt(false), &mut output).unwrap(),
        0
    );
    let calls = fake.calls.borrow();
    assert_eq!(calls.len(), 7);
    let options = [
        "-o",
        "BatchMode=yes",
        "-i",
        "/tmp/example-key",
        "-p",
        "2222",
        "-o",
        "StrictHostKeyChecking=yes",
        "--",
        "root@192.0.2.10",
    ];
    assert_eq!(calls[0].program, "ssh");
    assert_eq!(
        calls[0].args,
        options
            .iter()
            .copied()
            .chain(["uname -m"])
            .map(std::ffi::OsString::from)
            .collect::<Vec<_>>()
    );
    assert_eq!(calls[0].stdin, [] as [u8; 0]);
    for (index, op) in [
        (1, "Prepare"),
        (3, "Stage"),
        (4, "Plan"),
        (5, "Switch"),
        (6, "Check"),
    ] {
        let c = &calls[index];
        assert_eq!(c.program, "ssh");
        assert_eq!(
            c.args,
            options
                .iter()
                .copied()
                .chain([deploy::REMOTE_COMMAND])
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>()
        );
        let request = wire::read_deploy(c.stdin.as_slice()).unwrap();
        assert_eq!(serde_json::to_value(request).unwrap()["op"], op);
    }
    let copy = &calls[2];
    assert_eq!(copy.program, "scp");
    assert_eq!(copy.stdin, [] as [u8; 0]);
    assert_eq!(copy.args[4], "-P");
    assert_eq!(copy.args[9], args.archive.unwrap().canonicalize().unwrap());
    let prepare = wire::read_deploy(calls[1].stdin.as_slice()).unwrap();
    assert_eq!(
        copy.args[10],
        format!(
            "root@192.0.2.10:/usr/local/lib/scupper/deploy/{}/new/archive.tar.gz",
            prepare.operation.id()
        )
        .as_str()
    );
    let output = String::from_utf8(output).unwrap();
    assert!(output.contains("install plan\n") && output.contains("check healthy\n"));
}
#[test]
fn fresh_host_stops_after_verification_and_prints_exact_install_command() {
    let (_fixture, args, fake) = Fixture::new("fresh", true);
    let mut output = Vec::new();
    deploy::run(&args, &fake, &Prompt(false), &mut output).unwrap();
    let calls = fake.calls.borrow();
    assert_eq!(calls.len(), 4);
    let id = wire::read_deploy(calls[1].stdin.as_slice())
        .unwrap()
        .operation
        .id();
    assert!(String::from_utf8(output).unwrap().contains(&format!("/usr/local/lib/scupper/deploy/{id}/new/scupper install --binaries /usr/local/lib/scupper/deploy/{id}/new")));
}
#[test]
fn tty_and_checksum_failures_prevent_switch_and_remote_extraction() {
    let (fixture, mut args, fake) = Fixture::new("refuse", false);
    args.yes = false;
    assert!(deploy::run(&args, &fake, &Prompt(false), &mut Vec::new()).is_err());
    assert!(fake.calls.borrow().is_empty());
    args.yes = true;
    fs::write(fixture.0.join("SHA256SUMS"), "wrong\n").unwrap();
    assert!(deploy::run(&args, &fake, &Prompt(false), &mut Vec::new()).is_err());
    assert_eq!(fake.calls.borrow().len(), 1);
    let (_fixture, args, fake) = Fixture::new("gateway-mismatch", false);
    fake.responses.borrow_mut()[3] = Err("release checksum mismatch; extraction refused".into());
    assert!(deploy::run(&args, &fake, &Prompt(false), &mut Vec::new()).is_err());
    assert_eq!(fake.calls.borrow().len(), 4);
}
#[test]
fn architecture_allowlist() {
    assert_eq!(
        deploy::target("x86_64\n").unwrap(),
        "x86_64-unknown-linux-musl"
    );
    assert_eq!(
        deploy::target("aarch64\n").unwrap(),
        "aarch64-unknown-linux-musl"
    );
    for value in ["arm64", "i686", "x86_64; true", "$(uname -m)", ""] {
        assert!(deploy::target(value).is_err());
    }
    assert_eq!(deploy::host("2001:db8::10").unwrap(), "root@2001:db8::10");
    assert!(deploy::host("gateway.example").is_ok());
}
#[test]
#[cfg(target_os = "linux")]
fn restart_net_only_when_unit_changed() {
    assert_eq!(scupper::remote::restart_units(false), ["scupperd"]);
    assert_eq!(
        scupper::remote::restart_units(true),
        ["scupper-net", "scupperd"]
    );
}
proptest! {
    #[test]
    fn hostile_hosts_never_reach_transport(payload in ".{0,80}") {
        let fake = Fake { calls: RefCell::default(), responses: RefCell::default() };
        for host in [format!("-{payload}"), format!("a\n{payload}"), format!("a'\"{payload}"), format!("$(x){payload}"), format!("`x`{payload}")] {
            let args = DeployArgs { host, archive: None, yes: true, ssh_option: Vec::new() };
            prop_assert!(deploy::run(&args, &fake, &Prompt(false), &mut Vec::new()).is_err());
            prop_assert!(fake.calls.borrow().is_empty());
        }
    }
    #[test]
    fn hostile_options_never_reach_transport(payload in ".{0,60}") {
        let fake = Fake { calls: RefCell::default(), responses: RefCell::default() };
        for option in [format!("-o ProxyCommand={payload}"), format!("-i /tmp/$(x){payload}"), format!("-i /tmp/`x`{payload}"), format!("-i /tmp/\n{payload}"), format!("-i -{payload}")] {
            let args = DeployArgs { host: "198.51.100.10".into(), archive: None, yes: true, ssh_option: vec![option] };
            prop_assert!(deploy::run(&args, &fake, &Prompt(false), &mut Vec::new()).is_err());
            prop_assert!(fake.calls.borrow().is_empty());
        }
    }
}
#[test]
fn stdin_has_no_shell_argument_boundary() {
    assert!(!deploy::REMOTE_COMMAND.contains("$1"));
    let request =
        wire::read_deploy(br#"{"op":"Plan","args":{"id":"d1"},"request_id":"r1"}"#.as_slice())
            .unwrap();
    assert!(matches!(request.operation, DeployOp::Plan { .. }));
}

#[test]
fn bootstrap_command_is_valid_constant_shell_and_python() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    assert!(!include_str!("../src/deploy_bootstrap.py").contains('\''));
    let mut shell = Command::new("sh")
        .arg("-n")
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    shell
        .stdin
        .take()
        .unwrap()
        .write_all(deploy::REMOTE_COMMAND.as_bytes())
        .unwrap();
    assert!(shell.wait().unwrap().success());
    // Malformed requests are refused before bootstrap touches host paths.
    for request in [
        "null",
        "{}",
        "{",
        r#"{"op":"Switch","args":{"id":"d1"},"request_id":"r1"}"#,
    ] {
        let mut child = Command::new("python3")
            .args(["-c", include_str!("../src/deploy_bootstrap.py")])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(request.as_bytes())
            .unwrap();
        let result = child.wait_with_output().unwrap();
        assert!(!result.status.success());
        assert_eq!(result.stdout, [] as [u8; 0]);
    }
}

#[test]
fn fresh_bootstrap_verifies_before_extracting_and_is_tar_compatible() {
    use std::{
        io::Write,
        process::{Command, Stdio},
    };
    let (fixture, args, _fake) = Fixture::new("bootstrap-stage", true);
    let base = fixture.0.join("bootstrap/deploy");
    fs::create_dir_all(&base).unwrap();
    // Redirect only the bootstrap filesystem boundary into this test's private host.
    // The production command has no configurable paths or environment override.
    let script = include_str!("../src/deploy_bootstrap.py")
        .replace(
            "base = \"/usr/local/lib/scupper/deploy\"",
            &format!(
                "base = {}",
                serde_json::to_string(&base.to_string_lossy()).unwrap()
            ),
        )
        .replace(
            "    for path in (\"/\", \"/usr\", \"/usr/local\", \"/usr/local/lib\"):",
            "    for path in ():",
        )
        .replace(
            "    directory(\"/usr/local/lib/scupper\", op == \"Prepare\")",
            "",
        )
        .replace("m.st_uid != 0", "m.st_uid != os.geteuid()");
    let invoke = |request: serde_json::Value| {
        let mut child = Command::new("python3")
            .args(["-c", &script])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .take()
            .unwrap()
            .write_all(request.to_string().as_bytes())
            .unwrap();
        child.wait_with_output().unwrap()
    };
    let prepare = serde_json::json!({"op":"Prepare", "args":{"id":"d1"}, "request_id":"r1"});
    assert!(invoke(prepare.clone()).status.success());
    assert!(!invoke(prepare).status.success()); // exclusive deploy ID
    let stage = base.join("d1/new");
    let archive = fs::read(args.archive.unwrap()).unwrap();
    fs::write(stage.join("archive.tar.gz"), &archive).unwrap();
    let bad = serde_json::json!({"op":"Stage", "args":{"id":"d1", "sha256":"0".repeat(64)}, "request_id":"r1"});
    assert!(!invoke(bad).status.success());
    assert!(!stage.join("scupper").exists());
    assert!(!stage.join("MANIFEST").exists());
    let good = serde_json::json!({"op":"Stage", "args":{"id":"d1", "sha256":release::hash(&archive)}, "request_id":"r1"});
    let result = invoke(good);
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let decoded = release::decode(&archive, true).unwrap();
    for (name, data) in decoded {
        assert_eq!(fs::read(stage.join(name)).unwrap(), data);
    }
}

#[test]
fn explicit_archive_can_have_another_version_but_not_another_architecture() {
    let (fixture, mut args, fake) = Fixture::new("explicit", true);
    let renamed = fixture.0.join("scupper-candidate.tar.gz");
    fs::rename(args.archive.as_ref().unwrap(), &renamed).unwrap();
    let digest = release::hash(&fs::read(&renamed).unwrap());
    fs::write(
        fixture.0.join("SHA256SUMS"),
        format!("{digest}  scupper-candidate.tar.gz\n"),
    )
    .unwrap();
    args.archive = Some(renamed);
    deploy::run(&args, &fake, &Prompt(false), &mut Vec::new()).unwrap();
    let (_fixture, args, fake) = Fixture::new("wrong-arch", false);
    fake.responses.borrow_mut()[0] = Ok("aarch64\n".into());
    let error = deploy::run(&args, &fake, &Prompt(false), &mut Vec::new()).unwrap_err();
    assert!(error.contains("binaries do not match gateway architecture"));
    assert_eq!(fake.calls.borrow().len(), 1);
}
