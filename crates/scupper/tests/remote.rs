//! Gateway dispatch exercises the same installation and service paths as production.
#![cfg(target_os = "linux")]
#![allow(clippy::unwrap_used)]
#[path = "../../scupper-sys/tests/support/install.rs"]
mod support;
use scupper::{deploy, remote};
use scupper_core::{
    install as model,
    release::{self, Members},
};
use scupper_proto::deploy::{DeployPlan, SwitchOutcome};
use scupper_sys::{
    fs::{Fs, RealFs, TempFile},
    system::{ExecError, ExecOutput, ExecTarget, Program, System},
};
use serde_json::json;
use std::{
    cell::{Cell, RefCell},
    fs, io,
    path::{Path, PathBuf},
    time::Duration,
};
use support::{Fake, Host};

#[derive(Default)]
struct Gateway {
    fake: Fake,
    fail: RefCell<Option<&'static str>>,
    services: RefCell<Vec<Vec<String>>>,
    change_on_observe: RefCell<Option<(PathBuf, usize)>>,
}
impl System for Gateway {
    fn wg_quick_units(&self) -> io::Result<Vec<String>> {
        self.fake.wg_quick_units()
    }
    fn install_uid(&self) -> u32 {
        0
    }
    fn run(
        &self,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        if program == Program::Uname && args[0] == "-r" {
            let mut hook = self.change_on_observe.borrow_mut();
            if let Some((path, remaining)) = hook.as_mut() {
                *remaining -= 1;
                if *remaining == 0 {
                    fs::write(path, "external change before apply").unwrap();
                    hook.take();
                }
            }
        }
        if program == Program::Systemctl && matches!(args[0].as_str(), "restart" | "daemon-reload")
        {
            self.services.borrow_mut().push(args.to_vec());
            if args[0] == "restart" {
                assert!(args.iter().any(|a| a == "--job-mode=replace"));
                assert!(timeout >= Duration::from_secs(90));
            }
            match *self.fail.borrow() {
                Some("reload") if args[0] == "daemon-reload" => {
                    return Ok(ExecOutput {
                        status: Some(1),
                        stdout: String::new(),
                        stderr: String::new(),
                    });
                }
                Some("restart") if args.get(1).is_some_and(|a| a == "scupperd") => {
                    return Ok(ExecOutput {
                        status: Some(1),
                        stdout: String::new(),
                        stderr: String::new(),
                    });
                }
                Some("timeout") if args.get(1).is_some_and(|a| a == "scupperd") => {
                    return Err(ExecError::Timeout { after: timeout });
                }
                _ => {}
            }
            return Ok(ExecOutput {
                status: Some(0),
                stdout: String::new(),
                stderr: String::new(),
            });
        }
        self.fake.run(program, args, timeout)
    }
    fn run_with_stdin(
        &self,
        target: ExecTarget<'_>,
        program: Program,
        args: &[String],
        input: &[u8],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.fake
            .run_with_stdin(target, program, args, input, timeout)
    }
    fn now_unix_secs(&self) -> u64 {
        1000
    }
}
fn call(
    host: &Host,
    gateway: &Gateway,
    filesystem: &dyn Fs,
    op: &str,
    extra: Option<(&str, &str)>,
) -> (Result<u8, String>, String) {
    let mut args = json!({"id":"d1"});
    if let Some((key, value)) = extra {
        args[key] = value.into();
    }
    let bytes = serde_json::to_vec(&json!({"op":op,"args":args,"request_id":"r1"})).unwrap();
    let mut out = Vec::new();
    let result = remote::run_staged(bytes.as_slice(), &mut out, gateway, &host.paths, filesystem);
    (result, String::from_utf8(out).unwrap())
}
fn stage(host: &Host, gateway: &Gateway) -> PathBuf {
    fs::create_dir_all(host.paths.at("/usr/local/lib")).unwrap();
    assert!(call(host, gateway, &RealFs, "Prepare", None).0.is_ok());
    let stage = host.paths.at("/usr/local/lib/scupper/deploy/d1/new");
    let members: Members = [
        "scupper",
        "scupperd",
        "scupper-net.service",
        "scupperd.service",
    ]
    .into_iter()
    .map(|name| (name.into(), format!("release-{name}").into_bytes()))
    .collect();
    let archive = release::encode(members).unwrap();
    fs::write(stage.join("archive.tar.gz"), &archive).unwrap();
    let (result, output) = call(
        host,
        gateway,
        &RealFs,
        "Stage",
        Some(("sha256", &release::hash(&archive))),
    );
    result.unwrap();
    assert!(output.contains("MANIFEST verified"));
    stage
}
fn plan(host: &Host, gateway: &Gateway) -> DeployPlan {
    let (result, output) = call(host, gateway, &RealFs, "Plan", None);
    result.unwrap();
    serde_json::from_str(&output).unwrap()
}
fn installed() -> (Host, Gateway) {
    let host = Host::new();
    let gateway = Gateway::default();
    host.apply(&gateway.fake);
    gateway.fake.calls.borrow_mut().clear();
    (host, gateway)
}
fn switch(
    host: &Host,
    gateway: &Gateway,
    filesystem: &dyn Fs,
    digest: &str,
) -> (Result<u8, String>, String) {
    call(
        host,
        gateway,
        filesystem,
        "Switch",
        Some(("plan_sha256", digest)),
    )
}
#[test]
fn prepare_requires_store_head_and_both_units() {
    for case in ["binary-only", "no-units", "one-unit", "installed"] {
        let (host, gateway) = if case == "binary-only" {
            (Host::new(), Gateway::default())
        } else {
            installed()
        };
        if case == "binary-only" {
            fs::write(host.paths.at(model::SCUPPER_FILE), "binary").unwrap();
        }
        if matches!(case, "no-units" | "one-unit") {
            fs::remove_file(host.paths.at("/etc/systemd/system/scupperd.service")).unwrap();
            if case == "no-units" {
                fs::remove_file(host.paths.at("/etc/systemd/system/scupper-net.service")).unwrap();
            }
        }
        fs::create_dir_all(host.paths.at("/usr/local/lib")).unwrap();
        let (result, output) = call(&host, &gateway, &RealFs, "Prepare", None);
        result.unwrap();
        assert_eq!(
            output.trim(),
            if case == "installed" {
                "installed"
            } else {
                "fresh"
            }
        );
    }
}
#[test]
fn stage_plan_switch_and_actual_unit_restart_detection() {
    for unit in [None, Some("scupper-net"), Some("scupperd")] {
        let (host, gateway) = installed();
        let stage = stage(&host, &gateway);
        if let Some(unit) = unit {
            fs::write(
                host.paths
                    .at(&format!("/etc/systemd/system/{unit}.service")),
                "old unit",
            )
            .unwrap();
        }
        let plan = plan(&host, &gateway);
        switch(&host, &gateway, &RealFs, plan.plan_sha256.as_str())
            .0
            .unwrap();
        for binary in model::BINARIES {
            assert_eq!(
                fs::read(host.paths.at(&format!("/usr/local/bin/{binary}"))).unwrap(),
                fs::read(stage.join(binary)).unwrap()
            );
            assert_eq!(
                fs::read(host.paths.at(&format!("/usr/local/bin/{binary}.prev"))).unwrap(),
                format!("new-{binary}").as_bytes()
            );
        }
        let services = gateway.services.borrow();
        let restarts: Vec<_> = services
            .iter()
            .filter(|a| a[0] == "restart")
            .map(|a| a[1].as_str())
            .collect();
        assert_eq!(
            restarts,
            if unit == Some("scupper-net") {
                vec!["scupper-net", "scupperd"]
            } else {
                vec!["scupperd"]
            }
        );
        let reload = services
            .iter()
            .position(|a| a[0] == "daemon-reload")
            .unwrap();
        let restart = services.iter().position(|a| a[0] == "restart").unwrap();
        assert!(reload < restart);
    }
}
#[test]
fn tampered_members_refuse_plan_and_switch_without_mutations() {
    let (host, gateway) = installed();
    let stage = stage(&host, &gateway);
    let digest = plan(&host, &gateway).plan_sha256;
    fs::write(stage.join("scupperd"), "tampered").unwrap();
    let before = host.snapshot();
    for (op, extra) in [
        ("Plan", None),
        ("Switch", Some(("plan_sha256", digest.as_str()))),
    ] {
        let (result, output) = call(&host, &gateway, &RealFs, op, extra);
        let error = if op == "Switch" {
            assert_eq!(result.unwrap(), SwitchOutcome::RefusedNoChange.exit_code());
            assert!(output.contains("refused, nothing changed"));
            assert!(!output.contains(model::RESTORE_COMMANDS));
            output
        } else {
            result.unwrap_err()
        };
        assert!(error.contains("staged member mismatch"), "{error}");
        assert_eq!(host.snapshot(), before);
        assert!(gateway.services.borrow().is_empty());
    }
}
#[test]
fn stage_refuses_wrong_digest_before_writing_members() {
    let host = Host::new();
    let gateway = Gateway::default();
    fs::create_dir_all(host.paths.at("/usr/local/lib")).unwrap();
    call(&host, &gateway, &RealFs, "Prepare", None).0.unwrap();
    let path = host.paths.at("/usr/local/lib/scupper/deploy/d1/new");
    fs::write(path.join("archive.tar.gz"), "broken").unwrap();
    let before = host.snapshot();
    assert!(
        call(
            &host,
            &gateway,
            &RealFs,
            "Stage",
            Some(("sha256", &"0".repeat(64)))
        )
        .0
        .unwrap_err()
        .contains("checksum mismatch")
    );
    assert_eq!(host.snapshot(), before);
}
#[test]
fn changed_plan_is_refused_before_any_write_or_restart() {
    let (host, gateway) = installed();
    stage(&host, &gateway);
    let digest = plan(&host, &gateway).plan_sha256;
    // Change the old binary, keeping the displayed replacement plan identical.
    fs::write(host.paths.at(model::SCUPPER_FILE), "different old binary").unwrap();
    let before = host.snapshot();
    let (result, error) = switch(&host, &gateway, &RealFs, digest.as_str());
    assert_eq!(result.unwrap(), SwitchOutcome::RefusedNoChange.exit_code());
    assert!(error.contains("plan changed since confirmation"), "{error}");
    assert!(error.contains("refused, nothing changed"));
    assert!(!error.contains(model::RESTORE_COMMANDS));
    assert_eq!(before, host.snapshot());
    assert!(gateway.services.borrow().is_empty());
}
#[test]
fn failed_reload_never_restarts_and_failed_restart_or_timeout_prints_recovery() {
    for failure in ["reload", "restart", "timeout"] {
        let (host, gateway) = installed();
        stage(&host, &gateway);
        fs::write(
            host.paths.at("/etc/systemd/system/scupper-net.service"),
            "old unit",
        )
        .unwrap();
        let digest = plan(&host, &gateway).plan_sha256;
        *gateway.fail.borrow_mut() = Some(failure);
        let (result, output) = switch(&host, &gateway, &RealFs, digest.as_str());
        assert_eq!(
            result.unwrap(),
            SwitchOutcome::FailedAfterRename.exit_code()
        );
        let error = &output;
        assert_eq!(output.matches(model::RESTORE_COMMANDS).count(), 1);
        if failure == "reload" {
            assert!(gateway.services.borrow().iter().all(|a| a[0] != "restart"));
        }
        if failure == "timeout" {
            assert!(error.contains("timed out"), "{error}");
        }
    }
}
struct FailAfterFirstRename {
    bin: PathBuf,
    renames: RefCell<Vec<String>>,
}
impl Fs for FailAfterFirstRename {
    fn check_target(&self, path: &Path) -> io::Result<()> {
        RealFs.check_target(path)
    }
    fn cleanup_stale(&self, path: &Path) -> io::Result<()> {
        RealFs.cleanup_stale(path)
    }
    fn read(&self, path: &Path) -> io::Result<String> {
        RealFs.read(path)
    }
    fn create_temp(&self, path: &Path) -> io::Result<(PathBuf, Box<dyn TempFile>)> {
        RealFs.create_temp(path)
    }
    fn rename(&self, source: &Path, destination: &Path) -> io::Result<()> {
        let name = destination.file_name().unwrap().to_str().unwrap();
        if model::BINARIES.contains(&name) {
            // These assertions execute BEFORE the first live rename.
            for binary in model::BINARIES {
                assert_eq!(
                    fs::read(self.bin.join(format!("{binary}.prev"))).unwrap(),
                    format!("new-{binary}").as_bytes()
                );
            }
        }
        RealFs.rename(source, destination)?;
        self.renames.borrow_mut().push(name.into());
        Ok(())
    }
    fn sync_dir(&self, path: &Path) -> io::Result<()> {
        if self.renames.borrow().last().is_some_and(|s| s == "scupper") {
            return Err(io::Error::other("injected I/O failure after first rename"));
        }
        RealFs.sync_dir(path)
    }
    fn remove(&self, path: &Path) -> io::Result<()> {
        RealFs.remove(path)
    }
}
#[test]
fn first_rename_fault_has_both_previous_files_and_prints_recovery() {
    let (host, gateway) = installed();
    stage(&host, &gateway);
    let digest = plan(&host, &gateway).plan_sha256;
    let filesystem = FailAfterFirstRename {
        bin: host.paths.at(model::BIN_ROOT),
        renames: RefCell::default(),
    };
    let (result, output) = switch(&host, &gateway, &filesystem, digest.as_str());
    assert_eq!(
        result.unwrap(),
        SwitchOutcome::FailedAfterRename.exit_code()
    );
    assert_eq!(output.matches(model::RESTORE_COMMANDS).count(), 1);
    assert_eq!(
        *filesystem.renames.borrow(),
        ["scupper.prev", "scupperd.prev", "scupper"]
    );
    assert_eq!(
        fs::read(host.paths.at("/usr/local/bin/scupperd")).unwrap(),
        b"new-scupperd"
    );
    assert!(gateway.services.borrow().is_empty());
}
#[test]
fn dispatcher_has_clear_manual_upgrade_instructions() {
    assert!(deploy::REMOTE_COMMAND.contains(&format!(
        "requires scupper {} with M2-2u remote support",
        env!("CARGO_PKG_VERSION")
    )));
    assert!(deploy::REMOTE_COMMAND.contains("copy the matching release archive"));
    assert!(deploy::REMOTE_COMMAND.contains("install --binaries"));
}

#[test]
fn missing_binary_and_prepare_refusal_omit_recovery() {
    for refusal in ["missing-binary", "prepare"] {
        let (host, mut gateway) = installed();
        stage(&host, &gateway);
        if refusal == "missing-binary" {
            fs::remove_file(host.paths.at(model::SCUPPER_FILE)).unwrap();
        } else {
            gateway.fake.missing_packages = true;
        }
        let digest = if refusal == "prepare" {
            "0".repeat(64)
        } else {
            String::from(plan(&host, &gateway).plan_sha256)
        };
        let before = host.snapshot();
        let (result, output) = switch(&host, &gateway, &RealFs, &digest);
        assert_eq!(result.unwrap(), SwitchOutcome::RefusedNoChange.exit_code());
        assert!(output.contains("refused, nothing changed"), "{output}");
        if refusal == "missing-binary" {
            assert!(
                output.contains("requires both installed binaries"),
                "{output}"
            );
        }
        assert!(!output.contains(model::RESTORE_COMMANDS));
        assert_eq!(before, host.snapshot());
        assert!(gateway.services.borrow().is_empty());
    }
}
#[test]
fn empty_and_unit_only_plan_restart_failure_omit_recovery() {
    for unit_only in [false, true] {
        let (host, gateway) = installed();
        let stage = stage(&host, &gateway);
        // Match the release without creating .prev files in this switch.
        for binary in model::BINARIES {
            fs::copy(
                stage.join(binary),
                host.paths.at(&format!("/usr/local/bin/{binary}")),
            )
            .unwrap();
        }
        if unit_only {
            fs::write(
                host.paths.at("/etc/systemd/system/scupperd.service"),
                "old unit",
            )
            .unwrap();
        }
        let plan = plan(&host, &gateway);
        if !unit_only {
            assert!(plan.plan.contains("no changes"), "{}", plan.plan);
        }
        *gateway.fail.borrow_mut() = Some("restart");
        let (result, output) = switch(&host, &gateway, &RealFs, plan.plan_sha256.as_str());
        assert_eq!(result.unwrap(), SwitchOutcome::PossiblyChanged.exit_code());
        assert!(output.contains("possibly changed"));
        if unit_only {
            assert!(output.contains("changed: /etc/systemd/system/scupperd.service"));
        }
        assert!(output.contains("restart scupperd"));
        assert!(!output.contains(model::RESTORE_COMMANDS));
        for binary in model::BINARIES {
            assert!(
                !host
                    .paths
                    .at(&format!("/usr/local/bin/{binary}.prev"))
                    .exists()
            );
        }
    }
}

#[test]
fn apply_precondition_error_reports_no_rename_without_recovery() {
    let (host, gateway) = installed();
    let stage = stage(&host, &gateway);
    let prepared = scupper_sys::install::prepare(
        &gateway,
        &host.paths,
        &scupper_sys::install::Options {
            binaries: stage,
            ..Default::default()
        },
    )
    .unwrap();
    fs::write(host.paths.at(model::SCUPPER_FILE), "changed after prepare").unwrap();
    let before = host.snapshot();
    let error =
        scupper_sys::install::apply_with_fs(&gateway, &host.paths, prepared, &RealFs).unwrap_err();
    assert!(!error.replaced);
    assert!(error.reason.contains("host changed"), "{}", error.reason);
    assert!(!error.reason.contains(model::RESTORE_COMMANDS));
    assert_eq!(before, host.snapshot());
    assert!(gateway.services.borrow().is_empty());
}

#[test]
fn apply_error_directly_records_first_rename() {
    let (host, gateway) = installed();
    let stage = stage(&host, &gateway);
    let prepared = scupper_sys::install::prepare(
        &gateway,
        &host.paths,
        &scupper_sys::install::Options {
            binaries: stage,
            ..Default::default()
        },
    )
    .unwrap();
    let filesystem = FailAfterFirstRename {
        bin: host.paths.at(model::BIN_ROOT),
        renames: RefCell::default(),
    };
    let error = scupper_sys::install::apply_with_fs(&gateway, &host.paths, prepared, &filesystem)
        .unwrap_err();
    assert!(error.replaced);
    assert!(error.reason.contains("after first rename"));
}

#[test]
fn previous_file_failure_before_live_rename_omits_recovery() {
    let (host, gateway) = installed();
    stage(&host, &gateway);
    // A directory at .prev makes the durable backup write refuse before live renames.
    fs::create_dir(host.paths.at("/usr/local/bin/scupper.prev")).unwrap();
    let digest = plan(&host, &gateway).plan_sha256;
    let before = host.snapshot();
    let (result, output) = switch(&host, &gateway, &RealFs, digest.as_str());
    assert_eq!(result.unwrap(), SwitchOutcome::RefusedNoChange.exit_code());
    assert!(output.contains("refused, nothing changed"));
    assert!(!output.contains(model::RESTORE_COMMANDS));
    assert_eq!(before, host.snapshot());
    assert!(gateway.services.borrow().is_empty());
}

#[test]
fn apply_precondition_refusal_reaches_gateway_without_recovery() {
    let (host, gateway) = installed();
    stage(&host, &gateway);
    let digest = plan(&host, &gateway).plan_sha256;
    let path = host.paths.at(model::SCUPPER_FILE);
    let mut expected = host.snapshot();
    expected.get_mut(&path).unwrap().0 = b"external change before apply".to_vec();
    // Switch prepares once, then apply observes again under its own preconditions.
    *gateway.change_on_observe.borrow_mut() = Some((path, 2));
    let (result, output) = switch(&host, &gateway, &RealFs, digest.as_str());
    assert_eq!(result.unwrap(), SwitchOutcome::RefusedNoChange.exit_code());
    assert!(
        output.contains("host changed since install was planned"),
        "{output}"
    );
    assert!(output.contains("refused, nothing changed"));
    assert!(!output.contains(model::RESTORE_COMMANDS));
    assert_eq!(host.snapshot(), expected);
    assert!(gateway.services.borrow().is_empty());
}

struct FailUnitWrite {
    after_rename: bool,
    renamed: Cell<bool>,
}
impl Fs for FailUnitWrite {
    fn check_target(&self, p: &Path) -> io::Result<()> {
        RealFs.check_target(p)
    }
    fn cleanup_stale(&self, p: &Path) -> io::Result<()> {
        RealFs.cleanup_stale(p)
    }
    fn read(&self, p: &Path) -> io::Result<String> {
        RealFs.read(p)
    }
    fn create_temp(&self, p: &Path) -> io::Result<(PathBuf, Box<dyn TempFile>)> {
        RealFs.create_temp(p)
    }
    fn rename(&self, a: &Path, b: &Path) -> io::Result<()> {
        if b.file_name().is_some_and(|s| s == "scupperd.service") {
            if !self.after_rename {
                return Err(io::Error::other("injected failed unit write"));
            }
            RealFs.rename(a, b)?;
            self.renamed.set(true);
            Ok(())
        } else {
            RealFs.rename(a, b)
        }
    }
    fn sync_dir(&self, p: &Path) -> io::Result<()> {
        if self.renamed.get() {
            Err(io::Error::other("injected unit sync failure"))
        } else {
            RealFs.sync_dir(p)
        }
    }
    fn remove(&self, p: &Path) -> io::Result<()> {
        RealFs.remove(p)
    }
}
#[test]
fn unit_write_failure_reports_confirmed_and_possible_changes() {
    for after_rename in [false, true] {
        let (host, gateway) = installed();
        let stage = stage(&host, &gateway);
        for binary in model::BINARIES {
            fs::copy(
                stage.join(binary),
                host.paths.at(&format!("/usr/local/bin/{binary}")),
            )
            .unwrap();
        }
        let unit = host.paths.at("/etc/systemd/system/scupperd.service");
        fs::write(&unit, "old unit").unwrap();
        let digest = plan(&host, &gateway).plan_sha256;
        let filesystem = FailUnitWrite {
            after_rename,
            renamed: Cell::new(false),
        };
        let (result, output) = switch(&host, &gateway, &filesystem, digest.as_str());
        let outcome = if after_rename {
            SwitchOutcome::FailedAfterChange
        } else {
            SwitchOutcome::PossiblyChanged
        };
        assert_eq!(result.unwrap(), outcome.exit_code(), "{output}");
        assert!(
            output.contains(if after_rename {
                "changed: /etc/systemd/system/scupperd.service"
            } else {
                "possibly changed: /etc/systemd/system/scupperd.service"
            }),
            "{output}"
        );
        assert!(!output.contains("nothing changed"));
        assert_eq!(
            fs::read_to_string(unit).unwrap() == "old unit",
            !after_rename
        );
    }
}
