//! Retired-layout preflight observations through a scripted system.
#![allow(clippy::unwrap_used)]
use scupper_sys::{
    system::{EXEC_TIMEOUT, ExecError, ExecOutput, Program, SYSTEMCTL_TIMEOUT, System},
    v1_detect::{V1Marker, detect_v1_layout},
};
use std::{cell::RefCell, collections::VecDeque, time::Duration};
struct Reply {
    program: Program,
    args: Vec<String>,
    output: Result<ExecOutput, ExecError>,
}
struct Fake(RefCell<VecDeque<Reply>>);
impl Fake {
    fn new() -> Self {
        Self(RefCell::default())
    }
    fn push(&self, program: Program, args: &[&str], status: i32, stdout: &str) {
        self.0.borrow_mut().push_back(Reply {
            program,
            args: args.iter().map(|s| (*s).into()).collect(),
            output: Ok(ExecOutput {
                status: Some(status),
                stdout: stdout.into(),
                stderr: String::new(),
            }),
        });
    }
    fn units(&self, text: &str) {
        self.push(
            Program::Systemctl,
            &[
                "list-unit-files",
                "--type=service",
                "--no-legend",
                "--no-pager",
                "wg-quick@*.service",
            ],
            0,
            text,
        );
    }
    fn host(&self, tables: &str, links: &str) {
        self.push(Program::Nft, &["-j", "list", "tables"], 0, tables);
        self.push(Program::Ip, &["-d", "-j", "link", "show"], 0, links);
    }
}
impl System for Fake {
    fn run(
        &self,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        let reply = self.0.borrow_mut().pop_front().unwrap();
        assert_eq!(program, reply.program);
        assert_eq!(args, reply.args);
        assert_eq!(
            timeout,
            if program == Program::Systemctl {
                SYSTEMCTL_TIMEOUT
            } else {
                EXEC_TIMEOUT
            }
        );
        reply.output
    }
    fn now_unix_secs(&self) -> u64 {
        0
    }
}
#[test]
fn detects_enabled_instances_table_and_v1_tunnel_names_only() {
    let sys = Fake::new();
    sys.units("wg-quick@custom.service disabled enabled\nwg-quick@wg0.service enabled enabled\nwg-quick@proton0.service enabled enabled\n");
    sys.push(
        Program::Systemctl,
        &["is-enabled", "wg-quick@custom.service"],
        0,
        "enabled-runtime\n",
    );
    // The listing is just discovery: is-enabled is authoritative, even if it changed.
    sys.push(
        Program::Systemctl,
        &["is-enabled", "wg-quick@proton0.service"],
        1,
        "disabled\n",
    );
    sys.push(
        Program::Systemctl,
        &["is-enabled", "wg-quick@wg0.service"],
        0,
        "enabled\n",
    );
    sys.host(r#"{"nftables":[{"metainfo":{}},{"table":{"family":"inet","name":"scupper"}},{"table":{"family":"ip","name":"scupper"}}]}"#,
        r#"[{"ifname":"lo","flags":["UP"]},{"ifname":"eth0","flags":["UP"]},{"ifname":"wg0","flags":[]},{"ifname":"proton0","flags":[]},{"ifname":"ex-ch1","flags":[]}]"#);
    assert_eq!(
        detect_v1_layout(&sys).unwrap(),
        vec![
            V1Marker::EnabledWgQuick("wg-quick@custom.service".into()),
            V1Marker::EnabledWgQuick("wg-quick@wg0.service".into()),
            V1Marker::HostTable,
            V1Marker::HostLink("wg0".into()),
            V1Marker::HostLink("proton0".into())
        ]
    );
    assert!(sys.0.borrow().is_empty());
}
#[test]
fn absence_disabled_and_masked_units_are_clean() {
    for (state, status) in [
        ("disabled", 1),
        ("masked", 1),
        ("static", 0),
        ("not-found", 4),
        ("linked", 1),
    ] {
        let sys = Fake::new();
        sys.units("wg-quick@wg0.service disabled\n");
        sys.push(
            Program::Systemctl,
            &["is-enabled", "wg-quick@wg0.service"],
            status,
            state,
        );
        sys.host(r#"{"nftables":[{"table":{"family":"ip","name":"scupper"}},{"table":{"family":"inet","name":"other"}}]}"#, r#"[{"ifname":"eth0","flags":[]}]"#);
        assert_eq!(detect_v1_layout(&sys).unwrap(), []);
    }
    let sys = Fake::new();
    sys.units("wg-quick@.service disabled enabled\n");
    sys.host(r#"{"nftables":[]}"#, "[]");
    assert_eq!(detect_v1_layout(&sys).unwrap(), []);
}
#[test]
fn errors_and_malformed_observations_are_never_absence() {
    let sys = Fake::new();
    sys.units("unexpected output");
    assert!(detect_v1_layout(&sys).is_err());
    let sys = Fake::new();
    sys.units("wg-quick@wg0.service enabled\n");
    sys.push(
        Program::Systemctl,
        &["is-enabled", "wg-quick@wg0.service"],
        1,
        "",
    );
    assert!(detect_v1_layout(&sys).is_err());
    for tables in [
        "invalid",
        r#"{"nftables":[{}]}"#,
        r#"{"nftables":[{"table":{"name":"scupper"}}]}"#,
    ] {
        let sys = Fake::new();
        sys.units("");
        sys.host(tables, "[]");
        assert!(detect_v1_layout(&sys).is_err());
    }
    let sys = Fake::new();
    sys.units("");
    sys.host(r#"{"nftables":[]}"#, "malformed");
    assert!(detect_v1_layout(&sys).is_err());
    let sys = Fake::new();
    sys.units("");
    sys.0.borrow_mut().front_mut().unwrap().output = Err(ExecError::Timeout {
        after: SYSTEMCTL_TIMEOUT,
    });
    assert!(detect_v1_layout(&sys).is_err());
}
