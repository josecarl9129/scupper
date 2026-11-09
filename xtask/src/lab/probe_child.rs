//! Real privilege-dropping CLI probes, including bound unreachable-default DNS.
use super::{Lab, Result, addresses::A, fail};
use scupper_sys::{
    netns::NetnsHandle,
    probe_child::{
        ProbeCredentials, ProbeExec, ProbeIdentity, ProbeKind, ProbeRequest, ProbeResult, run_probe,
    },
    rules::IfName,
    system::{ExecError, ExecOutput, execute_file_command},
};
use std::{fs, io::Write, path::PathBuf, process::Command, time::Duration};

struct Executable(PathBuf);
impl ProbeExec for Executable {
    fn execute_probe(
        &self,
        json: &str,
        namespace: fs::File,
        timeout: Duration,
    ) -> std::result::Result<ExecOutput, ExecError> {
        let mut command = Command::new(&self.0);
        command.args(["probe", json]);
        execute_file_command(command, namespace, timeout)
    }
}
impl Lab {
    pub(super) fn probe_child_case(&mut self) -> Result<()> {
        let binary = std::env::current_exe()?
            .parent()
            .and_then(std::path::Path::parent)
            .ok_or("lab executable must be in target/{profile}")?
            .join("debug/scupper");
        let exec = Executable(fs::canonicalize(binary)?);
        let identity = ProbeIdentity::parse(
            &fs::read_to_string("/etc/passwd")?,
            &fs::read_to_string("/etc/group")?,
        )?;
        let handle = NetnsHandle::open("/run/netns/scupper")?;
        // ip netns exec's mount overlay is deliberately poisoned. setns alone
        // inherits the host mount namespace; neither source is ever consulted.
        let resolv = PathBuf::from("/etc/netns/scupper/resolv.conf");
        let old = fs::read(&resolv)?;
        fs::write(&resolv, "nameserver 127.0.0.53\n")?;
        let result = (|| {
            for (kind, bind) in [
                (ProbeKind::Path, None),
                (ProbeKind::ExitIp, None),
                (ProbeKind::Path, Some(IfName::new("ex-ch1")?)),
            ] {
                if bind.is_some() {
                    // Remove the connected provider route too, so reaching DNS
                    // depends on the bound-device IPv4 fallback (V-02).
                    // ex-ch1 carries a /32, so usually there is no connected route;
                    // an absent route is the state we want.
                    let _ = self.runner.output(
                        &super::command::Invocation::new(
                            "scupper",
                            "ip",
                            &["route", "del", A.exit_net, "dev", "ex-ch1"],
                        ),
                        None,
                    )?;
                    self.cmd(
                        "scupper",
                        "ip",
                        &["route", "replace", "unreachable", "default"],
                    )?;
                    self.cmd(
                        "scupper",
                        "sysctl",
                        &[
                            "-q",
                            "-w",
                            "net.ipv4.conf.all.rp_filter=0",
                            "net.ipv4.conf.ex-ch1.rp_filter=0",
                        ],
                    )?;
                }
                self.runner.check()?;
                let request: ProbeRequest = serde_json::from_value(serde_json::json!({
                    "kind": kind,
                    "bind": bind.as_ref().map(IfName::as_str),
                    "expected_netns": handle.identity(),
                    "dns": A.provider_inner,
                    "targets": ["https://probe-child.lab.test/"],
                    "deadline_ms": 0,
                }))?;
                let outcome = run_probe(&exec, &handle, &request)?;
                if outcome.credentials
                    != Some(ProbeCredentials {
                        uids: [identity.uid; 4],
                        gids: [identity.gid; 4],
                        no_new_privs: true,
                        cap_bnd: 0,
                    })
                    || outcome.threads_before_setns != Some(1)
                {
                    return fail("probe child parsed with unexpected credentials or thread count");
                }
                let expected = match kind {
                    ProbeKind::Path => matches!(outcome.result, ProbeResult::Success { ip: None }),
                    // The isolated sink has no trusted HTTPS service. DNS must
                    // work and connect/TLS failure must remain a path failure.
                    ProbeKind::ExitIp => matches!(
                        outcome.result,
                        ProbeResult::Path { .. } | ProbeResult::Timeout
                    ),
                };
                let path = self.artifacts.join("probe-child.outcomes.jsonl");
                writeln!(
                    fs::OpenOptions::new()
                        .create(true)
                        .append(true)
                        .open(path)?,
                    "{}",
                    serde_json::json!({"request": request, "outcome": outcome})
                )?;
                if !expected {
                    return fail(format!("unexpected child outcome: {:?}", outcome.result));
                }
            }
            Ok(())
        })();
        let restored_resolver = fs::write(resolv, old);
        // case() also restores forwarding/rules/sysctls on every error.
        let restored_route = self.restore_probe_child_routes();
        result?;
        restored_resolver?;
        restored_route
    }
    pub(super) fn restore_probe_child_routes(&mut self) -> Result<()> {
        self.cmd(
            "scupper",
            "ip",
            &[
                "route",
                "replace",
                A.exit_net,
                "dev",
                "ex-ch1",
                "scope",
                "link",
                "src",
                A.exit_inner,
            ],
        )?;
        self.cmd(
            "scupper",
            "ip",
            &["route", "replace", "default", "dev", "ex-ch1"],
        )?;
        Ok(())
    }
}
