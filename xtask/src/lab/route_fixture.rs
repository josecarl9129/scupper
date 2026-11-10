//! L19 policy drift after topology inventory, using the real staged driver.
use super::{Result, fail, probe_child::Executable};
use scupper_core::{
    config::{GatewayId, parse_site, validate},
    render::VersionStamp,
};
use scupper_sys::{
    check_v2::{self, Config, Dependencies},
    netns::NetnsHandle,
    store::VersionStore,
    system::{ExecError, ExecOutput, ExecTarget, Program, RealSystem, System},
};
use sha2::{Digest, Sha256};
use std::{cell::Cell, path::Path, time::Duration};

/// The lab changes kernel state, never collected observations. The first
/// forwarding read follows topology and default inventory in the real driver.
struct PolicyDrift {
    real: RealSystem,
    installed: Cell<bool>,
}
impl System for PolicyDrift {
    fn canon_cache(&self) -> Option<(&std::cell::RefCell<scupper_sys::canon::CanonCache>, &Path)> {
        self.real.canon_cache()
    }
    fn canon_worker(&self) -> Option<Box<dyn System + Send>> {
        self.real.canon_worker()
    }
    fn canon_executable(&self) -> &Path {
        self.real.canon_executable()
    }
    fn canon_run_root(&self) -> &Path {
        self.real.canon_run_root()
    }
    fn run(
        &self,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> std::result::Result<ExecOutput, ExecError> {
        self.run_in(ExecTarget::Host, program, args, timeout)
    }
    fn run_in(
        &self,
        target: ExecTarget<'_>,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> std::result::Result<ExecOutput, ExecError> {
        let output = self.real.run_in(target, program, args, timeout)?;
        if matches!(target, ExecTarget::Netns(_))
            && program == Program::Sysctl
            && args == ["-n", "net.ipv4.ip_forward"]
            && !self.installed.get()
        {
            let fault: Vec<_> = ["rule", "add", "pref", "100", "iif", "wg0", "unreachable"]
                .map(str::to_owned)
                .into();
            let result = self.real.run_in(target, Program::Ip, &fault, timeout)?;
            if result.status != Some(0) {
                return Err(ExecError::spawn("L19 policy drift installation failed"));
            }
            self.installed.set(true);
        }
        Ok(output)
    }
    fn now_unix_secs(&self) -> u64 {
        self.real.now_unix_secs()
    }
}

struct RecordingProbe<'a> {
    executable: &'a Path,
    binding: std::cell::RefCell<Option<String>>,
}
impl scupper_sys::probe_child::ProbeExec for RecordingProbe<'_> {
    fn execute_probe(
        &self,
        json: &str,
        namespace: std::fs::File,
        timeout: Duration,
    ) -> std::result::Result<ExecOutput, ExecError> {
        let value: serde_json::Value =
            serde_json::from_str(json).map_err(|_| ExecError::spawn("invalid probe request"))?;
        *self.binding.borrow_mut() = value["bind"].as_str().map(str::to_owned);
        Executable(self.executable.into()).execute_probe(json, namespace, timeout)
    }
}

/// Run inside gwhost; only lab paths and the disposable scupper namespace are used.
/// # Errors
/// Returns setup, real collection and fixture installation failures.
pub fn route_check(root: &Path, binary: &Path) -> Result<u8> {
    let state = root.join("var-lib/scupper");
    let store = VersionStore::read_only(&state, &root.join("etc/scupper"));
    let version = store.head()?.ok_or("missing lab head")?;
    let (text, _) = store.read(version)?;
    let site = validate(parse_site(&text)?).map_err(|e| format!("lab site: {e:?}"))?;
    let handle = NetnsHandle::open("/run/netns/scupper")?;
    let sys = PolicyDrift {
        real: RealSystem::default().with_canon_paths(binary.into(), root.join("run/scupper")),
        installed: Cell::new(false),
    };
    let probe = RecordingProbe {
        executable: binary,
        binding: std::cell::RefCell::new(None),
    };
    let (report, obs) = check_v2::run_with_observations(
        &Dependencies {
            system: &sys,
            probe_exec: &probe,
            handle: Some(&handle),
            run_root: &root.join("run/scupper"),
            state_root: &state,
        },
        &Config {
            site: &site,
            gateway: &GatewayId("gw1".into()),
            stamp: VersionStamp {
                version,
                sha256: Sha256::digest(text.as_bytes()).into(),
            },
        },
    );
    if !sys.installed.get() {
        return fail(format!("L19 did not reach forwarding stage: {report:?}"));
    }
    let report = report?;
    let code = report.verdict.exit_code();
    println!(
        "{}",
        serde_json::to_string(&serde_json::json!({
            "report": report, "routes_observed":obs.routes.is_some(), "defaults_observed":obs.defaults.is_some(), "fault_installed":sys.installed.get(), "probe_binding":*probe.binding.borrow(),
        }))?
    );
    Ok(code)
}
