//! Deterministic daemon-only stop during an interrupted inventory observation.
use super::{A, DaemonGuard, Duration, Result, Signal, fail, fs};
use scupper_proto::EventKind;
use scupper_sys::events::read_since;

impl DaemonGuard<'_> {
    pub(super) fn run_stop_observation(&mut self) -> Result<String> {
        let root = self.lab.prepare_check_v2()?;
        if let scupper_sys::state::StateRead::Present(state) =
            scupper_sys::state::StateFile::open(root.join("var-lib/scupper"), None)?.read()?
        {
            self.baseline_version = state.applied_version;
        }
        self.supervised_fixture(&root)?;
        self.lab.boot_gateway(&[], "stop-observation-boot")?;
        let (child, notify) = self.lab.daemon_start("stop-observation", &root)?;
        self.child = Some(child);
        self.notify = Some(notify);
        self.lab
            .daemon_ready_tick(self.notify.as_ref().ok_or("missing notify")?)?;
        self.expect_check(&root, 0, None, "before")?;
        let stem = "daemon-stop-observation";
        let port = self.lab.exit_port;
        self.lab.capture("wan", A.gwhost.wan_if, stem)?;
        let mut markers = Vec::new();
        self.lab.service_check(&mut markers)?;
        let run = root.join("run/scupper");
        fs::write(run.join("hold-observation"), b"hold")?;
        fs::write(run.join("pause-observation-once"), b"arm")?;
        self.lab
            .daemon_wait("observation pause", Duration::from_secs(8), |_| {
                Ok(run.join("observation-paused").exists())
            })?;
        let state = root.join("var-lib/scupper");
        let baseline = read_since(&state, 0, None)
            .collect::<std::io::Result<Vec<_>>>()?
            .last()
            .map_or(0, |event| event.seq);
        let before = self.lab.daemon_snapshot()?;
        let child = self.child.as_mut().ok_or("missing daemon")?;
        let pid = child.supervised_pid()?.ok_or("missing daemon PID")?;
        let pid = rustix::process::Pid::from_raw(pid.cast_signed()).ok_or("invalid daemon PID")?;
        self.notify
            .as_ref()
            .ok_or("missing notify")?
            .stop(Signal::TERM, || {
                // Match KillMode=mixed: TERM only the daemon, leave helpers alone.
                rustix::process::kill_process(pid, Signal::TERM)?;
                fs::remove_file(run.join("hold-observation"))?;
                let status = child.wait_timeout(Duration::from_secs(30))?;
                if !status.success() {
                    return fail(format!("stop observation exited {status}"));
                }
                Ok(())
            })?;
        self.child.take();
        super::cleanup_control_socket(&run, false)?;
        if before != self.lab.daemon_snapshot()? {
            return fail("stop observation changed kernel state");
        }
        if self
            .lab
            .cmd("scupper", "sysctl", &["-n", "net.ipv4.ip_forward"])?
            .trim()
            != "1"
        {
            return fail("stop observation left forwarding disabled");
        }
        let links: serde_json::Value = serde_json::from_str(&self.lab.cmd(
            "scupper",
            "ip",
            &["-j", "link", "show", "dev", "wg0"],
        )?)?;
        if !links[0]["flags"]
            .as_array()
            .is_some_and(|flags| flags.iter().any(|flag| flag == "UP"))
        {
            return fail("stop observation left wg0 down");
        }
        let events = read_since(&state, baseline, None).collect::<std::io::Result<Vec<_>>>()?;
        if events.iter().any(|event| {
            matches!(
                event.kind,
                EventKind::Repair { .. }
                    | EventKind::QuarantineChanged { active: true }
                    | EventKind::IngressQuarantineChanged { active: true }
            ) || event.alert().is_some_and(|alert| {
                matches!(
                    alert.key,
                    scupper_core::alerts::AlertKey::Quarantine
                        | scupper_core::alerts::AlertKey::IngressQuarantine
                )
            })
        }) {
            return fail("stop observation emitted a repair or quarantine alert");
        }
        if !state.join("events/clean").exists() {
            return fail("stop observation did not drain audit log");
        }
        fs::write(
            self.lab.artifacts.join("stop-observation-events.json"),
            serde_json::to_vec_pretty(&events)?,
        )?;
        self.lab.service_check(&mut markers)?;
        self.lab.stop_captures()?;
        self.lab.daemon_oracle(stem, &markers, port, port)?;
        self.lab.daemon_capture_control(stem)?;
        Ok("TERM inside observation; no repairs/quarantine; forwarding=1; wg0 UP; strict leak oracle and injected control passed".into())
    }
}
