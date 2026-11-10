//! Opt-in lab evidence for each worker attempt, using only public observations.
use crate::reconcile::Config;
use crate::{
    cmd::{IpCmd, KernelCmd, WgCmd, WgField, run_netns_cmd},
    netns::NetnsHandle,
    system::System,
};
use scupper_core::render::Family;
use scupper_core::verdict::v2::Report;
use scupper_proto::ApiError;
use std::time::{Duration, Instant};
use std::{fs::File, io::Write, path::Path};

pub(super) struct Trace {
    file: File,
    observation: serde_json::Value,
}
impl Trace {
    pub(super) fn start(
        system: &dyn System,
        held: &NetnsHandle,
        config: &Config,
        deadline: Instant,
        path: &Path,
    ) -> Option<Self> {
        // The lab creates this file only for the command being measured.
        let file = File::options().append(true).open(path).ok()?;
        let read = |command| {
            let budget = deadline
                .saturating_duration_since(Instant::now())
                .min(Duration::from_millis(250));
            if budget.is_zero() {
                return serde_json::json!({"error": "verification deadline"});
            }
            match run_netns_cmd(system, held, &command, budget) {
                Ok(output) => {
                    serde_json::json!({"status": output.status, "stdout": output.stdout, "stderr": output.stderr})
                }
                Err(error) => serde_json::json!({"error": error.to_string()}),
            }
        };
        let at = system.now_unix_secs();
        let mut handshakes = Vec::new();
        for exit in config.site.gateway(&config.gateway)?.exits() {
            let output = read(KernelCmd::Wg(WgCmd::Show {
                ifname: exit.ifname().ifname().clone(),
                field: WgField::LatestHandshakes,
            }));
            let ages = output["stdout"].as_str().unwrap_or_default().lines()
                .filter_map(|line| {
                    let mut fields = line.split_whitespace();
                    let peer = fields.next()?;
                    let timestamp = fields.next()?.parse::<u64>().ok()?;
                    Some(serde_json::json!({"peer": peer, "age": (timestamp != 0).then(|| at.saturating_sub(timestamp))}))
                }).collect::<Vec<_>>();
            handshakes
                .push(serde_json::json!({"exit": exit.ifname(), "ages": ages, "output": output}));
        }
        let mut trace = Self {
            file,
            observation: serde_json::json!({
                "phase": "started",
                "at": at, "remaining_ms": deadline.saturating_duration_since(Instant::now()).as_millis(),
                "handshakes": handshakes,
                "v4": read(KernelCmd::Ip(IpCmd::DefaultShowJson(Family::V4))),
                "v6": read(KernelCmd::Ip(IpCmd::DefaultShowJson(Family::V6))),
            }),
        };
        // Record the attempt before verification: a worker can still be
        // completing when the dispatcher replies at its ten-second deadline.
        trace.append();
        Some(trace)
    }
    fn append(&mut self) {
        let line = format!("{}\n", self.observation);
        let _ = self.file.write_all(line.as_bytes());
    }
    pub(super) fn finish(mut self, result: &Result<Report, ApiError>) {
        self.observation["phase"] = "finished".into();
        self.observation["result"] = match result {
            Ok(report) => serde_json::json!({"report": report}),
            Err(error) => serde_json::json!({"error": error}),
        };
        self.append();
    }
}
