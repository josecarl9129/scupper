use super::{Config, Kernel, Observation, StepError};
use crate::{
    boot::{self, BootDeps, BootReport},
    canon::{canonicalize, command_result, fingerprint},
    cmd::{
        ConntrackCmd, IpCmd, KernelCmd, NftCmd, SysctlCmd, run_netns_cmd, run_netns_cmd_with_stdin,
        write_sysctl_verified,
    },
    collect,
    lock::WriterGuard,
    netns::{NetnsError, NetnsHandle, restore_mount_until},
    system::EXEC_TIMEOUT,
};
use scupper_core::{
    planner::{Desired, LinkPhase, Step},
    render::{Scope, SysctlFamily, SysctlKey},
    rules::IfName,
    verdict::v2::HealthConfigV2,
};
use std::{
    cell::{Cell, RefCell},
    path::PathBuf,
    sync::Arc,
    time::Instant,
};

/// Production adapter sharing boot's command operations and held namespace.
/// No command targets the mutable namespace name after construction.
pub struct RealKernel<'a> {
    deps: BootDeps<'a>,
    held: Arc<NetnsHandle>,
    desired: Desired,
    exit_keys:
        std::collections::BTreeMap<scupper_core::config::ExitId, scupper_core::config::SecretName>,
    health: HealthConfigV2,
    namespace_path: PathBuf,
    edge_path: RefCell<Option<PathBuf>>,
    owned_links: RefCell<std::collections::BTreeMap<String, u32>>,
    memory_latch: Cell<bool>,
    owned_dirty: Cell<bool>,
    flushed: Cell<bool>,
    state: crate::state::StateFile,
    key_read: RefCell<
        Option<
            std::sync::mpsc::Receiver<
                std::collections::BTreeMap<scupper_core::config::ExitId, bool>,
            >,
        >,
    >,
}
impl<'a> RealKernel<'a> {
    /// Build from the applied renderer output and already held namespace.
    /// `health` supplies the existing route collector's connected-route policy.
    /// Supply successful boot's interface identities through `set_owned_links`
    /// before ticking; an empty handoff safely refuses adoption of live links.
    ///
    /// # Errors
    /// Returns invalid applied configuration or gateway errors.
    pub fn new(
        deps: BootDeps<'a>,
        held: Arc<NetnsHandle>,
        config: &Config,
        health: HealthConfigV2,
        namespace_path: PathBuf,
        edge_path: Option<PathBuf>,
    ) -> std::io::Result<Self> {
        let state = crate::state::StateFile::open(deps.state_root, None)?;
        Self::with_state(deps, held, config, health, namespace_path, edge_path, state)
    }
    fn with_state(
        deps: BootDeps<'a>,
        held: Arc<NetnsHandle>,
        config: &Config,
        health: HealthConfigV2,
        namespace_path: PathBuf,
        edge_path: Option<PathBuf>,
        state: crate::state::StateFile,
    ) -> std::io::Result<Self> {
        let desired = config.desired(
            &scupper_core::verdict::v2::Selection::Auto,
            &scupper_core::render::RouteTarget::Unreachable,
        )?;
        let gateway = config
            .site
            .gateway(&config.gateway)
            .ok_or_else(|| std::io::Error::other("unknown gateway"))?;
        let exit_keys = gateway
            .exits()
            .iter()
            .map(|e| (e.id().clone(), e.private_key_ref().clone()))
            .collect();
        Ok(Self {
            deps,
            held,
            desired,
            exit_keys,
            health,
            namespace_path,
            edge_path: RefCell::new(edge_path),
            owned_links: RefCell::new(std::collections::BTreeMap::new()),
            memory_latch: Cell::new(false),
            owned_dirty: Cell::new(false),
            flushed: Cell::new(false),
            state,
            key_read: RefCell::new(None),
        })
    }
    /// Resume ownership from the durable successful boot report, including after
    /// a reconciler restart. Namespace and applied-version identities must match.
    ///
    /// # Errors
    /// Refuses a failed, incomplete, stale or mismatched boot handoff.
    pub fn from_boot_file(
        deps: BootDeps<'a>,
        held: Arc<NetnsHandle>,
        config: &Config,
        health: HealthConfigV2,
        namespace_path: PathBuf,
        edge_path: Option<PathBuf>,
    ) -> std::io::Result<Self> {
        let report: BootReport =
            serde_json::from_slice(&std::fs::read(deps.run_root.join("boot.json"))?)
                .map_err(std::io::Error::other)?;
        let state = crate::state::StateFile::open(deps.state_root, None)?;
        let mut kernel = Self::from_boot_report(deps, held, config, health, report, state)?;
        kernel.namespace_path = namespace_path;
        kernel.edge_path = RefCell::new(edge_path);
        Ok(kernel)
    }
    pub(crate) fn from_boot_report(
        deps: BootDeps<'a>,
        held: Arc<NetnsHandle>,
        config: &Config,
        health: HealthConfigV2,
        report: BootReport,
        state: crate::state::StateFile,
    ) -> std::io::Result<Self> {
        if !report.succeeded()
            || report.applied_version != Some(config.stamp.version)
            || report.netns.map(|n| (n.dev, n.ino)) != Some(held.identity())
        {
            return Err(std::io::Error::other("invalid boot handoff"));
        }
        let kernel = Self::with_state(
            deps,
            held,
            config,
            health,
            "/run/netns/scupper".into(),
            None,
            state,
        )?;
        if kernel
            .desired
            .links()
            .keys()
            .any(|name| !report.owned_links.contains_key(name))
        {
            return Err(std::io::Error::other("missing boot link identities"));
        }
        kernel.set_owned_links(report.owned_links);
        Ok(kernel)
    }
    /// Refresh edge's namespace path after its supervisor reports a new PID.
    pub fn set_edge_path(&self, path: Option<PathBuf>) {
        *self.edge_path.borrow_mut() = path;
    }
    /// Adopt interface identities supplied by a successful boot handoff.
    /// Later observations require the same ifindex as well as `WireGuard` kind;
    /// a recreated same-name interface is a collision until explicitly adopted.
    pub fn set_owned_links(&self, links: std::collections::BTreeMap<String, u32>) {
        *self.owned_links.borrow_mut() = links;
    }
    #[allow(clippy::needless_pass_by_value)] // Commands are single-use values at the dispatch boundary.
    fn run(&self, command: KernelCmd) -> Result<(), StepError> {
        command_result(run_netns_cmd(
            self.deps.system,
            &self.held,
            &command,
            EXEC_TIMEOUT,
        ))
        .map(|_| ())
        .map_err(|_| StepError("kernel operation failed"))
    }
    fn verify(&self, required: [u8; 32]) -> Result<(), StepError> {
        if self.deps.system.canon_cache().is_some() {
            return if required == self.desired.fingerprint()
                && crate::canon::netns_rulesets(
                    self.deps.system,
                    &self.held,
                    self.desired.rendered(),
                )
                .is_ok_and(|(want, live)| want == live)
            {
                Ok(())
            } else {
                Err(StepError("ruleset verification failed"))
            };
        }
        let live = command_result(run_netns_cmd(
            self.deps.system,
            &self.held,
            &KernelCmd::Nft(NftCmd::ListRulesetJson),
            EXEC_TIMEOUT,
        ))
        .and_then(|s| Ok(canonicalize(&s)?));
        if live.is_ok_and(|value| fingerprint(&value) == Ok(required)) {
            Ok(())
        } else {
            Err(StepError("ruleset verification failed"))
        }
    }
    fn forwarding(&self, on: bool, only: Option<&str>) -> Result<(), StepError> {
        forwarding(&self.deps, &self.held, on, only)
    }
    fn link_step(&self, step: &Step) -> Result<(), StepError> {
        let name = match step {
            Step::LinkCreate { link, .. } | Step::LinkReconfigure { link } => &link.name,
            Step::ReResolveEndpoint { exit } => self
                .desired
                .exits()
                .get(exit)
                .ok_or(StepError("unknown exit"))?,
            _ => return Err(StepError("invalid link operation")),
        };
        let cfg = boot::inputs_for_link(&self.deps, &mut BootReport::default(), Some(name))
            .map_err(|_| StepError("applied boot inputs unavailable"))?;
        if cfg.rules != self.desired_rendered() {
            return Err(StepError("applied inputs changed"));
        }
        let result = match step {
            Step::LinkCreate { link, phase } => match phase {
                LinkPhase::CleanupHost => boot::links::cleanup_host(&self.deps, &link.name),
                LinkPhase::HostAddDown => boot::links::add_host(&self.deps, &link.name),
                LinkPhase::Move => boot::links::move_link(&self.deps, &self.held, &link.name),
                LinkPhase::Configure => {
                    boot::links::configure_one(&self.deps, &self.held, &cfg, &link.name)
                }
                LinkPhase::Up => boot::links::set_up(&self.deps, &self.held, &link.name, link.up),
            },
            Step::LinkReconfigure { link } => {
                boot::links::configure_one(&self.deps, &self.held, &cfg, &link.name)
                    .and_then(|()| boot::links::set_up(&self.deps, &self.held, &link.name, link.up))
            }
            Step::ReResolveEndpoint { exit } => self
                .desired
                .exits()
                .get(exit)
                .ok_or_else(|| "unknown exit".to_owned())
                .and_then(|name| boot::links::configure_peers(&self.deps, &self.held, &cfg, name)),
            _ => Err("invalid link operation".into()),
        };
        result.map_err(|_| StepError("boot link operation failed"))?;
        if matches!(
            step,
            Step::LinkCreate {
                phase: LinkPhase::Move,
                ..
            }
        ) {
            for link in boot::inventory(&self.deps, &self.held)
                .map_err(|_| StepError("link identity unavailable"))?
            {
                if link.ifname == *name {
                    self.owned_links
                        .borrow_mut()
                        .insert(link.ifname, link.ifindex);
                    self.owned_dirty.set(true);
                }
            }
        }
        Ok(())
    }
    fn desired_rendered(&self) -> &str {
        self.desired.rendered()
    }
}
impl Kernel for RealKernel<'_> {
    fn checkpoint_owned(&self, guard: &WriterGuard) -> Result<(), StepError> {
        if !self.owned_dirty.get() {
            return Ok(());
        }
        publish_owned(
            self.deps.run_root,
            self.held.identity(),
            &self.owned_links.borrow(),
            guard,
        )?;
        self.owned_dirty.set(false);
        Ok(())
    }

    fn invalidate_state(&self) {
        self.state.invalidate_reads();
    }
    fn observe(&self, held: &NetnsHandle) -> Observation {
        self.flushed.set(false);
        collect::reconcile::observe(
            self.deps.system,
            held,
            &self.desired,
            &self.health,
            &self.namespace_path,
            self.edge_path.borrow().as_deref(),
            &self.owned_links.borrow(),
        )
    }
    fn observe_rest(
        &self,
        held: &NetnsHandle,
        safety: Observation,
        deadline: Instant,
    ) -> Observation {
        let mut observation = collect::reconcile::observe_rest(
            self.deps.system,
            held,
            &self.desired,
            &self.health,
            safety,
            deadline,
        );
        #[cfg(feature = "testing")]
        let owner = self.deps.secret_owner;
        #[cfg(not(feature = "testing"))]
        let owner = 0;
        let mut pending = self.key_read.borrow_mut();
        if pending.is_none() && Instant::now() < deadline {
            let root = self.deps.config_root.to_path_buf();
            let keys = self.exit_keys.clone();
            let (send, receive) = std::sync::mpsc::sync_channel(1);
            if std::thread::Builder::new()
                .name("key-status".into())
                .spawn(move || {
                    let statuses = keys
                        .into_iter()
                        .map(|(exit, reference)| {
                            (
                                exit,
                                crate::secrets::SecretFile::checked_file(&root, &reference, owner)
                                    .is_ok(),
                            )
                        })
                        .collect();
                    let _ = send.send(statuses);
                })
                .is_ok()
            {
                *pending = Some(receive);
            }
        }
        let statuses = pending.as_ref().and_then(|receive| {
            receive
                .recv_timeout(deadline.saturating_duration_since(Instant::now()))
                .ok()
        });
        if let Some(statuses) = statuses {
            *pending = None;
            for (exit, link) in &mut observation.exit_links {
                link.key_present = statuses.get(exit).copied().unwrap_or(false);
            }
        } else {
            observation.complete = false;
            observation.exit_links.clear();
        }
        observation.complete &= Instant::now() < deadline;
        observation
    }
    #[allow(clippy::too_many_lines)]
    fn execute(&self, step: &Step) -> Result<(), StepError> {
        match step {
            Step::ForwardingOff => self.forwarding(false, None),
            Step::ForwardingOn { requires } => {
                // Re-read durable quarantine as well as the executor's memory gate.
                self.state.invalidate_reads();
                let state = self
                    .state
                    .read_until(Instant::now() + EXEC_TIMEOUT)
                    .map_err(|_| StepError("state unavailable"))?;
                let crate::state::StateRead::Present(state) = state else {
                    return Err(StepError("state unavailable"));
                };
                if state.applied_version != Some(self.desired.applied_version())
                    || self.memory_latch.get()
                    || state.quarantine.is_some()
                    || state.selection == scupper_core::verdict::v2::Selection::Disconnected
                    || !self.flushed.get()
                {
                    return Err(StepError("forwarding gate refused"));
                }
                self.verify(*requires)?;
                self.forwarding(true, None)
            }
            Step::LoadRuleset {
                fingerprint: required,
                rendered,
            } => {
                if *required != self.desired.fingerprint() || rendered != self.desired_rendered() {
                    return Err(StepError("unapplied ruleset refused"));
                }
                // The early version snapshot can time out. Never let that
                // authorize loading an obsolete render during containment.
                let state = self
                    .state
                    .read_until(Instant::now() + EXEC_TIMEOUT)
                    .map_err(|_| StepError("applied version unavailable"))?;
                if !matches!(state, crate::state::StateRead::Present(state) if state.applied_version == Some(self.desired.applied_version()))
                {
                    return Err(StepError("applied version changed"));
                }
                self.flushed.set(false);
                for cmd in [NftCmd::CheckStdin, NftCmd::LoadStdin] {
                    command_result(run_netns_cmd_with_stdin(
                        self.deps.system,
                        &self.held,
                        &KernelCmd::Nft(cmd),
                        rendered.as_bytes(),
                        EXEC_TIMEOUT,
                    ))
                    .map_err(|_| StepError("ruleset transaction failed"))?;
                }
                Ok(())
            }
            Step::VerifyRuleset { fingerprint } => self.verify(*fingerprint),
            Step::FlushConntrack => {
                self.run(KernelCmd::Conntrack(ConntrackCmd::Flush))?;
                self.flushed.set(true);
                Ok(())
            }
            Step::WriteSysctl { key, value } => write_sysctl_verified(
                self.deps.system,
                &self.held,
                key.sysctl(),
                value
                    .parse()
                    .map_err(|_| StepError("invalid sysctl value"))?,
                EXEC_TIMEOUT,
            )
            .map_err(|_| StepError("hardening write failed")),
            Step::ReadBackSysctls => {
                let actual = boot::inventory(&self.deps, &self.held)
                    .map_err(|_| StepError("link inventory failed"))?;
                for setting in self.desired.hardening() {
                    // Missing links are handled by their independent repair group.
                    if let Scope::Link(name) = &setting.key.scope
                        && !actual.iter().any(|l| l.ifname == name.as_str())
                    {
                        continue;
                    }
                    let value = command_result(run_netns_cmd(
                        self.deps.system,
                        &self.held,
                        &KernelCmd::Sysctl(SysctlCmd::Read(setting.key.clone())),
                        EXEC_TIMEOUT,
                    ))
                    .map_err(|_| StepError("hardening read failed"))?;
                    if value.trim() != setting.value {
                        return Err(StepError("hardening mismatch"));
                    }
                }
                Ok(())
            }
            Step::RouteReplace { family, target } => {
                self.run(KernelCmd::Ip(IpCmd::RouteReplace(*family, target.clone())))
            }
            Step::RouteDelete { route } => {
                crate::cmd::delete_observed_route(self.deps.system, &self.held, route)
                    .map_err(|_| StepError("route deletion failed"))
            }
            Step::RuleDelete { rule } => {
                crate::cmd::delete_observed_rule(self.deps.system, &self.held, rule)
                    .map_err(|_| StepError("rule deletion failed"))
            }
            Step::LinkDown { name } => boot::links::set_up(&self.deps, &self.held, name, false)
                .map_err(|_| StepError("link down failed")),
            Step::LinkForwardingOff { name } => self.forwarding(false, Some(name)),
            Step::LinkCreate { .. }
            | Step::LinkReconfigure { .. }
            | Step::ReResolveEndpoint { .. } => self.link_step(step),
            Step::TcDelete { name, hook } => {
                boot::links::delete_hook(&self.deps, &self.held, name, hook)
                    .map_err(|_| StepError("hook removal failed"))?;
                let links = boot::inventory(&self.deps, &self.held)
                    .map_err(|_| StepError("hook verification failed"))?;
                if let Some(link) = links.iter().find(|l| &l.ifname == name) {
                    let hooks =
                        collect::reconcile::hooks(self.deps.system, &self.held, name, link.xdp)
                            .map_err(|_| StepError("hook verification failed"))?;
                    if hooks.contains(hook) {
                        return Err(StepError("hook still present"));
                    }
                }
                Ok(())
            }
            Step::Emit(_) | Step::PersistLatch { .. } => {
                Err(StepError("userspace step dispatched to kernel"))
            }
        }
    }
    fn hold_latch(&self, latch: Option<&scupper_core::planner::Latch>) {
        self.memory_latch.set(latch.is_some());
    }
    fn restore_name(&self, held: &NetnsHandle, guard: &WriterGuard) -> Result<(), StepError> {
        self.restore_name_until(
            held,
            guard,
            Instant::now() + std::time::Duration::from_millis(100),
        )
    }
    fn restore_name_until(
        &self,
        held: &NetnsHandle,
        guard: &WriterGuard,
        deadline: Instant,
    ) -> Result<(), StepError> {
        restore_mount_until(held, &self.namespace_path, guard, deadline).map_err(|error| {
            if matches!(error, NetnsError::MountEscalation { .. }) {
                eprintln!("scupperd: {error}");
                StepError("namespace restore escalation")
            } else {
                StepError("namespace rebind failed")
            }
        })
    }
}

pub(crate) fn forwarding(
    deps: &BootDeps<'_>,
    held: &NetnsHandle,
    on: bool,
    only: Option<&str>,
) -> Result<(), StepError> {
    let mut failed = false;
    // Close both global gates before inventory or per-device work. A failed
    // family write never prevents attempting the other family or later gates.
    if only.is_none() {
        for (family, scope, name) in [
            (SysctlFamily::Ipv4, Scope::Global, "ip_forward"),
            (SysctlFamily::Ipv6, Scope::All, "forwarding"),
            (SysctlFamily::Ipv4, Scope::Default, "forwarding"),
            (SysctlFamily::Ipv6, Scope::Default, "forwarding"),
        ] {
            let result = write_sysctl_verified(
                deps.system,
                held,
                &SysctlKey {
                    family,
                    scope,
                    name,
                },
                i64::from(on),
                EXEC_TIMEOUT,
            );
            if on && result.is_err() {
                return Err(StepError("partial forwarding raise"));
            }
            failed |= result.is_err();
        }
    }
    let links = boot::inventory(deps, held).map_err(|_| StepError("link inventory failed"))?;
    for link in links
        .iter()
        .filter(|l| only.is_none_or(|name| name == l.ifname))
    {
        let Ok(name) = IfName::new(&link.ifname) else {
            failed = true;
            continue;
        };
        for family in [SysctlFamily::Ipv4, SysctlFamily::Ipv6] {
            let key = SysctlKey {
                family,
                scope: Scope::Link(name.clone()),
                name: "forwarding",
            };
            let result =
                write_sysctl_verified(deps.system, held, &key, i64::from(on), EXEC_TIMEOUT);
            if on && result.is_err() {
                return Err(StepError("partial forwarding raise"));
            }
            failed |= result.is_err();
        }
    }
    if failed {
        Err(StepError("forwarding write/readback failed"))
    } else {
        Ok(())
    }
}

// Publish only under the global writer capability and only for the held inode.
fn publish_owned(
    root: &std::path::Path,
    identity: crate::netns::NetnsId,
    links: &std::collections::BTreeMap<String, u32>,
    _guard: &WriterGuard,
) -> Result<(), StepError> {
    let bytes = std::fs::read(root.join("boot.json"))
        .map_err(|_| StepError("boot identity read failed"))?;
    let mut report: BootReport =
        serde_json::from_slice(&bytes).map_err(|_| StepError("boot identity invalid"))?;
    if report.netns.map(|n| (n.dev, n.ino)) != Some(identity) || !report.succeeded() {
        return Err(StepError("boot identity changed"));
    }
    report.owned_links.clone_from(links);
    boot::save_report_at(root, &report).map_err(|_| StepError("boot identity write failed"))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn recreated_link_identity_survives_a_restart_and_refuses_wrong_namespace() {
        use crate::boot::{BootStep, NamespaceIdentity, StepResult};
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || {
                    std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/tmp"
                    ))
                },
                std::path::PathBuf::from,
            )
            .join("owned-link-handoff")
            .join(std::process::id().to_string());
        let guard = crate::lock::WriterLock::acquire(&root).unwrap();
        let report = BootReport {
            applied_version: Some(1),
            netns: Some(NamespaceIdentity { dev: 1, ino: 2 }),
            owned_links: std::collections::BTreeMap::from([("wg0".into(), 3)]),
            steps: [
                BootStep::Lock,
                BootStep::Inputs,
                BootStep::Close,
                BootStep::Ruleset,
                BootStep::Links,
                BootStep::Routes,
                BootStep::Forwarding,
                BootStep::Record,
            ]
            .into_iter()
            .map(|step| StepResult {
                step,
                error: None,
                adopted: false,
            })
            .collect(),
            ..BootReport::default()
        };
        boot::save_report_at(&root, &report).unwrap();
        let links = std::collections::BTreeMap::from([("wg0".into(), 42)]);
        publish_owned(&root, (1, 2), &links, &guard).unwrap();
        let restarted: BootReport =
            serde_json::from_slice(&std::fs::read(root.join("boot.json")).unwrap()).unwrap();
        assert_eq!(restarted.owned_links, links);
        assert!(restarted.succeeded());
        assert!(publish_owned(&root, (1, 99), &report.owned_links, &guard).is_err());
        let unchanged: BootReport =
            serde_json::from_slice(&std::fs::read(root.join("boot.json")).unwrap()).unwrap();
        assert_eq!(unchanged.owned_links, links);
        std::fs::remove_dir_all(root).unwrap();
    }
}
