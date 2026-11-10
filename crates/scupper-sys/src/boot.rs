//! Serialized gateway construction. Every mutation prefix preserves containment.
//! A fresh namespace may inherit forwarding=1 until the first gate write, but has
//! only loopback then. Existing namespaces are closed before any build checkpoint.
//! Foreign links are all disabled and redirect hooks removed before failing closed.
//! Extra RPDB rules and main-table routes still require operator/planner repair.

pub(crate) mod links;

use crate::{
    canon, collect,
    fs::{Fs, RealFs, durable_replace},
    lock::{WriterGuard, WriterLock},
    netns::{NetnsError, NetnsHandle},
    secrets::{Secret, SecretFile},
    state::{State, StateFile},
    store::VersionStore,
    system::{EXEC_TIMEOUT, ExecTarget, Program, System},
};
use scupper_core::{
    config::{GatewayId, ValidatedSite, parse_site, validate},
    parse::parse_ip_link,
    render::{VersionStamp, desired_routes, desired_sysctls, render_netns, route_argv},
    rules::IfName,
    verdict::v2::{self, HealthConfigV2, NetnsIdentity, Next, Observations, RulesetObs, Selection},
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, path::Path};

/// Numbered boot checkpoints from DESIGN §15.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[repr(u8)]
pub enum BootStep {
    /// 0: acquire the global writer lock, with a bounded wait.
    Lock = 0,
    /// 1: resolve all inputs and open or create the foreign namespace.
    Inputs = 1,
    /// 2: close forwarding and verify hardening.
    Close = 2,
    /// 3: validate, load and canonically verify the ruleset.
    Ruleset = 3,
    /// 4: create host-born tunnels, move by descriptor and configure.
    Links = 4,
    /// 5: reassert the persisted default routes.
    Routes = 5,
    /// 6: enable forwarding only after verification, unless quarantined.
    Forwarding = 6,
    /// 7: durably publish the per-boot namespace identity and report.
    Record = 7,
}

/// A single step's outcome. Unrun steps do not appear in the report.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepResult {
    /// Numbered operation.
    pub step: BootStep,
    /// Failure reason, with bounded diagnostics but never secret command output.
    pub error: Option<String>,
    /// This step needed no writes because the namespace was adopted.
    pub adopted: bool,
}

/// Per-boot namespace identity, never persisted across reboots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NamespaceIdentity {
    /// Namespace filesystem device.
    pub dev: u64,
    /// Namespace inode.
    pub ino: u64,
}

/// Complete or stopped boot attempt; the first failed step ends the attempt.
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct BootReport {
    /// Ordered attempted steps.
    pub steps: Vec<StepResult>,
    /// Applied immutable configuration, when input resolution succeeded.
    pub applied_version: Option<u64>,
    /// Held namespace identity, when opened.
    pub netns: Option<NamespaceIdentity>,
    /// Alert-worthy input loss and operational warnings.
    pub warnings: Vec<String>,
    /// Whether the namespace passed the verify-only adoption criteria.
    pub adopted: bool,
    /// Owned `WireGuard` names and ifindexes verified through the held namespace.
    #[serde(default)]
    pub owned_links: BTreeMap<String, u32>,
}
impl BootReport {
    /// True only after every checkpoint, including durable publication, succeeded.
    #[must_use]
    pub fn succeeded(&self) -> bool {
        self.steps.len() == 8 && self.steps.iter().all(|step| step.error.is_none())
    }
}

/// Injectable namespace opening boundary. Creation itself uses the command trace.
pub trait BootNamespace {
    /// Published namespace name used by reconciliation after the handoff.
    fn path(&self) -> &Path {
        Path::new("/run/netns/scupper")
    }
    /// Opens the owned namespace, distinguishing absence from invalid/host handles.
    ///
    /// # Errors
    /// Returns namespace identity and filesystem errors.
    fn open(&self) -> Result<Option<NetnsHandle>, NetnsError>;
}

/// Production namespace marker; all later execution borrows the held descriptor.
pub struct GatewayNamespace;
impl BootNamespace for GatewayNamespace {
    fn open(&self) -> Result<Option<NetnsHandle>, NetnsError> {
        match NetnsHandle::open("/run/netns/scupper") {
            Ok(handle) => Ok(Some(handle)),
            Err(NetnsError::Io(rustix::io::Errno::NOENT)) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// Deterministic testing checkpoints. A hook may stop or kill the process.
#[cfg(feature = "testing")]
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BootPoint {
    /// Immediately after a completed numbered step.
    After(BootStep),
    /// The host-born, down, peerless link exists but has not been moved.
    LinkAdded(IfName),
}

/// Boot's explicit I/O dependencies. Production roots are fixed by the CLI.
#[derive(Clone, Copy)]
pub struct BootDeps<'a> {
    /// Kernel executor and clock.
    pub system: &'a dyn System,
    /// Namespace opening boundary, never a host fallback.
    pub namespace: &'a dyn BootNamespace,
    /// Immutable store and state root (`/var/lib/scupper`).
    pub state_root: &'a Path,
    /// Gateway ID and confined secret root (`/etc/scupper`).
    pub config_root: &'a Path,
    /// Lock and boot.json root (`/run/scupper`).
    pub run_root: &'a Path,
    /// Optional test-only interruption hook; absent from production builds.
    #[cfg(feature = "testing")]
    pub hook: Option<&'a dyn Fn(BootPoint) -> Result<(), String>>,
    /// Expected secret owner for unprivileged adapter tests only.
    #[cfg(feature = "testing")]
    pub secret_owner: u32,
}

type Result<T, E = String> = std::result::Result<T, E>;
pub(crate) struct Inputs {
    site: ValidatedSite,
    gateway: GatewayId,
    stamp: VersionStamp,
    state: State,
    pub(crate) rules: String,
    secrets: BTreeMap<String, Secret>,
    missing_state_alert: bool,
}

pub(crate) fn inputs(deps: &BootDeps<'_>, report: &mut BootReport) -> Result<Inputs> {
    inputs_for_link(deps, report, None)
}
pub(crate) fn inputs_for_link(
    deps: &BootDeps<'_>,
    report: &mut BootReport,
    only: Option<&str>,
) -> Result<Inputs> {
    let store = VersionStore::read_only(deps.state_root, deps.config_root);
    let head = store
        .head()
        .map_err(|e| e.to_string())?
        .ok_or("no configuration")?;
    let resolved = StateFile::open(deps.state_root, None)
        .and_then(|file| file.read())
        .map_err(|e| e.to_string())?
        .for_boot(true);
    if resolved.missing_state_alert {
        report.warnings.push("state.json missing with a configuration head: Disconnected; lost quarantine state requires operator attention".into());
    }
    // Missing state deliberately uses head with closed intent, without hiding the
    // loss by writing replacement state. Present state must name an applied version.
    let version = if resolved.missing_state_alert {
        head
    } else {
        resolved
            .state
            .applied_version
            .ok_or("state has no applied version")?
    };
    let (text, _) = store.read(version).map_err(|e| e.to_string())?;
    report.applied_version = Some(version);
    let site = validate(parse_site(&text).map_err(|_| "invalid configuration")?)
        .map_err(|_| "invalid configuration")?;
    let gateway = GatewayId(
        RealFs
            .read(&deps.config_root.join("gateway-id"))
            .map_err(|e| e.to_string())?
            .trim()
            .into(),
    );
    let gw = site.gateway(&gateway).ok_or("unknown gateway-id")?;
    let stamp = VersionStamp {
        version,
        sha256: Sha256::digest(text.as_bytes()).into(),
    };
    let rules = render_netns(&site, &gateway, &stamp).map_err(|e| e.to_string())?;
    match RealFs.read(&deps.state_root.join(format!("rendered/{version:06}.nft"))) {
        Ok(saved) if saved != rules => {
            return Err("stored render differs from applied configuration".into());
        }
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.to_string()),
    }
    let refs = std::iter::once((
        gw.client_tunnel().ifname().as_str(),
        &gw.client_tunnel().identity().private_key_ref,
    ))
    .chain(
        gw.exits()
            .iter()
            .map(|exit| (exit.ifname().as_str(), exit.private_key_ref())),
    );
    let mut secrets = BTreeMap::new();
    for (name, reference) in refs.filter(|(name, _)| only.is_none_or(|only| only == *name)) {
        #[cfg(feature = "testing")]
        let key = SecretFile::open_with_owner(deps.config_root, reference, deps.secret_owner);
        #[cfg(not(feature = "testing"))]
        let key = SecretFile::open(deps.config_root, reference);
        secrets.insert(name.into(), key.map_err(|e| e.to_string())?);
    }
    Ok(Inputs {
        site,
        gateway,
        stamp,
        state: resolved.state,
        rules,
        secrets,
        missing_state_alert: resolved.missing_state_alert,
    })
}

fn strings(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| (*s).into()).collect()
}

// Commands receiving secret stdin must never retain child diagnostics.
pub(crate) fn execute(
    deps: &BootDeps<'_>,
    target: ExecTarget<'_>,
    program: Program,
    args: &[String],
    input: Option<&[u8]>,
) -> Result<String> {
    if program == Program::Wg {
        crate::system::check_wg_args(deps.system, args).map_err(|e| e.to_string())?;
    }
    let out = match input {
        Some(input) => deps
            .system
            .run_with_stdin(target, program, args, input, EXEC_TIMEOUT),
        None => deps.system.run_in(target, program, args, EXEC_TIMEOUT),
    }
    .map_err(|e| format!("{program:?} execution failed: {e}"))?;
    if out.status != Some(0) {
        let diagnostic = if program == Program::Wg && input.is_some() {
            String::new()
        } else {
            diagnostic(&out.stderr)
        };
        return Err(format!(
            "{program:?} command failed (status {:?}): {diagnostic}",
            out.status
        ));
    }
    Ok(out.stdout)
}

fn diagnostic(stderr: &str) -> String {
    stderr
        .chars()
        .take(2048)
        .map(|c| if c.is_control() { ' ' } else { c })
        .collect()
}

pub(crate) fn inventory(
    deps: &BootDeps<'_>,
    handle: &NetnsHandle,
) -> Result<Vec<scupper_core::parse::IpLink>> {
    parse_ip_link(&execute(
        deps,
        ExecTarget::Netns(handle),
        Program::Ip,
        &strings(&["-d", "-j", "link", "show"]),
        None,
    )?)
    .map_err(|e| e.to_string())
}

pub(crate) fn sysctls(
    deps: &BootDeps<'_>,
    handle: &NetnsHandle,
    names: &[IfName],
    forwarding: bool,
    write: bool,
) -> Result<()> {
    let values = desired_sysctls(names, forwarding);
    let target = ExecTarget::Netns(handle);
    let mut write_errors = BTreeMap::new();
    if write {
        for value in &values {
            // procps can return nonzero even for a successful write. Read all
            // values after all writes, including hardening reset by ip_forward.
            let output = deps
                .system
                .run_in(
                    target,
                    Program::Sysctl,
                    &strings(&["-w", &format!("{}={}", value.key, value.value)]),
                    EXEC_TIMEOUT,
                )
                .map_err(|e| format!("Sysctl execution failed: {e}"))?;
            if output.status != Some(0) {
                write_errors.insert(value.key.to_string(), diagnostic(&output.stderr));
            }
        }
    }
    for value in values {
        let got = execute(
            deps,
            target,
            Program::Sysctl,
            &strings(&["-n", &value.key.to_string()]),
            None,
        )?;
        if got.trim() != value.value {
            return Err(format!(
                "sysctl readback mismatch: {}: {}",
                value.key,
                write_errors
                    .get(&value.key.to_string())
                    .map_or("", String::as_str)
            ));
        }
    }
    Ok(())
}

fn containment(
    deps: &BootDeps<'_>,
    handle: &NetnsHandle,
    cfg: &Inputs,
    identities: &mut BTreeMap<String, u32>,
) -> Result<()> {
    let (device, inode) = handle.identity();
    let health = HealthConfigV2::new(
        &cfg.site,
        &cfg.gateway,
        NetnsIdentity { device, inode },
        vec![std::net::Ipv4Addr::UNSPECIFIED.into()],
        cfg.stamp.version,
    )
    .map_err(|e| e.to_string())?;
    let obs = Observations {
        topology: Some(collect::topology_recorded(
            deps.system,
            handle,
            &cfg.site,
            &cfg.gateway,
            &cfg.stamp,
            identities,
        )),
        selection: cfg.state.selection.clone(),
        ..Observations::default()
    };
    match v2::next(&obs, &health, deps.system.now_unix_secs()) {
        Next::Defaults => Ok(()),
        _ => Err("stage-1 containment is not exact".into()),
    }
}

fn checkpoint(deps: &BootDeps<'_>, step: BootStep) -> Result<()> {
    #[cfg(feature = "testing")]
    if let Some(hook) = deps.hook {
        hook(BootPoint::After(step))?;
    }
    let _ = (deps, step);
    Ok(())
}

fn step(
    report: &mut BootReport,
    deps: &BootDeps<'_>,
    which: BootStep,
    adopted: bool,
    action: impl FnOnce() -> Result<()>,
) -> bool {
    let result = action().and_then(|()| checkpoint(deps, which));
    let ok = result.is_ok();
    report.steps.push(StepResult {
        step: which,
        error: result.err(),
        adopted,
    });
    ok
}

/// Builds or adopts the gateway under the bounded global writer lock. Stops on
/// the first failure; never deletes the namespace or clears the quarantine latch.
#[must_use]
#[allow(clippy::too_many_lines)] // The numbered sequence is intentionally visible in one function.
pub fn boot(deps: &BootDeps<'_>) -> BootReport {
    let mut report = BootReport::default();
    let guard = match WriterLock::acquire(deps.run_root) {
        Ok(guard) => guard,
        Err(error) => {
            report.steps.push(StepResult {
                step: BootStep::Lock,
                error: Some(error.to_string()),
                adopted: false,
            });
            return report;
        }
    };
    boot_with_guard(deps, &guard)
}

pub(crate) fn boot_with_guard(deps: &BootDeps<'_>, guard: &WriterGuard) -> BootReport {
    boot_apply_with_guard(deps, guard, false)
}

/// Explicit apply may open the gate while durable quarantine remains until verification.
pub(crate) fn boot_apply_with_guard(
    deps: &BootDeps<'_>,
    _guard: &WriterGuard,
    open_quarantined: bool,
) -> BootReport {
    let report = boot_locked(deps, BootReport::default(), open_quarantined);
    if !report.succeeded() {
        let mut report = report;
        if let Err(error) = save_report(deps, &report) {
            report
                .warnings
                .push(format!("failed to publish boot failure: {error}"));
        }
        return report;
    }
    report
}

fn save_report(deps: &BootDeps<'_>, report: &BootReport) -> Result<()> {
    save_report_at(deps.run_root, report)
}
pub(crate) fn save_report_at(run_root: &Path, report: &BootReport) -> Result<()> {
    let bytes = serde_json::to_vec(report).map_err(|e| e.to_string())?;
    durable_replace(
        &RealFs,
        &run_root.join("boot.json"),
        &bytes,
        0o644,
        &|_| Ok(()),
        &|_| Ok(()),
    )
    .map_err(|e| e.to_string())
}

#[allow(clippy::too_many_lines)] // Keep the ordered build and its failure boundaries together.
fn boot_locked(deps: &BootDeps<'_>, mut report: BootReport, open_quarantined: bool) -> BootReport {
    if !step(&mut report, deps, BootStep::Lock, false, || Ok(())) {
        return report;
    }
    let mut owned_links = BTreeMap::new();
    let prepared = (|| {
        let cfg = inputs(deps, &mut report)?;
        let existing = deps.namespace.open().map_err(|e| e.to_string())?;
        let existed = existing.is_some();
        let handle = if let Some(handle) = existing {
            handle
        } else {
            execute(
                deps,
                ExecTarget::Host,
                Program::Ip,
                &strings(&["netns", "add", "scupper"]),
                None,
            )?;
            deps.namespace
                .open()
                .map_err(|e| e.to_string())?
                .ok_or("created namespace missing")?
        };
        let (dev, ino) = handle.identity();
        report.netns = Some(NamespaceIdentity { dev, ino });
        let names = configured_names(&cfg)?;
        let adopted = existed
            && cfg.state.quarantine.is_none()
            && !cfg.missing_state_alert
            && links::adoptable(deps, &handle, &cfg).is_ok()
            && containment(deps, &handle, &cfg, &mut owned_links).is_ok()
            && (sysctls(deps, &handle, &names, true, false).is_ok()
                || (cfg.state.selection == Selection::Disconnected
                    && sysctls(deps, &handle, &names, false, false).is_ok()));
        let closed = if adopted {
            Ok(())
        } else {
            // A newly created netns can inherit forwarding=1. Close the gate
            // and redirect bypasses before publishing the Inputs checkpoint.
            sysctls(deps, &handle, &[], false, true)?;
            let closed = links::close(deps, &handle, &cfg);
            if closed.is_ok() {
                execute(
                    deps,
                    ExecTarget::Netns(&handle),
                    Program::Ip,
                    &strings(&["link", "set", "lo", "up"]),
                    None,
                )?;
            }
            closed
        };
        Ok((cfg, handle, adopted, existed, closed))
    })();
    let (cfg, handle, adopted, existed, closed) = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            step(&mut report, deps, BootStep::Inputs, false, || Err(error));
            return report;
        }
    };
    report.adopted = adopted;
    if !step(&mut report, deps, BootStep::Inputs, adopted, || Ok(())) {
        return report;
    }
    if !step(&mut report, deps, BootStep::Close, adopted, || {
        if adopted {
            return Ok(());
        }
        closed?;
        let actual = inventory(deps, &handle)?;
        let names = configured_names(&cfg)?
            .into_iter()
            .filter(|n| actual.iter().any(|l| l.ifname == n.as_str()))
            .collect::<Vec<_>>();
        sysctls(deps, &handle, &names, false, true)?;
        Ok(())
    }) {
        return report;
    }
    if !step(&mut report, deps, BootStep::Ruleset, adopted, || {
        if adopted {
            return Ok(());
        }
        for args in [strings(&["-c", "-f", "-"]), strings(&["-f", "-"])] {
            execute(
                deps,
                ExecTarget::Netns(&handle),
                Program::Nft,
                &args,
                Some(cfg.rules.as_bytes()),
            )?;
        }
        if canon::observe_netns_ruleset(deps.system, &handle, &cfg.rules)
            .map_err(|e| e.to_string())?
            != RulesetObs::Exact
        {
            return Err("ruleset canonical fingerprint mismatch".into());
        }
        if existed {
            execute(
                deps,
                ExecTarget::Netns(&handle),
                Program::Conntrack,
                &strings(&["-F"]),
                None,
            )
            .map_err(|e| {
                format!("conntrack flush required for rebuild (install conntrack): {e}")
            })?;
        }
        Ok(())
    }) {
        return report;
    }
    if !step(&mut report, deps, BootStep::Links, adopted, || {
        if adopted {
            Ok(())
        } else {
            links::configure(deps, &handle, &cfg)
        }
    }) {
        return report;
    }
    if !step(&mut report, deps, BootStep::Routes, false, || {
        let gw = cfg.site.gateway(&cfg.gateway).ok_or("unknown gateway")?;
        let selected = match &cfg.state.selection {
            Selection::Disconnected => None,
            Selection::Auto => gw
                .exits()
                .first()
                .map(scupper_core::config::ValidatedExit::id),
            Selection::Pin(id) | Selection::Prefer(id) => {
                if !gw.exits().iter().any(|e| e.id() == id) {
                    return Err("selection names an unconfigured exit".into());
                }
                Some(id)
            }
        };
        // Leaving a disconnect: exits closed by it come back up before routes use them
        // (a route via a down link is refused by the kernel).
        if cfg.state.selection != Selection::Disconnected {
            let links = inventory(deps, &handle)?;
            for exit in gw.exits() {
                let up = links.iter().any(|l| {
                    l.ifname == exit.ifname().as_str() && l.flags.iter().any(|f| f == "UP")
                });
                if up {
                    continue;
                }
                execute(
                    deps,
                    ExecTarget::Netns(&handle),
                    Program::Ip,
                    &strings(&["link", "set", "dev", exit.ifname().as_str(), "up"]),
                    None,
                )?;
            }
        }
        for (family, target) in desired_routes(&cfg.site, &cfg.gateway, selected) {
            execute(
                deps,
                ExecTarget::Netns(&handle),
                Program::Ip,
                &route_argv(family, &target),
                None,
            )?;
        }
        // An admin disconnect closes the exits too (also when adopting a namespace whose
        // exits are up): DESIGN §12 stage 2 counts it effective only when the kernel shows
        // both defaults unreachable and the exit links down or without peers.
        if cfg.state.selection == Selection::Disconnected {
            for exit in gw.exits() {
                execute(
                    deps,
                    ExecTarget::Netns(&handle),
                    Program::Ip,
                    &strings(&["link", "set", "dev", exit.ifname().as_str(), "down"]),
                    None,
                )?;
            }
        }
        Ok(())
    }) {
        return report;
    }
    if !step(&mut report, deps, BootStep::Forwarding, adopted, || {
        if adopted {
            return Ok(());
        }
        containment(deps, &handle, &cfg, &mut owned_links)?;
        sysctls(
            deps,
            &handle,
            &configured_names(&cfg)?,
            (cfg.state.quarantine.is_none() || open_quarantined) && !cfg.missing_state_alert,
            true,
        )
    }) {
        return report;
    }
    report.owned_links = owned_links;
    // Serialize the successful Record result as part of its own durable write.
    report.steps.push(StepResult {
        step: BootStep::Record,
        error: None,
        adopted: false,
    });
    let saved = save_report(deps, &report).and_then(|()| checkpoint(deps, BootStep::Record));
    if let Err(error) = saved
        && let Some(last) = report.steps.last_mut()
    {
        last.error = Some(error);
    }
    report
}

pub(crate) fn configured_names(cfg: &Inputs) -> Result<Vec<IfName>> {
    let gw = cfg.site.gateway(&cfg.gateway).ok_or("unknown gateway")?;
    std::iter::once("lo")
        .chain(std::iter::once(gw.client_tunnel().ifname().as_str()))
        .chain(gw.exits().iter().map(|e| e.ifname().as_str()))
        .map(|name| IfName::new(name).map_err(|e| e.to_string()))
        .collect()
}

/// Internal fixture boundary for release-restricted multi-gateway configurations.
#[cfg(feature = "testing")]
pub mod testing {
    /// Reconfigures the client link using the production peer/session path.
    /// # Errors
    /// Returns missing inputs, namespace or link configuration errors.
    pub fn configure_clients(
        deps: super::BootDeps<'_>,
        site: scupper_core::config::ValidatedSite,
    ) -> Result<(), String> {
        let mut cfg =
            super::inputs_for_link(&deps, &mut super::BootReport::default(), Some("wg0"))?;
        cfg.site = site;
        let held = deps
            .namespace
            .open()
            .map_err(|error| error.to_string())?
            .ok_or("missing namespace")?;
        super::links::configure_one(&deps, &held, &cfg, "wg0")
    }
}
