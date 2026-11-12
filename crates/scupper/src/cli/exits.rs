//! Gateway-only secret installation and optimistic public config commits.
use super::{Dependencies, config, confirm, output_error, require_root};
use clap::Subcommand;
use scupper_core::config::{
    ExitId, ExitName, SecretKind, SecretName, SiteConfig, parse_site, validate,
};
use scupper_sys::{
    lock::WriterLock,
    provider,
    secrets::SecretFile,
    state::{Selection, StateFile, StateRead},
    store::{MetaInput, VersionStore},
};
use std::{
    collections::BTreeSet,
    io::Write,
    path::PathBuf,
    time::{Duration, SystemTime},
};

#[derive(Clone, Subcommand)]
pub(super) enum ExitCommand {
    /// Import a provider wg-quick file held locally on the gateway.
    Import {
        file: PathBuf,
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        id: Option<String>,
        #[arg(long)]
        yes: bool,
        /// Show the full derived `WireGuard` public key.
        #[arg(long)]
        verbose: bool,
    },
    /// Remove an exit from configuration, then delete its local keys.
    Remove {
        exit: String,
        #[arg(long)]
        yes: bool,
    },
}
fn load(
    deps: &Dependencies<'_>,
) -> Result<
    (
        VersionStore,
        u64,
        SiteConfig,
        scupper_core::config::GatewayId,
    ),
    String,
> {
    let store = VersionStore::read_only(deps.state_root, deps.config_root);
    let parent = store
        .head()
        .map_err(|e| e.to_string())?
        .ok_or("configuration store has no head")?;
    let text = store.read(parent).map_err(|e| e.to_string())?.0;
    let validated = config::validate_text(&text)?;
    let gateway = config::gateway_id(deps, &validated)?;
    let site = parse_site(&text).map_err(|e| e.to_string())?;
    Ok((store, parent, site, gateway))
}
fn encode(site: &SiteConfig) -> Result<String, String> {
    validate(site.clone()).map_err(|errors| {
        format!(
            "proposed exit configuration fails current schema validation: {}",
            errors
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("; ")
        )
    })?;
    toml::to_string(site).map_err(|_| "cannot encode configuration".into())
}

#[allow(clippy::too_many_lines)]
pub(super) fn run(
    command: ExitCommand,
    deps: &Dependencies<'_>,
    out: &mut dyn Write,
) -> Result<u8, String> {
    let started = SystemTime::now();
    require_root(deps, "exit mutation")?;
    let (store, parent, mut site, gateway) = load(deps)?;
    match command {
        ExitCommand::Import {
            file,
            name,
            id,
            yes,
            verbose,
        } => {
            super::require_interactive_or_yes(deps, "exit import", yes)?;
            let provider = provider::read_provider(&file)?;

            let public = provider::public_key(deps.system, provider.private_key())
                .map_err(|e| e.to_string())?;
            let id = ExitId(id.unwrap_or_else(|| provider.suggested_id.0.clone()));
            if !id.is_valid() || id.as_str().len() > 32 {
                return Err(
                    "invalid exit id: expected at most 32 lowercase letters, digits or hyphens"
                        .into(),
                );
            }
            let name = ExitName(name.unwrap_or_else(|| provider.suggested_name.0.clone()));
            let generation = parent
                .checked_add(1)
                .ok_or("configuration version exhausted")?;
            let reference = SecretName::new(SecretKind::Wg, &format!("exit-{id}-v{generation}"))
                .map_err(|_| "invalid exit key reference")?;
            let psk_reference = provider
                .preshared_key()
                .map(|_| SecretName::new(SecretKind::Wg, &format!("exit-{id}-v{generation}-psk")))
                .transpose()
                .map_err(|_| "invalid preshared-key reference")?;
            duplicates(deps, &store, parent, &gateway, &provider, &public)?;
            let gw = site.gateways.get_mut(&gateway).ok_or("unknown gateway")?;
            if gw.exits.len() > 1 {
                return Err("M2 requires a single exit".into());
            }
            let previous = gw.exits.first().map(|e| (e.id.clone(), e.name.clone()));
            let ifname = gw
                .exits
                .first()
                .map_or_else(|| "ex-0".into(), |exit| exit.ifname.clone());
            gw.exits.clear();
            gw.exits.push(provider::exit_config(
                &provider,
                id.clone(),
                name,
                ifname,
                generation,
            )?);
            let label = format!(
                "{} [{}]",
                gw.exits.last().ok_or("missing proposed exit")?.name,
                id
            );
            site.policy.exits = vec![id.clone()];
            let text = encode(&site)?;
            let action = previous.as_ref().map_or_else(
                || format!("Install {label}"),
                |(old_id, old_name)| format!("Replace {old_name} [{old_id}] with {label}"),
            );
            let replaced = previous
                .as_ref()
                .map(|(old, _)| old)
                .filter(|old| *old != &id);
            let reset = replaced
                .map(|old| selection_reset(deps, old))
                .transpose()?
                .unwrap_or(false);
            let action = if reset {
                format!("{action}; reset Pin/Prefer selection to Auto after commit")
            } else {
                action
            };
            writeln!(out, "{action}").map_err(output_error)?;
            if verbose {
                writeln!(out, "{:#}", provider.summary(&public)).map_err(output_error)?;
            } else {
                writeln!(out, "{}", provider.summary(&public)).map_err(output_error)?;
            }
            out.flush().map_err(output_error)?;
            confirm(
                deps,
                "exit import",
                yes,
                &format!("{action} and commit a high-risk local change? [y/N]"),
                None,
            )?;
            // Serialize the entire import, including the socket commit gap, so
            // another import cannot sweep keys awaiting publication.
            let _import = WriterLock::acquire_timeout(
                deps.writer_root.join("exit-import"),
                Duration::from_secs(2),
            )
            .map_err(|e| e.to_string())?;
            {
                let _writer = WriterLock::acquire(deps.writer_root).map_err(|e| e.to_string())?;
                if store.head().map_err(|e| e.to_string())? != Some(parent) {
                    return Err("configuration conflict (409): head changed".into());
                }
                duplicates(deps, &store, parent, &gateway, &provider, &public)?;
                let live = live_keys(deps, &store)?;
                if let Some(key) = std::iter::once(&reference)
                    .chain(psk_reference.as_ref())
                    .find(|key| live.contains(key.name()))
                {
                    return Err(format!(
                        "secret {} is referenced by applied_version..=head; inspect config log and advance head before retrying",
                        key.name()
                    ));
                }
                // A timed-out commit may still publish this generation. Never
                // silently collect or overwrite it on a quick retry.
                let pending_psk =
                    SecretName::new(SecretKind::Wg, &format!("exit-{id}-v{generation}-psk"))
                        .map_err(|_| "invalid preshared-key reference")?;
                let mut leftovers = Vec::new();
                for key in [&reference, &pending_psk] {
                    let path = deps.config_root.join("secrets/wg").join(key.name());
                    match std::fs::symlink_metadata(&path) {
                        Ok(_) => {
                            if live.contains(key.name()) {
                                return Err(format!(
                                    "secret {} is referenced; inspect config log and advance head before retrying",
                                    key.name()
                                ));
                            }
                            writeln!(out, "Existing secret {} is unreferenced by applied_version..=head; a previous import may still be publishing. Check config log. Use --yes only after confirming that operation has finished, or wait until head has moved past {generation}.", key.name()).map_err(output_error)?;
                            leftovers.push(key);
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                        Err(e) => return Err(e.to_string()),
                    }
                }
                out.flush().map_err(output_error)?;
                if !leftovers.is_empty() && !yes {
                    return Err(
                        "previous import generation exists; confirmation with --yes is required"
                            .into(),
                    );
                }
                // Validate every leftover before removing any of them.
                for key in &leftovers {
                    SecretFile::open_with_owner(
                        deps.config_root,
                        key,
                        rustix::process::geteuid().as_raw(),
                    )
                    .map_err(|e| e.to_string())?;
                }
                for key in leftovers {
                    SecretFile::remove(deps.config_root, key).map_err(|e| e.to_string())?;
                }
                SecretFile::sweep_wg(
                    deps.config_root,
                    &exit_history(&store)?,
                    &live,
                    parent,
                    started,
                )
                .map_err(|e| e.to_string())?;
                install_key(deps, &reference, provider.private_key())?;
                if let (Some(reference_psk), Some(psk)) = (&psk_reference, provider.preshared_key())
                    && let Err(e) = install_key(deps, reference_psk, psk)
                {
                    if !live.contains(reference.name()) {
                        SecretFile::remove(deps.config_root, &reference)
                            .map_err(|cleanup| format!("{e}; key cleanup: {cleanup}"))?;
                    }
                    return Err(e);
                }
            }
            match commit(deps, parent, &text) {
                Ok(version) => {
                    writeln!(out, "exit imported as version {version}").map_err(output_error)?;
                    writeln!(out, "Delete {}: it holds a private key.", file.display())
                        .map_err(output_error)?;
                    if let Some(replaced) = replaced {
                        reset_selection(deps, replaced).map_err(|e| {
                            format!("version {version} committed; selection reset: {e}")
                        })?;
                    }
                    let _writer =
                        WriterLock::acquire(deps.writer_root).map_err(|e| e.to_string())?;
                    SecretFile::sweep_wg(
                        deps.config_root,
                        &exit_history(&store)?,
                        &live_keys(deps, &store)?,
                        store
                            .head()
                            .map_err(|e| e.to_string())?
                            .ok_or("missing head")?,
                        started,
                    )
                    .map_err(|e| format!("version {version} committed; key sweep: {e}"))?;
                }
                Err(error) => {
                    // A socket disconnect or mirror failure may follow head publication.
                    // Retain the keys if any committed version now references them.
                    if matches!(error, CommitOutcome::Unknown(_)) {
                        return Err(format!("{error}; keys retained"));
                    }
                    let _writer = WriterLock::acquire(deps.writer_root)
                        .map_err(|_| "cannot check commit outcome; keys retained")?;
                    let live = live_keys(deps, &store)
                        .map_err(|_| "cannot check committed history; keys retained")?;
                    for key in std::iter::once(&reference).chain(psk_reference.as_ref()) {
                        if !live.contains(key.name()) {
                            SecretFile::remove(deps.config_root, key)
                                .map_err(|e| format!("{error}; key cleanup: {e}"))?;
                        }
                    }
                    return Err(error.to_string());
                }
            }
        }
        ExitCommand::Remove { exit, yes } => {
            // Lift together with the single-exit release restrictions.
            const REMOVAL_SUPPORTED: bool = false;
            if !REMOVAL_SUPPORTED {
                return Err("exit remove is not supported in M2: one exit is required; use exit import to replace it".into());
            }
            let gw = site.gateways.get_mut(&gateway).ok_or("unknown gateway")?;
            let candidates = gw
                .exits
                .iter()
                .map(|e| (e.id.as_str(), e.name.as_str()))
                .collect::<Vec<_>>();
            let id = super::control::match_exit(&exit, &candidates, deps.prompt.is_terminal())?;
            let index = gw
                .exits
                .iter()
                .position(|e| e.id.as_str() == id)
                .ok_or("unknown exit")?;
            if gw.exits.len() == 1 {
                return Err("M2 requires one exit; use exit import to replace it".into());
            }
            let _removed = gw.exits.remove(index);
            site.policy.exits.retain(|e| e.as_str() != id);
            let text = encode(&site)?;
            confirm(
                deps,
                "exit remove",
                yes,
                "Remove this exit and its local keys? [y/N]",
                None,
            )?;
            let version = commit(deps, parent, &text).map_err(|e| e.to_string())?;
            let _writer = WriterLock::acquire(deps.writer_root).map_err(|e| e.to_string())?;
            SecretFile::sweep_wg(
                deps.config_root,
                &exit_history(&store)?,
                &live_keys(deps, &store)?,
                version,
                SystemTime::now(),
            )
            .map_err(|e| e.to_string())?;
            writeln!(
                out,
                "exit removed as version {version}; revoke the configuration at the provider."
            )
            .map_err(output_error)?;
        }
    }
    Ok(0)
}

fn duplicates(
    deps: &Dependencies<'_>,
    store: &VersionStore,
    head: u64,
    gateway: &scupper_core::config::GatewayId,
    provider: &scupper_core::config::provider::ProviderConfig,
    public: &scupper_core::config::PublicKey,
) -> Result<(), String> {
    let mut references = std::collections::BTreeSet::new();
    {
        let (text, _) = store.read(head).map_err(|e| e.to_string())?;
        let site = parse_site(&text).map_err(|_| "invalid historical configuration")?;
        let replaced = site.gateways.get(gateway).and_then(|g| g.exits.first());
        for exit in site
            .gateways
            .values()
            .flat_map(|g| &g.exits)
            .filter(|exit| !replaced.is_some_and(|old| std::ptr::eq(*exit, old)))
        {
            if exit.peer_public_key.bytes().ok() == provider.peer_public_key.bytes().ok() {
                return Err("peer public key already used by a configured exit".into());
            }
            if !references.insert(exit.private_key_ref.name().to_owned()) {
                continue;
            }
            let path = deps
                .config_root
                .join("secrets/wg")
                .join(exit.private_key_ref.name());
            match std::fs::symlink_metadata(path) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.to_string()),
                Ok(_) => {}
            }
            let key = SecretFile::open_with_owner(
                deps.config_root,
                &exit.private_key_ref,
                rustix::process::geteuid().as_raw(),
            )
            .map_err(|e| e.to_string())?;
            let existing =
                provider::public_key(deps.system, key.expose()).map_err(|e| e.to_string())?;
            if existing.bytes().ok() == public.bytes().ok() {
                return Err("private key already used by a configured exit".into());
            }
        }
    }
    Ok(())
}

#[derive(Debug)]
enum CommitOutcome {
    Refused(String),
    Unknown(String),
    Failed(String),
}
impl std::fmt::Display for CommitOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(s) | Self::Unknown(s) | Self::Failed(s) => f.write_str(s),
        }
    }
}

fn commit(deps: &Dependencies<'_>, parent: u64, text: &str) -> Result<u64, CommitOutcome> {
    use scupper_sys::daemon::control::{ClientError, RESPONSE_TIMEOUT, call, request};
    let op = scupper_proto::Op::Commit {
        parent: Some(parent),
        toml: text.into(),
        reason: scupper_proto::Reason::Operator,
    };
    match call(deps.writer_root, &request(op), RESPONSE_TIMEOUT) {
        Ok(response) => match response.result {
            Ok(scupper_proto::OpResult::Commit { version }) => Ok(version),
            Err(error) => Err(CommitOutcome::Refused(format!(
                "local commit refused: {error}"
            ))),
            _ => Err(CommitOutcome::Unknown(
                "local commit outcome unknown: unexpected response".into(),
            )),
        },
        Err(ClientError::Unavailable(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            (|| {
                // Match config load's local writer path, but never compete with scupperd.
                let _lease = scupper_sys::lock::SupervisorLease::try_acquire(deps.writer_root)
                    .map_err(|_| "scupperd owns the gateway; local socket unavailable")?;
                let writer = WriterLock::acquire_timeout(deps.writer_root, Duration::from_secs(2))
                    .map_err(|e| e.to_string())?;
                let store = VersionStore::open_with_mirror_root(
                    deps.state_root,
                    deps.config_root,
                    Some(&writer),
                )
                .map_err(|e| e.to_string())?;
                let actor = deps.privilege.user_name().map_err(|e| e.to_string())?;
                let site = config::validate_text(text)?;
                let gateway = config::gateway_id(deps, &site)?;
                SecretFile::preflight(
                    deps.config_root,
                    &parse_site(text).map_err(|e| e.to_string())?,
                    rustix::process::geteuid().as_raw(),
                )
                .map_err(|e| e.to_string())?;
                let version = store
                    .commit(
                        &writer,
                        Some(parent),
                        text,
                        MetaInput {
                            actor,
                            at: deps.system.now_unix_secs(),
                            reason: "exit mutation".into(),
                        },
                    )
                    .map_err(|e| e.to_string())?;
                let (_, meta) = store.read(version).map_err(|e| e.to_string())?;
                let rules = scupper_core::render::render_netns(
                    &site,
                    &gateway,
                    &config::stamp(version, &meta.sha256)?,
                )
                .map_err(|e| e.to_string())?;
                store
                    .write_rendered(&writer, version, &rules)
                    .map_err(|e| e.to_string())?;
                Ok(version)
            })()
            .map_err(CommitOutcome::Failed)
        }
        Err(ClientError::Unavailable(_)) => {
            Err(CommitOutcome::Failed("local commit unavailable".into()))
        }
        Err(ClientError::OutcomeUnknown(_)) => Err(CommitOutcome::Unknown(
            "local commit outcome unknown; inspect configuration head".into(),
        )),
    }
}

// Called under the writer lock. Missing state conservatively retains all history.
fn live_keys(deps: &Dependencies<'_>, store: &VersionStore) -> Result<BTreeSet<String>, String> {
    let head = store
        .head()
        .map_err(|e| e.to_string())?
        .ok_or("missing head")?;
    let saved = StateFile::open(deps.state_root, None)
        .and_then(|f| f.read())
        .map_err(|e| e.to_string())?;
    let applied = match saved {
        StateRead::Present(state) => state.applied_version.unwrap_or(1),
        StateRead::Missing => 1,
    };
    if applied == 0 || applied > head {
        return Err("invalid applied version; keys retained".into());
    }
    let mut live = BTreeSet::new();
    for version in applied..=head {
        let text = store.read(version).map_err(|e| e.to_string())?.0;
        let site =
            parse_site(&text).map_err(|_| "invalid retained configuration; keys retained")?;
        for key in site.identities.values().map(|i| &i.private_key_ref).chain(
            site.gateways.values().flat_map(|g| &g.exits).flat_map(|e| {
                std::iter::once(&e.private_key_ref).chain(e.preshared_key_ref.as_ref())
            }),
        ) {
            if key.kind() == SecretKind::Wg {
                live.insert(key.name().into());
            }
        }
    }
    Ok(live)
}

fn install_key(deps: &Dependencies<'_>, name: &SecretName, bytes: &[u8]) -> Result<(), String> {
    SecretFile::write_new(deps.config_root, name, bytes).map_err(|e| e.to_string())
}

fn selection_reset(deps: &Dependencies<'_>, id: &ExitId) -> Result<bool, String> {
    let saved = StateFile::open(deps.state_root, None)
        .and_then(|s| s.read())
        .map_err(|e| e.to_string())?;
    Ok(
        matches!(saved, StateRead::Present(state) if matches!(&state.selection, Selection::Pin(old) | Selection::Prefer(old) if old == id)),
    )
}

fn reset_selection(deps: &Dependencies<'_>, replaced: &ExitId) -> Result<(), String> {
    use scupper_sys::daemon::{
        admin,
        control::{ClientError, RESPONSE_TIMEOUT, call, request},
    };
    let op = scupper_proto::Op::ResetSelection {
        replaced: replaced.into(),
    };
    match call(deps.writer_root, &request(op.clone()), RESPONSE_TIMEOUT) {
        Ok(response) => response.result.map(|_| ()).map_err(|e| e.to_string()),
        Err(ClientError::Unavailable(e))
            if matches!(
                e.kind(),
                std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
            ) =>
        {
            admin::local(
                scupper_sys::boot::BootDeps {
                    system: deps.system,
                    namespace: &super::BootNamespaces(deps.namespaces),
                    state_root: deps.state_root,
                    config_root: deps.config_root,
                    run_root: deps.writer_root,
                    #[cfg(feature = "testing")]
                    hook: None,
                    #[cfg(feature = "testing")]
                    secret_owner: rustix::process::geteuid().as_raw(),
                },
                deps.probe_exec,
                op,
                0,
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
        }
        Err(_) => Err("selection operation outcome unknown; inspect selection".into()),
    }
}

// Only these historical exit refs, plus recognizable crashed import generations,
// are eligible for collection. Client identity and unrelated staged keys stay put.
fn exit_history(store: &VersionStore) -> Result<BTreeSet<String>, String> {
    let mut names = BTreeSet::new();
    for version in 1..=store
        .head()
        .map_err(|e| e.to_string())?
        .ok_or("missing head")?
    {
        let text = store.read(version).map_err(|e| e.to_string())?.0;
        let site = parse_site(&text).map_err(|e| e.to_string())?;
        for key in
            site.gateways.values().flat_map(|g| &g.exits).flat_map(|e| {
                std::iter::once(&e.private_key_ref).chain(e.preshared_key_ref.as_ref())
            })
        {
            names.insert(key.name().into());
        }
    }
    Ok(names)
}
