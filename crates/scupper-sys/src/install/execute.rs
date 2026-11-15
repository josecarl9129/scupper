//! Ordered durable installation mutations.
use super::{
    Change, Configuration, Digest, Fs, GatewayId, MetaInput, Path, Paths, PermissionsExt, Prepared,
    Program, RealFs, SecretFile, SecretKind, SecretName, Sha256, System, VersionStore, WriterLock,
    Zeroizing, bundle, command, config, fs, hash, initial_state, io, model, observe, optional,
    provider, read_regular, stdfs,
};
fn permissions(path: &Path, mode: u32) -> io::Result<()> {
    RealFs.check_target(path)?;
    // Production is root; tests exercise identical ownership checks as their uid.
    rustix::fs::chown(path, Some(rustix::process::geteuid()), None)?;
    stdfs::set_permissions(path, stdfs::Permissions::from_mode(mode))?;
    stdfs::File::open(path)?.sync_all()
}
fn new_identity() -> Result<Zeroizing<Vec<u8>>, String> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    let mut at = 0;
    while at < bytes.len() {
        match rustix::rand::getrandom(&mut bytes[at..], rustix::rand::GetRandomFlags::empty()) {
            Ok(0) => return Err("OS RNG made no progress".into()),
            Ok(n) => at += n,
            Err(rustix::io::Errno::INTR) => {}
            Err(_) => return Err("OS RNG failed".into()),
        }
    }
    bytes[0] &= 0xf8;
    bytes[31] &= 0x7f;
    bytes[31] |= 0x40;
    let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut key = Zeroizing::new(Vec::with_capacity(44));
    for chunk in bytes.chunks(3) {
        let a = chunk[0];
        let b = chunk.get(1).copied().unwrap_or(0);
        let c = chunk.get(2).copied().unwrap_or(0);
        key.push(alphabet[usize::from(a >> 2)]);
        key.push(alphabet[usize::from((a & 3) << 4 | b >> 4)]);
        key.push(if chunk.len() > 1 {
            alphabet[usize::from((b & 15) << 2 | c >> 6)]
        } else {
            b'='
        });
        key.push(if chunk.len() > 2 {
            alphabet[usize::from(c & 63)]
        } else {
            b'='
        });
    }
    Ok(key)
}
/// Applies a prepared plan after re-observing all preconditions under a writer lock.
/// Returns a public Mac peer section and device setup when head has no devices.
/// # Errors
/// Stops at the first failed operation. Never rotates an existing identity.
#[allow(clippy::too_many_lines)]
pub fn apply(system: &dyn System, paths: &Paths, prepared: Prepared) -> Result<String, String> {
    let recoverable = model::BINARIES
        .iter()
        .all(|name| paths.at(&format!("{}/{name}", model::BIN_ROOT)).is_file());
    apply_with_fs(system, paths, prepared, &RealFs).map_err(|error| {
        if error.replaced && recoverable {
            format!(
                "{}\nGateway binaries may be mixed or services stopped. Restore manually:\n{}",
                error.reason,
                model::RESTORE_COMMANDS
            )
        } else {
            error.reason
        }
    })
}
/// Confirmed and uncertain mutations, including failed operations with partial effects.
#[derive(Debug, Clone, Default)]
pub struct Mutations {
    /// Paths or service commands known to have completed a mutation.
    pub changed: std::collections::BTreeSet<String>,
    /// Paths or commands whose failed attempt may have mutated state.
    pub possibly_changed: std::collections::BTreeSet<String>,
}
impl Mutations {
    /// Mark a mutation before starting a write or command.
    pub fn begin(&mut self, path: &str) {
        self.possibly_changed.insert(path.into());
    }
    /// Record a completed mutation, even when a later durability step fails.
    pub fn complete(&mut self, path: &str) {
        self.possibly_changed.remove(path);
        self.changed.insert(path.into());
    }
    /// Human-readable mutation evidence.
    #[must_use]
    pub fn text(&self) -> String {
        use std::fmt::Write as _;
        let mut text = String::new();
        for path in &self.changed {
            let _ = writeln!(text, "changed: {path}");
        }
        for path in &self.possibly_changed {
            let _ = writeln!(text, "possibly changed: {path}");
        }
        if text.is_empty() {
            text.push_str("unchanged: no mutations attempted\n");
        }
        text
    }
}

/// Installation failure with the actual binary rename state.
#[derive(Debug)]
pub struct ApplyError {
    /// Underlying operation or precondition failure.
    pub reason: String,
    /// At least one live binary was renamed, even if directory sync then failed.
    pub replaced: bool,
    /// All completed and potentially partial changes.
    pub mutations: Mutations,
}
/// Applies installation using an injected binary-replacement filesystem boundary.
/// # Errors
/// Reports whether any binary was renamed; callers choose recovery diagnostics.
pub fn apply_with_fs(
    system: &dyn System,
    paths: &Paths,
    prepared: Prepared,
    filesystem: &dyn Fs,
) -> Result<String, ApplyError> {
    apply_with_fs_tracked(system, paths, prepared, filesystem).map(|(text, _)| text)
}
/// Apply with mutation evidence on both success and failure.
/// # Errors
/// Returns confirmed and possibly changed paths with the failure.
pub fn apply_with_fs_tracked(
    system: &dyn System,
    paths: &Paths,
    prepared: Prepared,
    filesystem: &dyn Fs,
) -> Result<(String, Mutations), ApplyError> {
    let replaced = std::cell::Cell::new(false);
    let mutations = std::cell::RefCell::new(Mutations::default());
    let result = apply_inner(system, paths, prepared, filesystem, &replaced, &mutations);
    let mutations = mutations.into_inner();
    match result {
        Ok(text) => Ok((text, mutations)),
        Err(reason) => Err(ApplyError {
            reason,
            replaced: replaced.get(),
            mutations,
        }),
    }
}
#[allow(clippy::too_many_lines)]
fn apply_inner(
    system: &dyn System,
    paths: &Paths,
    mut prepared: Prepared,
    filesystem: &dyn Fs,
    replaced: &std::cell::Cell<bool>,
    mutations: &std::cell::RefCell<Mutations>,
) -> Result<String, String> {
    // No directory or lock is created until the full plan and refusals exist.
    let mut current = observe(system, paths).map_err(|e| e.to_string())?;
    current.firewall_warnings =
        super::firewall_warnings(system, &prepared.firewall_site).map_err(|e| e.to_string())?;
    for path in prepared
        .facts
        .nodes
        .keys()
        .filter(|p| {
            p.starts_with(&format!("{}/", model::SECRETS_ROOT)) && !current.nodes.contains_key(*p)
        })
        .cloned()
        .collect::<Vec<_>>()
    {
        if let Some(mut node) = optional(&paths.at(&path), false).map_err(|e| e.to_string())? {
            if node.uid == rustix::process::geteuid().as_raw() {
                node.uid = 0;
            }
            current.nodes.insert(path, node);
        }
    }
    if current != prepared.facts {
        return Err("host changed since install was planned; rerun install".into());
    }
    if prepared.plan.steps.is_empty() {
        return peer_section(paths, &prepared.request.gateway_id);
    }
    let mut identity = prepared.client_public.take();
    // Keep mutations serialized, but release before systemd starts boot, which
    // needs this same lock. Service operations are the final plan steps.
    let guard = WriterLock::acquire(paths.at(model::RUN_ROOT)).map_err(|e| e.to_string())?;
    if VersionStore::read_only(&paths.at(model::STATE_ROOT), &paths.at(model::CONFIG_ROOT))
        .head()
        .map_err(|e| e.to_string())?
        != prepared.facts.head
    {
        return Err("configuration changed since planning; rerun install".into());
    }
    for (path, expected) in &prepared.secret_hashes {
        let bytes = Zeroizing::new(read_regular(&paths.at(path), 4096).map_err(|e| e.to_string())?);
        if &hash(&bytes) != expected {
            return Err("secret changed since planning; rerun install".into());
        }
    }
    let (mutation_steps, services) = prepared.plan.steps.split_at(
        prepared
            .plan
            .steps
            .iter()
            .position(|s| matches!(s.change, Change::DaemonReload | Change::Enable))
            .unwrap_or(prepared.plan.steps.len()),
    );
    for step in mutation_steps {
        let affected = affected_paths(&step.change);
        if !matches!(step.change, Change::Binary(..)) {
            for path in &affected {
                mutations.borrow_mut().begin(path);
            }
        }
        let result: Result<(), String> = (|| {
            match &step.change {
                Change::Group => {
                    let mut args = model::GROUP_ARGS.to_vec();
                    args.push(model::ADMIN_GROUP);
                    command(system, Program::Groupadd, &args).map_err(|e| e.to_string())?;
                }
                Change::User(user) => {
                    let mut args = model::USER_ARGS.to_vec();
                    args.push(user);
                    command(system, Program::Useradd, &args).map_err(|e| e.to_string())?;
                }
                Change::Directory(path, mode) => {
                    fs::durable_directory(&paths.at(path)).map_err(|e| e.to_string())?;
                    permissions(&paths.at(path), *mode).map_err(|e| e.to_string())?;
                }
                Change::ProvisionSessions => {
                    let store = VersionStore::read_only(
                        &paths.at(model::STATE_ROOT),
                        &paths.at(model::CONFIG_ROOT),
                    );
                    let version = store
                        .head()
                        .map_err(|e| e.to_string())?
                        .ok_or("cannot provision sessions without an installed version")?;
                    let (text, _) = store.read(version).map_err(|e| e.to_string())?;
                    let site =
                        config::validate(config::parse_site(&text).map_err(|e| e.to_string())?)
                            .map_err(|_| "invalid provisioned configuration")?;
                    let gateway = site
                        .gateway(&GatewayId(prepared.request.gateway_id.clone()))
                        .ok_or("unknown gateway")?;
                    crate::client_sessions::provision(
                        &paths.at(model::STATE_ROOT),
                        gateway.client_tunnel().identity().public_key.as_str(),
                        system.now_unix_secs(),
                        &guard,
                    )
                    .map_err(|e| e.to_string())?;
                }
                Change::InitializeState => {
                    crate::state::StateFile::open(paths.at(model::STATE_ROOT), Some(&guard))
                        .and_then(|f| f.write(&guard, &initial_state()))
                        .map_err(|e| e.to_string())?;
                }
                Change::Binary(name, _) => {
                    // The planner places both binaries together. Before the first
                    // rename, persist BOTH old executables, even if only one changes.
                    if !replaced.get() {
                        for binary in model::BINARIES {
                            let destination = paths.at(&format!("{}/{binary}", model::BIN_ROOT));
                            if destination.exists() {
                                let previous = format!("{}/{binary}.prev", model::BIN_ROOT);
                                let previous_path =
                                    destination.with_file_name(format!("{binary}.prev"));
                                filesystem
                                    .check_target(&previous_path)
                                    .map_err(|e| e.to_string())?;
                                match stdfs::symlink_metadata(&previous_path) {
                                    Ok(metadata) if !metadata.is_file() => {
                                        return Err("backup target is not a regular file".into());
                                    }
                                    Err(e) if e.kind() != io::ErrorKind::NotFound => {
                                        return Err(e.to_string());
                                    }
                                    _ => {}
                                }
                                let previous_bytes = read_regular(&destination, 128 * 1024 * 1024)
                                    .map_err(|e| e.to_string())?;
                                mutations.borrow_mut().begin(&previous);
                                fs::durable_replace(
                                    filesystem,
                                    &destination.with_file_name(format!("{binary}.prev")),
                                    &previous_bytes,
                                    model::BINARY_MODE,
                                    &|_| Ok(()),
                                    &|_| Ok(()),
                                )
                                .map_err(|e| e.to_string())?;
                                mutations.borrow_mut().complete(&previous);
                            }
                        }
                    }
                    mutations
                        .borrow_mut()
                        .begin(&format!("{}/{name}", model::BIN_ROOT));
                    fs::durable_replace(
                        filesystem,
                        &paths.at(&format!("{}/{name}", model::BIN_ROOT)),
                        &prepared.binaries[name],
                        model::BINARY_MODE,
                        &|_| Ok(()),
                        &|step| {
                            if step == fs::DurableStep::Renamed {
                                replaced.set(true);
                                mutations
                                    .borrow_mut()
                                    .complete(&format!("{}/{name}", model::BIN_ROOT));
                            }
                            Ok(())
                        },
                    )
                    .map_err(|e| e.to_string())?;
                }
                Change::GenerateIdentity => {
                    let key = new_identity()?;
                    let public =
                        provider::public_key(system, &key).map_err(|_| "wg pubkey failed")?;
                    let reference = SecretName::new(SecretKind::Wg, "wg0")
                        .map_err(|_| "invalid identity reference")?;
                    SecretFile::write_new(&paths.at(model::CONFIG_ROOT), &reference, &key)
                        .map_err(|e| e.to_string())?;
                    identity = Some(public);
                }
                Change::Configuration(Configuration::Initial { .. }) => {
                    let public = if let Some(key) = identity.take() {
                        key
                    } else {
                        let reference = SecretName::new(SecretKind::Wg, "wg0")
                            .map_err(|_| "invalid identity reference")?;
                        let key = SecretFile::open_with_owner(
                            paths.at(model::CONFIG_ROOT),
                            &reference,
                            rustix::process::geteuid().as_raw(),
                        )
                        .map_err(|e| e.to_string())?;
                        provider::public_key(system, key.expose())
                            .map_err(|_| "wg pubkey failed")?
                    };
                    prepared
                        .site
                        .identities
                        .get_mut("edge")
                        .ok_or("missing identity")?
                        .public_key = public;
                    let store = VersionStore::open_with_mirror_root(
                        paths.at(model::STATE_ROOT),
                        paths.at(model::CONFIG_ROOT),
                        Some(&guard),
                    )
                    .map_err(|e| e.to_string())?;
                    let gateway = GatewayId(prepared.request.gateway_id.clone());
                    let provider = prepared
                        .provider
                        .as_ref()
                        .ok_or("missing verified provider")?;
                    let id = prepared.exit_id.clone().ok_or("missing verified exit ID")?;
                    provider::import_initial_provider(
                        &store,
                        &guard,
                        &paths.at(model::CONFIG_ROOT),
                        prepared.site.clone(),
                        &gateway,
                        provider,
                        id,
                        MetaInput {
                            actor: "root".into(),
                            at: system.now_unix_secs(),
                            reason: "install".into(),
                        },
                    )?;
                }
                Change::Configuration(Configuration::Bundle { .. }) => {
                    let target = paths.at(model::STATE_ROOT);
                    fs::durable_directory(target.parent().ok_or("missing store parent")?)
                        .map_err(|e| e.to_string())?;
                    bundle::restore(
                        prepared
                            .archive
                            .as_deref()
                            .ok_or("missing verified bundle")?,
                        &target,
                    )
                    .map_err(|e| e.to_string())?;
                    let store = VersionStore::open_with_mirror_root(
                        &target,
                        paths.at(model::CONFIG_ROOT),
                        Some(&guard),
                    )
                    .map_err(|e| e.to_string())?;
                    for v in 1..=store
                        .head()
                        .map_err(|e| e.to_string())?
                        .ok_or("missing restored head")?
                    {
                        let (text, meta) = store.read(v).map_err(|e| e.to_string())?;
                        let site = config::validate(
                            config::parse_site(&text).map_err(|_| "invalid restored site")?,
                        )
                        .map_err(|_| "invalid restored site")?;
                        let rules = scupper_core::render::render_netns(
                            &site,
                            &GatewayId(prepared.request.gateway_id.clone()),
                            &scupper_core::render::VersionStamp {
                                version: v,
                                sha256: Sha256::digest(text.as_bytes()).into(),
                            },
                        )
                        .map_err(|e| e.to_string())?;
                        let _ = meta;
                        store
                            .write_rendered(&guard, v, &rules)
                            .map_err(|e| e.to_string())?;
                    }
                }
                Change::Configuration(Configuration::Existing) => {}
                Change::File(path, node) => {
                    fs::durable_replace(
                        filesystem,
                        &paths.at(path),
                        &prepared.files[path],
                        node.mode,
                        &|_| Ok(()),
                        &|step| {
                            if step == fs::DurableStep::Renamed {
                                mutations.borrow_mut().complete(path);
                            }
                            Ok(())
                        },
                    )
                    .map_err(|e| e.to_string())?;
                }
                Change::Permissions(path, mode) => {
                    permissions(&paths.at(path), *mode).map_err(|e| e.to_string())?;
                }
                Change::DaemonReload | Change::Enable => {
                    return Err("invalid install plan: service operation among mutations".into());
                }
            }
            Ok(())
        })();
        if result.is_ok() {
            for path in &affected {
                mutations.borrow_mut().complete(path);
            }
        }
        result?;
    }
    drop(guard);
    for step in services {
        let args = match step.change {
            Change::DaemonReload => vec!["daemon-reload"],
            Change::Enable => vec!["enable", "--now", model::UNITS[0], model::UNITS[1]],
            _ => return Err("invalid install plan: mutation after service operation".into()),
        };
        let label = format!("systemctl {}", args.join(" "));
        mutations.borrow_mut().begin(&label);
        command(system, Program::Systemctl, &args).map_err(|e| e.to_string())?;
        mutations.borrow_mut().complete(&label);
    }
    peer_section(paths, &prepared.request.gateway_id)
}
fn affected_paths(change: &Change) -> Vec<String> {
    match change {
        Change::Group => vec!["/etc/group".into(), "/etc/gshadow".into()],
        Change::User(_) => vec![
            "/etc/passwd".into(),
            "/etc/shadow".into(),
            "/etc/group".into(),
        ],
        Change::Directory(path, _) | Change::File(path, _) | Change::Permissions(path, _) => {
            vec![path.clone()]
        }
        Change::Binary(name, _) => vec![format!("{}/{name}", model::BIN_ROOT)],
        Change::ProvisionSessions => vec![
            format!("{}/gateway-incarnation", model::STATE_ROOT),
            format!("{}/client-sessions.json", model::STATE_ROOT),
        ],
        Change::InitializeState => vec![
            format!("{}/state.json", model::STATE_ROOT),
            format!("{}/repair-state.json", model::STATE_ROOT),
        ],
        Change::GenerateIdentity => vec![format!("{}/wg/wg0", model::SECRETS_ROOT)],
        Change::Configuration(Configuration::Existing) | Change::DaemonReload | Change::Enable => {
            vec![]
        }
        Change::Configuration(_) => vec![model::STATE_ROOT.into(), model::CONFIG_ROOT.into()],
    }
}
fn peer_section(paths: &Paths, gateway_id: &str) -> Result<String, String> {
    let store =
        VersionStore::read_only(&paths.at(model::STATE_ROOT), &paths.at(model::CONFIG_ROOT));
    let head = store
        .head()
        .map_err(|e| e.to_string())?
        .ok_or("missing head after install")?;
    let (text, _) = store.read(head).map_err(|e| e.to_string())?;
    let site = config::parse_site(&text).map_err(|_| "invalid installed site")?;
    let gateway = &site.gateways[&GatewayId(gateway_id.into())];
    let identity = &site.identities[&gateway.client_tunnel.identity];
    let endpoint = &gateway.endpoint;
    let peer = format!(
        "[Peer]\nPublicKey = {}\nEndpoint = {}\nAllowedIPs = 0.0.0.0/0, ::/0\n",
        identity.public_key, endpoint
    );
    if !site.devices.is_empty() {
        return Ok(peer);
    }
    let subnet = gateway
        .client_tunnel
        .address4
        .parse::<ipnet::Ipv4Net>()
        .map_err(|_| "invalid installed client subnet")?;
    let address = subnet
        .hosts()
        .find(|address| *address != subnet.addr())
        .ok_or("client subnet has no free address")?;
    let quote = |value: &str| toml::Value::String(value.into()).to_string();
    let (user, user_entry) = site.users.keys().next().map_or_else(
        || ("admin", "[users.admin]\nrole = \"admin\"\n\n"),
        |user| (user.as_str(), ""),
    );
    Ok(format!(
        "{peer}\nThe Mac device must still be added before a client can join.\nAdd this TOML to the complete configuration, replacing <MAC_PUBLIC_KEY>:\n```toml\n{user_entry}[devices.mac]\nuser = {user}\npublic_key = \"<MAC_PUBLIC_KEY>\"\naddress4 = \"{address}/32\"\ngateways = [{gateway}]\n```\nSave the complete edited configuration as FILE and commit it with:\nscupper config load FILE\n",
        user = quote(user),
        gateway = quote(gateway_id),
    ))
}
