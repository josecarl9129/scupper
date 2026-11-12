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
fn write(path: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
    fs::durable_replace(&RealFs, path, bytes, mode, &|_| Ok(()), &|_| Ok(()))
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
pub fn apply(system: &dyn System, paths: &Paths, mut prepared: Prepared) -> Result<String, String> {
    // No directory or lock is created until the full plan and refusals exist.
    let mut current = observe(system, paths).map_err(|e| e.to_string())?;
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
    let (mutations, services) = prepared.plan.steps.split_at(
        prepared
            .plan
            .steps
            .iter()
            .position(|s| matches!(s.change, Change::DaemonReload | Change::Enable))
            .unwrap_or(prepared.plan.steps.len()),
    );
    for step in mutations {
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
                Change::InitializeState => {
                    crate::state::StateFile::open(paths.at(model::STATE_ROOT), Some(&guard))
                        .and_then(|f| f.write(&guard, &initial_state()))
                        .map_err(|e| e.to_string())?;
                }
                Change::Binary(name, _) => {
                    let destination = paths.at(&format!("{}/{name}", model::BIN_ROOT));
                    if destination.exists() {
                        let previous = destination.with_file_name(format!("{name}.prev"));
                        // Copy old bytes durably without removing the executable;
                        // a failure cannot leave a gap at the live pathname.
                        write(
                            &previous,
                            &read_regular(&destination, 128 * 1024 * 1024)
                                .map_err(|e| e.to_string())?,
                            model::BINARY_MODE,
                        )
                        .map_err(|e| e.to_string())?;
                    }
                    write(&destination, &prepared.binaries[name], model::BINARY_MODE)
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
                    write(&paths.at(path), &prepared.files[path], node.mode)
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
        result?;
    }
    drop(guard);
    for step in services {
        let args = match step.change {
            Change::DaemonReload => vec!["daemon-reload"],
            Change::Enable => vec!["enable", "--now", model::UNITS[0], model::UNITS[1]],
            _ => return Err("invalid install plan: mutation after service operation".into()),
        };
        command(system, Program::Systemctl, &args).map_err(|e| e.to_string())?;
    }
    peer_section(paths, &prepared.request.gateway_id)
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
