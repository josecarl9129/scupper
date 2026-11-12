//! Gateway provider input and public-key derivation. Secret bytes never enter argv.
use crate::{
    cmd::{KernelCmd, WgCmd, run_cmd_with_stdin},
    system::{ExecTarget, System},
};
use scupper_core::config::{
    PublicKey,
    provider::{MAX_PROVIDER_BYTES, ProviderConfig, parse_provider},
};
use std::{
    fs::File,
    io::{self, Read},
    path::Path,
    time::Duration,
};
use zeroize::Zeroizing;

/// Reads a bounded regular provider file into zeroizing memory, then parses it.
/// # Errors
/// Refuses nonregular/oversize input before parsing; diagnostics omit input bytes.
pub fn read_provider(path: &Path) -> Result<ProviderConfig, String> {
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| "cannot open provider file")?;
    let file = File::from(fd);
    let metadata = file
        .metadata()
        .map_err(|_| "cannot inspect provider file")?;
    if !metadata.is_file() || metadata.len() > MAX_PROVIDER_BYTES as u64 {
        return Err("provider file must be regular and at most 16 KiB".into());
    }
    let mut bytes = Zeroizing::new(Vec::with_capacity(MAX_PROVIDER_BYTES + 1));
    file.take((MAX_PROVIDER_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| "cannot read provider file")?;
    if bytes.len() > MAX_PROVIDER_BYTES {
        return Err("provider file exceeds 16 KiB".into());
    }
    let input = std::str::from_utf8(&bytes).map_err(|_| "provider file must be UTF-8")?;
    parse_provider(input).map_err(|e| e.to_string())
}

/// Derives the public key using the existing constrained `wg pubkey` stdin command.
/// No supplied private key can be imported into the existing ring API.
/// # Errors
/// Returns a value-free error on any child failure or malformed public output.
pub fn public_key(system: &dyn System, private: &[u8]) -> io::Result<PublicKey> {
    let output = run_cmd_with_stdin(
        system,
        ExecTarget::Host,
        &KernelCmd::Wg(WgCmd::Pubkey),
        private,
        Duration::from_secs(5),
    )
    .map_err(|_| io::Error::other("wg pubkey failed"))?;
    if output.status != Some(0) {
        return Err(io::Error::other("wg pubkey failed"));
    }
    let mut key = PublicKey(output.stdout.trim().into());
    key.bytes()
        .map_err(|_| io::Error::other("invalid wg pubkey output"))?;
    if key.0.len() == 43 {
        key.0.push('=');
    }
    Ok(key)
}

/// Builds the public exit settings used by replacement and initial imports.
/// IPv6 provider settings are deliberately omitted in M2.
/// # Errors
/// Refuses IDs that cannot fit generation-specific secret references.
pub fn exit_config(
    provider: &ProviderConfig,
    id: scupper_core::config::ExitId,
    name: scupper_core::config::ExitName,
    ifname: String,
    generation: u64,
) -> Result<scupper_core::config::Exit, String> {
    use scupper_core::config::{DurationStr, Exit, SecretKind, SecretName};
    if !id.is_valid() || id.as_str().len() > 32 || generation == 0 {
        return Err("invalid import exit id or generation".into());
    }
    let private_key_ref = SecretName::new(SecretKind::Wg, &format!("exit-{id}-v{generation}"))
        .map_err(|_| "invalid exit key reference")?;
    let preshared_key_ref = provider
        .preshared_key()
        .map(|_| SecretName::new(SecretKind::Wg, &format!("exit-{id}-v{generation}-psk")))
        .transpose()
        .map_err(|_| "invalid preshared-key reference")?;
    Ok(Exit {
        id,
        name,
        tags: vec![],
        provider: "proton".into(),
        ifname,
        private_key_ref,
        preshared_key_ref,
        peer_public_key: provider.peer_public_key.clone(),
        endpoint: provider.endpoint.to_string(),
        address4: provider.address4.clone(),
        address6: None,
        dns: provider
            .dns
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(ToString::to_string)
            .collect(),
        keepalive: DurationStr(format!("{}s", provider.keepalive.unwrap_or(25))),
        mtu: u32::from(provider.mtu.unwrap_or(1420)),
        enabled: true,
    })
}

/// Imports the first provider exit into an empty version store for installer callers.
/// The supplied public site skeleton must have an empty gateway exit list. The
/// caller holds the writer lock and provisions all other referenced secrets.
/// Uses the same parser, exit settings and confined key writer as CLI imports.
/// # Errors
/// Refuses an existing head, nonempty exit list, invalid provider/site or unsafe
/// secrets. On a commit error, retains keys because publication may have succeeded;
/// the caller must inspect head before attempting recovery.
#[allow(clippy::too_many_arguments)]
pub fn import_initial(
    store: &crate::store::VersionStore,
    guard: &crate::lock::WriterGuard,
    config_root: &Path,
    mut site: scupper_core::config::SiteConfig,
    gateway: &scupper_core::config::GatewayId,
    file: &Path,
    meta: crate::store::MetaInput,
) -> Result<u64, String> {
    use crate::secrets::SecretFile;
    use scupper_core::config::validate;
    use sha2::{Digest, Sha256};
    if store.head().map_err(|e| e.to_string())?.is_some() {
        return Err("initial import requires an empty configuration store".into());
    }
    let gw = site.gateways.get_mut(gateway).ok_or("unknown gateway")?;
    if !gw.exits.is_empty() {
        return Err("initial import requires an empty exit list".into());
    }
    let provider = read_provider(file)?;
    let exit = exit_config(
        &provider,
        provider.suggested_id.clone(),
        provider.suggested_name.clone(),
        "ex-0".into(),
        1,
    )?;
    site.policy.exits = vec![exit.id.clone()];
    gw.exits.push(exit.clone());
    let validated = validate(site.clone()).map_err(|_| "invalid initial site configuration")?;
    let text = toml::to_string(&site).map_err(|_| "cannot encode initial site configuration")?;
    SecretFile::write_new(config_root, &exit.private_key_ref, provider.private_key())
        .map_err(|e| e.to_string())?;
    if let (Some(reference), Some(psk)) = (&exit.preshared_key_ref, provider.preshared_key()) {
        SecretFile::write_new(config_root, reference, psk).map_err(|e| e.to_string())?;
    }
    SecretFile::preflight(config_root, &site, rustix::process::geteuid().as_raw())
        .map_err(|e| e.to_string())?;
    let version = store
        .commit(guard, None, &text, meta)
        .map_err(|e| e.to_string())?;
    let rules = scupper_core::render::render_netns(
        &validated,
        gateway,
        &scupper_core::render::VersionStamp {
            version,
            sha256: Sha256::digest(text.as_bytes()).into(),
        },
    )
    .map_err(|e| format!("version {version} committed; render: {e}"))?;
    store
        .write_rendered(guard, version, &rules)
        .map_err(|e| format!("version {version} committed; render write: {e}"))?;
    Ok(version)
}
