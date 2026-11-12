//! Read-only installation observation and durable execution of pure plans.
use crate::{
    bundle,
    fs::{self, Fs, RealFs},
    lock::WriterLock,
    provider,
    secrets::SecretFile,
    store::{MetaInput, VersionStore},
    system::{EXEC_TIMEOUT, Program, SYSTEMCTL_TIMEOUT, System},
};
use scupper_core::{
    config::{self, ExitId, GatewayId, PublicKey, SecretKind, SecretName, SiteConfig},
    install::{self as model, Change, Configuration, Facts, Node, Plan, Refusal, Request},
};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs as stdfs,
    io::{self, Read},
    os::unix::fs::{MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
};
use zeroize::Zeroizing;

mod execute;
mod firewall;
mod observe;
pub use execute::apply;
use observe::observe;

/// Flag inputs. No field holds key material.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// Directory containing both executables.
    pub binaries: PathBuf,
    /// Optional verified-on-read bundle.
    pub bundle: Option<PathBuf>,
    /// Stable gateway ID.
    pub gateway_id: Option<String>,
    /// Host uplink interface.
    pub uplink: Option<String>,
    /// Explicit literal IPv4 endpoint for a new installation.
    pub endpoint: Option<String>,
    /// Downloaded provider file.
    pub exit_file: Option<PathBuf>,
    /// Stable exit ID.
    pub exit_id: Option<String>,
}
/// Path mapping for the production root or an isolated integration-test host.
#[derive(Debug, Clone)]
pub struct Paths {
    root: PathBuf,
}
impl Paths {
    /// Uses `/` on production; tests supply their private host root.
    #[must_use]
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }
    /// Resolves a fixed absolute installation path underneath this root.
    #[must_use]
    pub fn at(&self, path: &str) -> PathBuf {
        self.root.join(path.trim_start_matches('/'))
    }
}
/// Verified input and public plan. Private data has no Debug representation.
pub struct Prepared {
    /// All mutations, already decided.
    pub plan: Plan,
    facts: Facts,
    request: Request,
    files: BTreeMap<String, Vec<u8>>,
    binaries: BTreeMap<String, Vec<u8>>,
    provider: Option<config::provider::ProviderConfig>,
    archive: Option<Vec<u8>>,
    site: SiteConfig,
    exit_id: Option<ExitId>,
    client_public: Option<PublicKey>,
    secret_hashes: BTreeMap<String, String>,
}
impl std::fmt::Debug for Prepared {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Prepared")
            .field("plan", &self.plan)
            .finish_non_exhaustive()
    }
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn input(message: &'static str) -> Refusal {
    Refusal::Input(message)
}
fn command(system: &dyn System, program: Program, args: &[&str]) -> Result<String, Refusal> {
    let program_path = program.default_path();
    // enable --now waits for the units' bounded 90-second startup.
    let timeout = if program == Program::Systemctl && args.first() == Some(&"enable") {
        std::time::Duration::from_secs(120)
    } else {
        SYSTEMCTL_TIMEOUT
    };
    let out = system
        .run(
            program,
            &args.iter().map(|s| (*s).into()).collect::<Vec<_>>(),
            timeout,
        )
        .map_err(|_| {
            Refusal::CommandFailed(format!(
                "{program_path} {} failed (execution error)",
                args.join(" ")
            ))
        })?;
    if out.status != Some(0) {
        return Err(Refusal::CommandFailed(format!(
            "{program_path} {} failed (exit {})",
            args.join(" "),
            out.status
                .map_or_else(|| "signal".into(), |status| status.to_string())
        )));
    }
    Ok(out.stdout)
}
fn version(text: &str) -> Result<(u32, u32), Refusal> {
    let mut parts = text.trim().split(['.', '-']);
    let major = parts
        .next()
        .and_then(|s| s.parse().ok())
        .ok_or_else(|| input("invalid platform version"))?;
    let minor = parts
        .next()
        .unwrap_or("0")
        .parse()
        .map_err(|_| input("invalid platform version"))?;
    Ok((major, minor))
}
fn check_parents(path: &Path) -> Result<(), Refusal> {
    for parent in path.ancestors().skip(1) {
        match stdfs::symlink_metadata(parent) {
            Ok(m) if !m.is_dir() || m.is_symlink() => return Err(input("unsafe input parent")),
            Ok(_) => {}
            Err(e) if e.kind() == io::ErrorKind::NotFound => {}
            Err(_) => return Err(input("cannot inspect input parent")),
        }
    }
    Ok(())
}
fn optional(path: &Path, digest: bool) -> Result<Option<Node>, Refusal> {
    check_parents(path)?;
    match stdfs::symlink_metadata(path) {
        Ok(m) if m.is_symlink() || (!m.is_dir() && !m.is_file()) => {
            Err(input("unsafe installation path"))
        }
        Ok(m) => Ok(Some(Node {
            uid: m.uid(),
            mode: m.mode() & 0o7777,
            sha256: if digest {
                Some(hash(&read_regular(path, 128 * 1024 * 1024)?))
            } else {
                None
            },
        })),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(_) => Err(input("cannot inspect installation path")),
    }
}
fn read_regular(path: &Path, limit: usize) -> Result<Vec<u8>, Refusal> {
    check_parents(path)?;
    let fd = rustix::fs::open(
        path,
        rustix::fs::OFlags::RDONLY
            | rustix::fs::OFlags::NOFOLLOW
            | rustix::fs::OFlags::NONBLOCK
            | rustix::fs::OFlags::CLOEXEC,
        rustix::fs::Mode::empty(),
    )
    .map_err(|_| input("cannot open input file"))?;
    let file = stdfs::File::from(fd);
    let m = file
        .metadata()
        .map_err(|_| input("cannot inspect input file"))?;
    if !m.is_file() || m.len() > limit as u64 {
        return Err(input("input must be a bounded regular file"));
    }
    let mut bytes = Vec::new();
    file.take((limit + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| input("cannot read input file"))?;
    if bytes.len() > limit {
        return Err(input("input exceeds size limit"));
    }
    Ok(bytes)
}
fn skeleton(id: &str, uplink: &str, endpoint: &str) -> Result<SiteConfig, Refusal> {
    // Serialize values as TOML strings to keep flags out of syntax positions.
    let quote = |s: &str| toml::Value::String(s.into()).to_string();
    config::parse_site(&format!(
        r#"schema = 1
[site]
name = "scupper"
primary = {id}
[identities.edge]
public_key = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
private_key_ref = "wg0"
listen_port = 51820
[gateways.{id}]
netns = "scupper"
uplinks = [{uplink}]
endpoint = {endpoint}
exits = []
[gateways.{id}.client_tunnel]
ifname = "wg0"
identity = "edge"
address4 = "10.99.0.1/24"
[policy]
exits = []
"#,
        id = quote(id),
        uplink = quote(uplink),
        endpoint = quote(endpoint)
    ))
    .map_err(|_| input("invalid initial configuration"))
}
fn uplink_address(system: &dyn System, uplink: &str) -> Result<std::net::Ipv4Addr, Refusal> {
    scupper_core::rules::IfName::new(uplink).map_err(|_| input("invalid uplink"))?;
    let text = command(
        system,
        Program::Ip,
        &["-j", "-4", "address", "show", "dev", uplink],
    )?;
    let json: serde_json::Value =
        serde_json::from_str(&text).map_err(|_| input("invalid uplink observation"))?;
    let mut addresses: Vec<_> = json
        .as_array()
        .into_iter()
        .flatten()
        .flat_map(|link| link["addr_info"].as_array().into_iter().flatten())
        .filter(|addr| addr["scope"] == "global")
        .map(|addr| {
            addr["local"]
                .as_str()
                .ok_or_else(|| input("invalid uplink address"))?
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| input("invalid uplink address"))
        })
        .collect::<Result<_, _>>()?;
    addresses.sort_unstable();
    addresses.dedup();
    match addresses.as_slice() {
        [] => Err(input("uplink has no global IPv4 address")),
        [address] => endpoint_address(*address),
        _ => Err(Refusal::EndpointCandidates(
            addresses
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", "),
        )),
    }
}

fn endpoint_address(address: std::net::Ipv4Addr) -> Result<std::net::Ipv4Addr, Refusal> {
    if !config::valid_endpoint_ip(address.into()) {
        return Err(input(
            "endpoint must be a unicast IPv4 address, excluding loopback and link-local",
        ));
    }
    Ok(address)
}

/// Verifies every input and observes the host without writing any files.
/// # Errors
/// Refuses unsupported hosts, unsafe paths, conflicting flags, keys or store state.
#[allow(clippy::too_many_lines)]
pub fn prepare(system: &dyn System, paths: &Paths, options: &Options) -> Result<Prepared, Refusal> {
    let mut facts = observe(system, paths)?;
    if options.bundle.is_some()
        && (options.exit_file.is_some()
            || options.exit_id.is_some()
            || options.uplink.is_some()
            || options.endpoint.is_some())
    {
        return Err(input("--bundle conflicts with initial configuration flags"));
    }
    let endpoint = options
        .endpoint
        .as_deref()
        .map(|address| {
            address
                .parse::<std::net::Ipv4Addr>()
                .map_err(|_| input("--endpoint must be a literal IPv4 address"))
                .and_then(endpoint_address)
        })
        .transpose()?;
    let archive = options
        .bundle
        .as_ref()
        .map(|p| bundle::read_bundle(p).map_err(|_| input("cannot read bundle")))
        .transpose()?;
    let bundled = archive
        .as_ref()
        .map(|bytes| bundle::configurations(bytes).map_err(|_| input("bundle verification failed")))
        .transpose()?;
    let store =
        VersionStore::read_only(&paths.at(model::STATE_ROOT), &paths.at(model::CONFIG_ROOT));
    let mut private_endpoint = false;
    let mut site = if let Some(configs) = &bundled {
        configs
            .last()
            .cloned()
            .ok_or_else(|| input("bundle contains no versions"))?
    } else if let Some(head) = facts.head {
        config::parse_site(&store.read(head).map_err(|_| input("cannot read head"))?.0)
            .map_err(|_| input("invalid head"))?
    } else {
        let id = options
            .gateway_id
            .as_deref()
            .ok_or_else(|| input("--gateway-id is required"))?;
        let uplink = options
            .uplink
            .as_deref()
            .ok_or_else(|| input("--uplink is required"))?;
        let selected = endpoint.map_or_else(|| uplink_address(system, uplink), Ok)?;
        let [a, b, _, _] = selected.octets();
        private_endpoint =
            endpoint.is_none() && (selected.is_private() || (a == 100 && (64..=127).contains(&b)));
        skeleton(id, uplink, &format!("{selected}:51820"))?
    };
    let link_names: Vec<_> = site
        .gateways
        .values()
        .flat_map(|g| {
            std::iter::once(g.client_tunnel.ifname.as_str())
                .chain(g.exits.iter().map(|e| e.ifname.as_str()))
        })
        .collect();
    if !crate::v1_detect::detect_install_layout(system, &link_names, &facts.packages)
        .map_err(|_| input("cannot inspect configured host links"))?
        .is_empty()
    {
        return Err(Refusal::V1);
    }
    let gateway = site.site.primary.clone();
    facts.firewall_warning = firewall_warning(system, &site)?;

    if facts.head.is_some()
        && endpoint.is_some_and(|ip| site.gateways[&gateway].endpoint != format!("{ip}:51820"))
    {
        return Err(Refusal::ExistingConfiguration);
    }
    if options
        .gateway_id
        .as_ref()
        .is_some_and(|id| id != gateway.as_str())
    {
        return Err(Refusal::ExistingConfiguration);
    }
    if (facts.identity_named || bundled.is_some()) && !facts.nodes.contains_key(model::WG0_FILE) {
        return Err(Refusal::MissingIdentity);
    }
    let provider = options
        .exit_file
        .as_ref()
        .map(|p| provider::read_provider(p).map_err(|_| input("invalid provider file")))
        .transpose()?;
    let configuration;
    let mut initial_refs = Vec::new();
    if facts.head.is_some() {
        if let Some(bytes) = &archive
            && bundle::export(&paths.at(model::STATE_ROOT), None)
                .map_err(|_| input("cannot compare restored bundle"))?
                != *bytes
        {
            return Err(Refusal::ExistingConfiguration);
        }
        let gw = site
            .gateways
            .get(&gateway)
            .ok_or_else(|| input("unknown gateway"))?;
        let exit = gw
            .exits
            .first()
            .ok_or_else(|| input("existing store has no exit"))?;
        if let Some(provider) = &provider {
            let mut proposed = provider::exit_config(
                provider,
                exit.id.clone(),
                exit.name.clone(),
                exit.ifname.clone(),
                1,
            )
            .map_err(|_| input("invalid exit ID"))?;
            proposed.private_key_ref = exit.private_key_ref.clone();
            proposed
                .preshared_key_ref
                .clone_from(&exit.preshared_key_ref);
            proposed.tags.clone_from(&exit.tags);
            proposed.enabled = exit.enabled;
            if serde_json::to_value(&proposed).ok() != serde_json::to_value(exit).ok() {
                return Err(Refusal::ExistingConfiguration);
            }
            verify_same_key(paths, &exit.private_key_ref, provider.private_key())?;
            match (&exit.preshared_key_ref, provider.preshared_key()) {
                (Some(reference), Some(key)) => verify_same_key(paths, reference, key)?,
                (None, None) => {}
                _ => return Err(Refusal::ExistingConfiguration),
            }
        }
        configuration = Configuration::Existing;
    } else if let Some(bytes) = &archive {
        // Restore requires an empty target. Detect conflicting partial layouts
        // before provisioning accounts, directories or binaries.
        if paths.at(model::STATE_ROOT).exists()
            && stdfs::read_dir(paths.at(model::STATE_ROOT))
                .map_err(|_| input("cannot inspect restore target"))?
                .next()
                .is_some()
        {
            return Err(input("bundle restore target is not empty"));
        }
        configuration = Configuration::Bundle {
            sha256: hash(bytes),
        };
    } else {
        let provider = provider
            .as_ref()
            .ok_or_else(|| input("--exit-file is required"))?;
        let id = ExitId(
            options
                .exit_id
                .clone()
                .ok_or_else(|| input("--exit-id is required"))?,
        );
        let exit = provider::exit_config(
            provider,
            id,
            provider.suggested_name.clone(),
            "ex-0".into(),
            1,
        )
        .map_err(|_| input("invalid exit ID"))?;
        initial_refs.extend(
            std::iter::once(exit.private_key_ref.clone()).chain(exit.preshared_key_ref.clone()),
        );
        // Validate the completed template, without publishing placeholder identity.
        let gw = site
            .gateways
            .get_mut(&gateway)
            .ok_or_else(|| input("unknown gateway"))?;
        gw.exits.push(exit.clone());
        site.policy.exits = vec![exit.id.clone()];
        config::validate(site.clone()).map_err(|_| input("invalid initial site configuration"))?;
        for (reference, key) in std::iter::once((&exit.private_key_ref, provider.private_key()))
            .chain(
                exit.preshared_key_ref
                    .as_ref()
                    .zip(provider.preshared_key()),
            )
        {
            if optional(
                &paths.at(&format!("{}/{}", model::WG_ROOT, reference.name())),
                false,
            )?
            .is_some()
            {
                verify_same_key(paths, reference, key)?;
            }
        }
        let text = toml::to_string(&site).map_err(|_| input("cannot encode initial site"))?;
        configuration = Configuration::Initial {
            sha256: hash(text.as_bytes()),
        };
        site.gateways
            .get_mut(&gateway)
            .ok_or_else(|| input("unknown gateway"))?
            .exits
            .clear();
        site.policy.exits.clear();
    }
    // Fresh intent is persisted before publishing version one, so a crash never
    // leaves a committed fresh gateway with missing safety state.
    let saved = crate::state::StateFile::open(paths.at(model::STATE_ROOT), None)
        .and_then(|f| f.read())
        .map_err(|_| input("invalid safety state"))?;
    match &saved {
        crate::state::StateRead::Missing if facts.head.is_some() => {
            return Err(input(
                "state.json is missing; restore safety state before rerunning install",
            ));
        }
        crate::state::StateRead::Present(state) => {
            if facts.head.is_none() && *state != initial_state() {
                return Err(input("nonempty safety state without a configuration head"));
            }
            if let Some(head) = facts.head
                && state.applied_version.is_none_or(|v| v == 0 || v > head)
            {
                return Err(input("invalid applied version in safety state"));
            }
        }
        crate::state::StateRead::Missing => {}
    }
    let mut required_sites = vec![site.clone()];
    if let Some(bytes) = &archive {
        let state = bundle::read_state(bytes).map_err(|_| input("invalid bundle state"))?;
        let applied = state
            .applied_version
            .ok_or_else(|| input("bundle state has no applied version"))?;
        let start =
            usize::try_from(applied - 1).map_err(|_| input("invalid bundle applied version"))?;
        required_sites = bundled
            .as_ref()
            .and_then(|s| s.get(start..))
            .ok_or_else(|| input("invalid bundle applied version"))?
            .to_vec();
    } else if let (Some(head), crate::state::StateRead::Present(state)) = (facts.head, &saved) {
        for version in state.applied_version.unwrap_or(head)..head {
            let text = store
                .read(version)
                .map_err(|_| input("invalid applied history"))?
                .0;
            required_sites
                .push(config::parse_site(&text).map_err(|_| input("invalid applied history"))?);
        }
    }
    // Validate secrets before provisioning, while allowing permission repairs
    // already represented in the plan. Symlinks and foreign owners are refused.
    let refs: Vec<_> = required_sites
        .iter()
        .flat_map(|site| {
            site.identities
                .values()
                .map(|i| &i.private_key_ref)
                .chain(site.gateways.values().flat_map(|g| &g.exits).flat_map(|e| {
                    std::iter::once(&e.private_key_ref).chain(e.preshared_key_ref.as_ref())
                }))
                .chain(site.alerts.sinks.values().map(config::AlertSink::url_ref))
                .chain(site.heartbeat.as_ref().map(|h| &h.url_ref))
                .cloned()
        })
        .chain(initial_refs)
        .collect();
    let mut secret_hashes = BTreeMap::new();
    for reference in refs {
        let path = secret_path(&reference);
        if configuration == Configuration::Existing || archive.is_some() || paths.at(&path).exists()
        {
            let key = read_install_secret(paths, &reference)?;
            secret_hashes.insert(path.clone(), hash(&key));
            let mut node = optional(&paths.at(&path), false)?
                .ok_or_else(|| input("missing configured secret"))?;
            if node.uid == rustix::process::geteuid().as_raw() {
                node.uid = 0;
            }
            facts.nodes.insert(path, node);
        }
    }
    let client_public = if facts.nodes.contains_key(model::WG0_FILE) {
        let reference = SecretName::new(SecretKind::Wg, "wg0")
            .map_err(|_| input("invalid identity reference"))?;
        let secret = read_install_secret(paths, &reference)?;
        let public = provider::public_key(system, &secret)
            .map_err(|_| input("cannot derive wg0 public key"))?;
        if configuration == Configuration::Existing || archive.is_some() {
            for required in &required_sites {
                let identity = required
                    .identities
                    .values()
                    .find(|i| i.private_key_ref.name() == "wg0")
                    .ok_or_else(|| input("client identity must use wg0"))?;
                if public.bytes().ok() != identity.public_key.bytes().ok() {
                    return Err(input("wg0 key does not match configured public key"));
                }
            }
        }
        secret_hashes.insert(model::WG0_FILE.into(), hash(&secret));
        Some(public)
    } else {
        None
    };
    let mut files = BTreeMap::from([
        (
            model::GATEWAY_FILE.into(),
            format!("{gateway}\n").into_bytes(),
        ),
        (
            format!("{}/scupper-net.service", model::UNIT_ROOT),
            scupper_core::render::units::scupper_net()
                .as_bytes()
                .to_vec(),
        ),
        (
            format!("{}/scupperd.service", model::UNIT_ROOT),
            scupper_core::render::units::scupperd().as_bytes().to_vec(),
        ),
    ]);
    if let Some(head) = facts.head {
        files.insert(
            model::MIRROR_FILE.into(),
            store
                .read(head)
                .map_err(|_| input("cannot read mirror source"))?
                .0
                .into_bytes(),
        );
    }
    // Verify the unit directory itself, even when every unit is absent.
    if optional(&paths.at(model::UNIT_ROOT), false)?.is_none() {
        return Err(input("systemd unit directory is missing"));
    }
    let binaries: BTreeMap<String, Vec<u8>> = model::BINARIES
        .into_iter()
        .map(|name| {
            Ok((
                name.into(),
                read_regular(&options.binaries.join(name), 128 * 1024 * 1024)?,
            ))
        })
        .collect::<Result<BTreeMap<_, _>, Refusal>>()?;
    let request = Request {
        gateway_id: gateway.to_string(),
        configuration,
        files: files
            .iter()
            .map(|(path, bytes)| {
                (
                    path.clone(),
                    Node {
                        uid: 0,
                        mode: if path == model::MIRROR_FILE {
                            model::MIRROR_MODE
                        } else {
                            model::PUBLIC_MODE
                        },
                        sha256: Some(hash(bytes)),
                    },
                )
            })
            .collect(),
        config_inputs: [
            ("uplink", options.uplink.as_ref()),
            ("exit-id", options.exit_id.as_ref()),
        ]
        .into_iter()
        .filter_map(|(key, value)| value.map(|v| (key.into(), v.clone())))
        .collect(),
        binaries: binaries
            .iter()
            .map(|(name, bytes)| (name.clone(), hash(bytes)))
            .collect(),
    };
    let mut plan = model::plan(&facts, &request)?;
    if private_endpoint {
        plan.warnings.push("the sole uplink IPv4 address is private or shared; use --endpoint IP to specify the public address clients can reach");
    }
    Ok(Prepared {
        plan,
        facts,
        request,
        files,
        binaries,
        provider,
        archive,
        site,
        exit_id: options.exit_id.clone().map(ExitId),
        client_public,
        secret_hashes,
    })
}
fn firewall_warning(system: &dyn System, site: &SiteConfig) -> Result<bool, Refusal> {
    let ruleset = command(system, Program::Nft, &["-j", "list", "ruleset"])?;
    let ruleset =
        serde_json::from_str(&ruleset).map_err(|_| input("invalid firewall observation"))?;
    let gateway = site
        .gateways
        .get(&site.site.primary)
        .ok_or_else(|| input("unknown gateway"))?;
    Ok(gateway
        .uplinks
        .iter()
        .any(|uplink| firewall::may_block(&ruleset, uplink)))
}
fn verify_same_key(paths: &Paths, reference: &SecretName, key: &[u8]) -> Result<(), Refusal> {
    let secret = read_install_secret(paths, reference)?;
    if secret.as_slice() != key {
        return Err(input(
            "unreferenced or configured exit key differs; inspect the leftover key or use scupper exit import",
        ));
    }
    Ok(())
}
fn initial_state() -> crate::state::State {
    crate::state::State {
        applied_version: Some(1),
        ..crate::state::State::default()
    }
}
fn secret_path(reference: &SecretName) -> String {
    format!(
        "{}/secrets/{}/{}",
        model::CONFIG_ROOT,
        if reference.kind() == SecretKind::Wg {
            "wg"
        } else {
            "url"
        },
        reference.name()
    )
}
fn read_install_secret(
    paths: &Paths,
    reference: &SecretName,
) -> Result<Zeroizing<Vec<u8>>, Refusal> {
    let path = paths.at(&secret_path(reference));
    let metadata =
        stdfs::symlink_metadata(&path).map_err(|_| input("missing configured secret"))?;
    if metadata.uid() != rustix::process::geteuid().as_raw() {
        return Err(input("foreign secret owner"));
    }
    let bytes = Zeroizing::new(read_regular(&path, 4096)?);
    let text = std::str::from_utf8(&bytes).map_err(|_| input("invalid secret encoding"))?;
    let valid = match reference.kind() {
        SecretKind::Wg => config::valid_wg_secret(text.strip_suffix('\n').unwrap_or(text)),
        SecretKind::Url => config::valid_https_url(text.strip_suffix('\n').unwrap_or(text)),
    };
    if !valid {
        return Err(input("invalid configured secret"));
    }
    Ok(bytes)
}
