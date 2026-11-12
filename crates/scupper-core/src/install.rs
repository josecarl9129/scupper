//! Pure installation decisions. Facts and plans contain no secret values.
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt::{self, Write},
};

/// Required distribution packages, in the order used in diagnostics.
pub const PACKAGES: [&str; 4] = ["wireguard-tools", "nftables", "iproute2", "conntrack"];
/// Unprivileged helper accounts; M2 has no edge account.
pub const USERS: [&str; 2] = ["scupper-probe", "scupper-alert"];
/// Administrative group (administration still requires uid zero in M2).
pub const ADMIN_GROUP: &str = "scupper-admin";
/// Fixed system account arguments preceding the account name.
pub const USER_ARGS: [&str; 7] = [
    "--system",
    "--no-create-home",
    "--home-dir",
    "/nonexistent",
    "--shell",
    "/usr/sbin/nologin",
    "--user-group",
];
/// Fixed group creation arguments.
pub const GROUP_ARGS: [&str; 1] = ["--system"];
/// Gateway configuration root.
pub const CONFIG_ROOT: &str = "/etc/scupper";
/// Confined secret hierarchy.
pub const SECRETS_ROOT: &str = "/etc/scupper/secrets";
/// `WireGuard` secret directory.
pub const WG_ROOT: &str = "/etc/scupper/secrets/wg";
/// URL secret directory.
pub const URL_ROOT: &str = "/etc/scupper/secrets/url";
/// Boot ownership evidence.
pub const BOOT_FILE: &str = "/run/scupper/boot.json";
/// Named gateway namespace.
pub const NETNS_FILE: &str = "/run/netns/scupper";
/// Installed CLI.
pub const SCUPPER_FILE: &str = "/usr/local/bin/scupper";
/// Authoritative store root.
pub const STATE_ROOT: &str = "/var/lib/scupper";
/// Store configuration hierarchy.
pub const STORE_CONFIG_ROOT: &str = "/var/lib/scupper/config";
/// Immutable versions.
pub const VERSIONS_ROOT: &str = "/var/lib/scupper/config/versions";
/// Rendered version artifacts.
pub const RENDERED_ROOT: &str = "/var/lib/scupper/rendered";
/// Runtime root.
pub const RUN_ROOT: &str = "/run/scupper";
/// Local gateway selector.
pub const GATEWAY_FILE: &str = "/etc/scupper/gateway-id";
/// Client identity file.
pub const WG0_FILE: &str = "/etc/scupper/secrets/wg/wg0";
/// Read-only head mirror.
pub const MIRROR_FILE: &str = "/etc/scupper/scupper.toml";
/// Durable safety state.
pub const STATE_FILE: &str = "/var/lib/scupper/state.json";
/// Unit root.
pub const UNIT_ROOT: &str = "/etc/systemd/system";
/// Installed executable root.
pub const BIN_ROOT: &str = "/usr/local/bin";
/// Private directory mode.
pub const PRIVATE_DIR_MODE: u32 = 0o700;
/// Secret file mode.
pub const KEY_MODE: u32 = 0o600;
/// Mirror mode.
pub const MIRROR_MODE: u32 = 0o444;
/// Public configuration and unit mode.
pub const PUBLIC_MODE: u32 = 0o644;
/// Immutable version and rendered file mode.
pub const STORE_FILE_MODE: u32 = 0o640;
/// Executable mode.
pub const BINARY_MODE: u32 = 0o755;
/// Installation directories in parent-first order.
pub const DIRECTORIES: [(&str, u32); 8] = [
    (CONFIG_ROOT, PRIVATE_DIR_MODE),
    (SECRETS_ROOT, PRIVATE_DIR_MODE),
    (WG_ROOT, PRIVATE_DIR_MODE),
    (URL_ROOT, PRIVATE_DIR_MODE),
    (STATE_ROOT, PRIVATE_DIR_MODE),
    (STORE_CONFIG_ROOT, PRIVATE_DIR_MODE),
    (VERSIONS_ROOT, PRIVATE_DIR_MODE),
    (RENDERED_ROOT, PRIVATE_DIR_MODE),
];
/// Executables installed as one atomic replacement each.
pub const BINARIES: [&str; 2] = ["scupper", "scupperd"];
/// Units enabled after configuration is durable.
pub const UNITS: [&str; 2] = ["scupper-net", "scupperd"];

/// Observed ownership, permissions and optional public content digest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Node {
    /// Unix owner.
    pub uid: u32,
    /// Permission bits.
    pub mode: u32,
    /// SHA-256 for public files and executables only.
    pub sha256: Option<String>,
}
/// Public facts collected without changing the host.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Facts {
    /// Distribution ID.
    pub os: String,
    /// Distribution version components.
    pub os_version: (u32, u32),
    /// Kernel version components.
    pub kernel: (u32, u32),
    /// Architecture reported by uname.
    pub arch: String,
    /// Effective uid.
    pub uid: u32,
    /// A namespace exists without matching boot ownership evidence.
    pub foreign_namespace: bool,
    /// v1 evidence, including the installed binary.
    pub v1_markers: Vec<String>,
    /// Packages in installed state.
    pub packages: BTreeSet<String>,
    /// Helper users with safe system uid, home and shell.
    pub users: BTreeSet<String>,
    /// Present groups.
    pub groups: BTreeSet<String>,
    /// Inspected files and directories; absence means missing.
    pub nodes: BTreeMap<String, Node>,
    /// Enabled units.
    pub enabled: BTreeSet<String>,
    /// Public configuration settings observed at head.
    pub config_inputs: BTreeMap<String, String>,
    /// Current head (all history has been verified).
    pub head: Option<u64>,
    /// A committed historical identity names the wg0 public key.
    pub identity_named: bool,
    /// Existing selector.
    pub gateway_id: Option<String>,
    /// A locally visible firewall may block the listen port.
    pub firewall_warning: bool,
}
/// Configuration publication requested after all input has been verified.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Configuration {
    /// Use current head unchanged.
    Existing,
    /// Import the first exit into an empty store.
    Initial {
        /// Digest of the verified public configuration template.
        sha256: String,
    },
    /// Restore the exact verified archive.
    Bundle {
        /// Digest of the archive.
        sha256: String,
    },
}
/// Verified desired public state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Stable local selector.
    pub gateway_id: String,
    /// Already validated config operation.
    pub configuration: Configuration,
    /// Public files with exact desired bytes identified by digest and mode.
    pub files: BTreeMap<String, Node>,
    /// Explicit flag settings to compare against an existing head.
    pub config_inputs: BTreeMap<String, String>,
    /// Hashes of the two verified source binaries.
    pub binaries: BTreeMap<String, String>,
}
/// Refusals occur before returning any executable steps.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Refusal {
    /// Unsupported host.
    #[error(
        "install requires Ubuntu >= 22.04 or Debian >= 12, kernel >= 5.15, x86_64 or aarch64, and uid 0"
    )]
    Host,
    /// Foreign namespace.
    #[error(
        "foreign netns named scupper: neither boot.json nor scupperd Ping names its device/inode; install refused; if scupperd is starting, retry in a minute"
    )]
    ForeignNamespace,
    /// Retired layout must be migrated on a fresh host.
    #[error("v1 layout detected; build a fresh host (ADR 0014)")]
    V1,
    /// Missing packages are never automatically installed.
    #[error("missing packages; run: {0}")]
    Packages(String),
    /// Never silently change a client identity.
    #[error(
        "wg0 key is missing but committed history names its public key; restore the original key"
    )]
    MissingIdentity,
    /// Installer cannot change existing configuration.
    #[error("existing configuration differs; use scupper config or scupper exit import")]
    ExistingConfiguration,
    /// Ambiguous uplink addresses, safe to name in diagnostics.
    #[error("uplink has multiple global IPv4 addresses: {0}; specify --endpoint IP")]
    EndpointCandidates(String),
    /// Public host command failed; stderr is never included.
    #[error("{0}")]
    CommandFailed(String),
    /// Unrecognized systemctl is-enabled response, with bounded public diagnostics.
    #[error("install input: cannot inspect unit enabled state (status {status:?}): {stderr}")]
    UnitState {
        /// Exit code, or signal termination.
        status: Option<i32>,
        /// Size-capped stderr with control characters removed.
        stderr: String,
    },
    /// Input validation, with value-free diagnostics.
    #[error("install input: {0}")]
    Input(&'static str),
}
/// A typed change and the exact observation required before applying it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Step {
    /// Preconditions checked against an observed host before application.
    pub before: Condition,
    /// Exact change.
    pub change: Change,
}
/// Preconditions on an individual installation step.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Condition {
    /// Named object absent.
    Absent(String),
    /// Path's exact previous public metadata.
    Node(String, Option<Node>),
    /// Store must still be empty.
    EmptyStore,
    /// All earlier steps must be durable.
    PreviousSteps,
}
/// Ordered installation mutations.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// Create administrative group.
    Group,
    /// Create system helper account.
    User(String),
    /// Ensure root ownership and specified directory mode.
    Directory(String, u32),
    /// Replace executable by temp/fsync/rename, retaining previous bytes as .prev.
    Binary(String, String),
    /// Generate and clamp a fresh wg0 identity, using wg pubkey on stdin.
    GenerateIdentity,
    /// Initialize a new store with Auto intent and applied version one.
    InitializeState,
    /// Publish config from verified input.
    Configuration(Configuration),
    /// Write exact public content by temp/fsync/rename.
    File(String, Node),
    /// Repair ownership and permissions without rewriting content.
    Permissions(String, u32),
    /// Reload units after changed unit files.
    DaemonReload,
    /// Enable and start the M2 units.
    Enable,
}
/// Fully decided ordered operations plus availability warnings.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// Steps; empty on an unchanged rerun.
    pub steps: Vec<Step>,
    /// Value-free availability notices.
    pub warnings: Vec<&'static str>,
}
impl Plan {
    /// Stable, secret-free display for --plan and confirmation.
    #[must_use]
    pub fn text(&self) -> String {
        let mut out = String::new();
        for warning in &self.warnings {
            let _ = writeln!(out, "warning: {warning}");
        }
        if self.steps.is_empty() {
            out.push_str("install: no changes\n");
        }
        for (i, step) in self.steps.iter().enumerate() {
            let _ = writeln!(out, "{}. {}", i + 1, DisplayChange(&step.change));
        }
        out
    }
}
struct DisplayChange<'a>(&'a Change);
impl fmt::Display for DisplayChange<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Change::Group => write!(f, "groupadd --system {ADMIN_GROUP}"),
            Change::User(user) => write!(f, "useradd {} {user}", USER_ARGS.join(" ")),
            Change::Directory(path, mode) => write!(f, "directory {path} uid=0 mode={mode:04o}"),
            Change::Binary(name, hash) => write!(
                f,
                "binary {BIN_ROOT}/{name} sha256={hash} mode=0755 (atomic; keep .prev)"
            ),
            Change::GenerateIdentity => {
                write!(f, "generate wg0 identity mode=0600 (wg pubkey via stdin)")
            }
            Change::InitializeState => write!(
                f,
                "initialize state applied_version=1 selection=Auto mode=0600"
            ),
            Change::Configuration(config) => write!(f, "publish {config:?} configuration"),
            Change::File(path, node) => write!(
                f,
                "file {path} uid=0 mode={:04o} sha256={} (atomic)",
                node.mode,
                node.sha256.as_deref().unwrap_or("none")
            ),
            Change::Permissions(path, mode) => {
                write!(f, "permissions {path} uid=0 mode={mode:04o}")
            }
            Change::DaemonReload => write!(f, "systemctl daemon-reload"),
            Change::Enable => write!(f, "systemctl enable --now {}", UNITS.join(" ")),
        }
    }
}
/// Checks host support and safety without producing or executing any steps.
/// # Errors
/// Refuses unsupported hosts, v1 markers, foreign namespaces, missing packages or identity loss.
pub fn preflight(facts: &Facts) -> Result<(), Refusal> {
    if facts.uid != 0
        || !matches!(facts.arch.as_str(), "x86_64" | "aarch64")
        || facts.kernel < (5, 15)
        || !((facts.os == "ubuntu" && facts.os_version >= (22, 4))
            || (facts.os == "debian" && facts.os_version >= (12, 0)))
    {
        return Err(Refusal::Host);
    }
    if facts.foreign_namespace {
        return Err(Refusal::ForeignNamespace);
    }
    if !facts.v1_markers.is_empty() {
        return Err(Refusal::V1);
    }
    let missing: Vec<_> = PACKAGES
        .into_iter()
        .filter(|p| !facts.packages.contains(*p))
        .collect();
    if !missing.is_empty() {
        return Err(Refusal::Packages(format!(
            "apt-get install -y {}",
            PACKAGES.join(" ")
        )));
    }
    if facts.identity_named && !facts.nodes.contains_key(WG0_FILE) {
        return Err(Refusal::MissingIdentity);
    }
    Ok(())
}

/// Decides all refusals before constructing an ordered plan. Performs no I/O.
/// # Errors
/// Returns typed preflight, package, identity or configuration refusals.
#[allow(clippy::too_many_lines)]
pub fn plan(facts: &Facts, request: &Request) -> Result<Plan, Refusal> {
    preflight(facts)?;
    if facts.head.is_some()
        && request
            .config_inputs
            .iter()
            .any(|(key, value)| facts.config_inputs.get(key) != Some(value))
    {
        return Err(Refusal::ExistingConfiguration);
    }
    if facts.head.is_none() && request.configuration == Configuration::Existing {
        return Err(Refusal::Input("configuration store has no head"));
    }
    if facts
        .gateway_id
        .as_ref()
        .is_some_and(|id| id != &request.gateway_id)
        || (facts.head.is_some() && request.configuration != Configuration::Existing)
    {
        return Err(Refusal::ExistingConfiguration);
    }
    let mut steps = Vec::new();
    if !facts.groups.contains(ADMIN_GROUP) {
        steps.push(Step {
            before: Condition::Absent(ADMIN_GROUP.into()),
            change: Change::Group,
        });
    }
    for user in USERS {
        if !facts.users.contains(user) {
            steps.push(Step {
                before: Condition::Absent(user.into()),
                change: Change::User(user.into()),
            });
        }
    }
    for (path, mode) in DIRECTORIES {
        if matches!(request.configuration, Configuration::Bundle { .. })
            && path.starts_with(STATE_ROOT)
        {
            continue;
        }
        let wanted = Node {
            uid: 0,
            mode,
            sha256: None,
        };
        if facts.nodes.get(path) != Some(&wanted) {
            steps.push(Step {
                before: Condition::Node(path.into(), facts.nodes.get(path).cloned()),
                change: Change::Directory(path.into(), mode),
            });
        }
    }
    for (path, node) in &facts.nodes {
        let mode = if path.starts_with(&format!("{SECRETS_ROOT}/"))
            && !DIRECTORIES.iter().any(|(dir, _)| dir == path)
            || path == STATE_FILE
        {
            KEY_MODE
        } else if path.starts_with(&format!("{VERSIONS_ROOT}/"))
            || path.starts_with(&format!("{RENDERED_ROOT}/"))
        {
            STORE_FILE_MODE
        } else {
            continue;
        };
        if node.mode != mode || node.uid != 0 {
            steps.push(Step {
                before: Condition::Node(path.clone(), Some(node.clone())),
                change: Change::Permissions(path.clone(), mode),
            });
        }
    }
    for name in BINARIES {
        let hash = request
            .binaries
            .get(name)
            .ok_or(Refusal::Input("missing source binary"))?;
        let path = format!("{BIN_ROOT}/{name}");
        let wanted = Node {
            uid: 0,
            mode: BINARY_MODE,
            sha256: Some(hash.clone()),
        };
        if facts.nodes.get(&path) != Some(&wanted) {
            let change = if facts
                .nodes
                .get(&path)
                .is_some_and(|node| node.sha256 == wanted.sha256)
            {
                Change::Permissions(path.clone(), BINARY_MODE)
            } else {
                Change::Binary(name.into(), hash.clone())
            };
            steps.push(Step {
                before: Condition::Node(path.clone(), facts.nodes.get(&path).cloned()),
                change,
            });
        }
    }
    if !facts.nodes.contains_key(WG0_FILE) {
        steps.push(Step {
            before: Condition::Absent(WG0_FILE.into()),
            change: Change::GenerateIdentity,
        });
    }
    if matches!(request.configuration, Configuration::Initial { .. })
        && !facts.nodes.contains_key(STATE_FILE)
    {
        steps.push(Step {
            before: Condition::Absent(STATE_FILE.into()),
            change: Change::InitializeState,
        });
    }
    if request.configuration != Configuration::Existing {
        steps.push(Step {
            before: Condition::EmptyStore,
            change: Change::Configuration(request.configuration.clone()),
        });
    }
    if matches!(request.configuration, Configuration::Bundle { .. }) {
        for (path, mode) in DIRECTORIES
            .into_iter()
            .filter(|(p, _)| p.starts_with(STATE_ROOT))
        {
            steps.push(Step {
                before: Condition::PreviousSteps,
                change: Change::Directory(path.into(), mode),
            });
        }
    }
    let mut units_changed = false;
    for (path, node) in &request.files {
        if facts.nodes.get(path) != Some(node) {
            let change = if facts
                .nodes
                .get(path)
                .is_some_and(|old| old.sha256 == node.sha256)
            {
                Change::Permissions(path.clone(), node.mode)
            } else {
                units_changed |= path.starts_with(UNIT_ROOT);
                Change::File(path.clone(), node.clone())
            };
            steps.push(Step {
                before: Condition::Node(path.clone(), facts.nodes.get(path).cloned()),
                change,
            });
        }
    }
    if units_changed {
        steps.push(Step {
            before: Condition::PreviousSteps,
            change: Change::DaemonReload,
        });
    }
    if units_changed || UNITS.iter().any(|u| !facts.enabled.contains(*u)) {
        steps.push(Step {
            before: Condition::PreviousSteps,
            change: Change::Enable,
        });
    }
    Ok(Plan {
        steps,
        warnings: if facts.firewall_warning {
            vec!["host firewall may block UDP 51820; inspect locally visible rules"]
        } else {
            vec![]
        },
    })
}
