//! M2 observations. Every namespace command targets the borrowed, held handle.
//! Missing boot.json or state.json is an observation error, never a reset to Auto.
//! No collector reads a private key or asks `WireGuard` for a secret-bearing field.

pub(crate) mod forwarding;
pub(crate) mod reconcile;
pub(crate) mod routes;
pub(crate) mod topology;
pub(crate) use topology::topology_recorded;

pub use forwarding::forwarding;
pub use routes::{defaults, routes};
pub use topology::topology;

use crate::{
    canon::command_result,
    cmd::{KernelCmd, WgCmd, run_cmd},
    fs::{Fs, RealFs},
    netns::NetnsHandle,
    probe_child::{ProbeExec, ProbeKind, ProbeRequest, Url, run_probe},
    state::{State, StateFile, StateRead},
    system::{EXEC_TIMEOUT, ExecTarget, System},
};
use scupper_core::{
    config::{ExitId, GatewayId, PublicKey, ValidatedSite},
    parse::{Handshake, PeerKey, WgField, WgOutput, parse_wg},
    rules::IfName,
    verdict::v2::{HealthConfigV2, NetnsIdentity, Probe, ProbeError, Supervisor},
};
use serde::Deserialize;
use std::{collections::BTreeMap, net::IpAddr, path::Path};

#[allow(clippy::needless_pass_by_value)] // Own the single-use typed command at the collection boundary.
pub(super) fn observe(sys: &dyn System, handle: &NetnsHandle, cmd: KernelCmd) -> Probe<String> {
    command_result(run_cmd(sys, ExecTarget::Netns(handle), &cmd, EXEC_TIMEOUT))
}

pub(super) fn key_bytes(key: &PeerKey) -> Probe<[u8; 32]> {
    PublicKey(key.as_str().into())
        .bytes()
        .map_err(|_| ProbeError::io("invalid public key"))
}

pub(super) fn wg(
    sys: &dyn System,
    handle: &NetnsHandle,
    name: &str,
    field: WgField,
) -> Probe<WgOutput> {
    let ifname =
        IfName::new(name).map_err(|_| ProbeError::io("unrepresentable WireGuard interface"))?;
    let text = observe(sys, handle, KernelCmd::Wg(WgCmd::Show { ifname, field }))?;
    Ok(parse_wg(field, &text)?)
}

pub(super) fn peer_field(
    sys: &dyn System,
    handle: &NetnsHandle,
    name: &str,
    field: WgField,
) -> Probe<Vec<scupper_core::parse::WgPeer>> {
    match wg(sys, handle, name, field)? {
        WgOutput::Peers(peers) => Ok(peers),
        _ => Err(ProbeError::io("unexpected WireGuard response type")),
    }
}

/// Reads the expected identity from `root/boot.json` (`/run/scupper` in production). Absence is a required-observation
/// error: a live inode cannot establish the identity boot was meant to create.
/// The remaining boot report fields are intentionally ignored.
///
/// # Errors
/// Returns missing/unsafe file, malformed identity and I/O errors.
pub fn boot_identity(root: &Path) -> Probe<NetnsIdentity> {
    #[derive(Deserialize)]
    struct Boot {
        netns: Identity,
    }
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Identity {
        dev: u64,
        ino: u64,
    }
    let text = RealFs
        .read(&root.join("boot.json"))
        .map_err(|error| ProbeError::io(&format!("read boot.json: {error}")))?;
    let boot: Boot = serde_json::from_str(&text)
        .map_err(|_| ProbeError::io("invalid boot.json namespace identity"))?;
    if boot.netns.ino == 0 {
        return Err(ProbeError::io("zero boot.json namespace inode"));
    }
    Ok(NetnsIdentity {
        device: boot.netns.dev,
        inode: boot.netns.ino,
    })
}

/// Reads persisted selection and quarantine without changing or creating state.
/// Missing state on an M2 gateway is an error; only boot may resolve absence.
///
/// # Errors
/// Returns absent, invalid, unsafe or unreadable state as an observation error.
pub fn selection(root: &Path) -> Probe<State> {
    selection_with_run(root, root)
}

/// Read state while honoring per-boot uncertainty at the supplied runtime root.
/// # Errors
/// Returns state observation failures.
pub fn selection_with_run(root: &Path, run_root: &Path) -> Probe<State> {
    match StateFile::open(root, None)
        .and_then(|file| file.safety_read(run_root))
        .map_err(|error| ProbeError::io(&format!("read state.json: {error}")))?
    {
        StateRead::Present(state) => Ok(state),
        StateRead::Missing => Err(ProbeError::io("state.json is missing")),
    }
}

pub(super) fn handshake_map(
    sys: &dyn System,
    handle: &NetnsHandle,
    name: &str,
) -> Probe<BTreeMap<[u8; 32], Handshake>> {
    peer_field(sys, handle, name, WgField::LatestHandshakes)?
        .into_iter()
        .map(|peer| {
            Ok((
                key_bytes(&peer.public_key)?,
                peer.handshake
                    .ok_or_else(|| ProbeError::io("missing handshake field"))?,
            ))
        })
        .collect()
}

/// Observes the configured exit's actual peer handshake, including explicit Never.
///
/// # Errors
/// Returns command/parse errors or a missing/unexpected handshake peer.
pub fn handshakes(
    sys: &dyn System,
    handle: &NetnsHandle,
    cfg: &HealthConfigV2,
) -> Probe<BTreeMap<ExitId, Handshake>> {
    let map = handshake_map(sys, handle, cfg.exit_iface.as_str())?;
    let expected = cfg
        .peers
        .get(cfg.exit_iface.as_str())
        .and_then(|peers| peers.first())
        .ok_or_else(|| ProbeError::io("exit peer expectation missing"))?;
    if map.len() != 1 {
        return Err(ProbeError::io("exit handshake peer inventory differs"));
    }
    let handshake = *map
        .get(&expected.public_key)
        .ok_or_else(|| ProbeError::io("exit handshake peer missing"))?;
    Ok(BTreeMap::from([(cfg.exit.clone(), handshake)]))
}

/// Runs the active exit's unbound IPv4 HTTPS observation after route verification.
///
/// # Errors
/// Preserves setup versus path failures from the isolated probe protocol.
pub fn exit_probe(
    _sys: &dyn System,
    exec: &dyn ProbeExec,
    handle: &NetnsHandle,
    site: &ValidatedSite,
    gateway: &GatewayId,
) -> Probe<IpAddr> {
    let exit = site
        .gateway(gateway)
        .and_then(|gw| gw.exits().first())
        .ok_or_else(|| ProbeError::setup("active exit missing"))?;
    let dns = exit
        .dns()
        .iter()
        .find_map(|ip| {
            if let IpAddr::V4(ip) = ip {
                Some(*ip)
            } else {
                None
            }
        })
        .ok_or_else(|| ProbeError::setup("active exit has no IPv4 DNS server"))?;
    #[cfg(not(feature = "lab-mutation"))]
    let bind = None;
    #[cfg(feature = "lab-mutation")]
    let bind = scupper_core::lab_mutation::probe_binding(
        scupper_core::lab_mutation::active(),
        exit.ifname().ifname(),
    );
    let request = ProbeRequest {
        kind: ProbeKind::ExitIp,
        bind,
        expected_netns: handle.identity(),
        dns,
        targets: site
            .health()
            .probe_targets()
            .iter()
            .map(|url| Url::new(url.as_str()))
            .collect::<Probe<_>>()?,
        deadline_ms: 0,
        #[cfg(feature = "testing")]
        identity: None,
    };
    run_probe(exec, handle, &request)?
        .result
        .into_probe()?
        .ok_or_else(|| ProbeError::setup("exit probe returned no IP"))
}

/// scupperd is not implemented in this step. Required supervision is Dead;
/// optional supervision is explicitly `NotRequired` and never an invented ping.
#[must_use]
pub fn supervisor(_sys: &dyn System, _handle: &NetnsHandle, cfg: &HealthConfigV2) -> Supervisor {
    if cfg.require_daemon {
        Supervisor::Dead
    } else {
        Supervisor::NotRequired
    }
}

/// Reserved single-exit stage; requesting it is a driver protocol error.
///
/// # Errors
/// Always returns Setup until multi-exit support is implemented.
pub fn standby_probe(_sys: &dyn System, _handle: &NetnsHandle, _cfg: &HealthConfigV2) -> Probe<()> {
    Err(ProbeError::setup("standby probes are not supported in M2"))
}

/// Reserved DNS-forwarder stage; requesting it is a driver protocol error.
///
/// # Errors
/// Always returns Setup until the M4 forwarder exists.
pub fn dns(_sys: &dyn System, _handle: &NetnsHandle, _cfg: &HealthConfigV2) -> Probe<()> {
    Err(ProbeError::setup("DNS self-tests are not supported in M2"))
}
