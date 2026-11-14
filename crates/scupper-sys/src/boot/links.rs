use super::{BootDeps, Inputs, Result, execute, inventory, strings, sysctls};
use crate::{
    cmd::{KernelCmd, WgCmd},
    netns::NetnsHandle,
    system::{ExecError, ExecTarget, Program},
};
use scupper_core::{
    parse::{
        PeerKey, WgField, WgOutput, parse_ip_addr, parse_ip_link, parse_tc_qdisc, parse_wg,
        parse_wg_public_key,
    },
    rules::IfName,
};

// Host mutations are deliberately confined here: an unconfigured host-born WG
// link is the sole exception to namespace-only mutation dispatch.
pub(crate) fn cleanup_host(deps: &BootDeps<'_>, name: &str) -> Result<()> {
    let links = parse_ip_link(&execute(
        deps,
        ExecTarget::Host,
        Program::Ip,
        &strings(&["-d", "-j", "link", "show"]),
        None,
    )?)
    .map_err(|e| e.to_string())?;
    if let Some(link) = links.iter().find(|link| link.ifname == name) {
        if !host_link_removable(deps.system, link)
            .map_err(|e| format!("cannot inspect host link: {e}"))?
        {
            return Err(
                "host link name collision: not a down, peerless, unaddressed WireGuard link".into(),
            );
        }
        execute(
            deps,
            ExecTarget::Host,
            Program::Ip,
            &strings(&["link", "delete", "dev", name]),
            None,
        )?;
    }
    Ok(())
}

/// Distinguishes execution failures from unsuccessful or invalid observations.
#[derive(Debug, thiserror::Error)]
pub(crate) enum HostLinkError {
    #[error("{0}")]
    Exec(#[from] ExecError),
    #[error("{program:?} failed (status {status:?}): {stderr}")]
    Status {
        program: Program,
        status: Option<i32>,
        stderr: String,
    },
    #[error("invalid host link addresses: {0}")]
    Parse(String),
}

/// Read-only predicate shared by boot cleanup and installation detection.
pub(crate) fn host_link_removable(
    system: &dyn crate::system::System,
    link: &scupper_core::parse::IpLink,
) -> std::result::Result<bool, HostLinkError> {
    if link.kind.as_deref() != Some("wireguard") || link.flags.iter().any(|f| f == "UP") || link.xdp
    {
        return Ok(false);
    }
    let run = |program, args: &[&str]| {
        let args = strings(args);
        if program == Program::Wg {
            crate::system::check_wg_args(system, &args)?;
        }
        let output = system.run(program, &args, crate::system::EXEC_TIMEOUT)?;
        if output.status != Some(0) {
            return Err(HostLinkError::Status {
                program,
                status: output.status,
                stderr: super::diagnostic(&output.stderr),
            });
        }
        Ok(output.stdout)
    };
    let peers = run(Program::Wg, &["show", &link.ifname, "peers"])?;
    let addresses = parse_ip_addr(&run(Program::Ip, &["-j", "addr", "show"])?)
        .map_err(|e| HostLinkError::Parse(e.to_string()))?;
    Ok(peers.trim().is_empty()
        && addresses.iter().any(|a| {
            a.ifname == link.ifname && a.ifindex == link.ifindex && a.addresses.is_empty()
        }))
}

pub(crate) fn add_host(deps: &BootDeps<'_>, name: &str) -> Result<()> {
    raw_name(name)?;
    execute(
        deps,
        ExecTarget::Host,
        Program::Ip,
        &strings(&["link", "add", name, "type", "wireguard"]),
        None,
    )?;
    #[cfg(feature = "testing")]
    if let Some(hook) = deps.hook {
        hook(super::BootPoint::LinkAdded(
            IfName::new(name).map_err(|e| e.to_string())?,
        ))?;
    }
    Ok(())
}

pub(crate) fn move_link(deps: &BootDeps<'_>, handle: &NetnsHandle, name: &str) -> Result<()> {
    raw_name(name)?;
    execute(
        deps,
        ExecTarget::Host,
        Program::Ip,
        &strings(&[
            "link",
            "set",
            name,
            "netns",
            &handle.child_fd_path().to_string_lossy(),
        ]),
        None,
    )?;
    Ok(())
}

pub(super) fn configure(
    deps: &BootDeps<'_>,
    handle: &NetnsHandle,
    cfg: &Inputs,
    guard: &crate::lock::WriterGuard,
    daemonless_empty: bool,
    open_quarantined: bool,
) -> Result<()> {
    let gw = cfg.site.gateway(&cfg.gateway).ok_or("unknown gateway")?;
    for name in super::configured_names(cfg)?
        .iter()
        .filter(|n| n.as_str() != "lo")
    {
        let name = name.as_str();
        let existing = inventory(deps, handle)?;
        if let Some(link) = existing.iter().find(|l| l.ifname == name) {
            if link.kind.as_deref() != Some("wireguard") {
                return Err("configured namespace link has foreign kind".into());
            }
            if name != gw.client_tunnel().ifname().as_str() {
                set_up(deps, handle, name, false)?;
            }
        } else {
            cleanup_host(deps, name)?;
            add_host(deps, name)?;
            move_link(deps, handle, name)?;
        }
        let up = name == gw.client_tunnel().ifname().as_str()
            || cfg.state.selection != scupper_core::verdict::v2::Selection::Disconnected;
        if name == gw.client_tunnel().ifname().as_str() {
            let was_down = !existing
                .iter()
                .any(|l| l.ifname == name && l.flags.iter().any(|f| f == "UP"));
            configure_body(deps, handle, cfg, name, false, true)?;
            if cfg.state.quarantine.is_some() && !open_quarantined {
                set_up(deps, handle, name, false)?;
                continue;
            }
            if daemonless_empty && !cfg.site.health().require_daemon() {
                let retire = || {
                    crate::client_sessions::retire_empty(
                        deps.state_root,
                        deps.run_root,
                        gw.client_tunnel().identity().public_key.as_str(),
                        deps.system.now_unix_secs(),
                        guard,
                    )
                };
                // A sampler finishing an old write, or a delayed directory sync,
                // must get another bounded opportunity before boot gives up.
                if retire().is_err() && retire().is_err() {
                    set_up(deps, handle, name, false)?;
                    return Err("daemonless EMPTY retirement failed after retry".into());
                }
            }
            crate::client_sessions::before_up(
                deps.system,
                handle,
                name,
                deps.state_root,
                deps.run_root,
                gw.client_tunnel().identity().public_key.as_str(),
                was_down,
                guard,
            )
            .map_err(|_| "client session baseline unavailable".to_string())?;
            let may_serve = crate::client_sessions::may_serve(
                deps.state_root,
                gw.client_tunnel().identity().public_key.as_str(),
                deps.system.now_unix_secs(),
            );
            set_up(deps, handle, name, may_serve)?;
            if daemonless_empty && !cfg.site.health().require_daemon() && !may_serve {
                return Err("daemonless client device cannot serve after opening hook".into());
            }
        } else {
            configure_body(deps, handle, cfg, name, up, true)?;
        }
    }
    Ok(())
}

pub(crate) fn configure_one(
    deps: &BootDeps<'_>,
    handle: &NetnsHandle,
    cfg: &Inputs,
    name: &str,
) -> Result<()> {
    let existing = inventory(deps, handle)?;
    if let Some(link) = existing.iter().find(|l| l.ifname == name) {
        if link.kind.as_deref() != Some("wireguard") {
            return Err("configured namespace link has foreign kind".into());
        }
        let client = cfg
            .site
            .gateway(&cfg.gateway)
            .ok_or("unknown gateway")?
            .client_tunnel();
        if name != client.ifname().as_str() {
            execute(
                deps,
                ExecTarget::Netns(handle),
                Program::Ip,
                &strings(&["link", "set", "dev", name, "down"]),
                None,
            )?;
        }
    } else {
        return Err("link missing before configuration".into());
    }
    configure_body(deps, handle, cfg, name, false, false)
}

fn configure_body(
    deps: &BootDeps<'_>,
    handle: &NetnsHandle,
    cfg: &Inputs,
    name: &str,
    up: bool,
    global_gates_and_hardening: bool,
) -> Result<()> {
    let gw = cfg.site.gateway(&cfg.gateway).ok_or("unknown gateway")?;
    let client = gw.client_tunnel();
    let (address, mtu) = if name == client.ifname().as_str() {
        (client.address4().to_string(), client.mtu())
    } else {
        let exit = gw
            .exits()
            .iter()
            .find(|e| e.ifname().as_str() == name)
            .ok_or("unknown link")?;
        (exit.address4().to_string(), exit.mtu())
    };
    let target = ExecTarget::Netns(handle);
    let key = cfg.secrets.get(name).ok_or("resolved link key missing")?;
    wg(
        deps,
        handle,
        WgCmd::SetPrivateKeyFromStdin {
            ifname: IfName::new(name).map_err(|e| e.to_string())?,
        },
        Some(key.expose()),
    )?;
    // Preserve configured client sessions and roamed endpoints. Exit sessions
    // may be recreated; unknown client peers must still be removed.
    let peers = execute(
        deps,
        target,
        Program::Wg,
        &strings(&["show", name, "peers"]),
        None,
    )?;
    for peer in peers.split_whitespace() {
        if name == client.ifname().as_str()
            && cfg.site.devices().values().any(|device| {
                device.gateways().contains(&cfg.gateway)
                    && device.public_key_text().as_str() == peer
            })
        {
            continue;
        }
        wg(
            deps,
            handle,
            WgCmd::RemovePeer {
                ifname: IfName::new(name).map_err(|e| e.to_string())?,
                public_key: PeerKey::new(peer).map_err(|e| e.to_string())?,
            },
            None,
        )?;
    }
    configure_peers(deps, handle, cfg, name)?;
    execute(
        deps,
        target,
        Program::Ip,
        &strings(&["addr", "flush", "dev", name]),
        None,
    )?;
    execute(
        deps,
        target,
        Program::Ip,
        &strings(&["addr", "add", &address, "dev", name]),
        None,
    )?;
    // Setting all/default hardening again also covers the just-moved link.
    if global_gates_and_hardening {
        let actual = inventory(deps, handle)?;
        let names = super::configured_names(cfg)?
            .into_iter()
            .filter(|name| actual.iter().any(|link| link.ifname == name.as_str()))
            .collect::<Vec<_>>();
        sysctls(deps, handle, &names, false, true)?;
    }
    let mtu = mtu.to_string();
    let mut args = vec!["link", "set", name, "mtu", &mtu];
    if up {
        args.push("up");
    }
    execute(deps, target, Program::Ip, &strings(&args), None)?;
    Ok(())
}

pub(crate) fn set_up(
    deps: &BootDeps<'_>,
    handle: &NetnsHandle,
    name: &str,
    up: bool,
) -> Result<()> {
    raw_name(name)?;
    execute(
        deps,
        ExecTarget::Netns(handle),
        Program::Ip,
        &strings(&["link", "set", "dev", name, if up { "up" } else { "down" }]),
        None,
    )?;
    Ok(())
}

pub(crate) fn configure_peers(
    deps: &BootDeps<'_>,
    handle: &NetnsHandle,
    cfg: &Inputs,
    name: &str,
) -> Result<()> {
    let gw = cfg.site.gateway(&cfg.gateway).ok_or("unknown gateway")?;
    let client = gw.client_tunnel();
    if name == client.ifname().as_str() {
        wg(
            deps,
            handle,
            WgCmd::SetListenPort {
                ifname: client.ifname().clone(),
                port: u16::try_from(client.identity().listen_port).map_err(|e| e.to_string())?,
            },
            None,
        )?;
        for device in cfg
            .site
            .devices()
            .values()
            .filter(|d| d.gateways().contains(&cfg.gateway))
        {
            wg(
                deps,
                handle,
                WgCmd::SetPeer {
                    ifname: client.ifname().clone(),
                    public_key: PeerKey::new(device.public_key_text().as_str())
                        .map_err(|e| e.to_string())?,
                    allowed_ips: vec![device.address4().into()],
                    endpoint: None,
                    keepalive: Some(0),
                },
                None,
            )?;
        }
    } else {
        let exit = gw
            .exits()
            .iter()
            .find(|e| e.ifname().as_str() == name)
            .ok_or("exit missing")?;
        wg(
            deps,
            handle,
            WgCmd::SetPeer {
                ifname: IfName::new(exit.ifname().as_str()).map_err(|e| e.to_string())?,
                public_key: PeerKey::new(exit.peer_public_key_text().as_str())
                    .map_err(|e| e.to_string())?,
                allowed_ips: vec!["0.0.0.0/0".parse().map_err(|_| "invalid default prefix")?],
                endpoint: Some(exit.endpoint()),
                keepalive: Some(
                    u16::try_from(exit.keepalive().as_secs()).map_err(|e| e.to_string())?,
                ),
            },
            None,
        )?;
        if exit.preshared_key_ref().is_some() {
            let secret = cfg
                .secrets
                .get(&format!("{}:psk", exit.ifname()))
                .ok_or("resolved preshared key missing")?;
            wg(
                deps,
                handle,
                WgCmd::SetPresharedKeyFromStdin {
                    ifname: IfName::new(exit.ifname().as_str()).map_err(|e| e.to_string())?,
                    public_key: PeerKey::new(exit.peer_public_key_text().as_str())
                        .map_err(|e| e.to_string())?,
                },
                Some(secret.expose()),
            )?;
        }
    }
    Ok(())
}

// All boot WG mutations are rendered by the complete typed allow-list. Secret
// bytes stay separate from the command and execute redacts their diagnostics.
fn wg(
    deps: &BootDeps<'_>,
    handle: &NetnsHandle,
    cmd: WgCmd,
    input: Option<&[u8]>,
) -> Result<String> {
    let (program, args) = KernelCmd::Wg(cmd).render();
    execute(deps, ExecTarget::Netns(handle), program, &args, input)
}

pub(crate) fn raw_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 15
        || name
            .chars()
            .any(|c| c == '\0' || c == '/' || c.is_whitespace())
    {
        return Err("invalid raw kernel link name; refusing namespace rebuild".into());
    }
    Ok(())
}

pub(super) fn close(deps: &BootDeps<'_>, handle: &NetnsHandle, cfg: &Inputs) -> Result<()> {
    let actual = inventory(deps, handle)?;
    let configured = super::configured_names(cfg)?;
    let foreign = |link: &scupper_core::parse::IpLink| {
        link.ifname != "lo"
            && (!configured.iter().any(|n| n.as_str() == link.ifname)
                || link.kind.as_deref() != Some("wireguard"))
    };
    let mut errors = Vec::new();
    // Complete the whole down pass before inspecting hooks or any per-link sysctl.
    for link in actual.iter().filter(|link| foreign(link)) {
        let result = raw_name(&link.ifname).and_then(|()| {
            execute(
                deps,
                ExecTarget::Netns(handle),
                Program::Ip,
                &strings(&["link", "set", "dev", &link.ifname, "down"]),
                None,
            )
            .map(|_| ())
        });
        if let Err(error) = result {
            errors.push(error);
        }
    }
    for link in &actual {
        let result = raw_name(&link.ifname).and_then(|()| clear_hooks(deps, handle, &link.ifname));
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if !errors.is_empty() {
        return Err(errors.join("; "));
    }
    if actual.iter().any(foreign) {
        return Err("foreign namespace links disabled; operator attention required".into());
    }
    Ok(())
}

pub(crate) fn clear_hooks(deps: &BootDeps<'_>, handle: &NetnsHandle, name: &str) -> Result<()> {
    let target = ExecTarget::Netns(handle);
    let mut errors = Vec::new();
    for kind in ["clsact", "ingress"] {
        // Deleting an absent qdisc returns nonzero. Accept that only after a
        // successful inventory proves absence; other errors remain failures.
        let result = (|| {
            if let Err(error) = execute(
                deps,
                target,
                Program::Tc,
                &strings(&["qdisc", "del", "dev", name, kind]),
                None,
            ) {
                let got = execute(
                    deps,
                    target,
                    Program::Tc,
                    &strings(&["-j", "qdisc", "show", "dev", name]),
                    None,
                )?;
                if parse_tc_qdisc(&got)
                    .map_err(|e| e.to_string())?
                    .iter()
                    .any(|q| q.kind == kind)
                {
                    return Err(error);
                }
            }
            Ok(())
        })();
        if let Err(error) = result {
            errors.push(error);
        }
    }
    if let Err(error) = execute(
        deps,
        target,
        Program::Ip,
        &strings(&["link", "set", "dev", name, "xdp", "off"]),
        None,
    ) {
        errors.push(error);
    }
    if errors.is_empty() {
        return Ok(());
    }
    // A failed detach must not leave a configured link able to redirect traffic.
    if let Err(error) = execute(
        deps,
        target,
        Program::Ip,
        &strings(&["link", "set", "dev", name, "down"]),
        None,
    ) {
        errors.push(error);
    }
    Err(errors.join("; "))
}

// Stage 1 already checks peer keys, AllowedIPs and addresses. Adoption also
// requires every value boot writes that is intentionally outside drift checks.
pub(super) fn adoptable(deps: &BootDeps<'_>, handle: &NetnsHandle, cfg: &Inputs) -> Result<()> {
    let actual = inventory(deps, handle)?;
    let gw = cfg.site.gateway(&cfg.gateway).ok_or("unknown gateway")?;
    if !actual
        .iter()
        .any(|l| l.ifname == "lo" && l.flags.iter().any(|f| f == "UP"))
    {
        return Err("loopback is down or missing".into());
    }
    for (name, mtu) in std::iter::once((
        gw.client_tunnel().ifname().as_str(),
        gw.client_tunnel().mtu(),
    ))
    .chain(gw.exits().iter().map(|e| (e.ifname().as_str(), e.mtu())))
    {
        if !actual.iter().any(|l| {
            l.ifname == name
                && l.kind.as_deref() == Some("wireguard")
                && l.mtu == mtu
                && (l.flags.iter().any(|f| f == "UP")
                    || (cfg.state.selection == scupper_core::verdict::v2::Selection::Disconnected
                        && name != gw.client_tunnel().ifname().as_str()))
        }) {
            return Err("configured link missing, down, wrong kind or MTU".into());
        }
        let secret = cfg.secrets.get(name).ok_or("resolved link key missing")?;
        let derived = wg(deps, handle, WgCmd::Pubkey, Some(secret.expose()))?;
        let live = wg(
            deps,
            handle,
            WgCmd::Show {
                ifname: IfName::new(name).map_err(|e| e.to_string())?,
                field: WgField::PublicKey,
            },
            None,
        )?;
        let derived = parse_wg_public_key(&derived).map_err(|e| e.to_string())?;
        if derived.is_none() || derived != parse_wg_public_key(&live).map_err(|e| e.to_string())? {
            return Err("configured link identity differs".into());
        }
    }
    let client = gw.client_tunnel();
    let port = wg(
        deps,
        handle,
        WgCmd::Show {
            ifname: client.ifname().clone(),
            field: WgField::ListenPort,
        },
        None,
    )?;
    if parse_wg(WgField::ListenPort, &port).map_err(|e| e.to_string())?
        != WgOutput::ListenPort(
            u16::try_from(client.identity().listen_port).map_err(|e| e.to_string())?,
        )
    {
        return Err("client listen port differs".into());
    }
    for exit in gw.exits() {
        for field in [WgField::Endpoints, WgField::PersistentKeepalive] {
            let text = wg(
                deps,
                handle,
                WgCmd::Show {
                    ifname: IfName::new(exit.ifname().as_str()).map_err(|e| e.to_string())?,
                    field,
                },
                None,
            )?;
            let WgOutput::Peers(peers) = parse_wg(field, &text).map_err(|e| e.to_string())? else {
                return Err("invalid peer observation".into());
            };
            if peers.len() != 1
                || peers[0].public_key.as_str() != exit.peer_public_key_text().as_str()
                || (field == WgField::Endpoints && peers[0].endpoint != Some(exit.endpoint()))
                || (field == WgField::PersistentKeepalive
                    && peers[0].keepalive.map(u64::from) != Some(exit.keepalive().as_secs()))
            {
                return Err("exit peer configuration differs".into());
            }
        }
    }
    Ok(())
}

/// Remove only the positively observed attachment class, then let the caller verify.
pub(crate) fn delete_hook(
    deps: &BootDeps<'_>,
    held: &NetnsHandle,
    name: &str,
    hook: &str,
) -> Result<()> {
    raw_name(name)?;
    if hook == "root" {
        if let Err(error) = execute(
            deps,
            ExecTarget::Netns(held),
            Program::Tc,
            &strings(&["qdisc", "del", "dev", name, "root"]),
            None,
        ) {
            let remaining = crate::collect::reconcile::hooks(deps.system, held, name, false)
                .map_err(|e| e.to_string())?;
            if remaining.iter().any(|h| h == hook) {
                return Err(error);
            }
        }
        Ok(())
    } else if matches!(
        hook,
        "clsact" | "ingress" | "ingress-filters" | "egress-filters" | "xdp"
    ) {
        clear_hooks(deps, held, name)
    } else {
        Err("unknown hook identity".into())
    }
}
