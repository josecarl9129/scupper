use super::{BootDeps, Inputs, Result, execute, inventory, strings, sysctls};
use crate::{
    cmd::{KernelCmd, WgCmd},
    netns::NetnsHandle,
    system::{ExecTarget, Program},
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
fn create(deps: &BootDeps<'_>, handle: &NetnsHandle, name: &str) -> Result<()> {
    let links = parse_ip_link(&execute(
        deps,
        ExecTarget::Host,
        Program::Ip,
        &strings(&["-d", "-j", "link", "show"]),
        None,
    )?)
    .map_err(|e| e.to_string())?;
    if let Some(link) = links.iter().find(|link| link.ifname == name) {
        if link.kind.as_deref() != Some("wireguard")
            || link.flags.iter().any(|f| f == "UP")
            || link.xdp
        {
            return Err("host link name collision: not positively ours".into());
        }
        let peers = execute(
            deps,
            ExecTarget::Host,
            Program::Wg,
            &strings(&["show", name, "peers"]),
            None,
        )?;
        let addresses = parse_ip_addr(&execute(
            deps,
            ExecTarget::Host,
            Program::Ip,
            &strings(&["-j", "addr", "show"]),
            None,
        )?)
        .map_err(|e| e.to_string())?;
        if !peers.trim().is_empty()
            || !addresses
                .iter()
                .any(|a| a.ifname == name && a.ifindex == link.ifindex && a.addresses.is_empty())
        {
            return Err("host link name collision: peers or addresses present".into());
        }
        execute(
            deps,
            ExecTarget::Host,
            Program::Ip,
            &strings(&["link", "delete", "dev", name]),
            None,
        )?;
    }
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

pub(super) fn configure(deps: &BootDeps<'_>, handle: &NetnsHandle, cfg: &Inputs) -> Result<()> {
    let gw = cfg.site.gateway(&cfg.gateway).ok_or("unknown gateway")?;
    let client = gw.client_tunnel();
    // Under an admin disconnect the exit links stay down: the closure DESIGN §12 stage 2
    // requires is both defaults unreachable and exit links down or without peers.
    let exits_up = cfg.state.selection != scupper_core::verdict::v2::Selection::Disconnected;
    let links = std::iter::once((
        client.ifname().as_str(),
        client.address4().to_string(),
        client.mtu(),
        true,
    ))
    .chain(gw.exits().iter().map(|e| {
        (
            e.ifname().as_str(),
            e.address4().to_string(),
            e.mtu(),
            exits_up,
        )
    }));
    for (name, address, mtu, up) in links {
        let existing = inventory(deps, handle)?;
        if let Some(link) = existing.iter().find(|l| l.ifname == name) {
            if link.kind.as_deref() != Some("wireguard") {
                return Err("configured namespace link has foreign kind".into());
            }
            execute(
                deps,
                ExecTarget::Netns(handle),
                Program::Ip,
                &strings(&["link", "set", "dev", name, "down"]),
                None,
            )?;
        } else {
            create(deps, handle, name)?;
        }
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
        // Recover interrupted configuration without retaining any stale peer.
        let peers = execute(
            deps,
            target,
            Program::Wg,
            &strings(&["show", name, "peers"]),
            None,
        )?;
        for peer in peers.split_whitespace() {
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
        let actual = inventory(deps, handle)?;
        let names = super::configured_names(cfg)?
            .into_iter()
            .filter(|name| actual.iter().any(|link| link.ifname == name.as_str()))
            .collect::<Vec<_>>();
        sysctls(deps, handle, &names, false, true)?;
        let mtu = mtu.to_string();
        let mut args = vec!["link", "set", name, "mtu", &mtu];
        if up {
            args.push("up");
        }
        execute(deps, target, Program::Ip, &strings(&args), None)?;
    }
    Ok(())
}

fn configure_peers(
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
                    keepalive: None,
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

fn raw_name(name: &str) -> Result<()> {
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

fn clear_hooks(deps: &BootDeps<'_>, handle: &NetnsHandle, name: &str) -> Result<()> {
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
                && l.flags.iter().any(|f| f == "UP")
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
