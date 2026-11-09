use super::{BootDeps, Inputs, Result, execute, inventory, strings, sysctls};
use crate::{
    netns::NetnsHandle,
    system::{ExecTarget, Program},
};
use scupper_core::{
    parse::{parse_ip_addr, parse_ip_link},
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
    let links = std::iter::once((
        client.ifname().as_str(),
        client.address4().to_string(),
        client.mtu(),
    ))
    .chain(
        gw.exits()
            .iter()
            .map(|e| (e.ifname().as_str(), e.address4().to_string(), e.mtu())),
    );
    for (name, address, mtu) in links {
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
        execute(
            deps,
            target,
            Program::Wg,
            &strings(&["set", name, "private-key", "/dev/stdin"]),
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
            scupper_core::parse::PeerKey::new(peer).map_err(|e| e.to_string())?;
            execute(
                deps,
                target,
                Program::Wg,
                &strings(&["set", name, "peer", peer, "remove"]),
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
        let names = inventory(deps, handle)?
            .iter()
            .map(|l| IfName::new(&l.ifname).map_err(|e| e.to_string()))
            .collect::<Result<Vec<_>>>()?;
        sysctls(deps, handle, &names, false, true)?;
        execute(
            deps,
            target,
            Program::Ip,
            &strings(&["link", "set", name, "mtu", &mtu.to_string(), "up"]),
            None,
        )?;
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
    let target = ExecTarget::Netns(handle);
    if name == client.ifname().as_str() {
        execute(
            deps,
            target,
            Program::Wg,
            &strings(&[
                "set",
                name,
                "listen-port",
                &client.identity().listen_port.to_string(),
            ]),
            None,
        )?;
        for device in cfg
            .site
            .devices()
            .values()
            .filter(|d| d.gateways().contains(&cfg.gateway))
        {
            execute(
                deps,
                target,
                Program::Wg,
                &strings(&[
                    "set",
                    name,
                    "peer",
                    device.public_key_text().as_str(),
                    "allowed-ips",
                    &device.address4().to_string(),
                ]),
                None,
            )?;
        }
    } else {
        let exit = gw
            .exits()
            .iter()
            .find(|e| e.ifname().as_str() == name)
            .ok_or("exit missing")?;
        execute(
            deps,
            target,
            Program::Wg,
            &strings(&[
                "set",
                name,
                "peer",
                exit.peer_public_key_text().as_str(),
                "endpoint",
                &exit.endpoint().to_string(),
                "allowed-ips",
                "0.0.0.0/0",
                "persistent-keepalive",
                &exit.keepalive().as_secs().to_string(),
            ]),
            None,
        )?;
    }
    Ok(())
}
