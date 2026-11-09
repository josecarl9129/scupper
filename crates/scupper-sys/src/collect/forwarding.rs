use super::{handshake_map, key_bytes, observe, wg};
use crate::{
    canon::command_result,
    cmd::{KernelCmd, SysctlCmd},
    netns::NetnsHandle,
    state::State,
    system::{EXEC_TIMEOUT, ExecTarget, Program, System},
};
use scupper_core::{
    parse::{WgField, WgOutput, parse_proc_net_udp, parse_proc_net_udp6, parse_sysctl},
    render::{Scope, SysctlFamily, SysctlKey, desired_sysctls},
    rules::IfName,
    verdict::v2::{Forwarding, HealthConfigV2, Probe, ProbeError, RepairKind},
};

pub(super) fn host_wireguard_ports(
    sys: &dyn System,
    listen_port: u16,
    errors: &mut Vec<ProbeError>,
) -> Probe<Vec<String>> {
    // Only public field reads are used, including for raw foreign interface names.
    let interfaces = command_result(sys.run_in(
        ExecTarget::Host,
        Program::Wg,
        &["show".into(), "interfaces".into()],
        EXEC_TIMEOUT,
    ))?;
    let mut host_wireguard_on_client_port = Vec::new();
    for name in interfaces.split_whitespace() {
        let port = command_result(sys.run_in(
            ExecTarget::Host,
            Program::Wg,
            &["show".into(), name.into(), "listen-port".into()],
            EXEC_TIMEOUT,
        ))
        .and_then(|text| Ok(scupper_core::parse::parse_wg(WgField::ListenPort, &text)?));
        let port = match port {
            Ok(WgOutput::ListenPort(port)) => port,
            Ok(_) => {
                errors.push(ProbeError::io("unexpected host listen-port response"));
                continue;
            }
            Err(error) => {
                errors.push(error);
                continue;
            }
        };
        if port == listen_port {
            host_wireguard_on_client_port.push(name.into());
        }
    }
    Ok(host_wireguard_on_client_port)
}

/// Reads forwarding and hardening inside the held namespace, public listener
/// identity and client handshakes there, and UDP socket tables in both namespaces.
///
/// # Errors
/// Preserves all command, procfs, parse and missing client-handshake errors.
pub fn forwarding(
    sys: &dyn System,
    handle: &NetnsHandle,
    cfg: &HealthConfigV2,
    state: &State,
) -> Probe<Forwarding> {
    let names = std::iter::once("lo")
        .chain(cfg.links.keys().map(String::as_str))
        .map(IfName::new)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| ProbeError::io("invalid sysctl interface"))?;
    let mut values = Vec::new();
    let mut hardening = Vec::new();
    for setting in desired_sysctls(&names, true) {
        let value = parse_sysctl(&observe(
            sys,
            handle,
            KernelCmd::Sysctl(SysctlCmd::Read(setting.key.clone())),
        )?)?;
        if values.len() >= 2 && value.to_string() != setting.value {
            hardening.push(setting.key.to_string());
        }
        values.push(value);
    }
    let client_v4 = parse_sysctl(&observe(
        sys,
        handle,
        KernelCmd::Sysctl(SysctlCmd::Read(SysctlKey {
            family: SysctlFamily::Ipv4,
            scope: Scope::Link(
                IfName::new(&cfg.client_iface)
                    .map_err(|_| ProbeError::io("invalid client interface"))?,
            ),
            name: "forwarding",
        })),
    )?)?;
    let mut netns_sockets = parse_proc_net_udp(&observe(sys, handle, KernelCmd::ReadUdp(false))?)?;
    netns_sockets.extend(parse_proc_net_udp6(&observe(
        sys,
        handle,
        KernelCmd::ReadUdp(true),
    )?)?);
    let client_public_key = match wg(sys, handle, &cfg.client_iface, WgField::PublicKey)? {
        WgOutput::PublicKey(key) => key.as_ref().map(key_bytes).transpose()?,
        _ => return Err(ProbeError::io("unexpected public-key response")),
    };
    let WgOutput::ListenPort(listen_port) =
        wg(sys, handle, &cfg.client_iface, WgField::ListenPort)?
    else {
        return Err(ProbeError::io("unexpected listen-port response"));
    };
    let mut host_sockets = parse_proc_net_udp(
        &sys.read_host_udp(false)
            .map_err(|error| ProbeError::io(&error.to_string()))?,
    )?;
    host_sockets.extend(parse_proc_net_udp6(
        &sys.read_host_udp(true)
            .map_err(|error| ProbeError::io(&error.to_string()))?,
    )?);
    let client_handshakes = handshake_map(sys, handle, &cfg.client_iface)?;
    Ok(Forwarding {
        client_v4,
        netns_sockets,
        v4: values[0],
        v6: values[1],
        hardening,
        quarantine: state.quarantine.as_ref().map(|_| RepairKind::SafetyDrift),
        client_public_key,
        listen_port,
        host_sockets,
        client_handshakes,
    })
}
