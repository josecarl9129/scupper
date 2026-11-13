//! Capture-local proof for the socketless reset following an alert's abortive close.
use std::{collections::BTreeMap, net::SocketAddr};

use super::{Class, Policy, decode::Ip};

#[derive(Default)]
struct Flow {
    fin_ack: Option<u32>,
    last_ack: Option<u32>,
    abort_seen: bool,
}

#[derive(Default)]
pub(super) struct LateResets {
    flows: BTreeMap<(SocketAddr, SocketAddr), Flow>,
}

impl LateResets {
    /// Called only for complete, unfragmented packets after all safety checks.
    /// Returns true only for the single empty RST proved by earlier capture records.
    pub(super) fn observe(&mut self, policy: &Policy, ip: &Ip<'_>, class: &Class) -> bool {
        let Some(mark) = policy.heartbeat_dscp else {
            return false;
        };
        let Some(endpoint) = policy.heartbeat else {
            return false;
        };
        // The diagnosed kernel reply is IPv4 with a bare 20-byte TCP header.
        if ip.proto != 6 || !ip.src.is_ipv4() || ip.payload.len() < 20 {
            return false;
        }
        let tcp = ip.payload;
        let source = SocketAddr::new(ip.src, u16::from_be_bytes([tcp[0], tcp[1]]));
        let destination = SocketAddr::new(ip.dst, u16::from_be_bytes([tcp[2], tcp[3]]));
        let outbound = destination == endpoint && policy.uplink_addrs.contains(&ip.src);
        let inbound = source == endpoint && policy.uplink_addrs.contains(&ip.dst);
        if !outbound && !inbound {
            return false;
        }
        let key = if outbound {
            (source, destination)
        } else {
            (destination, source)
        };
        let flags = tcp[13];
        let trusted = matches!(class, Class::Allowed(rule) if rule == "heartbeat");
        if outbound && flags & 2 != 0 {
            // A new SYN (including an unmarked one) revokes a previous tuple's proof.
            self.flows.remove(&key);
            if trusted && ip.dscp == mark && flags == 2 {
                self.flows.insert(key, Flow::default());
            }
            return false;
        }
        let Some(flow) = self.flows.get_mut(&key) else {
            return false;
        };
        let seq = u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]);
        let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
        let bare = tcp.len() == 20 && tcp[12] == 0x50;
        let empty = tcp.len() == usize::from(tcp[12] >> 4) * 4;
        if inbound && trusted && flags & 0x10 != 0 {
            flow.last_ack = Some(ack);
            if flags == 0x11 && empty {
                flow.fin_ack = Some(ack);
                flow.abort_seen = false;
            }
        }
        if outbound
            && trusted
            && ip.dscp == mark
            && flags == 0x14
            && empty
            && flow.fin_ack == Some(seq)
        {
            flow.abort_seen = true;
        }
        let allowed = outbound
            && ip.dscp == 0
            && flags == 4
            && bare
            && ack == 0
            && flow.abort_seen
            && flow.fin_ack == Some(seq)
            && flow.last_ack == Some(seq);
        if allowed {
            self.flows.remove(&key); // One closing reply cannot authorize subsequent traffic.
        }
        allowed
    }
}
