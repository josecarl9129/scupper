//! Address fields in ICMP and IPv6 link control messages.
use std::net::IpAddr;

use super::{
    Location, Policy, Reason,
    decode::{self, Ip},
};

type Checked<T> = Result<T, Reason>;

fn address(policy: &Policy, addr: IpAddr, location: &Location) -> Checked<()> {
    if policy.forbidden(addr) {
        return Err(Reason::ForbiddenAddress {
            addr,
            location: location.clone(),
        });
    }
    Ok(())
}

/// Check address-bearing ICMP fields even when no control allow rule applies.
pub(super) fn fields(policy: &Policy, proto: u8, data: &[u8], location: &Location) -> Checked<()> {
    let kind = *data.first().ok_or(Reason::Truncated)?;
    if proto == 1 && kind == 5 {
        address(policy, decode::address4(data, 4)?, location)?;
    }
    if proto != 58 {
        return Ok(());
    }
    let options_at = match kind {
        133 => Some(8),
        134 => {
            decode::bytes(data, 0, 16)?;
            Some(16)
        }
        135 | 136 => {
            address(policy, decode::address6(data, 8)?, location)?;
            Some(24)
        }
        137 => {
            address(policy, decode::address6(data, 8)?, location)?;
            address(policy, decode::address6(data, 24)?, location)?;
            Some(40)
        }
        131 | 132 => {
            address(policy, decode::address6(data, 8)?, location)?;
            None
        }
        143 => {
            let count = usize::from(decode::word(data, 6)?);
            let mut at = 8;
            for _ in 0..count {
                let h = decode::bytes(data, at, 20)?;
                address(policy, decode::address6(h, 4)?, location)?;
                let sources = usize::from(decode::word(h, 2)?);
                for i in 0..sources {
                    address(policy, decode::address6(data, at + 20 + i * 16)?, location)?;
                }
                at += 20 + sources * 16 + usize::from(h[1]) * 4;
                decode::bytes(data, 0, at)?;
            }
            if at != data.len() {
                return Err(Reason::MalformedPacket);
            }
            None
        }
        _ => None,
    };
    if let Some(at) = options_at {
        let mut options = data.get(at..).ok_or(Reason::Truncated)?;
        while !options.is_empty() {
            let h = decode::bytes(options, 0, 2)?;
            let len = usize::from(h[1]) * 8;
            if len == 0 {
                return Err(Reason::MalformedPacket);
            }
            let option = decode::bytes(options, 0, len)?;
            match h[0] {
                3 => {
                    // Prefix Information
                    if len != 32 {
                        return Err(Reason::MalformedPacket);
                    }
                    address(policy, decode::address6(option, 16)?, location)?;
                }
                24 => {
                    // Route Information, with a zero-extended prefix.
                    if !matches!(len, 8 | 16 | 24) {
                        return Err(Reason::MalformedPacket);
                    }
                    let mut prefix = [0; 16];
                    prefix[..len - 8].copy_from_slice(&option[8..]);
                    address(policy, std::net::Ipv6Addr::from(prefix).into(), location)?;
                }
                25 => {
                    // Recursive DNS Server addresses
                    if len < 24 || !(len - 8).is_multiple_of(16) {
                        return Err(Reason::MalformedPacket);
                    }
                    for at in (8..len).step_by(16) {
                        address(policy, decode::address6(option, at)?, location)?;
                    }
                }
                _ => {}
            }
            options = &options[len..];
        }
    }
    Ok(())
}

pub(super) fn ndp(policy: &Policy, ip: &Ip<'_>, data: &[u8]) -> Checked<bool> {
    let kind = data[0]; // transport has already checked the eight-byte header.
    if !matches!(kind, 131 | 133..=136 | 143) {
        return Ok(false);
    }
    if data[1] != 0 || (matches!(kind, 133..=136) && ip.hop_limit != 255) {
        return Err(Reason::MalformedPacket);
    }
    let own = policy.uplink_addrs.contains(&ip.src);
    let link_local = matches!(ip.src, IpAddr::V6(a) if a.is_unicast_link_local());
    let source = own || link_local || (kind == 135 && ip.src.is_unspecified());
    let multicast = ip.dst.is_multicast();
    // Preserve inbound NS/NA for our own target, and allow the uplink to
    // resolve its router. RS/RA and reports must use a multicast destination.
    let permitted = match kind {
        135 | 136 => source || policy.uplink_addrs.contains(&decode::address6(data, 8)?),
        131 | 133 | 134 => (own || link_local) && multicast,
        // RFC 3810 §5.2.13: MLDv2 reports may be sent from the unspecified address while the
        // interface's link-local address is still tentative (duplicate address detection).
        143 => (own || link_local || ip.src.is_unspecified()) && multicast,
        _ => false,
    };
    Ok(policy.ndp && permitted)
}
