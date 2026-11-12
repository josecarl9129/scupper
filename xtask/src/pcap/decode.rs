//! Bounds-checked wire decoders; checksums are intentionally not used (offloaded captures).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use super::Reason;

type Parsed<T> = Result<T, Reason>;

pub(super) fn bytes(data: &[u8], start: usize, len: usize) -> Parsed<&[u8]> {
    data.get(start..start.checked_add(len).ok_or(Reason::Truncated)?)
        .ok_or(Reason::Truncated)
}

pub(super) fn word(data: &[u8], start: usize) -> Parsed<u16> {
    let b = bytes(data, start, 2)?;
    Ok(u16::from_be_bytes([b[0], b[1]]))
}

fn dword(data: &[u8], start: usize) -> Parsed<u32> {
    let b = bytes(data, start, 4)?;
    Ok(u32::from_be_bytes([b[0], b[1], b[2], b[3]]))
}

pub(super) enum Link<'a> {
    Ip(&'a [u8]),
    Arp(&'a [u8]),
    Other,
}

pub(super) fn link(data: &[u8], kind: u32) -> Parsed<Link<'_>> {
    let (mut offset, mut protocol) = match kind {
        1 => {
            bytes(data, 0, 14)?;
            (14, word(data, 12)?)
        }
        113 => {
            bytes(data, 0, 16)?;
            (16, word(data, 14)?)
        }
        276 => {
            bytes(data, 0, 20)?;
            (20, word(data, 0)?)
        }
        101 => return Ok(Link::Ip(data)),
        _ => return Err(Reason::UnparsableLinkLayer),
    };
    while matches!(protocol, 0x8100 | 0x88a8 | 0x9100) {
        protocol = word(data, offset + 2)?;
        offset += 4;
    }
    let data = bytes(data, offset, data.len().saturating_sub(offset))?;
    match protocol {
        0x0800 if data.first().is_some_and(|b| b >> 4 == 4) => Ok(Link::Ip(data)),
        0x86dd if data.first().is_some_and(|b| b >> 4 == 6) => Ok(Link::Ip(data)),
        0x0800 | 0x86dd if data.is_empty() => Err(Reason::Truncated),
        0x0800 | 0x86dd => Err(Reason::UnparsableLinkLayer),
        0x0806 => Ok(Link::Arp(data)),
        _ => Ok(Link::Other),
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(super) struct Key {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub id: u32,
    pub proto: u8,
}

#[derive(Clone)]
pub(super) struct Fragment {
    pub key: Key,
    pub offset: usize,
    pub more: bool,
}

pub(super) struct Ip<'a> {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: u8,
    pub payload: &'a [u8],
    pub raw: &'a [u8],
    pub trailer: &'a [u8],
    pub addresses: Vec<IpAddr>,
    pub fragment: Option<Fragment>,
    pub truncated: bool,
    pub hop_limit: u8,
    pub dscp: u8,
}

pub(super) fn ip(data: &[u8], quoted: bool) -> Parsed<Ip<'_>> {
    match bytes(data, 0, 1)?[0] >> 4 {
        4 => ipv4(data, quoted),
        6 => ipv6(data, quoted),
        _ => Err(Reason::MalformedPacket),
    }
}

fn ipv4(data: &[u8], quoted: bool) -> Parsed<Ip<'_>> {
    let header = bytes(data, 0, 20)?;
    let ihl = usize::from(header[0] & 15) * 4;
    if ihl < 20 {
        return Err(Reason::MalformedPacket);
    }
    bytes(data, 0, ihl)?;
    let total = usize::from(word(data, 2)?);
    if total < ihl {
        return Err(Reason::MalformedPacket);
    }
    let flags = word(data, 6)?;
    if flags & 0x8000 != 0 {
        return Err(Reason::MalformedPacket);
    }
    let src = IpAddr::V4(Ipv4Addr::new(
        header[12], header[13], header[14], header[15],
    ));
    let dst = IpAddr::V4(Ipv4Addr::new(
        header[16], header[17], header[18], header[19],
    ));
    let fragment = (flags & 0x3fff != 0).then(|| Fragment {
        key: Key {
            src,
            dst,
            id: u32::from(u16::from_be_bytes([header[4], header[5]])),
            proto: header[9],
        },
        offset: usize::from(flags & 0x1fff) * 8,
        more: flags & 0x2000 != 0,
    });
    Ok(Ip {
        src,
        dst,
        proto: header[9],
        payload: &data[ihl..total.min(data.len())],
        raw: &data[..total.min(data.len())],
        trailer: data.get(total..).unwrap_or_default(),
        addresses: ipv4_options(&data[20..ihl])?,
        fragment,
        truncated: !quoted && total > data.len(),
        hop_limit: header[8],
        dscp: header[1] >> 2,
    })
}

fn ipv6(data: &[u8], quoted: bool) -> Parsed<Ip<'_>> {
    let h = bytes(data, 0, 40)?;
    let addr = |at| -> Parsed<IpAddr> {
        let mut octets = [0; 16];
        octets.copy_from_slice(bytes(h, at, 16)?);
        Ok(IpAddr::V6(Ipv6Addr::from(octets)))
    };
    let src = addr(8)?;
    let dst = addr(24)?;
    let total = 40 + usize::from(word(h, 4)?);
    let (proto, payload, addresses) = extensions(h[6], &data[40..total.min(data.len())])?;
    let (proto, payload, fragment) = if proto == 44 {
        let f = bytes(payload, 0, 8)?;
        let flags = word(f, 2)?;
        if f[1] != 0 || flags & 6 != 0 {
            return Err(Reason::MalformedPacket);
        }
        let key = Key {
            src,
            dst,
            id: dword(f, 4)?,
            proto: f[0],
        };
        (
            f[0],
            &payload[8..],
            Some(Fragment {
                key,
                offset: usize::from(flags & 0xfff8),
                more: flags & 1 != 0,
            }),
        )
    } else {
        (proto, payload, None)
    };
    Ok(Ip {
        src,
        dst,
        proto,
        payload,
        raw: &data[..total.min(data.len())],
        trailer: data.get(total..).unwrap_or_default(),
        addresses,
        fragment,
        truncated: !quoted && total > data.len(),
        hop_limit: h[7],
        dscp: ((h[0] & 15) << 2) | (h[1] >> 6),
    })
}

fn ipv4_options(mut data: &[u8]) -> Parsed<Vec<IpAddr>> {
    let mut addresses = Vec::new();
    while let Some(&kind) = data.first() {
        if kind == 0 {
            break;
        }
        if kind == 1 {
            data = &data[1..];
            continue;
        }
        let len = usize::from(bytes(data, 0, 2)?[1]);
        if len < 2 {
            return Err(Reason::MalformedPacket);
        }
        let option = bytes(data, 0, len)?;
        match kind {
            // Record route, loose and strict source routes: type/length/pointer,
            // followed by four-byte addresses (including unused list slots).
            7 | 131 | 137 => {
                if len < 3 || !(len - 3).is_multiple_of(4) {
                    return Err(Reason::MalformedPacket);
                }
                for at in (3..len).step_by(4) {
                    addresses.push(address4(option, at)?);
                }
            }
            // Timestamp flags 1 and 3 contain address/timestamp pairs; flag 0
            // contains timestamps only. The overflow counter is in the high nibble.
            68 => {
                let flags = bytes(option, 0, 4)?[3] & 15;
                let stride = match flags {
                    0 => 4,
                    1 | 3 => 8,
                    _ => return Err(Reason::MalformedPacket),
                };
                if !(len - 4).is_multiple_of(stride) {
                    return Err(Reason::MalformedPacket);
                }
                if flags != 0 {
                    for at in (4..len).step_by(8) {
                        addresses.push(address4(option, at)?);
                    }
                }
            }
            _ => {}
        }
        data = &data[len..];
    }
    Ok(addresses)
}

pub(super) fn address4(data: &[u8], at: usize) -> Parsed<IpAddr> {
    let b = bytes(data, at, 4)?;
    Ok(Ipv4Addr::new(b[0], b[1], b[2], b[3]).into())
}

pub(super) fn address6(data: &[u8], at: usize) -> Parsed<IpAddr> {
    let mut b = [0; 16];
    b.copy_from_slice(bytes(data, at, 16)?);
    Ok(Ipv6Addr::from(b).into())
}

/// Stop at fragment headers, including when called after reassembly. Raw bytes
/// remain in `Ip::raw`; the returned addresses cover defined extension fields.
pub(super) fn extensions(mut proto: u8, mut data: &[u8]) -> Parsed<(u8, &[u8], Vec<IpAddr>)> {
    let mut addresses = Vec::new();
    while matches!(proto, 0 | 43 | 60 | 51) {
        let h = bytes(data, 0, 2)?;
        let len = if proto == 51 {
            (usize::from(h[1]) + 2) * 4
        } else {
            (usize::from(h[1]) + 1) * 8
        };
        let header = bytes(data, 0, len)?;
        if proto == 43 {
            bytes(header, 0, 8)?;
            let count = match header[2] {
                0 => {
                    if !(len - 8).is_multiple_of(16) {
                        return Err(Reason::MalformedPacket);
                    }
                    (len - 8) / 16
                }
                2 => {
                    if len != 24 {
                        return Err(Reason::MalformedPacket);
                    }
                    1
                }
                4 => usize::from(header[4]) + 1,
                // Unknown routing formats cannot safely hide address fields.
                _ => return Err(Reason::MalformedPacket),
            };
            for i in 0..count {
                addresses.push(address6(header, 8 + 16 * i)?);
            }
        } else if matches!(proto, 0 | 60) {
            let mut at = 2;
            while at < len {
                let kind = header[at];
                if kind == 0 {
                    at += 1;
                    continue;
                }
                let size = usize::from(bytes(header, at, 2)?[1]);
                bytes(header, at + 2, size)?;
                // Mobile IPv6 Home Address destination option (RFC 6275).
                if kind == 201 {
                    if size != 16 {
                        return Err(Reason::MalformedPacket);
                    }
                    addresses.push(address6(header, at + 2)?);
                }
                at += 2 + size;
            }
        }
        proto = h[0];
        data = &data[len..];
    }
    Ok((proto, data, addresses))
}

pub(super) struct Transport<'a> {
    pub ports: Option<(u16, u16)>,
    pub payload: &'a [u8],
    pub quotation: Option<&'a [u8]>,
}

pub(super) fn transport(proto: u8, data: &[u8], v6: bool) -> Parsed<Transport<'_>> {
    let mut ports = None;
    let mut quotation = None;
    let payload = match proto {
        17 => {
            bytes(data, 0, 8)?;
            let len = usize::from(word(data, 4)?);
            if len < 8 || len != data.len() {
                return Err(Reason::MalformedPacket);
            }
            ports = Some((word(data, 0)?, word(data, 2)?));
            &data[8..]
        }
        6 => {
            let h = bytes(data, 0, 20)?;
            let len = usize::from(h[12] >> 4) * 4;
            if len < 20 {
                return Err(Reason::MalformedPacket);
            }
            bytes(data, 0, len)?;
            ports = Some((word(data, 0)?, word(data, 2)?));
            &data[len..]
        }
        1 | 58 => {
            let h = bytes(data, 0, 8)?;
            if (proto == 1 && v6) || (proto == 58 && !v6) {
                return Err(Reason::MalformedPacket);
            }
            if (proto == 1 && matches!(h[0], 3 | 4 | 5 | 11 | 12))
                || (proto == 58 && matches!(h[0], 1..=4))
            {
                quotation = Some(&data[8..]);
            }
            &data[8..]
        }
        _ => data,
    };
    Ok(Transport {
        ports,
        payload,
        quotation,
    })
}

pub(super) fn arp(data: &[u8]) -> Parsed<(IpAddr, IpAddr)> {
    bytes(data, 0, 28)?;
    if word(data, 0)? != 1
        || word(data, 2)? != 0x0800
        || data[4] != 6
        || data[5] != 4
        || !matches!(word(data, 6)?, 1 | 2)
    {
        return Err(Reason::MalformedPacket);
    }
    let addr = |at| {
        IpAddr::V4(Ipv4Addr::new(
            data[at],
            data[at + 1],
            data[at + 2],
            data[at + 3],
        ))
    };
    Ok((addr(14), addr(24)))
}
