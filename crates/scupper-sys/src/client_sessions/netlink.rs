//! Minimal read-only generic netlink codec. No key material leaves this module.
use super::Sample;
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::BTreeMap,
    io::{self, Read},
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

fn invalid() -> io::Error {
    io::Error::other("invalid WireGuard netlink observation")
}
fn u16_at(b: &[u8], n: usize) -> io::Result<u16> {
    Ok(u16::from_ne_bytes(
        b.get(n..n + 2)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn u32_at(b: &[u8], n: usize) -> io::Result<u32> {
    Ok(u32::from_ne_bytes(
        b.get(n..n + 4)
            .ok_or_else(invalid)?
            .try_into()
            .map_err(|_| invalid())?,
    ))
}
fn u64_value(b: &[u8]) -> io::Result<u64> {
    Ok(u64::from_ne_bytes(b.try_into().map_err(|_| invalid())?))
}
fn attributes(
    mut bytes: &[u8],
    mut visit: impl FnMut(u16, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    while !bytes.is_empty() {
        let len = usize::from(u16_at(bytes, 0)?);
        if len < 4 || len > bytes.len() {
            return Err(invalid());
        }
        visit(u16_at(bytes, 2)? & 0x3fff, &bytes[4..len])?;
        let aligned = (len + 3) & !3;
        if aligned > bytes.len() {
            return Err(invalid());
        }
        bytes = &bytes[aligned..];
    }
    Ok(())
}
fn attr(kind: u16, data: &[u8]) -> io::Result<Vec<u8>> {
    let len = u16::try_from(data.len() + 4).map_err(|_| invalid())?;
    let mut result = Vec::from(len.to_ne_bytes());
    result.extend(kind.to_ne_bytes());
    result.extend(data);
    result.resize((result.len() + 3) & !3, 0);
    Ok(result)
}
fn request(family: u16, command: u8, flags: u16, seq: u32, attrs: &[u8]) -> io::Result<Vec<u8>> {
    let mut bytes = Vec::from(
        u32::try_from(20 + attrs.len())
            .map_err(|_| invalid())?
            .to_ne_bytes(),
    );
    bytes.extend(family.to_ne_bytes());
    bytes.extend(flags.to_ne_bytes());
    bytes.extend(seq.to_ne_bytes());
    bytes.extend(0_u32.to_ne_bytes());
    bytes.extend([command, 1, 0, 0]);
    bytes.extend(attrs);
    Ok(bytes)
}
fn exchange(
    socket: &Socket,
    request: &[u8],
    seq: u32,
    mut visit: impl FnMut(u16, &[u8]) -> io::Result<()>,
) -> io::Result<()> {
    if socket.send(request)? != request.len() {
        return Err(invalid());
    }
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut buffer = Zeroizing::new(vec![0_u8; 65536]);
    for _ in 0..1024 {
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
        // Generic netlink autobinds on send; its default destination is the kernel.
        let size = (&*socket).read(&mut buffer)?;
        if size == 0 || size == buffer.len() {
            return Err(invalid());
        }
        let mut bytes = &buffer[..size];
        let mut multipart = false;
        while !bytes.is_empty() {
            let len = usize::try_from(u32_at(bytes, 0)?).map_err(|_| invalid())?;
            if len < 16 || len > bytes.len() || u32_at(bytes, 8)? != seq {
                return Err(invalid());
            }
            let kind = u16_at(bytes, 4)?;
            let flags = u16_at(bytes, 6)?;
            if flags & 0x10 != 0 {
                return Err(invalid());
            } // NLM_F_DUMP_INTR
            let payload = &bytes[16..len];
            if kind == 2 {
                return Err(invalid());
            } // NLMSG_ERROR, no ACK requested
            if kind == 3 {
                // NLMSG_DONE may include a signed error.
                if !payload.is_empty() && u32_at(payload, 0)? != 0 {
                    return Err(invalid());
                }
                return Ok(());
            }
            if kind < 0x10 {
                return Err(invalid());
            }
            visit(kind, payload)?;
            multipart |= flags & 2 != 0;
            bytes = bytes.get((len + 3) & !3..).ok_or_else(invalid)?;
        }
        if !multipart {
            return Ok(());
        }
    }
    Err(invalid())
}
#[derive(Default)]
struct PartialSample {
    handshake: Option<(u64, u32)>,
    rx: Option<u64>,
    tx: Option<u64>,
}
fn peers(bytes: &[u8], peers: &mut BTreeMap<[u8; 32], PartialSample>) -> io::Result<()> {
    attributes(bytes, |_, peer| {
        let mut key = None;
        let mut sample = PartialSample::default();
        attributes(peer, |kind, value| {
            match kind {
                1 => key = Some(<[u8; 32]>::try_from(value).map_err(|_| invalid())?),
                6 => {
                    if value.len() != 16 {
                        return Err(invalid());
                    }
                    let secs = u64_value(&value[..8])?;
                    let nanos = u64_value(&value[8..])?;
                    if secs > i64::MAX as u64 || nanos >= 1_000_000_000 {
                        return Err(invalid());
                    }
                    sample.handshake = Some((secs, u32::try_from(nanos).map_err(|_| invalid())?));
                }
                7 => sample.rx = Some(u64_value(value)?),
                8 => sample.tx = Some(u64_value(value)?),
                _ => {} // In particular, never copy private/preshared key attributes.
            }
            Ok(())
        })?;
        let entry = peers.entry(key.ok_or_else(invalid)?).or_default();
        // A large AllowedIPs list can split a peer across dump messages.
        if let Some(value) = sample.handshake {
            entry.handshake = Some(value);
        }
        if let Some(value) = sample.rx {
            entry.rx = Some(value);
        }
        if let Some(value) = sample.tx {
            entry.tx = Some(value);
        }
        Ok(())
    })
}
pub(super) fn read(iface: &str) -> io::Result<Vec<Sample>> {
    // AF_NETLINK=16, NETLINK_GENERIC=16. socket2 safely owns the descriptor;
    // std::io::Read avoids uninitialized buffers and raw sockaddr construction.
    let socket = Socket::new(Domain::from(16), Type::DGRAM, Some(Protocol::from(16)))?;
    socket.set_read_timeout(Some(Duration::from_secs(1)))?;
    socket.set_write_timeout(Some(Duration::from_secs(1)))?;
    let mut family = None;
    exchange(
        &socket,
        &request(0x10, 3, 1, 1, &attr(2, b"wireguard\0")?)?,
        1,
        |_, payload| {
            attributes(payload.get(4..).ok_or_else(invalid)?, |kind, value| {
                if kind == 1 {
                    if value.len() != 2 {
                        return Err(invalid());
                    }
                    family = Some(u16_at(value, 0)?);
                }
                Ok(())
            })
        },
    )?;
    let family = family.ok_or_else(invalid)?;
    let mut name = iface.as_bytes().to_vec();
    name.push(0);
    let mut samples = BTreeMap::new();
    exchange(
        &socket,
        &request(family, 0, 0x301, 2, &attr(2, &name)?)?,
        2,
        |kind, payload| {
            if kind != family {
                return Err(invalid());
            }
            attributes(payload.get(4..).ok_or_else(invalid)?, |kind, value| {
                if kind == 8 {
                    peers(value, &mut samples)?;
                }
                Ok(())
            })
        },
    )?;
    samples
        .into_iter()
        .map(|(key, s)| {
            Ok(Sample {
                key,
                handshake: s.handshake.ok_or_else(invalid)?,
                rx: s.rx.ok_or_else(invalid)?,
                tx: s.tx.ok_or_else(invalid)?,
            })
        })
        .collect()
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[test]
    fn generic_netlink_autobind_receives_kernel_control_reply() {
        let socket = Socket::new(Domain::from(16), Type::DGRAM, Some(Protocol::from(16))).unwrap();
        socket
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let mut found = false;
        exchange(
            &socket,
            &request(0x10, 3, 1, 1, &attr(2, b"nlctrl\0").unwrap()).unwrap(),
            1,
            |kind, payload| {
                assert_eq!(kind, 0x10);
                attributes(&payload[4..], |kind, value| {
                    if kind == 1 {
                        found = u16_at(value, 0)? == 0x10;
                    }
                    Ok(())
                })
            },
        )
        .unwrap();
        assert!(found);
    }
    #[test]
    fn full_resolution_and_split_peers_without_copying_keys() {
        let mut peer = attr(1, &[7; 32]).unwrap();
        peer.extend(attr(2, &[99; 32]).unwrap());
        let mut time = 123_u64.to_ne_bytes().to_vec();
        time.extend(456_u64.to_ne_bytes());
        peer.extend(attr(6, &time).unwrap());
        peer.extend(attr(7, &92_u64.to_ne_bytes()).unwrap());
        peer.extend(attr(8, &148_u64.to_ne_bytes()).unwrap());
        let mut map = BTreeMap::new();
        peers(&attr(0x8001, &peer).unwrap(), &mut map).unwrap();
        peers(
            &attr(0x8001, &attr(1, &[7; 32]).unwrap()).unwrap(),
            &mut map,
        )
        .unwrap();
        assert_eq!(map[&[7; 32]].handshake, Some((123, 456)));
        assert_eq!(map[&[7; 32]].rx, Some(92));
        assert_eq!(map.len(), 1);
    }
    #[test]
    fn malformed_and_truncated_attributes_are_errors() {
        for bytes in [
            &[0, 0, 0, 0][..],
            &[8, 0, 1, 0, 1],
            &[4, 0, 1],
            &[5, 0, 1, 0, 7],
        ] {
            assert!(attributes(bytes, |_, _| Ok(())).is_err());
        }
        let mut peer = attr(1, &[7; 32]).unwrap();
        peer.extend(attr(6, &[255; 16]).unwrap());
        assert!(peers(&attr(1, &peer).unwrap(), &mut BTreeMap::new()).is_err());
    }
}
