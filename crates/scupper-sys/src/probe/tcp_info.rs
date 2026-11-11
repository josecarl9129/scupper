//! Read `TCP_INFO` through `INET_DIAG_INFO` without unsafe getsockopt bindings.
//! The existing safe socket libraries do not expose `TCP_INFO`. `SOCK_DIAG` returns
//! the same kernel `tcp_info` structure, selected by tuple and socket cookie.
use rustix::net::{self, AddressFamily, RecvFlags, SendFlags, SocketFlags, SocketType};
use std::{io, net::TcpStream, time::Duration};

pub(super) fn rto(stream: &TcpStream) -> io::Result<Duration> {
    let local = stream.local_addr()?;
    let peer = stream.peer_addr()?;
    let (std::net::IpAddr::V4(source), std::net::IpAddr::V4(dest)) = (local.ip(), peer.ip()) else {
        return Err(io::ErrorKind::InvalidInput.into());
    };
    let fd = net::socket_with(
        AddressFamily::NETLINK,
        SocketType::DGRAM,
        SocketFlags::CLOEXEC,
        Some(net::netlink::SOCK_DIAG),
    )?;
    net::sockopt::set_socket_timeout(
        &fd,
        net::sockopt::Timeout::Recv,
        Some(Duration::from_millis(50)),
    )?;
    // nlmsghdr + inet_diag_req_v2, native-endian integers except network tuple.
    let mut request = [0u8; 72];
    request[0..4].copy_from_slice(&72u32.to_ne_bytes());
    request[4..6].copy_from_slice(&20u16.to_ne_bytes()); // SOCK_DIAG_BY_FAMILY
    request[6..8].copy_from_slice(&1u16.to_ne_bytes()); // NLM_F_REQUEST
    request[8..12].copy_from_slice(&1u32.to_ne_bytes());
    request[16] = 2; // AF_INET
    request[17] = 6; // IPPROTO_TCP
    request[18] = 2; // INET_DIAG_INFO extension
    request[20..24].copy_from_slice(&u32::MAX.to_ne_bytes());
    request[24..26].copy_from_slice(&local.port().to_be_bytes());
    request[26..28].copy_from_slice(&peer.port().to_be_bytes());
    request[28..32].copy_from_slice(&source.octets());
    request[44..48].copy_from_slice(&dest.octets());
    let cookie = net::sockopt::socket_cookie(stream)?;
    let cookie_bytes = cookie.to_le_bytes();
    let low = u32::from_le_bytes(
        cookie_bytes[..4]
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?,
    );
    let high = u32::from_le_bytes(
        cookie_bytes[4..]
            .try_into()
            .map_err(|_| io::ErrorKind::InvalidData)?,
    );
    request[64..68].copy_from_slice(&low.to_ne_bytes());
    request[68..72].copy_from_slice(&high.to_ne_bytes());
    net::sendto(
        &fd,
        &request,
        SendFlags::empty(),
        &net::netlink::SocketAddrNetlink::new(0, 0),
    )?;
    let mut response = [0u8; 4096];
    let (count, _) = net::recv(&fd, &mut response, RecvFlags::empty())?;
    parse_rto(&response[..count])
}
fn parse_rto(response: &[u8]) -> io::Result<Duration> {
    let invalid = || io::Error::from(io::ErrorKind::InvalidData);
    let word = |at| -> io::Result<u16> {
        Ok(u16::from_ne_bytes(
            response
                .get(at..at + 2)
                .ok_or_else(invalid)?
                .try_into()
                .map_err(|_| invalid())?,
        ))
    };
    if response.len() < 88 || word(4)? != 20 {
        return Err(invalid());
    }
    let length = u32::from_ne_bytes(response[..4].try_into().map_err(|_| invalid())?) as usize;
    if length > response.len() {
        return Err(invalid());
    }
    let mut at = 88; // nlmsghdr + inet_diag_msg
    while at + 4 <= length {
        let size = usize::from(word(at)?);
        if size < 4 || at + size > length {
            return Err(invalid());
        }
        if word(at + 2)? == 2 {
            // INET_DIAG_INFO: tcp_info.tcpi_rto at byte 8
            if size < 16 {
                return Err(invalid());
            }
            let micros = u32::from_ne_bytes(
                response[at + 12..at + 16]
                    .try_into()
                    .map_err(|_| invalid())?,
            );
            if micros == 0 {
                return Err(invalid());
            }
            return Ok(Duration::from_micros(u64::from(micros)));
        }
        at += (size + 3) & !3;
    }
    Err(invalid())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rejects_missing_truncated_or_zero_tcp_info() {
        assert!(parse_rto(&[]).is_err());
        let mut message = [0u8; 104];
        message[..4].copy_from_slice(&104u32.to_ne_bytes());
        message[4..6].copy_from_slice(&20u16.to_ne_bytes());
        message[88..90].copy_from_slice(&16u16.to_ne_bytes());
        message[90..92].copy_from_slice(&2u16.to_ne_bytes());
        assert!(parse_rto(&message).is_err());
        message[100..104].copy_from_slice(&200_000u32.to_ne_bytes());
        assert_eq!(parse_rto(&message).ok(), Some(Duration::from_millis(200)));
        assert!(parse_rto(&message[..103]).is_err());
    }
}
