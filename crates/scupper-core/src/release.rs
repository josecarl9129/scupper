//! Deterministic release archives: regular ustar files in a stored-block gzip stream.
use sha2::{Digest, Sha256};
use std::{collections::BTreeMap, io};

/// Maximum decoded release size (512 MiB).
pub const MAX_RELEASE: usize = 512 * 1024 * 1024;
/// Flat, allow-listed release files.
pub type Members = BTreeMap<String, Vec<u8>>;
fn invalid() -> io::Error {
    io::Error::other("invalid release archive")
}
/// SHA256 in lowercase hexadecimal.
#[must_use]
pub fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn allowed(name: &str) -> bool {
    matches!(
        name,
        "scupper" | "scupperd" | "scupper-net.service" | "scupperd.service" | "MANIFEST"
    )
}
fn octal(field: &mut [u8], value: usize) -> io::Result<()> {
    let text = format!("{value:0width$o}", width = field.len() - 1);
    if text.len() >= field.len() {
        return Err(invalid());
    }
    field[..text.len()].copy_from_slice(text.as_bytes());
    Ok(())
}
fn manifest(members: &Members) -> String {
    let mut text = String::new();
    for (name, bytes) in members.iter().filter(|(n, _)| n.as_str() != "MANIFEST") {
        text.push_str(&hash(bytes));
        text.push_str("  ");
        text.push_str(name);
        text.push('\n');
    }
    text
}
fn crc32(bytes: &[u8]) -> u32 {
    let mut crc = !0_u32;
    for byte in bytes {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = (crc >> 1) ^ (0xedb8_8320 & 0_u32.wrapping_sub(crc & 1));
        }
    }
    !crc
}
/// Encodes sorted members, root ownership, epoch timestamps and fixed modes.
/// `MANIFEST` covers every payload member (it cannot hash itself).
/// # Errors
/// Rejects unknown names, missing CLI or oversized input.
pub fn encode(mut members: Members) -> io::Result<Vec<u8>> {
    if !members.contains_key("scupper")
        || members.contains_key("MANIFEST")
        || members.keys().any(|n| !allowed(n))
    {
        return Err(invalid());
    }
    members.insert("MANIFEST".into(), manifest(&members).into_bytes());
    let mut tar = Vec::new();
    for (name, bytes) in &members {
        if bytes.len() > MAX_RELEASE || tar.len().saturating_add(bytes.len() + 1024) > MAX_RELEASE {
            return Err(invalid());
        }
        let mut h = [0_u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        octal(
            &mut h[100..108],
            if name.starts_with("scupper") && !name.ends_with(".service") {
                0o755
            } else {
                0o644
            },
        )?;
        octal(&mut h[108..116], 0)?;
        octal(&mut h[116..124], 0)?;
        octal(&mut h[124..136], bytes.len())?;
        octal(&mut h[136..148], 0)?;
        h[148..156].fill(b' ');
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        let sum: usize = h.iter().map(|b| usize::from(*b)).sum();
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        tar.extend(h);
        tar.extend(bytes);
        tar.resize(tar.len().next_multiple_of(512), 0);
    }
    tar.resize(tar.len() + 1024, 0);
    // Stored DEFLATE blocks make output identical on macOS and Linux without
    // depending on a compressor version or introducing a dependency.
    let mut gzip = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255];
    let chunks = tar.chunks(65535);
    let count = chunks.len();
    for (i, chunk) in chunks.enumerate() {
        gzip.push(u8::from(i + 1 == count));
        let size = u16::try_from(chunk.len()).map_err(|_| invalid())?;
        gzip.extend(size.to_le_bytes());
        gzip.extend((!size).to_le_bytes());
        gzip.extend(chunk);
    }
    gzip.extend(crc32(&tar).to_le_bytes());
    gzip.extend(
        u32::try_from(tar.len())
            .map_err(|_| invalid())?
            .to_le_bytes(),
    );
    Ok(gzip)
}
fn number(bytes: &[u8]) -> io::Result<usize> {
    let text = std::str::from_utf8(bytes)
        .map_err(|_| invalid())?
        .trim_matches(['\0', ' ']);
    usize::from_str_radix(text, 8).map_err(|_| invalid())
}
/// Verifies gzip, the complete tar namespace and all manifest hashes before writes.
/// Only the deterministic gzip encoding produced by `encode` is accepted.
/// # Errors
/// Refuses corruption, links, traversal, duplicates, missing or unknown members.
pub fn decode(bytes: &[u8], gateway: bool) -> io::Result<Members> {
    let tar = gunzip(bytes)?;
    let mut members = Members::new();
    let mut pos = 0;
    loop {
        let h = tar.get(pos..pos + 512).ok_or_else(invalid)?;
        if h.iter().all(|b| *b == 0) {
            if tar.len() - pos < 1024 || tar[pos..].iter().any(|b| *b != 0) {
                return Err(invalid());
            }
            break;
        }
        let sum: usize = h
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    32
                } else {
                    usize::from(*b)
                }
            })
            .sum();
        let end = h[..100].iter().position(|b| *b == 0).ok_or_else(invalid)?;
        let name = std::str::from_utf8(&h[..end]).map_err(|_| invalid())?;
        if !allowed(name)
            || h[end..100].iter().any(|b| *b != 0)
            || h[156] != b'0'
            || h[157..257].iter().any(|b| *b != 0)
            || h[345..500].iter().any(|b| *b != 0)
            || &h[257..263] != b"ustar\0"
            || &h[263..265] != b"00"
            || number(&h[148..156])? != sum
        {
            return Err(invalid());
        }
        let size = number(&h[124..136])?;
        if size > MAX_RELEASE {
            return Err(invalid());
        }
        pos += 512;
        let data = tar
            .get(
                pos..pos
                    .checked_add(size.next_multiple_of(512))
                    .ok_or_else(invalid)?,
            )
            .ok_or_else(invalid)?;
        if data[size..].iter().any(|b| *b != 0)
            || members.insert(name.into(), data[..size].to_vec()).is_some()
        {
            return Err(invalid());
        }
        pos += data.len();
    }
    let expected = if gateway {
        vec![
            "MANIFEST",
            "scupper",
            "scupper-net.service",
            "scupperd",
            "scupperd.service",
        ]
    } else {
        vec!["MANIFEST", "scupper"]
    };
    if members.keys().map(String::as_str).collect::<Vec<_>>() != expected
        || members.get("MANIFEST").map(Vec::as_slice) != Some(manifest(&members).as_bytes())
    {
        return Err(invalid());
    }
    Ok(members)
}

fn gunzip(bytes: &[u8]) -> io::Result<Vec<u8>> {
    if bytes.len() > MAX_RELEASE + 65536
        || bytes.get(..10) != Some(&[0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255])
    {
        return Err(invalid());
    }
    let mut pos = 10;
    let mut tar = Vec::new();
    loop {
        let h = bytes.get(pos..pos + 5).ok_or_else(invalid)?;
        if h[0] > 1 {
            return Err(invalid());
        }
        let size = u16::from_le_bytes([h[1], h[2]]);
        if size != !u16::from_le_bytes([h[3], h[4]]) || tar.len() + usize::from(size) > MAX_RELEASE
        {
            return Err(invalid());
        }
        pos += 5;
        tar.extend(
            bytes
                .get(pos..pos + usize::from(size))
                .ok_or_else(invalid)?,
        );
        pos += usize::from(size);
        if h[0] == 1 {
            break;
        }
    }
    let mut trailer = Vec::from(crc32(&tar).to_le_bytes());
    trailer.extend(
        u32::try_from(tar.len())
            .map_err(|_| invalid())?
            .to_le_bytes(),
    );
    if bytes.get(pos..) != Some(trailer.as_slice()) {
        return Err(invalid());
    }
    Ok(tar)
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    fn gateway() -> Members {
        [
            "scupper",
            "scupperd",
            "scupper-net.service",
            "scupperd.service",
        ]
        .into_iter()
        .map(|name| (name.into(), name.as_bytes().to_vec()))
        .collect()
    }
    // Re-wrap a deliberately changed tar with a valid gzip checksum, so these
    // cases exercise archive validation rather than just corruption detection.
    fn rewrap(tar: &[u8]) -> Vec<u8> {
        let mut bytes = vec![0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255, 1];
        let size = u16::try_from(tar.len()).unwrap();
        bytes.extend(size.to_le_bytes());
        bytes.extend((!size).to_le_bytes());
        bytes.extend(tar);
        bytes.extend(crc32(tar).to_le_bytes());
        bytes.extend(u32::try_from(tar.len()).unwrap().to_le_bytes());
        bytes
    }
    fn header_checksum(tar: &mut [u8]) {
        tar[148..156].fill(b' ');
        let sum: usize = tar[..512].iter().map(|b| usize::from(*b)).sum();
        tar[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
    }
    #[test]
    fn decoder_refuses_links_traversal_and_manifest_tampering() {
        let original = gunzip(&encode(gateway()).unwrap()).unwrap();
        for kind in *b"125x" {
            let mut tar = original.clone();
            tar[156] = kind;
            header_checksum(&mut tar);
            assert!(decode(&rewrap(&tar), true).is_err());
        }
        let mut tar = original.clone();
        tar[..100].fill(0);
        tar[..9].copy_from_slice(b"../escape");
        header_checksum(&mut tar);
        assert!(decode(&rewrap(&tar), true).is_err());
        let mut tar = original;
        tar[512] ^= 1;
        assert!(decode(&rewrap(&tar), true).is_err());
    }
    proptest::proptest! {
        #[test]
        fn arbitrary_archives_are_bounded_and_do_not_panic(bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..4096)) {
            let _ = decode(&bytes, true);
        }
    }
}
