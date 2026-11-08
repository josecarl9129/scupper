//! DNS name expansion with bounded pointer traversal, including TCP framing.

use super::{
    Reason,
    decode::{bytes, word},
};

pub(super) fn names(data: &[u8], tcp: bool) -> Result<Vec<Vec<u8>>, Reason> {
    let (output, status) = scan(data, tcp);
    status?;
    Ok(output)
}

// Retain names found before a quotation's normal short tail. Full outer DNS
// messages still require the entire parse to succeed through `names`.
pub(super) fn scan(data: &[u8], tcp: bool) -> (Vec<Vec<u8>>, Result<(), Reason>) {
    let mut output = Vec::new();
    let status = (|| {
        if tcp {
            let mut remaining = data;
            while !remaining.is_empty() {
                let len = usize::from(word(remaining, 0)?);
                // Scan the available part, even if an ICMP quote cut this frame.
                let available = &remaining[2..remaining.len().min(2 + len)];
                message(available, &mut output)?;
                bytes(remaining, 2, len)?;
                remaining = &remaining[2 + len..];
            }
        } else {
            message(data, &mut output)?;
        }
        Ok(())
    })();
    (output, status)
}

fn message(data: &[u8], output: &mut Vec<Vec<u8>>) -> Result<(), Reason> {
    bytes(data, 0, 12)?;
    let mut offset = 12;
    for _ in 0..word(data, 4)? {
        let (name, next) = name(data, offset)?;
        output.push(name);
        bytes(data, next, 4)?;
        offset = next + 4;
    }
    // Validate owners and domain names in common answer RDATA, as well as questions.
    let count = u32::from(word(data, 6)?) + u32::from(word(data, 8)?) + u32::from(word(data, 10)?);
    for _ in 0..count {
        let (owner, next) = name(data, offset)?;
        output.push(owner);
        bytes(data, next, 10)?;
        let kind = word(data, next)?;
        let len = usize::from(word(data, next + 8)?);
        let start = next + 10;
        bytes(data, start, len)?;
        let name_at = match kind {
            2 | 5 | 12 => Some(start),
            15 => Some(start + 2),
            33 => Some(start + 6),
            _ => None,
        };
        if let Some(at) = name_at {
            let (expanded, end) = name(data, at)?;
            if end > start + len {
                return Err(Reason::MalformedPacket);
            }
            output.push(expanded);
        }
        offset = start + len;
    }
    Ok(())
}

fn name(data: &[u8], start: usize) -> Result<(Vec<u8>, usize), Reason> {
    let mut offset = start;
    let mut resume = None;
    let mut result = Vec::new();
    // DNS names are <=255 octets; a pointer chain may not consume unbounded work.
    for _ in 0..256 {
        let len = bytes(data, offset, 1)?[0];
        if len & 0xc0 == 0xc0 {
            let target = usize::from(word(data, offset)? & 0x3fff);
            resume.get_or_insert(offset + 2);
            offset = target;
            continue;
        }
        if len & 0xc0 != 0 {
            return Err(Reason::MalformedPacket);
        }
        offset += 1;
        if len == 0 {
            return Ok((result, resume.unwrap_or(offset)));
        }
        if !result.is_empty() {
            result.push(b'.');
        }
        result.extend_from_slice(bytes(data, offset, usize::from(len))?);
        if result.len() > 253 {
            return Err(Reason::MalformedPacket);
        }
        offset += usize::from(len);
    }
    Err(Reason::MalformedPacket)
}
