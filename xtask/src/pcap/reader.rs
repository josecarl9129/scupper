//! Small classic-pcap reader. No allocation derives from untrusted length fields.

use super::{Error, Timestamp};

pub(super) struct Record<'a> {
    pub timestamp: Timestamp,
    pub data: &'a [u8],
    pub truncated: bool,
}

pub(super) struct Capture<'a> {
    pub linktype: u32,
    pub fcs_len: usize,
    pub records: Vec<Record<'a>>,
}

pub(super) fn read(data: &[u8]) -> Result<Capture<'_>, Error> {
    let error = || Error::Capture("invalid or truncated classic-pcap container".into());
    let header = data.get(..24).ok_or_else(error)?;
    let (little, nano) = match header[..4] {
        [0xd4, 0xc3, 0xb2, 0xa1] => (true, false),
        [0xa1, 0xb2, 0xc3, 0xd4] => (false, false),
        [0x4d, 0x3c, 0xb2, 0xa1] => (true, true),
        [0xa1, 0xb2, 0x3c, 0x4d] => (false, true),
        _ => return Err(error()),
    };
    let word = |b: &[u8]| {
        if little {
            u16::from_le_bytes([b[0], b[1]])
        } else {
            u16::from_be_bytes([b[0], b[1]])
        }
    };
    let dword = |b: &[u8]| {
        if little {
            u32::from_le_bytes([b[0], b[1], b[2], b[3]])
        } else {
            u32::from_be_bytes([b[0], b[1], b[2], b[3]])
        }
    };
    if word(&header[4..]) != 2 || word(&header[6..]) != 4 {
        return Err(error());
    }
    let snaplen = dword(&header[16..]);
    if snaplen == 0 {
        return Err(error());
    }
    // Lower 16 bits are LINKTYPE; upper bits may contain pcap FCS metadata.
    let network = dword(&header[20..]);
    let linktype = network & 0xffff;
    let fcs_len = if linktype == 1 && network & (1 << 26) != 0 {
        usize::try_from((network >> 28) * 2).map_err(|_| error())?
    } else {
        0
    };
    if !matches!(fcs_len, 0 | 4) {
        return Err(Error::Capture(
            "Ethernet FCS must be absent or four bytes".into(),
        ));
    }
    let mut remaining = &data[24..];
    let mut records = Vec::new();
    while !remaining.is_empty() {
        let h = remaining.get(..16).ok_or_else(error)?;
        let seconds = dword(h);
        let fraction = dword(&h[4..]);
        if fraction >= if nano { 1_000_000_000 } else { 1_000_000 } {
            return Err(error());
        }
        let incl = dword(&h[8..]);
        let orig = dword(&h[12..]);
        if incl > orig || incl > snaplen {
            return Err(error());
        }
        let len = usize::try_from(incl).map_err(|_| error())?;
        let end = 16_usize.checked_add(len).ok_or_else(error)?;
        let packet = remaining.get(16..end).ok_or_else(error)?;
        records.push(Record {
            timestamp: Timestamp {
                seconds,
                nanoseconds: if nano { fraction } else { fraction * 1000 },
            },
            data: packet,
            truncated: incl < orig,
        });
        remaining = &remaining[end..];
    }
    Ok(Capture {
        linktype,
        fcs_len,
        records,
    })
}
