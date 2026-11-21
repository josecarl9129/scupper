//! Portable main-image identity and conservative native arm64 Mach-O parsing.
use crate::platform::{ImageId, SysError};

const INVALID: SysError = SysError::Failed("native: image layout");
/// Qualified `proc_uniqidentifierinfo` size.
pub const IDENTIFIER_BYTES: usize = 56;
/// SDK fields consumed by the portable decoder.
pub const IDENTIFIER_FIELDS: [(&str, usize); 3] =
    [("p_uuid", 0), ("p_uniqueid", 16), ("p_idversion", 32)];

/// One exec-sensitive identity read; idversion changes on exec.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Identifier {
    /// Main-image UUID and reuse-free process identifier.
    pub image: ImageId,
    /// Exec-sensitive PID version, not an ownership key.
    pub idversion: i32,
}
/// Decode precisely one complete kernel reply.
///
/// # Errors
/// Rejects short/long replies, zero UUIDs and zero unique identifiers.
pub fn identifier(bytes: &[u8]) -> Result<Identifier, SysError> {
    if bytes.len() != IDENTIFIER_BYTES {
        return Err(INVALID);
    }
    let uuid = bytes[..16].try_into().map_err(|_| INVALID)?;
    let uniqueid = u64::from_le_bytes(bytes[16..24].try_into().map_err(|_| INVALID)?);
    let idversion = i32::from_le_bytes(bytes[32..36].try_into().map_err(|_| INVALID)?);
    if uuid == [0; 16] || uniqueid == 0 {
        return Err(INVALID);
    }
    Ok(Identifier {
        image: ImageId { uuid, uniqueid },
        idversion,
    })
}
fn word(bytes: &[u8], at: usize, big: bool) -> Result<u32, SysError> {
    let raw = bytes
        .get(at..at.checked_add(4).ok_or(INVALID)?)
        .ok_or(INVALID)?
        .try_into()
        .map_err(|_| INVALID)?;
    Ok(if big {
        u32::from_be_bytes(raw)
    } else {
        u32::from_le_bytes(raw)
    })
}
fn wide(bytes: &[u8], at: usize) -> Result<usize, SysError> {
    let raw = bytes
        .get(at..at.checked_add(8).ok_or(INVALID)?)
        .ok_or(INVALID)?
        .try_into()
        .map_err(|_| INVALID)?;
    usize::try_from(u64::from_be_bytes(raw)).map_err(|_| INVALID)
}
fn thin(bytes: &[u8]) -> Result<[u8; 16], SysError> {
    if word(bytes, 0, false)? != 0xfeed_facf
        || word(bytes, 4, false)? != 0x0100_000c
        || !matches!(word(bytes, 8, false)? & 0x00ff_ffff, 0 | 2)
        || word(bytes, 12, false)? != 2
    {
        return Err(INVALID);
    }
    let count = usize::try_from(word(bytes, 16, false)?).map_err(|_| INVALID)?;
    let size = usize::try_from(word(bytes, 20, false)?).map_err(|_| INVALID)?;
    let end = 32_usize
        .checked_add(size)
        .filter(|end| *end <= bytes.len())
        .ok_or(INVALID)?;
    let mut at = 32_usize;
    let mut uuid = None;
    if count > size / 8 {
        return Err(INVALID);
    }
    for _ in 0..count {
        let command = word(bytes, at, false)?;
        let length = usize::try_from(word(bytes, at + 4, false)?).map_err(|_| INVALID)?;
        let next = at
            .checked_add(length)
            .filter(|n| *n <= end && length >= 8 && length % 8 == 0)
            .ok_or(INVALID)?;
        if command == 0x1b {
            if length != 24 || uuid.is_some() {
                return Err(INVALID);
            }
            uuid = Some(bytes[at + 8..next].try_into().map_err(|_| INVALID)?);
        }
        at = next;
    }
    if at != end {
        return Err(INVALID);
    }
    uuid.filter(|u| *u != [0; 16]).ok_or(INVALID)
}
/// Read the UUID a native arm64 helper can execute. Thin arm64/arm64e are
/// supported. Fat files are accepted only when all native arm64 slices agree;
/// subtype preference cannot then change the result. Translated children are refused.
///
/// # Errors
/// Rejects malformed, overlapping, ambiguous, unsupported or UUID-less images.
pub fn macho_uuid(bytes: &[u8]) -> Result<[u8; 16], SysError> {
    read_macho_uuid(bytes.len() as u64, |offset, length| {
        let offset = usize::try_from(offset).map_err(|_| INVALID)?;
        bytes
            .get(offset..offset.checked_add(length).ok_or(INVALID)?)
            .map(<[u8]>::to_vec)
            .ok_or(INVALID)
    })
}

/// Bounded random-access parser: headers/table, then at most 1 MiB of load
/// commands per native slice. The reader checks its deadline before each read.
/// All native arm64 slices must agree; no subtype preference is inferred.
///
/// # Errors
/// Rejects malformed, overlapping, ambiguous or oversized images and read errors.
#[allow(clippy::too_many_lines)] // Fat range validation and thin load commands share one bounded reader.
pub fn read_macho_uuid(
    file_size: u64,
    mut read: impl FnMut(u64, usize) -> Result<Vec<u8>, SysError>,
) -> Result<[u8; 16], SysError> {
    fn read_thin(
        read: &mut impl FnMut(u64, usize) -> Result<Vec<u8>, SysError>,
        offset: u64,
        size: u64,
        expected: Option<(u32, u32)>,
    ) -> Result<[u8; 16], SysError> {
        if size < 32 {
            return Err(INVALID);
        }
        let mut header = read(offset, 32)?;
        if let Some((cpu, subtype)) = expected
            && (word(&header, 4, false)? != cpu || word(&header, 8, false)? != subtype)
        {
            return Err(INVALID);
        }
        let commands = usize::try_from(word(&header, 20, false)?).map_err(|_| INVALID)?;
        if commands > 1024 * 1024 || 32 + commands as u64 > size {
            return Err(INVALID);
        }
        header.extend(read(offset.checked_add(32).ok_or(INVALID)?, commands)?);
        thin(&header)
    }
    if file_size < 8 {
        return Err(INVALID);
    }
    let header = read(0, 8)?;
    let magic = word(&header, 0, true)?;
    if !matches!(magic, 0xcafe_babe | 0xcafe_babf) {
        return read_thin(&mut read, 0, file_size, None);
    }
    let count = usize::try_from(word(&header, 4, true)?).map_err(|_| INVALID)?;
    let stride = if magic == 0xcafe_babf { 32 } else { 20 };
    if count == 0 || count > 64 {
        return Err(INVALID);
    }
    let table_end = 8 + count * stride;
    if table_end as u64 > file_size {
        return Err(INVALID);
    }
    let table = read(8, count * stride)?;
    let mut ranges = Vec::new();
    let mut slices = Vec::new();
    for i in 0..count {
        let at = i * stride;
        let cpu = word(&table, at, true)?;
        let subtype = word(&table, at + 4, true)?;
        let (offset, size) = if stride == 32 {
            (wide(&table, at + 8)? as u64, wide(&table, at + 16)? as u64)
        } else {
            (
                u64::from(word(&table, at + 8, true)?),
                u64::from(word(&table, at + 12, true)?),
            )
        };
        let end = offset
            .checked_add(size)
            .filter(|end| *end <= file_size && offset >= table_end as u64 && size > 0)
            .ok_or(INVALID)?;
        let align = word(&table, at + if stride == 32 { 24 } else { 16 }, true)?;
        if align > 31
            || offset % (1_u64 << align) != 0
            || ranges.iter().any(|&(a, b)| offset < b && a < end)
        {
            return Err(INVALID);
        }
        ranges.push((offset, end));
        if cpu == 0x0100_000c {
            slices.push((offset, size, cpu, subtype));
        }
    }
    let mut uuid = None;
    for (offset, size, cpu, subtype) in slices {
        let value = read_thin(&mut read, offset, size, Some((cpu, subtype)))?;
        if uuid.is_some_and(|previous| previous != value) {
            return Err(INVALID);
        }
        uuid = Some(value);
    }
    uuid.ok_or(INVALID)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    #[test]
    fn identifier_size_uuid_and_exec_version() -> Result<(), SysError> {
        let mut bytes = [0; IDENTIFIER_BYTES];
        assert!(identifier(&bytes).is_err());
        bytes[..16].fill(1);
        assert!(identifier(&bytes).is_err());
        bytes[16..24].copy_from_slice(&42_u64.to_le_bytes());
        bytes[32..36].copy_from_slice(&7_i32.to_le_bytes());
        let id = identifier(&bytes)?;
        assert_eq!(id.image.uniqueid, 42);
        assert_eq!(id.idversion, 7);
        assert!(identifier(&bytes[..55]).is_err());
        assert!(identifier(&[1; 57]).is_err());
        Ok(())
    }
    #[test]
    fn real_thin_header_and_malformed_commands() -> Result<(), SysError> {
        let bytes = include_bytes!("../../tests/fixtures/macos/layout/thin-arm64-header.bin");
        let uuid = macho_uuid(bytes)?;
        assert_ne!(uuid, [0; 16]);
        for end in 0..bytes.len() {
            assert!(macho_uuid(&bytes[..end]).is_err());
        }
        let mut broken = bytes.to_vec();
        broken[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(macho_uuid(&broken).is_err());
        Ok(())
    }
    fn minimal(uuid: [u8; 16], subtype: u32) -> Vec<u8> {
        let mut b = vec![0; 56];
        for (at, value) in [
            (0, 0xfeed_facf_u32),
            (4, 0x0100_000c),
            (8, subtype),
            (12, 2),
            (16, 1),
            (20, 24),
            (32, 0x1b),
            (36, 24),
        ] {
            b[at..at + 4].copy_from_slice(&value.to_le_bytes());
        }
        b[40..56].copy_from_slice(&uuid);
        b
    }
    #[test]
    fn fat_agreement_subtypes_and_command_bounds() -> Result<(), SysError> {
        let mut b = vec![0; 48];
        b[..4].copy_from_slice(&0xcafe_babe_u32.to_be_bytes());
        b[4..8].copy_from_slice(&2_u32.to_be_bytes());
        for (index, subtype) in [0_u32, 2].into_iter().enumerate() {
            let at = 8 + index * 20;
            for (delta, value) in [
                (0, 0x0100_000c_u32),
                (4, subtype),
                (8, 48 + u32::try_from(index).map_err(|_| INVALID)? * 56),
                (12, 56),
            ] {
                b[at + delta..at + delta + 4].copy_from_slice(&value.to_be_bytes());
            }
            b.extend(minimal([3; 16], subtype));
        }
        assert_eq!(macho_uuid(&b)?, [3; 16]);
        b[144..160].fill(4);
        assert!(macho_uuid(&b).is_err());
        for subtype in [0, 2] {
            assert_eq!(macho_uuid(&minimal([4; 16], subtype))?, [4; 16]);
        }
        assert!(macho_uuid(&minimal([0; 16], 0)).is_err());
        assert!(macho_uuid(&minimal([1; 16], 1)).is_err());
        let mut duplicate = minimal([1; 16], 0);
        duplicate.extend_from_within(32..);
        duplicate[16..20].copy_from_slice(&2_u32.to_le_bytes());
        duplicate[20..24].copy_from_slice(&48_u32.to_le_bytes());
        assert!(macho_uuid(&duplicate).is_err());
        Ok(())
    }
    #[test]
    fn bounded_reader_limits_commands_and_propagates_deadline() -> Result<(), SysError> {
        let mut header = minimal([7; 16], 0);
        let mut reads = Vec::new();
        let uuid = read_macho_uuid(1024 * 1024 * 1024, |offset, length| {
            reads.push((offset, length));
            let offset = usize::try_from(offset).map_err(|_| INVALID)?;
            header
                .get(offset..offset + length)
                .map(<[u8]>::to_vec)
                .ok_or(INVALID)
        })?;
        assert_eq!(uuid, [7; 16]);
        assert_eq!(reads, [(0, 8), (0, 32), (32, 24)]);
        header[20..24].copy_from_slice(&(1024 * 1024 + 1_u32).to_le_bytes());
        let mut reads = Vec::new();
        assert!(
            read_macho_uuid(u64::MAX, |offset, length| {
                reads.push(length);
                let offset = usize::try_from(offset).map_err(|_| INVALID)?;
                Ok(header[offset..offset + length].to_vec())
            })
            .is_err()
        );
        assert_eq!(reads, [8, 32]);
        let mut count = 0;
        assert_eq!(
            read_macho_uuid(56, |_, _| {
                count += 1;
                if count == 1 {
                    Ok(minimal([7; 16], 0)[..8].to_vec())
                } else {
                    Err(SysError::TimedOut)
                }
            }),
            Err(SysError::TimedOut)
        );
        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_images_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..8192)) {
            let _ = macho_uuid(&bytes);
            let _ = identifier(&bytes);
        }
        #[test]
        fn structured_macho_commands_never_panic(
            uuid in any::<[u8;16]>(), subtype in any::<u32>(),
            count in any::<u32>(), command_size in any::<u32>(), total_size in any::<u32>()) {
            let mut bytes = minimal(uuid, subtype);
            bytes[16..20].copy_from_slice(&count.to_le_bytes());
            bytes[20..24].copy_from_slice(&total_size.to_le_bytes());
            bytes[36..40].copy_from_slice(&command_size.to_le_bytes());
            let _ = macho_uuid(&bytes);
        }
        #[test]
        fn structured_fat_ranges_never_panic(offset in any::<u32>(), size in any::<u32>(), align in any::<u32>()) {
            let mut bytes = vec![0;32];
            for (at,value) in [(0,0xcafe_babe_u32),(4,1),(8,0x0100_000c),(12,0),(16,offset),(20,size),(24,align)] {
                bytes[at..at+4].copy_from_slice(&value.to_be_bytes());
            }
            bytes.extend(minimal([1;16],0));
            let _ = macho_uuid(&bytes);
        }
        #[test]
        fn integral_identifiers_never_panic(bytes in prop::collection::vec(any::<u8>(), 56)) {
            if let Ok(id) = identifier(&bytes) { prop_assert_ne!(id.image.uuid, [0;16]); prop_assert_ne!(id.image.uniqueid, 0); }
        }
    }
}
