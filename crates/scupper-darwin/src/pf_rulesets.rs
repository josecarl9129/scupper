//! Qualification-only `pfioc_ruleset` layout pin against XNU-published constants.
//! Apple XNU `bsd/net/pfvar.h`: `nr`, `path[MAXPATHLEN]`, `name[PF_ANCHOR_NAME_SIZE]`.
//! <https://github.com/apple-oss-distributions/xnu/blob/main/bsd/net/pfvar.h>
#[repr(C)]
pub(crate) struct Request {
    pub nr: u32,
    pub path: [u8; 1024],
    pub name: [u8; 64],
}
pub(crate) const SIZE: usize = std::mem::size_of::<Request>();
pub(crate) const FIELDS: [usize; 3] = [
    std::mem::offset_of!(Request, nr),
    std::mem::offset_of!(Request, path),
    std::mem::offset_of!(Request, name),
];
pub(crate) const GET_RULESETS: u32 = 0xC444_443A;
pub(crate) const GET_RULESET: u32 = 0xC444_443B;
impl Request {
    pub fn new(path: &str) -> Option<Self> {
        if path.len() >= 1024 || path.as_bytes().contains(&0) {
            return None;
        }
        let mut request = Self {
            nr: 0,
            path: [0; 1024],
            name: [0; 64],
        };
        request.path[..path.len()].copy_from_slice(path.as_bytes());
        Some(request)
    }
}
// Darwin EINVAL: pass-2 missing-parent cross-check is pfctl's rc-0
// "Anchor '<path>' not found." row. ENOENT is never absence authority.
const EINVAL: i32 = 22;
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum CensusError {
    Io(i32),
    Invalid,
    Overflow,
    Changed,
}
pub(crate) fn enumerate(
    path: &str,
    mut ioctl: impl FnMut(u32, &mut Request) -> Result<(), i32>,
) -> Result<Option<Vec<String>>, CensusError> {
    let mut request = Request::new(path).ok_or(CensusError::Invalid)?;
    match ioctl(GET_RULESETS, &mut request) {
        Ok(()) => (),
        Err(EINVAL) => return Ok(None),
        Err(error) => return Err(CensusError::Io(error)),
    }
    let count = request.nr;
    if count > 64 {
        return Err(CensusError::Overflow);
    }
    let mut names = std::collections::BTreeSet::new();
    for nr in 0..count {
        let mut row = Request::new(path).ok_or(CensusError::Invalid)?;
        row.nr = nr;
        ioctl(GET_RULESET, &mut row).map_err(CensusError::Io)?;
        let end = row
            .name
            .iter()
            .position(|b| *b == 0)
            .ok_or(CensusError::Invalid)?;
        let name = std::str::from_utf8(&row.name[..end]).map_err(|_| CensusError::Invalid)?;
        if name.is_empty()
            || matches!(name, "." | "..")
            || !name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_-.".contains(&b))
            || !names.insert(name.to_owned())
        {
            return Err(CensusError::Invalid);
        }
    }
    let mut after = Request::new(path).ok_or(CensusError::Invalid)?;
    ioctl(GET_RULESETS, &mut after).map_err(CensusError::Io)?;
    if after.nr != count {
        return Err(CensusError::Changed);
    }
    Ok(Some(names.into_iter().collect()))
}
const _: () = {
    assert!(SIZE == 1092);
    assert!(FIELDS[0] == 0 && FIELDS[1] == 4 && FIELDS[2] == 1028);
};
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn missing_anchor_errno_only_on_initial_count() {
        assert_eq!(enumerate("fresh", |_, _| Err(22)), Ok(None));
        for errno in [2, 16, 5] {
            assert_eq!(
                enumerate("fresh", |_, _| Err(errno)),
                Err(CensusError::Io(errno))
            );
        }
        for fail_at in [1, 2] {
            let mut call = 0;
            let result = enumerate("fresh", |command, request| {
                call += 1;
                if call == fail_at + 1 {
                    return Err(22);
                }
                if command == GET_RULESETS {
                    request.nr = 1;
                } else {
                    request.name[..2].copy_from_slice(b"x\0");
                }
                Ok(())
            });
            assert_eq!(result, Err(CensusError::Io(22)));
        }
        let mut calls = 0;
        assert_eq!(
            enumerate("bad\0path", |_, _| {
                calls += 1;
                Ok(())
            }),
            Err(CensusError::Invalid)
        );
        assert_eq!(calls, 0);
    }
    #[test]
    fn xnu_published_layout_pin_and_darwin_ioctl_encoding() {
        assert_eq!(SIZE, 1092);
        assert_eq!(std::mem::align_of::<Request>(), 4);
        assert_eq!(FIELDS, [0, 4, 1028]);
        assert_eq!(
            GET_RULESETS,
            0xc000_0000 | (1092 << 16) | (u32::from(b'D') << 8) | 0x3a
        );
        assert_eq!(GET_RULESET, GET_RULESETS + 1);
        assert!(Request::new(&"a".repeat(1024)).is_none());
        assert!(Request::new("a\0b").is_none());
        let request = Request::new("scupper-qual/children").unwrap();
        assert_eq!(&request.path[..22], b"scupper-qual/children\0");
        assert_eq!(request.nr, 0);
        assert_eq!(request.name, [0; 64]);
    }
}
