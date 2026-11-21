//! Portable decoding of the qualified 64-bit Darwin process record.
use crate::{
    platform::{ProcInfo, ProcState, ProcessError, SysError},
    snapshot::StartTime,
};

/// SDK name limit, excluding NUL.
pub const MAXCOMLEN: usize = 16;
/// Qualified LP64 `kinfo_proc` stride; Q-SMOKE compares it with the SDK.
pub const RECORD_BYTES: usize = 648;
/// Consumed process-record offsets, compared with the SDK before qualification.
pub const FIELDS: [(&str, usize); 7] = [
    ("kp_proc.p_starttime.tv_sec", START_SEC),
    ("kp_proc.p_starttime.tv_usec", START_USEC),
    ("kp_proc.p_stat", STAT),
    ("kp_proc.p_pid", PID),
    ("kp_proc.p_comm", COMM),
    ("kp_eproc.e_ppid", PPID),
    ("kp_eproc.e_pgid", PGID),
];
/// Start seconds offset.
pub const START_SEC: usize = 0;
/// Start microseconds offset.
pub const START_USEC: usize = 8;
/// State offset.
pub const STAT: usize = 36;
/// PID offset.
pub const PID: usize = 40;
/// Command name offset.
pub const COMM: usize = 243;
/// Parent PID offset.
pub const PPID: usize = 560;
/// Process group offset.
pub const PGID: usize = 564;
const INVALID: SysError = SysError::Failed("native: process layout");

/// Decode the S* state byte; unknown states cannot establish completeness.
///
/// # Errors
/// Returns a layout error for an unrecognised kernel state.
pub fn state(stat: u8) -> Result<ProcState, SysError> {
    match stat {
        1 | 2 => Ok(ProcState::Running),
        3 => Ok(ProcState::Sleeping),
        4 => Ok(ProcState::Stopped),
        5 => Ok(ProcState::Zombie),
        _ => Err(INVALID),
    }
}

/// Decode a NUL-terminated `p_comm`, validating the SDK limit and UTF-8.
/// Unrepresentable names are unknown, never guessed with replacement characters.
#[must_use]
pub fn name(comm: &[u8]) -> Option<String> {
    if comm.len() != MAXCOMLEN + 1 {
        return None;
    }
    let end = comm.iter().position(|b| *b == 0)?;
    if end == 0 {
        return None;
    }
    std::str::from_utf8(&comm[..end]).ok().map(str::to_owned)
}

/// Validate a kernel wall-clock start identity without losing microseconds.
///
/// # Errors
/// Rejects negative seconds or fractional parts outside `0..1_000_000`.
pub fn start(sec: i64, usec: i32) -> Result<StartTime, SysError> {
    let seconds = u64::try_from(sec).map_err(|_| INVALID)?;
    let microseconds = u32::try_from(usec).map_err(|_| INVALID)?;
    if microseconds >= 1_000_000 {
        return Err(INVALID);
    }
    Ok(StartTime {
        seconds,
        microseconds,
    })
}

/// Decode an integral LP64 little-endian sysctl fixture. Paths and executable
/// identities are deliberately absent; this does not establish a live inventory.
///
/// # Errors
/// Rejects nonintegral lengths, invalid identifiers, states or start times.
pub fn records(bytes: &[u8]) -> Result<Vec<ProcInfo>, SysError> {
    if !bytes.len().is_multiple_of(RECORD_BYTES) {
        return Err(INVALID);
    }
    bytes
        .as_chunks::<RECORD_BYTES>()
        .0
        .iter()
        .filter(|b| b[PID..PID + 4] != [0; 4])
        .map(|b| {
            let i32_at = |offset| -> Result<i32, SysError> {
                Ok(i32::from_le_bytes(
                    b.get(offset..offset + 4)
                        .ok_or(INVALID)?
                        .try_into()
                        .map_err(|_| INVALID)?,
                ))
            };
            let id = |offset| -> Result<u32, SysError> {
                u32::try_from(i32_at(offset)?).map_err(|_| INVALID)
            };
            let pid = id(PID)?;
            let sec = i64::from_le_bytes(
                b[START_SEC..START_SEC + 8]
                    .try_into()
                    .map_err(|_| INVALID)?,
            );
            Ok(ProcInfo {
                pid,
                ppid: id(PPID)?,
                pgid: id(PGID)?,
                state: state(b[STAT])?,
                start: start(sec, i32_at(START_USEC)?)?,
                name: name(&b[COMM..=COMM + MAXCOMLEN]),
                path: None,
                exe: None,
            })
        })
        .collect()
}

/// A complete inventory must retain the helper identity read before the table.
#[cfg(any(target_os = "macos", test))]
pub(crate) fn require_self(
    list: &[ProcInfo],
    pid: u32,
    start: StartTime,
) -> Result<(), ProcessError> {
    if list.iter().any(|p| p.pid == pid && p.start == start) {
        Ok(())
    } else {
        Err(SysError::Failed("native: process table implausible").into())
    }
}

/// Resolve one path lookup against a subsequent complete PID lookup. The first
/// record brackets the lookup with the same `(pid, start)`; neither a failed
/// path read nor a recycled PID can establish absence of the listed process.
///
/// # Errors
/// A confirmed live pathless process retains its PID in the incomplete result.
/// A mismatched PID in the re-lookup is an invalid record, never evidence of exit.
pub fn resolve_path(
    mut listed: ProcInfo,
    path: Option<std::path::PathBuf>,
    current: Option<ProcInfo>,
) -> Result<Option<ProcInfo>, ProcessError> {
    if listed.state == ProcState::Zombie {
        return Ok(Some(listed));
    }
    let Some(current) = current else {
        return Ok(None);
    };
    if current.pid != listed.pid {
        return Err(ProcessError {
            pid: None,
            error: INVALID,
        });
    }
    if current.start != listed.start {
        return Ok(None);
    }
    if current.state == ProcState::Zombie {
        return Ok(Some(current));
    }
    listed.path = Some(path.ok_or(ProcessError {
        pid: Some(listed.pid),
        error: SysError::Failed("native: live pathless process"),
    })?);
    Ok(Some(listed))
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn states_names_and_fractional_starts() -> Result<(), SysError> {
        for (raw, expected) in [
            (1, ProcState::Running),
            (2, ProcState::Running),
            (3, ProcState::Sleeping),
            (4, ProcState::Stopped),
            (5, ProcState::Zombie),
        ] {
            assert_eq!(state(raw)?, expected);
        }
        assert!(state(0).is_err());
        assert!(state(6).is_err());
        assert_eq!(name(b"wireguard-go\0\0\0\0\0"), Some("wireguard-go".into()));
        assert_eq!(name(&[b'a'; 17]), None);
        assert_eq!(name(b"abcdefghijklmnop\0"), Some("abcdefghijklmnop".into()));
        assert_eq!(name(&[0; 17]), None);
        assert!(start(-1, 0).is_err());
        assert!(start(1, -1).is_err());
        assert!(start(1, 1_000_000).is_err());
        assert_eq!(start(123, 999_999)?.microseconds, 999_999);
        Ok(())
    }

    #[test]
    fn redacted_fixture_decodes_on_linux() -> Result<(), SysError> {
        let bytes = include_bytes!("../../tests/fixtures/macos/layout/kinfo_proc.bin");
        let list = records(bytes)?;
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].pid, 123);
        assert_eq!(list[0].ppid, 1);
        assert_eq!(list[0].pgid, 123);
        assert_eq!(list[0].state, ProcState::Stopped);
        assert_eq!(list[0].name.as_deref(), Some("wireguard-go"));
        assert_eq!(
            list[0].start,
            StartTime {
                seconds: 456,
                microseconds: 789
            }
        );
        assert!(records(&bytes[..647]).is_err());
        Ok(())
    }

    #[test]
    fn replay_all_available_fixtures_including_synthetic_layout()
    -> Result<(), Box<dyn std::error::Error>> {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/macos");
        let mut count = 0;
        for entry in std::fs::read_dir(root)? {
            let path = entry?.path().join("kinfo_proc.bin");
            if path.is_file() {
                let bytes = std::fs::read(path)?;
                let decoded = records(&bytes)?;
                assert_ne!(decoded, Vec::<ProcInfo>::new());
                assert!(
                    decoded
                        .iter()
                        .all(|p| p.pid > 0 && p.exe.is_none() && p.path.is_none())
                );
                count += 1;
            }
        }
        assert!(count > 0);
        Ok(())
    }

    #[test]
    fn failed_paths_require_a_pid_recheck_and_reuse_never_attaches_a_path()
    -> Result<(), ProcessError> {
        let listed = records(include_bytes!(
            "../../tests/fixtures/macos/layout/kinfo_proc.bin"
        ))?
        .remove(0);
        let pid = listed.pid;
        let error = resolve_path(listed.clone(), None, Some(listed.clone()));
        assert_eq!(
            error,
            Err(ProcessError {
                pid: Some(pid),
                error: SysError::Failed("native: live pathless process")
            })
        );
        assert_eq!(resolve_path(listed.clone(), None, None)?, None);
        let mut recycled = listed.clone();
        recycled.start.microseconds += 1;
        assert_eq!(
            resolve_path(listed.clone(), Some("/bin/sleep".into()), Some(recycled))?,
            None
        );
        let mut zombie = listed.clone();
        zombie.state = ProcState::Zombie;
        assert_eq!(
            resolve_path(listed.clone(), None, Some(zombie.clone()))?,
            Some(zombie.clone())
        );
        assert_eq!(resolve_path(zombie.clone(), None, None)?, Some(zombie));
        let valid = resolve_path(
            listed.clone(),
            Some("/bin/sleep".into()),
            Some(listed.clone()),
        )?
        .ok_or(SysError::Failed("missing entry"))?;
        assert_eq!(valid.path, Some("/bin/sleep".into()));
        assert_eq!(valid.exe, None);
        let mut wrong = listed.clone();
        wrong.pid += 1;
        assert_eq!(
            resolve_path(listed, None, Some(wrong)),
            Err(ProcessError::from(INVALID))
        );
        Ok(())
    }
    #[test]
    fn complete_inventory_requires_self_with_the_same_start() -> Result<(), SysError> {
        let list = records(include_bytes!(
            "../../tests/fixtures/macos/layout/kinfo_proc.bin"
        ))?;
        let own = &list[0];
        assert!(require_self(&list, own.pid, own.start).is_ok());
        for missing in [&[][..], &list[..]] {
            let error = require_self(missing, own.pid + 1, own.start);
            assert_eq!(
                error,
                Err(ProcessError::from(SysError::Failed(
                    "native: process table implausible"
                )))
            );
        }
        let mut reused = own.start;
        reused.microseconds += 1;
        assert!(require_self(&list, own.pid, reused).is_err());
        Ok(())
    }

    proptest! {
        #[test]
        fn arbitrary_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..4096), sec in any::<i64>(), usec in any::<i32>(), stat in any::<u8>()) {
            let _ = records(&bytes);
            let _ = name(&bytes);
            let _ = state(stat);
            if let Ok(value) = start(sec, usec) { prop_assert!(value.microseconds < 1_000_000); }
        }
        #[test]
        fn arbitrary_integral_records_never_panic(bytes in prop::collection::vec(any::<u8>(), RECORD_BYTES)) {
            let _ = records(&bytes);
        }
    }
}
