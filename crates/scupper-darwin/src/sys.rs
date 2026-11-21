use std::ffi::{CStr, CString, c_int};

use rustix::io::Errno;

const MAX_STRING_BYTES: usize = 1024 * 1024;

/// Read a NUL-terminated UTF-8 sysctl value into owned storage.
///
/// # Errors
/// Returns the syscall errno, `INVAL` for a malformed string/name or returned
/// length, and `NOMEM` for an excessive size or repeated size races. No partial
/// result is returned. The caller owns the buffer for the entire synchronous call.
pub fn sysctl_string(name: &str) -> Result<String, Errno> {
    let name = CString::new(name).map_err(|_| Errno::INVAL)?;
    for _ in 0..8 {
        let mut needed = 0;
        // SAFETY: name is a live NUL-terminated CString. oldp is null for a size
        // probe; needed is an aligned, initialised size_t, live until return.
        // newp is null and newlen is zero: this never writes a sysctl value.
        // The returned size is checked before allocating or exposing any bytes.
        let result = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                std::ptr::null_mut(),
                &raw mut needed,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 {
            return Err(last_errno());
        }
        if needed == 0 {
            return Err(Errno::INVAL);
        }
        if needed > MAX_STRING_BYTES {
            return Err(Errno::NOMEM);
        }
        // Every byte is initialised before the kernel can see the buffer.
        let mut bytes = vec![0_u8; needed];
        let mut returned = bytes.len();
        // SAFETY: name and bytes remain owned and live through this synchronous
        // call; u8 needs only byte alignment. returned is an aligned initialised
        // size_t and initially bounds writes to bytes.len(). All buffer bytes
        // are initialised. No timeout can free either allocation. On success we
        // check returned <= bytes.len() and the complete NUL-terminated string
        // before exposing it; on error no buffer contents are used.
        let result = unsafe {
            libc::sysctlbyname(
                name.as_ptr(),
                bytes.as_mut_ptr().cast(),
                &raw mut returned,
                std::ptr::null_mut(),
                0,
            )
        };
        if result != 0 {
            let error = last_errno();
            if error == Errno::NOMEM {
                continue;
            }
            return Err(error);
        }
        if returned == 0 || returned > bytes.len() {
            return Err(Errno::INVAL);
        }
        bytes.truncate(returned);
        let value = CStr::from_bytes_with_nul(&bytes).map_err(|_| Errno::INVAL)?;
        return value.to_str().map(str::to_owned).map_err(|_| Errno::INVAL);
    }
    Err(Errno::NOMEM)
}

fn last_errno() -> Errno {
    std::io::Error::last_os_error()
        .raw_os_error()
        .map_or(Errno::IO, Errno::from_raw_os_error)
}

/// SDK process-name limit, excluding the terminating NUL.
pub const MAXCOMLEN: usize = 16;
/// Size of the supported 64-bit SDK process record.
pub const KINFO_PROC_SIZE: usize = 648;

// Only integer/byte fields: every bit pattern is valid, including kernel-written
// opaque padding. Explicit padding prevents accidental exposure of kernel pointers.
#[repr(C)]
#[derive(Clone)]
struct KinfoProc {
    start_sec: i64,
    start_usec: i32,
    pad_start: [u8; 24],
    stat: u8,
    pad_stat: [u8; 3],
    pid: i32,
    pad_pid: [u8; 199],
    comm: [u8; MAXCOMLEN + 1],
    pad_comm: [u8; 36],
    eproc: [u8; 264],
    ppid: i32,
    pgid: i32,
    tail: [u8; 80],
}

/// Actual Rust offsets compared with the SDK probe by Q-SMOKE.
pub const KINFO_PROC_FIELDS: [(&str, usize); 10] = [
    ("kp_proc", 0),
    ("kp_eproc", std::mem::offset_of!(KinfoProc, eproc)),
    ("kp_proc.p_pid", std::mem::offset_of!(KinfoProc, pid)),
    ("kp_proc.p_stat", std::mem::offset_of!(KinfoProc, stat)),
    (
        "kp_proc.p_starttime",
        std::mem::offset_of!(KinfoProc, start_sec),
    ),
    (
        "kp_proc.p_starttime.tv_sec",
        std::mem::offset_of!(KinfoProc, start_sec),
    ),
    (
        "kp_proc.p_starttime.tv_usec",
        std::mem::offset_of!(KinfoProc, start_usec),
    ),
    ("kp_proc.p_comm", std::mem::offset_of!(KinfoProc, comm)),
    ("kp_eproc.e_ppid", std::mem::offset_of!(KinfoProc, ppid)),
    ("kp_eproc.e_pgid", std::mem::offset_of!(KinfoProc, pgid)),
];
const _: () = {
    assert!(std::mem::size_of::<KinfoProc>() == KINFO_PROC_SIZE);
    let expected = [0, 296, 40, 36, 0, 0, 8, 243, 560, 564];
    let mut i = 0;
    while i < expected.len() {
        assert!(KINFO_PROC_FIELDS[i].1 == expected[i]);
        i += 1;
    }
};

impl KinfoProc {
    fn zeroed() -> Self {
        Self {
            start_sec: 0,
            start_usec: 0,
            pad_start: [0; 24],
            stat: 0,
            pad_stat: [0; 3],
            pid: 0,
            pad_pid: [0; 199],
            comm: [0; 17],
            pad_comm: [0; 36],
            eproc: [0; 264],
            ppid: 0,
            pgid: 0,
            tail: [0; 80],
        }
    }
    fn owned(&self) -> KProc {
        KProc {
            pid: self.pid,
            ppid: self.ppid,
            pgid: self.pgid,
            stat: self.stat,
            start: (self.start_sec, self.start_usec),
            comm: self.comm,
        }
    }
}

/// Owned process fields; never includes SDK padding or pointers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KProc {
    /// Process id.
    pub pid: i32,
    /// Parent id.
    pub ppid: i32,
    /// Process group id.
    pub pgid: i32,
    /// Kernel S* status byte.
    pub stat: u8,
    /// Wall-clock start seconds and microseconds.
    pub start: (i64, i32),
    /// Kernel name including space for NUL.
    pub comm: [u8; MAXCOMLEN + 1],
}

/// Process enumeration errors distinguish exhausted churn from syscall errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProcError {
    /// Syscall failure; partial bytes have been discarded.
    Os(Errno),
    /// Successful syscall returned an invalid length or record.
    Layout,
    /// Eight size-race attempts were exhausted, or the bounded allocation overflowed.
    Incomplete,
}
impl std::fmt::Display for ProcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "process read: {self:?}")
    }
}
impl std::error::Error for ProcError {}

/// Read all processes, retrying ENOMEM at most eight times without decoding failures.
///
/// # Errors
/// Returns `Incomplete` on churn, `Layout` on invalid lengths, otherwise the errno.
pub fn sysctl_kern_proc_all() -> Result<Vec<KProc>, ProcError> {
    read_processes([libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_ALL, 0])
}

/// Read one process; a successful zero-length response confirms absence.
///
/// # Errors
/// Invalid pids/lengths and syscall failures prove no absence.
pub fn sysctl_kern_proc_pid(pid: u32) -> Result<Option<KProc>, ProcError> {
    let pid = i32::try_from(pid).map_err(|_| ProcError::Os(Errno::INVAL))?;
    if pid <= 0 {
        return Err(ProcError::Os(Errno::INVAL));
    }
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    let mut records = read_pid_with(|buffer| process_sysctl(&mut mib, Some(buffer)))?;
    if records.len() > 1 || records.first().is_some_and(|p| p.pid != pid) {
        return Err(ProcError::Layout);
    }
    Ok(records.pop())
}

fn read_pid_with(
    mut query: impl FnMut(&mut [KinfoProc]) -> Result<usize, Errno>,
) -> Result<Vec<KProc>, ProcError> {
    // One record plus a sentinel slot to detect an over-long successful reply.
    for _ in 0..8 {
        let mut records = [KinfoProc::zeroed(), KinfoProc::zeroed()];
        let returned = match query(&mut records) {
            Ok(returned) => returned,
            Err(Errno::NOMEM) => continue,
            Err(error) => return Err(ProcError::Os(error)),
        };
        if returned > KINFO_PROC_SIZE || returned % KINFO_PROC_SIZE != 0 {
            return Err(ProcError::Layout);
        }
        return Ok(records[..returned / KINFO_PROC_SIZE]
            .iter()
            .map(KinfoProc::owned)
            .collect());
    }
    Err(ProcError::Incomplete)
}

fn read_processes(mut mib: [i32; 4]) -> Result<Vec<KProc>, ProcError> {
    read_processes_with(|buffer| process_sysctl(&mut mib, buffer))
}

fn process_sysctl(mib: &mut [i32; 4], buffer: Option<&mut [KinfoProc]>) -> Result<usize, Errno> {
    let (pointer, mut returned) = buffer.map_or((std::ptr::null_mut(), 0), |records| {
        (records.as_mut_ptr().cast(), std::mem::size_of_val(records))
    });
    // SAFETY: mib and the aligned initialised size live through this synchronous
    // call. A null pointer requests size only; otherwise the exclusive slice
    // supplies aligned, fully initialised KinfoProc records (all bit patterns
    // valid), with exactly size_of_val(slice) writable bytes. No timeout can
    // free them while the call runs. No new sysctl value is supplied. Failure
    // discards the returned size and all partial contents. The caller checks
    // successful lengths against the slice byte length and 648-byte stride
    // before accessing any fields; opaque padding is never returned.
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            4,
            pointer,
            &raw mut returned,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc == 0 {
        Ok(returned)
    } else {
        Err(last_errno())
    }
}

fn read_processes_with(
    mut query: impl FnMut(Option<&mut [KinfoProc]>) -> Result<usize, Errno>,
) -> Result<Vec<KProc>, ProcError> {
    const MAX_BYTES: usize = 64 * 1024 * 1024;
    let mut previous = 0;
    for _ in 0..8 {
        let needed = match query(None) {
            Ok(needed) => needed,
            Err(Errno::NOMEM) => continue,
            Err(error) => return Err(ProcError::Os(error)),
        };
        let need = needed.max(previous);
        let count = need
            .checked_add(need / 4)
            .and_then(|n| n.checked_add(64 * KINFO_PROC_SIZE))
            .and_then(|n| n.checked_add(KINFO_PROC_SIZE - 1))
            .ok_or(ProcError::Incomplete)?
            / KINFO_PROC_SIZE;
        let bytes = count
            .checked_mul(KINFO_PROC_SIZE)
            .filter(|n| *n <= MAX_BYTES)
            .ok_or(ProcError::Incomplete)?;
        let mut records = vec![KinfoProc::zeroed(); count];
        let returned = match query(Some(&mut records)) {
            Ok(returned) => returned,
            Err(Errno::NOMEM) => {
                previous = bytes;
                continue;
            }
            Err(error) => return Err(ProcError::Os(error)),
        };
        if returned > bytes || returned % KINFO_PROC_SIZE != 0 {
            return Err(ProcError::Layout);
        }
        return Ok(records[..returned / KINFO_PROC_SIZE]
            .iter()
            .map(KinfoProc::owned)
            .collect());
    }
    Err(ProcError::Incomplete)
}

/// Read the executable path, preserving ENOENT versus ESRCH versus other errnos.
///
/// # Errors
/// Returns the original errno, or INVAL for invalid pid/path length/termination.
pub fn proc_pidpath(pid: u32) -> Result<std::path::PathBuf, Errno> {
    use std::os::unix::ffi::OsStringExt;
    let pid = i32::try_from(pid).map_err(|_| Errno::INVAL)?;
    if pid <= 0 {
        return Err(Errno::INVAL);
    }
    let mut bytes = vec![0_u8; 4096];
    let capacity = u32::try_from(bytes.len()).map_err(|_| Errno::INVAL)?;
    // SAFETY: __error takes no arguments and returns this thread's live errno
    // slot. The pointer stays on this thread and is used immediately below.
    let errno = unsafe { libc::__error() };
    // SAFETY: errno is this thread's aligned, writable, non-null errno slot.
    // Reset it before libproc, which can return an empty path without setting it.
    unsafe { *errno = 0 };
    // SAFETY: the owned, initialised byte buffer lives through the synchronous
    // call and has precisely the advertised capacity. No data is used on
    // failure. Success checks returned length and NUL termination before use.
    let rc = unsafe { libc::proc_pidpath(pid, bytes.as_mut_ptr().cast(), capacity) };
    if rc <= 0 {
        return Err(std::io::Error::last_os_error()
            .raw_os_error()
            .filter(|error| *error != 0)
            .map_or(Errno::INVAL, Errno::from_raw_os_error));
    }
    let len = usize::try_from(rc).map_err(|_| Errno::INVAL)?;
    if len >= bytes.len() || bytes[len] != 0 || bytes[..len].contains(&0) || bytes[0] != b'/' {
        return Err(Errno::INVAL);
    }
    bytes.truncate(len);
    Ok(std::ffi::OsString::from_vec(bytes).into())
}

/// Size and consumed offsets of XNU's API `proc_uniqidentifierinfo` (flavor 17).
pub const IDENTIFIER_SIZE: usize = 56;
/// Identifier field offsets, checked against the C probe and portable decoder.
pub const IDENTIFIER_FIELDS: [(&str, usize); 3] = [
    ("p_uuid", std::mem::offset_of!(UniqueIdentifier, uuid)),
    (
        "p_uniqueid",
        std::mem::offset_of!(UniqueIdentifier, uniqueid),
    ),
    (
        "p_idversion",
        std::mem::offset_of!(UniqueIdentifier, idversion),
    ),
];
#[repr(C)]
struct UniqueIdentifier {
    uuid: [u8; 16],
    uniqueid: u64,
    parent: u64,
    idversion: i32,
    parent_version: i32,
    reserved: [u64; 2],
}
const _: () = {
    assert!(std::mem::size_of::<UniqueIdentifier>() == IDENTIFIER_SIZE);
    assert!(IDENTIFIER_FIELDS[0].1 == 0);
    assert!(IDENTIFIER_FIELDS[1].1 == 16);
    assert!(IDENTIFIER_FIELDS[2].1 == 32);
};
/// Read the main-image UUID, reuse-free uniqueid and exec-sensitive idversion.
/// Decoding remains the caller's portable responsibility.
///
/// # Errors
/// Rejects every short/long reply and invalid pid; preserves syscall errno.
#[allow(clippy::cast_possible_truncation, clippy::cast_possible_wrap)] // SDK-pinned size 56 fits c_int.
pub fn proc_identifier(pid: u32) -> Result<[u8; IDENTIFIER_SIZE], Errno> {
    let pid = i32::try_from(pid).map_err(|_| Errno::INVAL)?;
    if pid <= 0 {
        return Err(Errno::INVAL);
    }
    let mut bytes = [0_u8; IDENTIFIER_SIZE];
    // SAFETY: the exclusive, initialized 56-byte buffer lives through this
    // synchronous call; proc_pidinfo copies bytes and requires no alignment.
    // Flavor 17 is read-only. Only a full-sized success exposes these bytes.
    let returned = unsafe {
        libc::proc_pidinfo(
            pid,
            17,
            0,
            bytes.as_mut_ptr().cast(),
            IDENTIFIER_SIZE as c_int,
        )
    };
    if returned <= 0 {
        return Err(last_errno());
    }
    if returned != IDENTIFIER_SIZE as c_int {
        return Err(Errno::INVAL);
    }
    Ok(bytes)
}

/// Sleep-counting, unadjusted clock id used by `NativePlatform::now`.
pub const NOW_CLOCK_ID: libc::clockid_t = libc::CLOCK_MONOTONIC_RAW;
/// Sleep-excluding raw clock id, reserved for the wake-delta monitor.
pub const UPTIME_CLOCK_ID: libc::clockid_t = libc::CLOCK_UPTIME_RAW;

/// Read the raw sleep-counting clock. An impossible OS failure terminates the
/// helper rather than inventing time in the infallible platform contract.
#[must_use]
pub fn monotonic_raw() -> std::time::Duration {
    clock(NOW_CLOCK_ID)
}
/// Read the raw sleep-excluding clock for wake-delta measurements.
#[must_use]
pub fn uptime_raw() -> std::time::Duration {
    clock(UPTIME_CLOCK_ID)
}
fn clock(id: libc::clockid_t) -> std::time::Duration {
    let mut time = libc::timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // SAFETY: time is an aligned, initialised timespec, exclusively borrowed
    // and live through this synchronous call. Fields are read only on success
    // and checked for nonnegative seconds and fractional nanoseconds.
    let rc = unsafe { libc::clock_gettime(id, &raw mut time) };
    if rc != 0 {
        std::process::abort();
    }
    let (Ok(seconds), Ok(nanos)) = (u64::try_from(time.tv_sec), u32::try_from(time.tv_nsec)) else {
        std::process::abort()
    };
    if nanos >= 1_000_000_000 {
        std::process::abort();
    }
    std::time::Duration::new(seconds, nanos)
}

/// Read effective uid for the text-only qualification census.
///
/// # Errors
/// Returns errno or INVAL on short replies or a mismatched PID.
pub fn proc_uid(pid: u32) -> Result<u32, Errno> {
    let pid = i32::try_from(pid).map_err(|_| Errno::INVAL)?;
    if pid <= 0 {
        return Err(Errno::INVAL);
    }
    let mut bytes = [0_u8; 136];
    // SAFETY: exclusive initialized storage has the full pinned proc_bsdinfo
    // size. The synchronous call writes only bytes; fields are decoded only
    // after checking its exact length and matching PID. Flavor 3 is read-only.
    let returned = unsafe { libc::proc_pidinfo(pid, 3, 0, bytes.as_mut_ptr().cast(), 136) };
    if returned <= 0 {
        return Err(last_errno());
    }
    if returned != 136
        || i32::from_ne_bytes(bytes[12..16].try_into().map_err(|_| Errno::INVAL)?) != pid
    {
        return Err(Errno::INVAL);
    }
    Ok(u32::from_ne_bytes(
        bytes[20..24].try_into().map_err(|_| Errno::INVAL)?,
    ))
}
const _: () = {
    assert!(std::mem::size_of::<libc::proc_bsdinfo>() == 136);
    assert!(std::mem::offset_of!(libc::proc_bsdinfo, pbi_uid) == 20);
    assert!(std::mem::offset_of!(libc::proc_bsdinfo, pbi_pid) == 12);
};

#[cfg(test)]
mod process_tests {
    use super::*;
    #[test]
    fn partial_failures_are_discarded_and_churn_is_bounded() -> Result<(), ProcError> {
        let mut copies = 0;
        let mut previous_count = 0;
        let records = read_processes_with(|buffer| {
            let Some(buffer) = buffer else {
                return Ok(KINFO_PROC_SIZE);
            };
            assert!(buffer.len() >= 66);
            assert!(buffer.len() > previous_count);
            previous_count = buffer.len();
            copies += 1;
            if copies == 1 {
                buffer[0].pid = 999; // Failed partial record must never escape.
                Err(Errno::NOMEM)
            } else {
                assert_eq!(buffer[0].pid, 0);
                buffer[0].pid = 123;
                Ok(KINFO_PROC_SIZE)
            }
        })?;
        assert_eq!(copies, 2);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].pid, 123);
        let mut attempts = 0;
        assert_eq!(
            read_processes_with(|buffer| {
                if let Some(buffer) = buffer {
                    attempts += 1;
                    buffer[0].pid = 999;
                    Err(Errno::NOMEM)
                } else {
                    Ok(KINFO_PROC_SIZE)
                }
            }),
            Err(ProcError::Incomplete)
        );
        assert_eq!(attempts, 8);
        Ok(())
    }

    #[test]
    fn malformed_success_and_other_errors_never_return_records() {
        for excess in [false, true] {
            assert_eq!(
                read_processes_with(|buffer| {
                    buffer.map_or(Ok(KINFO_PROC_SIZE), |buffer| {
                        Ok(if excess {
                            std::mem::size_of_val(buffer) + KINFO_PROC_SIZE
                        } else {
                            KINFO_PROC_SIZE - 1
                        })
                    })
                }),
                Err(ProcError::Layout)
            );
        }
        assert_eq!(
            read_processes_with(|buffer| {
                if let Some(buffer) = buffer {
                    buffer[0].pid = 999;
                    Err(Errno::PERM)
                } else {
                    Ok(KINFO_PROC_SIZE)
                }
            }),
            Err(ProcError::Os(Errno::PERM))
        );
        assert_eq!(
            read_processes_with(|_| Ok(usize::MAX)),
            Err(ProcError::Incomplete)
        );
        assert_eq!(read_processes_with(|_| Ok(0)), Ok(Vec::new()));
    }
    #[test]
    fn pid_reads_use_two_records_and_reject_malformed_success() -> Result<(), ProcError> {
        assert_eq!(
            read_pid_with(|buffer| {
                assert_eq!(buffer.len(), 2);
                Ok(0)
            })?,
            Vec::new()
        );
        let mut attempts = 0;
        let got = read_pid_with(|buffer| {
            assert_eq!(buffer.len(), 2);
            assert_eq!(buffer[0].pid, 0);
            attempts += 1;
            buffer[0].pid = 123;
            if attempts == 1 {
                Err(Errno::NOMEM)
            } else {
                Ok(KINFO_PROC_SIZE)
            }
        })?;
        assert_eq!(attempts, 2);
        assert_eq!(got[0].pid, 123);
        for length in [
            1,
            KINFO_PROC_SIZE - 1,
            2 * KINFO_PROC_SIZE,
            3 * KINFO_PROC_SIZE,
        ] {
            assert_eq!(read_pid_with(|_| Ok(length)), Err(ProcError::Layout));
        }
        assert_eq!(
            read_pid_with(|_| Err(Errno::NOMEM)),
            Err(ProcError::Incomplete)
        );
        assert_eq!(
            read_pid_with(|_| Err(Errno::PERM)),
            Err(ProcError::Os(Errno::PERM))
        );
        Ok(())
    }
    #[test]
    fn raw_clock_ids_are_pinned() {
        assert_eq!(NOW_CLOCK_ID, 4);
        assert_eq!(UPTIME_CLOCK_ID, 8);
        let before = monotonic_raw();
        let _ = uptime_raw();
        assert!(monotonic_raw() >= before);
    }
    #[test]
    fn own_process_and_length_validation() -> Result<(), Box<dyn std::error::Error>> {
        let pid = std::process::id();
        let own = sysctl_kern_proc_pid(pid)?.ok_or("self absent")?;
        assert_eq!(u32::try_from(own.pid)?, pid);
        assert!(
            sysctl_kern_proc_all()?
                .iter()
                .any(|p| p.pid == own.pid && p.start == own.start)
        );
        assert!(proc_pidpath(pid)?.is_absolute());
        assert!(sysctl_kern_proc_pid(u32::MAX).is_err());
        assert!(proc_pidpath(u32::MAX).is_err());
        Ok(())
    }
}
