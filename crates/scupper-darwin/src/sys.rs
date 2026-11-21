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
    pad_start: [u8; 20],
    flags: i32,
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
            pad_start: [0; 20],
            flags: 0,
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
            translated: crate::rules::translated(self.flags),
            start: (self.start_sec, self.start_usec),
            comm: self.comm,
        }
    }
}

/// Owned process fields; never includes SDK padding or pointers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KProc {
    /// Kernel `P_TRANSLATED` flag (owned children must be native).
    pub translated: bool,
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
const IDENTIFIER_SIZE_C: c_int = 56;
const _: () = {
    assert!(IDENTIFIER_SIZE <= c_int::MAX as usize);
    assert!(IDENTIFIER_SIZE == IDENTIFIER_SIZE_C as usize);
};
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
pub fn proc_identifier(pid: u32) -> Result<[u8; IDENTIFIER_SIZE], Errno> {
    let pid = i32::try_from(pid).map_err(|_| Errno::INVAL)?;
    if pid <= 0 {
        return Err(Errno::INVAL);
    }
    let mut bytes = [0_u8; IDENTIFIER_SIZE];
    // SAFETY: the exclusive, initialized 56-byte buffer lives through this
    // synchronous call; proc_pidinfo copies bytes and requires no alignment.
    // Flavor 17 is read-only. Only a full-sized success exposes these bytes.
    let returned =
        unsafe { libc::proc_pidinfo(pid, 17, 0, bytes.as_mut_ptr().cast(), IDENTIFIER_SIZE_C) };
    if returned <= 0 {
        return Err(last_errno());
    }
    if returned != IDENTIFIER_SIZE_C {
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

/// XNU sys/proc.h `P_TRANSLATED`; pinned by the SDK probe.
pub const P_TRANSLATED: i32 = crate::rules::P_TRANSLATED;
const _: () = assert!(std::mem::offset_of!(KinfoProc, flags) == 32);

use std::os::fd::{AsRawFd, BorrowedFd, OwnedFd};

/// Fixed environment for every native spawn; never inherits the caller's env.
pub const SPAWN_ENV: [&str; 2] = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"];
/// Explicit fd handoff, borrowed until synchronous spawn returns.
pub struct FdAction<'a> {
    /// Open source descriptor.
    pub source: BorrowedFd<'a>,
    /// Descriptor in the executed child. Self-dup2 is rejected.
    pub target: i32,
}

struct Attributes(libc::posix_spawnattr_t);
impl Drop for Attributes {
    fn drop(&mut self) {
        // SAFETY: this object was successfully initialized, is exclusively owned,
        // and is destroyed exactly once after the synchronous spawn returned.
        if unsafe { libc::posix_spawnattr_destroy(&raw mut self.0) } != 0 {
            std::process::abort();
        }
    }
}
struct Actions(libc::posix_spawn_file_actions_t);
impl Drop for Actions {
    fn drop(&mut self) {
        // SAFETY: successfully initialized exclusive object, destroyed once; no
        // foreign call retains this pointer after synchronous posix_spawn.
        if unsafe { libc::posix_spawn_file_actions_destroy(&raw mut self.0) } != 0 {
            std::process::abort();
        }
    }
}
fn spawn_errno(rc: i32) -> Result<(), Errno> {
    if rc == 0 {
        Ok(())
    } else {
        Err(Errno::from_raw_os_error(rc))
    }
}

/// Owned exact-child reap capability. Only `spawn` can construct one. Never
/// waits in Drop; the adapter retains unsettled records in its separate lists.
#[derive(Debug)]
pub struct Spawned {
    pid: i32,
    outcome: Wait,
}
/// Exact-PID nonblocking reap evidence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// No status returned; the child may still run.
    Pending,
    /// Actual wait status (zero means successful exit).
    Status(i32),
    /// ECHILD from the reap syscall.
    NoChild,
}
impl Spawned {
    /// PID recorded by `posix_spawn`, without another syscall.
    #[must_use]
    pub fn pid(&self) -> u32 {
        // Construction checked this positive pid; never use a narrowing cast.
        u32::try_from(self.pid).unwrap_or_else(|_| std::process::abort())
    }
    /// Inspect socket descriptors only through this owned-child capability.
    ///
    /// # Errors
    /// Incomplete libproc evidence is never returned as an empty inventory.
    pub fn socket_fds(&self) -> Result<Vec<i32>, Errno> {
        socket_fds(self.pid())
    }
    /// Observe one owned child's socket; callers bracket the process image.
    ///
    /// # Errors
    /// Non-sockets, short reads and libproc errors fail closed.
    pub fn control_socket(&self, fd: i32) -> Result<Option<ControlSocket>, Errno> {
        read_control(self.pid(), fd)
    }
    /// Observe an `AF_UNIX` stream listener through this owned-child capability.
    ///
    /// # Errors
    /// Incomplete socket records or malformed bound addresses fail closed.
    pub fn unix_listener(&self, fd: i32) -> Result<Option<std::path::PathBuf>, Errno> {
        read_unix_listener(self.pid(), fd)
    }
    /// Poll only this own spawn record. No wildcard wait or arbitrary-pid API.
    ///
    /// # Errors
    /// Other syscall errors leave the record unsettled.
    pub fn try_reap(&mut self) -> Result<Wait, Errno> {
        if self.outcome != Wait::Pending {
            return Ok(self.outcome);
        }
        let mut status = 0;
        // SAFETY: pid is positive and comes exclusively from our own successful
        // spawn. status is aligned, initialized and live for this nonblocking
        // call. Its bytes are consumed only when this exact pid is returned.
        let rc = unsafe { libc::waitpid(self.pid, &raw mut status, libc::WNOHANG) };
        self.outcome = if rc == self.pid {
            Wait::Status(status)
        } else if rc == 0 {
            Wait::Pending
        } else if rc == -1 && last_errno() == Errno::CHILD {
            Wait::NoChild
        } else {
            return Err(last_errno());
        };
        Ok(self.outcome)
    }
    /// Kill this unreaped own child. Exclusive borrow serializes kill and reap.
    ///
    /// # Errors
    /// Preserves kill errno; a settled child is never signalled again.
    pub fn kill(&mut self) -> Result<(), Errno> {
        if self.outcome != Wait::Pending {
            return Ok(());
        }
        signal_kill(self.pid, false)
    }
}

/// Synchronous absolute-path spawn with fixed environment and signal isolation.
/// Does not change process groups. Every attr/action errno is checked directly.
///
/// # Errors
/// Rejects relative/dot paths, interior NULs, empty argv, invalid/duplicate fd
/// targets and self-dup2. On success the PID is immediately owned by the result.
pub fn spawn(
    path: &std::path::Path,
    argv: &[&str],
    fds: &[FdAction<'_>],
) -> Result<Spawned, Errno> {
    spawn_inner(path, argv, &SPAWN_ENV, fds)
}

/// A reviewed, compile-time argv/environment pair for a foreground executable.
/// Tool launches always use the separate fixed `SPAWN_ENV` environment.
pub struct Launch {
    /// Fixed argument vector, including argv[0].
    pub argv: &'static [&'static str],
    /// Fixed environment; no caller environment is inherited.
    pub env: &'static [&'static str],
}
/// Spawn a foreground executable with its reviewed fixed launch definition.
///
/// # Errors
/// Same validation and owned-child semantics as `spawn`.
pub fn spawn_launch(
    path: &std::path::Path,
    launch: &Launch,
    fds: &[FdAction<'_>],
) -> Result<Spawned, Errno> {
    spawn_inner(path, launch.argv, launch.env, fds)
}
fn spawn_inner(
    path: &std::path::Path,
    argv: &[&str],
    environment: &[&str],
    fds: &[FdAction<'_>],
) -> Result<Spawned, Errno> {
    use std::os::unix::ffi::OsStrExt;
    check_sigchld()?;
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
        || argv.is_empty()
    {
        return Err(Errno::INVAL);
    }
    for (i, action) in fds.iter().enumerate() {
        if action.target < 0
            || action.source.as_raw_fd() == action.target
            || fds[..i].iter().any(|a| a.target == action.target)
        {
            return Err(Errno::INVAL);
        }
        // No earlier action may clobber a later action's source.
        if fds[..i]
            .iter()
            .any(|a| a.target == action.source.as_raw_fd())
        {
            return Err(Errno::INVAL);
        }
    }
    let path = CString::new(path.as_os_str().as_bytes()).map_err(|_| Errno::INVAL)?;
    let argv = argv
        .iter()
        .map(|s| CString::new(*s).map_err(|_| Errno::INVAL))
        .collect::<Result<Vec<_>, _>>()?;
    let env = environment
        .iter()
        .map(|s| CString::new(*s).map_err(|_| Errno::INVAL))
        .collect::<Result<Vec<_>, _>>()?;
    let mut argument_pointers: Vec<_> = argv
        .iter()
        .map(|s| s.as_ptr().cast_mut())
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect();
    let mut envp: Vec<_> = env
        .iter()
        .map(|s| s.as_ptr().cast_mut())
        .chain(std::iter::once(std::ptr::null_mut()))
        .collect();
    let mut attr = std::mem::MaybeUninit::uninit();
    // SAFETY: attr points to aligned writable storage for the SDK object. It is
    // read only after successful init; on failure no initialized resource exists.
    spawn_errno(unsafe { libc::posix_spawnattr_init(attr.as_mut_ptr()) })?;
    // SAFETY: successful init above fully initialized this opaque SDK object.
    let mut attr = Attributes(unsafe { attr.assume_init() });
    let mut actions = std::mem::MaybeUninit::uninit();
    // SAFETY: exclusive aligned writable SDK storage, used only on init success.
    spawn_errno(unsafe { libc::posix_spawn_file_actions_init(actions.as_mut_ptr()) })?;
    // SAFETY: init succeeded. RAII destroys the object on every later error.
    let mut actions = Actions(unsafe { actions.assume_init() });
    let mut full = 0;
    let mut empty = 0;
    // SAFETY: aligned, initialized sigset storage, live through the call.
    if unsafe { libc::sigfillset(&raw mut full) } != 0 {
        return Err(last_errno());
    }
    // SAFETY: aligned, initialized sigset storage, live through the call.
    if unsafe { libc::sigemptyset(&raw mut empty) } != 0 {
        return Err(last_errno());
    }
    let flags = i16::try_from(
        libc::POSIX_SPAWN_SETSIGDEF
            | libc::POSIX_SPAWN_SETSIGMASK
            | libc::POSIX_SPAWN_CLOEXEC_DEFAULT,
    )
    .map_err(|_| Errno::INVAL)?;
    // SAFETY: initialized exclusive attr; flags are the required SDK bits only.
    spawn_errno(unsafe { libc::posix_spawnattr_setflags(&raw mut attr.0, flags) })?;
    // SAFETY: initialized attr and full signal set live through synchronous copy.
    spawn_errno(unsafe { libc::posix_spawnattr_setsigdefault(&raw mut attr.0, &raw const full) })?;
    // SAFETY: initialized attr and empty signal set live through synchronous copy.
    spawn_errno(unsafe { libc::posix_spawnattr_setsigmask(&raw mut attr.0, &raw const empty) })?;
    for fd in fds {
        // SAFETY: initialized action object; borrowed live fd and validated distinct
        // nonnegative target. posix_spawn consumes actions before borrows expire.
        spawn_errno(unsafe {
            libc::posix_spawn_file_actions_adddup2(
                &raw mut actions.0,
                fd.source.as_raw_fd(),
                fd.target,
            )
        })?;
    }
    let mut pid = 0;
    // SAFETY: pid is aligned initialized output; path/argv/envp are live NUL-
    // terminated owned C strings and null-terminated pointer arrays. Initialized
    // attr/actions and borrowed fds live until this synchronous call returns.
    // No buffers or SDK pointers escape. Failure returns the direct errno.
    spawn_errno(unsafe {
        libc::posix_spawn(
            &raw mut pid,
            path.as_ptr(),
            &raw const actions.0,
            &raw const attr.0,
            argument_pointers.as_mut_ptr(),
            envp.as_mut_ptr(),
        )
    })?;
    if pid <= 1 {
        std::process::abort();
    }
    Ok(Spawned {
        pid,
        outcome: Wait::Pending,
    })
}

/// Duplicate an owned fd above the standard descriptor range. Used for pipe
/// sources so even a helper with closed stdio never generates self-dup2.
///
/// # Errors
/// Preserves `F_DUPFD_CLOEXEC` failure; the original fd is always closed by RAII.
pub fn high_fd(fd: OwnedFd) -> Result<OwnedFd, Errno> {
    rustix::io::fcntl_dupfd_cloexec(fd, 10)
}

/// Send SIGKILL; callers must guard and immediately recheck PID/start/group.
///
/// # Errors
/// Rejects special pids/groups and preserves the kill errno.
pub(crate) fn signal_kill(pid: i32, group: bool) -> Result<(), Errno> {
    if pid <= 1
        || pid == rustix::process::getpid().as_raw_pid()
        || (group && pid == rustix::process::getpgrp().as_raw_pid())
    {
        return Err(Errno::INVAL);
    }
    signal_validated(pid, group)
}
fn signal_validated(pid: i32, group: bool) -> Result<(), Errno> {
    let rc = if group {
        // SAFETY: positive validated group id, no pointers. The adapter rechecked
        // identity immediately before entering this function and serializes reap.
        unsafe { libc::killpg(pid, libc::SIGKILL) }
    } else {
        // SAFETY: positive validated pid, no pointers. Own-child callers hold the
        // exclusive spawn record, others accept the documented PID reuse window.
        unsafe { libc::kill(pid, libc::SIGKILL) }
    };
    if rc == 0 { Ok(()) } else { Err(last_errno()) }
}

/// List a live child's descriptors using `PROC_PIDLISTFDS` (flavor 1), with bounded
/// size-race retries. The caller brackets identity separately.
///
/// # Errors
/// Invalid pids, lengths, churn and syscall failure prove no fd-table result.
#[cfg(feature = "qualification")]
pub fn proc_fds(pid: u32) -> Result<Vec<i32>, Errno> {
    Ok(proc_fd_records(pid)?
        .into_iter()
        .map(|(fd, _)| fd)
        .collect())
}

/// List socket descriptors only; errors never masquerade as a complete inventory.
///
/// # Errors
/// Same bounded libproc errors as `proc_fds`.
// XNU proc_info.h; compared against the SDK ABI probe.
const PROX_FDTYPE_SOCKET: u32 = 2;
fn socket_fds(pid: u32) -> Result<Vec<i32>, Errno> {
    Ok(proc_fd_records(pid)?
        .into_iter()
        .filter(|(_, kind)| *kind == PROX_FDTYPE_SOCKET)
        .map(|(fd, _)| fd)
        .collect())
}
fn proc_fd_records(pid: u32) -> Result<Vec<(i32, u32)>, Errno> {
    let pid = i32::try_from(pid).map_err(|_| Errno::INVAL)?;
    if pid <= 1 {
        return Err(Errno::INVAL);
    }
    for _ in 0..8 {
        let mut records = vec![
            libc::proc_fdinfo {
                proc_fd: 0,
                proc_fdtype: 0
            };
            4096
        ];
        let bytes =
            i32::try_from(std::mem::size_of_val(records.as_slice())).map_err(|_| Errno::INVAL)?;
        // SAFETY: initialized aligned records provide exactly bytes writable
        // storage for synchronous read-only libproc. No contents used on failure;
        // successful returned length is checked against capacity and stride.
        let rc = unsafe { libc::proc_pidinfo(pid, 1, 0, records.as_mut_ptr().cast(), bytes) };
        if rc <= 0 {
            return Err(last_errno());
        }
        if rc == bytes {
            continue;
        }
        let n = usize::try_from(rc).map_err(|_| Errno::INVAL)?;
        if rc > bytes || n % std::mem::size_of::<libc::proc_fdinfo>() != 0 {
            return Err(Errno::INVAL);
        }
        return Ok(records[..n / std::mem::size_of::<libc::proc_fdinfo>()]
            .iter()
            .map(|r| (r.proc_fd, r.proc_fdtype))
            .collect());
    }
    Err(Errno::NOMEM)
}

/// Set nonblocking mode on a parent pipe end and suppress SIGPIPE on writes.
///
/// # Errors
/// Returns fcntl errno; the caller retains ownership on every path.
pub fn nonblocking_pipe(fd: BorrowedFd<'_>, writer: bool) -> Result<(), Errno> {
    let flags = rustix::fs::fcntl_getfl(fd)?;
    rustix::fs::fcntl_setfl(fd, flags | rustix::fs::OFlags::NONBLOCK)?;
    if writer {
        // SAFETY: borrowed live pipe descriptor; integer-only fcntl command sets
        // Darwin's per-fd SIGPIPE suppression, without changing process signals.
        if unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_SETNOSIGPIPE, 1) } == -1 {
            return Err(last_errno());
        }
    }
    Ok(())
}

/// Poll parent stdin/stdout/stderr pipe ends, including hangup/error readiness.
///
/// # Errors
/// EINTR is returned for retry within the caller's deadline, never swallowed.
pub fn poll_pipes(
    fds: [Option<BorrowedFd<'_>>; 3],
    timeout: std::time::Duration,
) -> Result<[bool; 3], Errno> {
    let mut pollfds = std::array::from_fn::<_, 3, _>(|i| libc::pollfd {
        fd: fds[i].map_or(-1, |fd| fd.as_raw_fd()),
        events: if i == 0 { libc::POLLOUT } else { libc::POLLIN },
        revents: 0,
    });
    let millis = i32::try_from(timeout.as_millis()).unwrap_or(i32::MAX);
    // SAFETY: exclusive initialized three-element array provides exactly nfds
    // entries for this synchronous bounded call. All nonnegative fds are borrowed
    // live until return. revents is used only on success; no pointers escape.
    let rc = unsafe { libc::poll(pollfds.as_mut_ptr(), 3, millis) };
    if rc < 0 {
        Err(last_errno())
    } else {
        Ok(pollfds.map(|p| p.revents != 0))
    }
}

/// Qualification spawn with a deliberately blocked SIGUSR1 and ignored SIGTERM
/// in the parent, restored on every return. Call only from the serialized harness.
///
/// # Errors
/// Returns signal setup/restore or spawn errno. A restore failure aborts rather
/// than leave the helper with an unreported changed signal environment.
#[cfg(feature = "qualification")]
pub fn spawn_signal_probe(
    path: &std::path::Path,
    argv: &[&str],
    fds: &[FdAction<'_>],
) -> Result<Spawned, Errno> {
    let mut mask = 0;
    let mut previous = 0;
    // SAFETY: aligned initialized signal set writable for this call only.
    if unsafe { libc::sigemptyset(&raw mut mask) } != 0 {
        return Err(last_errno());
    }
    // SAFETY: exclusive initialized set and valid catchable signal number.
    if unsafe { libc::sigaddset(&raw mut mask, libc::SIGUSR1) } != 0 {
        return Err(last_errno());
    }
    // SAFETY: live initialized input/output sets, synchronous thread-only mask
    // change. pthread_sigmask returns errno directly, unlike sigprocmask.
    spawn_errno(unsafe {
        libc::pthread_sigmask(libc::SIG_BLOCK, &raw const mask, &raw mut previous)
    })?;
    // SAFETY: valid signal and SDK constant disposition; no Rust callback or
    // pointer is installed. Previous disposition is restored below.
    let old = unsafe { libc::signal(libc::SIGTERM, libc::SIG_IGN) };
    let result = if old == libc::SIG_ERR {
        Err(last_errno())
    } else {
        spawn(path, argv, fds)
    };
    if old != libc::SIG_ERR {
        // SAFETY: old is the exact disposition returned by signal above.
        if unsafe { libc::signal(libc::SIGTERM, old) } == libc::SIG_ERR {
            std::process::abort();
        }
    }
    // SAFETY: previous was initialized by successful pthread_sigmask. The null
    // output asks for no old value; the exclusive calling thread restores itself.
    if unsafe {
        libc::pthread_sigmask(libc::SIG_SETMASK, &raw const previous, std::ptr::null_mut())
    } != 0
    {
        std::process::abort();
    }
    result
}

// SDK socket_fdinfo consumed prefix/control union, from XNU bsd/sys/proc_info.h.
// https://github.com/apple-oss-distributions/xnu/blob/main/bsd/sys/proc_info.h
// Unconsumed bytes are initialized opaque storage, never exposed.
#[repr(C, align(8))]
struct SocketFdInfo {
    prefix: [u8; 176],
    socket_type: i32,
    protocol: i32,
    family: i32,
    options: i16,
    buffer_fields: [u8; 66],
    kind: i32,
    reserved: [u8; 4],
    protocol_fields: [u8; 528],
}
// XNU socket_fdinfo union offsets, pinned against the SDK in CONTROL_FIELDS.
const CONTROL_UNIT: usize = 20;
const CONTROL_NAME: usize = 24;
const UNIX_ADDR: usize = 16;
const UNIX_PATH: usize = UNIX_ADDR + 2;
const UNIX_PATH_LEN: usize = 104;
const SOCKINFO_UN: i32 = 3;
/// Owned selected control fields; name decoding is the portable caller's job.
#[derive(Clone, Debug)]
pub struct ControlSocket {
    /// Kernel control name, including its bounded NUL terminator.
    pub name: [u8; 96],
    /// Kernel control unit (the utun numeric name suffix plus one).
    pub unit: u32,
}
/// Read one socket's kernel-control fields from a supervised child's fd.
///
/// # Errors
/// Preserves libproc errors (including non-socket fd), rejects short replies.
/// A non-control socket returns None; the caller must bracket process identity.
fn read_control(pid: u32, fd: i32) -> Result<Option<ControlSocket>, Errno> {
    let pid = i32::try_from(pid).map_err(|_| Errno::INVAL)?;
    if pid <= 1 || fd < 0 {
        return Err(Errno::INVAL);
    }
    let record = read_socket(pid, fd)?;
    if record.kind != 6 {
        return Ok(None);
    }
    let mut name = [0; 96];
    name.copy_from_slice(&record.protocol_fields[CONTROL_NAME..CONTROL_NAME + 96]);
    let unit = u32::from_ne_bytes(
        record.protocol_fields[CONTROL_UNIT..CONTROL_NAME]
            .try_into()
            .map_err(|_| Errno::INVAL)?,
    );
    Ok(Some(ControlSocket { name, unit }))
}
fn read_socket(pid: i32, fd: i32) -> Result<SocketFdInfo, Errno> {
    let mut record = SocketFdInfo {
        prefix: [0; 176],
        socket_type: 0,
        protocol: 0,
        family: 0,
        options: 0,
        buffer_fields: [0; 66],
        kind: 0,
        reserved: [0; 4],
        protocol_fields: [0; 528],
    };
    // SAFETY: aligned initialized SDK-sized storage provides exactly 792 bytes
    // for synchronous read-only libproc. All field bit patterns are valid. No
    // pointers escape; fields are read only after checking the full reply size.
    let returned = unsafe { libc::proc_pidfdinfo(pid, fd, 3, (&raw mut record).cast(), 792) };
    if returned <= 0 {
        return Err(last_errno());
    }
    if returned != 792 {
        return Err(Errno::INVAL);
    }
    Ok(record)
}
fn read_unix_listener(pid: u32, fd: i32) -> Result<Option<std::path::PathBuf>, Errno> {
    use std::os::unix::ffi::OsStrExt;
    let pid = i32::try_from(pid).map_err(|_| Errno::INVAL)?;
    if pid <= 1 || fd < 0 {
        return Err(Errno::INVAL);
    }
    let record = read_socket(pid, fd)?;
    if record.kind != SOCKINFO_UN
        || record.family != libc::AF_UNIX
        || record.socket_type != libc::SOCK_STREAM
        || i32::from(record.options) & libc::SO_ACCEPTCONN == 0
    {
        return Ok(None);
    }
    let addr = &record.protocol_fields;
    let length = usize::from(addr[UNIX_ADDR]);
    if addr[UNIX_ADDR + 1] != u8::try_from(libc::AF_UNIX).map_err(|_| Errno::INVAL)?
        || !(3..=UNIX_PATH_LEN + 2).contains(&length)
    {
        return Err(Errno::INVAL);
    }
    let path = &addr[UNIX_PATH..UNIX_PATH + UNIX_PATH_LEN];
    let end = path.iter().position(|b| *b == 0).ok_or(Errno::INVAL)?;
    // sun_len may exclude the NUL, but must cover every pathname byte.
    if end == 0 || end > length - 2 || path[0] != b'/' {
        return Err(Errno::INVAL);
    }
    Ok(Some(std::path::PathBuf::from(std::ffi::OsStr::from_bytes(
        &path[..end],
    ))))
}
/// Resolve a live interface name; zero or an invalid C string fails closed.
///
/// # Errors
/// Returns errno when the interface does not exist.
pub fn interface_index(name: &str) -> Result<u32, Errno> {
    let name = std::ffi::CString::new(name).map_err(|_| Errno::INVAL)?;
    // SAFETY: live NUL-terminated name, read-only synchronous lookup.
    let index = unsafe { libc::if_nametoindex(name.as_ptr()) };
    if index == 0 {
        Err(last_errno())
    } else {
        Ok(index)
    }
}
/// Socket/control layout compared to the SDK probe in every tool cell.
pub const CONTROL_FIELDS: [(&str, usize); 15] = [
    ("size", std::mem::size_of::<SocketFdInfo>()),
    ("psi.soi_kind", std::mem::offset_of!(SocketFdInfo, kind)),
    (
        "psi.soi_type",
        std::mem::offset_of!(SocketFdInfo, socket_type),
    ),
    ("psi.soi_family", std::mem::offset_of!(SocketFdInfo, family)),
    (
        "psi.soi_options",
        std::mem::offset_of!(SocketFdInfo, options),
    ),
    (
        "psi.soi_proto.pri_kern_ctl",
        std::mem::offset_of!(SocketFdInfo, protocol_fields),
    ),
    (
        "psi.soi_proto.pri_kern_ctl.kcsi_unit",
        std::mem::offset_of!(SocketFdInfo, protocol_fields) + CONTROL_UNIT,
    ),
    (
        "psi.soi_proto.pri_kern_ctl.kcsi_name",
        std::mem::offset_of!(SocketFdInfo, protocol_fields) + CONTROL_NAME,
    ),
    (
        "psi.soi_proto.pri_un.unsi_addr",
        std::mem::offset_of!(SocketFdInfo, protocol_fields) + UNIX_ADDR,
    ),
    (
        "psi.soi_proto.pri_un.unsi_addr.ua_sun.sun_path",
        std::mem::offset_of!(SocketFdInfo, protocol_fields) + UNIX_PATH,
    ),
    ("SOCKINFO_KERN_CTL", 6),
    ("SOCKINFO_UN", SOCKINFO_UN as usize),
    ("PROX_FDTYPE_SOCKET", PROX_FDTYPE_SOCKET as usize),
    ("SO_ACCEPTCONN", libc::SO_ACCEPTCONN as usize),
    ("UNIX_PATH_LEN", UNIX_PATH_LEN),
];
const _: () = assert!(std::mem::size_of::<SocketFdInfo>() == 792);

/// Refuse spawn unless exited children remain ours until an exact-pid reap.
/// The helper is a single spawner and never changes SIGCHLD after construction.
///
/// # Errors
/// Returns the sigaction errno or INVAL for any non-default/auto-reap disposition.
pub fn check_sigchld() -> Result<(), Errno> {
    let mut old = std::mem::MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: valid signal, null input makes this read-only; aligned writable
    // output is consumed only after sigaction reports success.
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), old.as_mut_ptr()) } != 0 {
        return Err(last_errno());
    }
    // SAFETY: successful sigaction initialized the complete output object.
    let old = unsafe { old.assume_init() };
    if crate::rules::sigchld_safe(
        old.sa_sigaction == libc::SIG_DFL,
        old.sa_flags & libc::SA_NOCLDWAIT != 0,
    ) {
        Ok(())
    } else {
        Err(Errno::INVAL)
    }
}

/// Qualification-only non-CLOEXEC duplicate. The serialized harness retains it
/// across each spawn to make descriptor inheritance assertions non-vacuous.
///
/// # Errors
/// Returns fcntl failure. The owned duplicate closes on every return.
#[cfg(feature = "qualification")]
pub fn qual_inheritable_fd(fd: BorrowedFd<'_>, minimum: i32) -> Result<OwnedFd, Errno> {
    use std::os::fd::FromRawFd;
    // SAFETY: borrowed live fd, integer-only F_DUPFD creates a distinct owned fd.
    let raw = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_DUPFD, minimum) };
    if raw < 0 {
        return Err(last_errno());
    }
    // SAFETY: successful F_DUPFD returned a new exclusively owned descriptor.
    let owned = unsafe { OwnedFd::from_raw_fd(raw) };
    // SAFETY: owned live descriptor; F_SETFD clears close-on-exec deliberately.
    if unsafe { libc::fcntl(raw, libc::F_SETFD, 0) } < 0 {
        return Err(last_errno());
    }
    Ok(owned)
}

/// Exercise actual spawn refusal under both inherited auto-reap dispositions.
/// Call only in a serialized qualification process; restores the exact action.
///
/// # Errors
/// Returns syscall errors or INVAL if either unsafe disposition allowed spawn.
#[cfg(feature = "qualification")]
pub fn qual_sigchld_refusals(path: &std::path::Path) -> Result<(), Errno> {
    let mut old = std::mem::MaybeUninit::<libc::sigaction>::uninit();
    // SAFETY: read-only query with valid signal and aligned writable output.
    if unsafe { libc::sigaction(libc::SIGCHLD, std::ptr::null(), old.as_mut_ptr()) } != 0 {
        return Err(last_errno());
    }
    // SAFETY: successful query initialized the entire object.
    let old = unsafe { old.assume_init() };
    let mut result = Ok(());
    for (handler, flags) in [(libc::SIG_IGN, 0), (libc::SIG_DFL, libc::SA_NOCLDWAIT)] {
        let action = libc::sigaction {
            sa_sigaction: handler,
            sa_mask: 0,
            sa_flags: flags,
        };
        // SAFETY: live initialized action, valid signal; exact old action restored below.
        if unsafe { libc::sigaction(libc::SIGCHLD, &raw const action, std::ptr::null_mut()) } != 0 {
            result = Err(last_errno());
            break;
        }
        match spawn(path, &["tool-child", "exit0"], &[]) {
            Err(Errno::INVAL) => {}
            Err(e) => {
                result = Err(e);
                break;
            }
            Ok(mut child) => {
                // A mutant has invalidated owned-pid lifetime protection. This
                // exit0 fixture needs no signal; never kill under auto-reaping.
                for _ in 0..200 {
                    if child.try_reap().is_ok_and(|s| s != Wait::Pending) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(5));
                }
                result = Err(Errno::INVAL);
                break;
            }
        }
    }
    // SAFETY: old was read successfully; restoring it never installs a Rust callback.
    if unsafe { libc::sigaction(libc::SIGCHLD, &raw const old, std::ptr::null_mut()) } != 0 {
        std::process::abort();
    }
    result
}

/// Result of an immediate kernel identity check followed by a guarded signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalOutcome {
    /// Expected leader no longer exists (does not certify an empty group).
    Gone,
    /// Start or group changed; nothing signalled.
    StartChanged,
    /// SIGKILL delivered.
    Signalled,
}
/// Guard self/special ids and re-read kernel start/group immediately before kill.
///
/// # Errors
/// Returns invalid target or syscall errors; incomplete lookup never signals.
pub fn kill_checked(
    pid: u32,
    group: Option<u32>,
    start: (u64, u32),
) -> Result<SignalOutcome, Errno> {
    let os_pid = i32::try_from(pid).map_err(|_| Errno::INVAL)?;
    let target = i32::try_from(group.unwrap_or(pid)).map_err(|_| Errno::INVAL)?;
    if os_pid <= 1
        || target <= 1
        || os_pid == rustix::process::getpid().as_raw_pid()
        || target == rustix::process::getpid().as_raw_pid()
        || (group.is_some() && target == rustix::process::getpgrp().as_raw_pid())
    {
        return Err(Errno::INVAL);
    }
    let Some(current) = sysctl_kern_proc_pid(pid).map_err(|e| match e {
        ProcError::Os(e) => e,
        _ => Errno::INVAL,
    })?
    else {
        return Ok(SignalOutcome::Gone);
    };
    let expected = (
        i64::try_from(start.0).map_err(|_| Errno::INVAL)?,
        i32::try_from(start.1).map_err(|_| Errno::INVAL)?,
    );
    if current.start != expected || group.is_some_and(|_| current.pgid != target) {
        return Ok(SignalOutcome::StartChanged);
    }
    // Self/group guards ran before the identity query. No intervening syscall
    // is allowed between this last identity check and the actual signal.
    match signal_validated(target, group.is_some()) {
        Ok(()) => Ok(SignalOutcome::Signalled),
        Err(Errno::SRCH) => Ok(SignalOutcome::Gone),
        Err(e) => Err(e),
    }
}
/// Qualification-only unguarded kill for supervised launchd teardown experiments.
///
/// # Errors
/// Rejects self/special ids and preserves signal errno.
#[cfg(feature = "qualification")]
pub fn qual_signal_kill(pid: i32, group: bool) -> Result<(), Errno> {
    signal_kill(pid, group)
}

/// Qualification-only arbitrary-pid socket inventory.
///
/// # Errors
/// Preserves bounded libproc inventory failures.
#[cfg(feature = "qualification")]
pub fn proc_socket_fds(pid: u32) -> Result<Vec<i32>, Errno> {
    socket_fds(pid)
}
/// Qualification-only arbitrary-pid control observation.
///
/// # Errors
/// Preserves socket read failures, including short or non-socket replies.
#[cfg(feature = "qualification")]
pub fn proc_control(pid: u32, fd: i32) -> Result<Option<ControlSocket>, Errno> {
    read_control(pid, fd)
}
