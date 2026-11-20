use std::ffi::{CStr, CString};

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
