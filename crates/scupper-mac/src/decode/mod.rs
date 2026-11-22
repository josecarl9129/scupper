//! Portable decoding and Darwin wire-format constants.

/// Darwin IOC direction bit for copying into the kernel.
pub const IOC_IN: u32 = 0x8000_0000;
/// Darwin IOC direction bit for copying out of the kernel.
pub const IOC_OUT: u32 = 0x4000_0000;

/// Encode a Darwin ioctl command (`_IOC`, including the 13-bit size mask).
#[must_use]
pub const fn ioc(direction: u32, group: u8, number: u8, size: u32) -> u32 {
    direction | ((size & 0x1fff) << 16) | ((group as u32) << 8) | number as u32
}

/// Encode Darwin `_IOWR` for an argument of the supplied size.
#[must_use]
pub const fn iowr(group: u8, number: u8, size: u32) -> u32 {
    ioc(IOC_IN | IOC_OUT, group, number, size)
}

#[cfg(test)]
mod tests {
    #[test]
    fn darwin_get_starters_is_not_the_host_ioctl_encoding() {
        assert_eq!(super::iowr(b'D', 5, 16), 0xC010_4405);
    }
}

pub mod proc;

pub mod image;

pub mod pftext;
pub mod pftoken;

#[cfg(all(feature = "qualification", any(target_os = "macos", test)))]
pub(crate) mod pfcapture;
