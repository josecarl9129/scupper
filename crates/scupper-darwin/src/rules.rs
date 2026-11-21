//! Portable decisions shared by the Darwin syscall boundary and its tests.
/// XNU sys/proc.h `P_TRANSLATED`, also checked against the SDK by qualification.
pub(crate) const P_TRANSLATED: i32 = 0x0002_0000;
pub(crate) fn translated(flags: i32) -> bool {
    flags & P_TRANSLATED != 0
}
pub(crate) fn sigchld_safe(default_handler: bool, no_child_wait: bool) -> bool {
    default_handler && !no_child_wait
}
#[cfg(test)]
mod tests {
    #[test]
    fn translated_refusal_uses_p_flag_bit() {
        assert!(!super::translated(0));
        assert!(super::translated(0x0002_0000));
        assert!(super::translated(-1));
        assert!(!super::translated(!0x0002_0000));
    }
    #[test]
    fn sigchld_requires_default_and_waitable_children() {
        assert!(super::sigchld_safe(true, false));
        assert!(!super::sigchld_safe(false, false));
        assert!(!super::sigchld_safe(true, true));
        assert!(!super::sigchld_safe(false, true));
    }
}
