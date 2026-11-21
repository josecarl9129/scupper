//! Typed, owned Darwin system interfaces. Empty on other operating systems.
//! All foreign calls are confined to the private `sys` module (ADR 0034).

#[cfg(any(target_os = "macos", test))]
mod rules;

#[cfg(target_os = "macos")]
#[allow(unsafe_code)]
mod sys;

#[cfg(target_os = "macos")]
pub use sys::{
    CONTROL_FIELDS, ControlSocket, FdAction, IDENTIFIER_FIELDS, IDENTIFIER_SIZE, KINFO_PROC_FIELDS,
    KINFO_PROC_SIZE, KProc, Launch, MAXCOMLEN, NOW_CLOCK_ID, P_TRANSLATED, ProcError, SPAWN_ENV,
    SignalOutcome, Spawned, UPTIME_CLOCK_ID, Wait, check_sigchld, high_fd, interface_index,
    kill_checked, monotonic_raw, nonblocking_pipe, poll_pipes, proc_identifier, proc_pidpath,
    proc_uid, spawn, spawn_launch, sysctl_kern_proc_all, sysctl_kern_proc_pid, sysctl_string,
    uptime_raw,
};

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::sysctl_string;
    use rustix::io::Errno;

    #[test]
    fn osversion_is_a_nonempty_string() -> Result<(), Errno> {
        assert_ne!(sysctl_string("kern.osversion")?, "");
        Ok(())
    }

    #[test]
    fn unknown_name_returns_noent() {
        assert_eq!(
            sysctl_string("kern.scupper_nonexistent_qualification_oid"),
            Err(Errno::NOENT)
        );
    }

    #[test]
    fn interior_nul_returns_inval() {
        assert_eq!(sysctl_string("kern.osversion\0ignored"), Err(Errno::INVAL));
    }

    #[test]
    fn integer_oid_is_rejected_as_a_string() {
        assert_eq!(sysctl_string("hw.ncpu"), Err(Errno::INVAL));
    }
}

#[cfg(all(target_os = "macos", feature = "qualification"))]
pub use sys::{
    proc_control, proc_fds, proc_socket_fds, qual_inheritable_fd, qual_sigchld_refusals,
    qual_signal_kill, spawn_signal_probe,
};
