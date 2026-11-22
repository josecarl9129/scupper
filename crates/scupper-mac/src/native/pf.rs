//! Native pf tools share the ordinary bounded runner and its mutation fence.
use super::{NativePlatform, tool};
use crate::{
    decode::pftoken::{self, Assumption, ReadError},
    platform::{Deadline, SysError, Tool, runtime::Reap},
};
use std::{os::fd::AsFd, path::Path, time::Duration};

impl NativePlatform {
    /// Override kernel assumptions only for this qualification instance.
    #[cfg(feature = "qualification")]
    pub fn reference_assumptions(&mut self, assumptions: pftoken::Assumptions) {
        self.pf_assumptions = pftoken::Override::Qualification(assumptions);
    }
    /// Drain actual adapter ioctl slice lengths, including zero-length queries.
    #[cfg(feature = "qualification")]
    #[must_use]
    pub fn reference_capacities(&mut self) -> Vec<usize> {
        self.pf_capacities
            .lock()
            .map_or_else(|_| Vec::new(), |mut sizes| std::mem::take(&mut *sizes))
    }
    pub(super) fn pf_tool(
        &mut self,
        args: &[&str],
        deadline: Deadline,
    ) -> Result<tool::ToolResult, SysError> {
        self.check_pin(Path::new(crate::engine::PFCTL), deadline)?;
        tool::run(
            &mut self.records,
            Tool::Pfctl,
            Path::new(crate::engine::PFCTL),
            args,
            &[],
            1024 * 1024,
            deadline,
        )
    }
    pub(super) fn pf_build() -> Result<String, SysError> {
        scupper_darwin::sysctl_string("kern.osversion").map_err(|_| SysError::Unknown)
    }
    pub(super) fn read_references(
        &mut self,
        deadline: Deadline,
    ) -> Result<Vec<crate::platform::RefLine>, SysError> {
        if self.pf_assumptions.assumptions().pf_token_layout != Assumption::Established {
            return Err(SysError::Failed("pf token layout unqualified"));
        }
        let end = Duration::from_secs(deadline.0);
        #[cfg(feature = "qualification")]
        let capacities = self.pf_capacities.clone();
        let result = self.pf_reader.read(
            end.saturating_sub(scupper_darwin::monotonic_raw()),
            move || {
                let fd =
                    scupper_darwin::pf_open().map_err(|_| SysError::Failed("pf token open"))?;
                pftoken::enumerate(
                    |bytes| {
                        #[cfg(feature = "qualification")]
                        capacities
                            .lock()
                            .map_err(|_| ReadError::Other)?
                            .push(bytes.len());
                        scupper_darwin::pf_starters(fd.as_fd(), bytes).map_err(|e| {
                            if e == rustix::io::Errno::NOENT {
                                ReadError::Noent
                            } else {
                                ReadError::Other
                            }
                        })
                    },
                    || scupper_darwin::monotonic_raw() >= end,
                )
            },
        );
        if scupper_darwin::monotonic_raw() >= end {
            return Err(SysError::TimedOut);
        }
        result
    }
}
/// Return an exit code only with complete bounded streams and synchronous reap.
pub(super) fn status(result: &tool::ToolResult) -> Result<i32, SysError> {
    if result.timed_out
        || result.io_failed
        || result.stdin_unsent != 0
        || result.stdout.truncated
        || result.stderr.truncated
    {
        return Err(SysError::Unknown);
    }
    match result.reap {
        Reap::Status(status) if status.trailing_zeros() >= 7 => Ok((status >> 8) & 0xff),
        _ => Err(SysError::Unknown),
    }
}
