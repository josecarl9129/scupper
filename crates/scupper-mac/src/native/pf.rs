//! Native pf tools share the ordinary bounded runner and its mutation fence.
use super::{NativePlatform, tool};
use crate::{
    decode::pftoken::{self, Assumption, ReadError},
    platform::{Deadline, SysError, Tool},
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
    /// Reduce enumeration spares for disposable-runner churn only (default 16).
    #[cfg(feature = "qualification")]
    pub fn reference_spare_slots(&mut self, spare: usize) {
        self.pf_spare_slots = spare;
    }
    /// Drain actual adapter copy decisions, including internal full-buffer retries.
    #[cfg(feature = "qualification")]
    #[must_use]
    pub fn reference_copy_decisions(&mut self) -> Vec<pftoken::EnumerationEvent> {
        self.pf_copy_decisions.lock().map_or_else(
            |_| Vec::new(),
            |mut decisions| std::mem::take(&mut *decisions),
        )
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
        #[cfg(feature = "qualification")]
        let spare = self.pf_spare_slots;
        #[cfg(feature = "qualification")]
        let decisions = self.pf_copy_decisions.clone();
        let result = self.pf_reader.read(
            end.saturating_sub(scupper_darwin::monotonic_raw()),
            move || {
                let fd =
                    scupper_darwin::pf_open().map_err(|_| SysError::Failed("pf token open"))?;
                let read = |bytes: &mut [u8]| {
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
                };
                let expired = || scupper_darwin::monotonic_raw() >= end;
                #[cfg(feature = "qualification")]
                {
                    pftoken::enumerate_with_spare(read, expired, spare, |classification| {
                        if let Ok(mut decisions) = decisions.lock() {
                            decisions.push(classification);
                        }
                    })
                }
                #[cfg(not(feature = "qualification"))]
                pftoken::enumerate(read, expired)
            },
        );
        if scupper_darwin::monotonic_raw() >= end {
            return Err(SysError::TimedOut);
        }
        result
    }
}
/// Borrow native capture fields without making any outcome decision.
pub(super) fn evidence(
    attempt: &Result<(String, tool::ToolResult), SysError>,
) -> crate::decode::pftext::Attempt<'_> {
    attempt
        .as_ref()
        .map(|(build, result)| {
            (
                build.as_str(),
                crate::decode::pftext::ToolEvidence {
                    pid: result.pid,
                    reap: result.reap,
                    stdout: &result.stdout.bytes,
                    stderr: &result.stderr.bytes,
                    stdout_truncated: result.stdout.truncated,
                    stderr_truncated: result.stderr.truncated,
                    timed_out: result.timed_out,
                    io_failed: result.io_failed,
                    stdin_unsent: result.stdin_unsent,
                },
            )
        })
        .map_err(Clone::clone)
}
