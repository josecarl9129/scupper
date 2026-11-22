//! Native pf tools share the ordinary bounded runner and its mutation fence.
use super::{NativePlatform, tool};
use crate::{
    decode::pftoken::{self, Assumption, ReadError},
    platform::{Deadline, SysError, Tool},
};
use std::{os::fd::AsFd, path::Path, time::Duration};

impl NativePlatform {
    /// Save full adapter mutator attempts before any text interpretation.
    #[cfg(feature = "qualification")]
    pub fn capture_pf_text(&mut self, out: Option<std::path::PathBuf>) {
        self.pf_text_out = out;
    }
    #[cfg(feature = "qualification")]
    fn save_pf_text(
        &self,
        build: &crate::decode::pftext::Build,
        args: &[&str],
        result: &tool::ToolResult,
        started_unix_ms: u128,
        started: std::time::Instant,
    ) -> Result<(), String> {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let Some(out) = &self.pf_text_out else {
            return Ok(());
        };
        let evidence = crate::qual::Evidence {
            command: crate::decode::pfcapture::command(args),
            stdin: None,
            pid: Some(result.pid),
            exit_code: match result.reap {
                crate::platform::runtime::Reap::Status(s) if s.trailing_zeros() >= 7 => {
                    Some((s >> 8) & 255)
                }
                _ => None,
            },
            started_unix_ms,
            elapsed_ms: started.elapsed().as_millis(),
            timed_out: result.timed_out,
            truncated: result.io_failed
                || result.stdout.truncated
                || result.stderr.truncated
                || result.stdin_unsent != 0,
            stdout: String::from_utf8_lossy(&result.stdout.bytes).into_owned(),
            stderr: String::from_utf8_lossy(&result.stderr.bytes).into_owned(),
        };
        let save = || -> Result<(), Box<dyn std::error::Error>> {
            let capture = evidence.pf_text_capture(
                build.as_str(),
                &result.stdout.bytes,
                &result.stderr.bytes,
            )?;
            let name = format!(
                "pf-text-native-{}-{}.json",
                result.pid,
                scupper_darwin::monotonic_raw().as_nanos()
            );
            let mut file = std::fs::OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(out.join(name))?;
            serde_json::to_writer_pretty(&mut file, &capture)?;
            file.write_all(b"\n")?;
            file.sync_all()?;
            Ok(())
        };
        save().map_err(|error| error.to_string())
    }
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
    /// Read the OS build before spawning for every native parser and capture.
    pub(super) fn pf_attempt(
        &mut self,
        args: &[&str],
        deadline: Deadline,
    ) -> Result<(crate::decode::pftext::Build, tool::ToolResult), SysError> {
        let build = crate::decode::pftext::Build::system()?;
        self.check_pin(Path::new(crate::engine::PFCTL), deadline)?;
        #[cfg(feature = "qualification")]
        let started = std::time::Instant::now();
        #[cfg(feature = "qualification")]
        let started_unix_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_millis());
        #[cfg_attr(not(feature = "qualification"), allow(unused_mut))]
        let mut result = tool::run(
            &mut self.records,
            Tool::Pfctl,
            Path::new(crate::engine::PFCTL),
            args,
            &[],
            1024 * 1024,
            deadline,
        )?;
        #[cfg(feature = "qualification")]
        if crate::decode::pfcapture::captured_mutator(args) {
            let saved = self.save_pf_text(&build, args, &result, started_unix_ms, started);
            crate::decode::pfcapture::record_failure(
                args,
                saved,
                &mut result.io_failed,
                &mut self.pf_capture_failures,
            );
        }
        Ok((build, result))
    }
    /// Drain capture failures into the qualification case detail.
    #[cfg(feature = "qualification")]
    pub fn take_pf_capture_failures(&mut self) -> Vec<String> {
        std::mem::take(&mut self.pf_capture_failures)
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
    attempt: &Result<(crate::decode::pftext::Build, tool::ToolResult), SysError>,
) -> crate::decode::pftext::Attempt<'_> {
    attempt
        .as_ref()
        .map(|(build, result)| {
            (
                build,
                crate::decode::pftext::ToolEvidence::from_output(
                    result.pid,
                    result.reap,
                    &result.stdout,
                    &result.stderr,
                    result.timed_out,
                    result.io_failed,
                    result.stdin_unsent,
                ),
            )
        })
        .map_err(Clone::clone)
}
