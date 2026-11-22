//! Portable selection and failure accounting for native pfctl captures.

pub(crate) fn captured_mutator(args: &[&str]) -> bool {
    args.first() == Some(&crate::engine::PFCTL)
        && matches!(args.get(1), Some(&"-e" | &"-E" | &"-X" | &"-d"))
}

pub(crate) fn command(args: &[&str]) -> Vec<String> {
    args.iter().map(|arg| (*arg).to_owned()).collect()
}

pub(crate) fn record_failure(
    args: &[&str],
    saved: Result<(), String>,
    io_failed: &mut bool,
    failures: &mut Vec<String>,
) {
    if let Err(error) = saved {
        // Post-spawn uncertainty: a successful -E may still hold a real token.
        *io_failed = true;
        failures.push(format!(
            "pf text capture write failed for {}: {error:?}",
            args.join(" ")
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        decode::pftext::{self, Build, ToolEvidence},
        platform::{
            ToolOutcome,
            runtime::{Output, Reap},
        },
    };

    #[test]
    fn capture_selects_argument_and_preserves_command_once() {
        for flag in ["-e", "-E", "-X", "-d"] {
            let args = [crate::engine::PFCTL, flag, "42"];
            assert!(captured_mutator(&args));
            assert_eq!(command(&args), args);
        }
        for args in [
            &[][..],
            &["-E"][..],
            &[crate::engine::PFCTL][..],
            &[crate::engine::PFCTL, "-s", "info"][..],
            &["other", "-E"][..],
        ] {
            assert!(!captured_mutator(args));
        }
    }

    #[test]
    fn capture_failure_after_successful_acquire_retains_unknown_and_reason() {
        let stdout = Output::default();
        let mut stderr = Output::default();
        stderr.append(b"Token : 42\n", 1024);
        let mut io_failed = false;
        let mut failures = vec![];
        let outcome = |failed| {
            pftext::acquire_outcome(Ok((
                &Build::fixture("24H232"),
                ToolEvidence::from_output(123, Reap::Status(0), &stdout, &stderr, false, failed, 0),
            )))
        };
        assert_eq!(outcome(false), ToolOutcome::Ok((42, 123)));
        record_failure(
            &[crate::engine::PFCTL, "-E"],
            Err("disk full".into()),
            &mut io_failed,
            &mut failures,
        );
        assert_eq!(outcome(io_failed), ToolOutcome::Unknown { reaped: true });
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("disk full"));
        assert!(failures[0].contains("capture write failed for /sbin/pfctl -E"));
        record_failure(
            &[crate::engine::PFCTL, "-E"],
            Ok(()),
            &mut io_failed,
            &mut failures,
        );
        assert!(io_failed);
        assert_eq!(failures.len(), 1);
        assert!(failures[0].contains("disk full"));
    }
}
