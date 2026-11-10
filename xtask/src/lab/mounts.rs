//! Mount evidence is read directly, without entering an extra mount namespace.
use super::Result;
use std::{fs, path::Path};

pub(super) const SCUPPER: &str = "/run/netns/scupper";

pub(super) fn count(info: &str, path: &str) -> usize {
    info.lines()
        .filter(|line| line.split_whitespace().nth(4) == Some(path))
        .count()
}

fn netns_lines(info: &str) -> String {
    info.lines()
        .filter(|line| {
            line.split_whitespace()
                .nth(4)
                .is_some_and(|point| point == "/run/netns" || point.starts_with("/run/netns/"))
        })
        .fold(String::new(), |mut saved, line| {
            saved.push_str(line);
            saved.push('\n');
            saved
        })
}

pub(super) fn save(artifacts: &Path, stage: &str, daemon_pid: Option<u32>) -> Result<usize> {
    let host = fs::read_to_string("/proc/self/mountinfo")?;
    fs::write(
        artifacts.join(format!("{stage}-host.mountinfo")),
        netns_lines(&host),
    )?;
    let host_ns = fs::read_link("/proc/self/ns/mnt")?;
    let host_count = count(&host, SCUPPER);
    let mut different_counts = false;
    let mut summary = serde_json::json!({
        "host_mount_namespace": host_ns,
        "host_scupper_mounts": host_count,
    });
    if let Some(pid) = daemon_pid {
        let daemon_ns = fs::read_link(format!("/proc/{pid}/ns/mnt"))?;
        let daemon = fs::read_to_string(format!("/proc/{pid}/mountinfo"))?;
        fs::write(
            artifacts.join(format!("{stage}-daemon.mountinfo")),
            netns_lines(&daemon),
        )?;
        let daemon_count = count(&daemon, SCUPPER);
        different_counts = host_count != daemon_count;
        summary["daemon_pid"] = pid.into();
        summary["daemon_mount_namespace"] = serde_json::to_value(&daemon_ns)?;
        summary["same_mount_namespace"] = (host_ns == daemon_ns).into();
        summary["daemon_scupper_mounts"] = daemon_count.into();
    }
    fs::write(
        artifacts.join(format!("{stage}-mounts.json")),
        serde_json::to_vec_pretty(&summary)?,
    )?;
    if different_counts {
        return super::fail(format!(
            "{stage}: host and daemon namespace mount counts differ; see mount artifacts"
        ));
    }
    Ok(host_count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn evidence_preserves_stacks_and_parent_propagation_fields() {
        let info = "10 1 0:1 / /run/netns rw shared:7 - tmpfs tmpfs rw\n\
                    11 10 0:4 net:[42] /run/netns/scupper rw shared:8 - nsfs nsfs rw\n\
                    12 10 0:4 net:[42] /run/netns/scupper rw - nsfs nsfs rw\n\
                    13 1 0:1 / /run/netns-other rw - tmpfs tmpfs rw\n";
        assert_eq!(count(info, SCUPPER), 2);
        assert_eq!(count(info, "/run/netns/missing"), 0);
        let saved = netns_lines(info);
        assert_eq!(saved.lines().count(), 3);
        assert!(saved.contains("shared:7"));
        assert!(saved.contains("shared:8"));
        assert_eq!(count(&saved, SCUPPER), 2);
    }
}
