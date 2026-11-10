//! Mount evidence is read directly, without entering an extra mount namespace.
use super::Result;
use scupper_sys::netns::mountinfo;
use std::{fs, path::Path};

pub(super) const SCUPPER: &str = "/run/netns/scupper";

pub(super) fn count(info: &str, path: &str) -> std::io::Result<usize> {
    mountinfo::count(info, Path::new(path))
}

// Compare the propagated copies with an untouched iproute2 namespace. Shared
// group numbers differ between names, but must agree among each name's copies.
fn peer_shape(info: &str, path: &str) -> Result<(Vec<u64>, u64)> {
    let mut parents = Vec::new();
    let mut peer_group = None;
    let mut root = None;
    for line in info.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.get(4) != Some(&path) {
            continue;
        }
        let separator = fields
            .iter()
            .position(|field| *field == "-")
            .ok_or("malformed mountinfo")?;
        let shared = fields
            .get(6..separator)
            .and_then(|fields| {
                fields
                    .iter()
                    .find_map(|field| field.strip_prefix("shared:"))
            })
            .filter(|group| group.parse::<u64>().is_ok_and(|group| group > 0))
            .ok_or("namespace mount is not shared")?;
        if fields.get(separator + 1) != Some(&"nsfs")
            || peer_group.is_some_and(|group| group != shared)
            || root.is_some_and(|root| root != fields[3])
        {
            return super::fail("namespace copies are not shared nsfs peers");
        }
        peer_group = Some(shared);
        root = Some(fields[3]);
        parents.push(fields[1].parse()?);
    }
    if parents.is_empty() || count(info, path)? != 1 {
        return super::fail("namespace has no single visible shared mount");
    }
    parents.sort_unstable();
    Ok((
        parents,
        peer_group.ok_or("missing namespace peer group")?.parse()?,
    ))
}

fn verify_peer_shape(info: &str) -> Result<u64> {
    let (parents, group) = peer_shape(info, SCUPPER)?;
    if parents != peer_shape(info, "/run/netns/wan")?.0 {
        return super::fail("restored namespace propagation differs from iproute2 namespace");
    }
    Ok(group)
}

pub(super) fn verify_restored_peers(daemon_pid: Option<u32>) -> Result<()> {
    let host_group = verify_peer_shape(&mountinfo::read("/proc/self/mountinfo")?)?;
    if let Some(pid) = daemon_pid {
        let daemon_group = verify_peer_shape(&mountinfo::read(format!("/proc/{pid}/mountinfo"))?)?;
        if daemon_group != host_group {
            return super::fail("host and daemon namespace mounts are not shared peers");
        }
    }
    Ok(())
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
    let host = mountinfo::read("/proc/self/mountinfo")?;
    fs::write(
        artifacts.join(format!("{stage}-host.mountinfo")),
        netns_lines(&host),
    )?;
    let host_ns = fs::read_link("/proc/self/ns/mnt")?;
    let host_count = count(&host, SCUPPER)?;
    let mut different_counts = false;
    let mut summary = serde_json::json!({
        "host_mount_namespace": host_ns,
        "host_scupper_mounts": host_count,
    });
    if let Some(pid) = daemon_pid {
        let daemon_ns = fs::read_link(format!("/proc/{pid}/ns/mnt"))?;
        let daemon = mountinfo::read(format!("/proc/{pid}/mountinfo"))?;
        fs::write(
            artifacts.join(format!("{stage}-daemon.mountinfo")),
            netns_lines(&daemon),
        )?;
        let daemon_count = count(&daemon, SCUPPER)?;
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

    const HOST: &str = "59 35 0:29 /netns /run/netns rw,nosuid,nodev shared:12 - tmpfs tmpfs rw,size=1624600k,nr_inodes=819200,mode=755,inode64\n\
        229 59 0:5 net:[4026532276] /run/netns/wan rw shared:324 - nsfs nsfs rw\n\
        230 35 0:5 net:[4026532276] /run/netns/wan rw shared:324 - nsfs nsfs rw\n\
        480 59 0:5 net:[4026532579] /run/netns/scupper rw shared:418 - nsfs nsfs rw\n\
        482 35 0:5 net:[4026532579] /run/netns/scupper rw shared:418 - nsfs nsfs rw\n";

    #[test]
    fn evidence_preserves_peers_without_counting_them_as_stacks() -> Result<()> {
        assert_eq!(count(HOST, SCUPPER)?, 1);
        assert_eq!(count(HOST, "/run/netns/missing")?, 0);
        let saved = netns_lines(HOST);
        assert_eq!(saved.lines().count(), 5);
        assert!(saved.contains("shared:12"));
        assert!(saved.contains("shared:418"));
        assert_eq!(count(&saved, SCUPPER)?, 1);
        let stacked = format!("{HOST}483 480 0:5 net:[42] /run/netns/scupper rw - nsfs nsfs rw\n");
        assert_eq!(count(&stacked, SCUPPER)?, 2);
        Ok(())
    }

    #[test]
    fn restored_shape_requires_matching_shared_peers() -> Result<()> {
        verify_peer_shape(HOST)?;
        assert!(verify_peer_shape(&HOST.replace("shared:418", "")).is_err());
        assert!(verify_peer_shape(&HOST.replace("482 35", "482 59")).is_err());
        assert!(
            verify_peer_shape(&HOST.replace(
                "482 35 0:5 net:[4026532579] /run/netns/scupper rw shared:418",
                "482 35 0:5 net:[4026532579] /run/netns/scupper rw shared:419"
            ))
            .is_err()
        );
        assert!(
            verify_peer_shape(
                &HOST
                    .lines()
                    .filter(|line| !line.starts_with("482 "))
                    .collect::<Vec<_>>()
                    .join("\n")
            )
            .is_err()
        );
        assert!(
            verify_peer_shape(&HOST.replace("482 35 0:5 net:[4026532579]", "482 35 0:5 net:[43]"))
                .is_err()
        );
        Ok(())
    }
}
