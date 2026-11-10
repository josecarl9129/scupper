//! Bounded mountinfo reads and counts in the visible mount tree.
use std::{
    collections::BTreeSet,
    fs::File,
    io::{self, Read},
    os::unix::ffi::OsStrExt,
    path::Path,
};

const MAX_BYTES: u64 = 8 * 1024 * 1024;

/// Read mountinfo with an 8 MiB limit, rejecting truncation.
///
/// # Errors
/// Returns read, UTF-8 or size-limit failures.
pub fn read(path: impl AsRef<Path>) -> io::Result<String> {
    read_capped(File::open(path)?)
}

fn read_capped(reader: impl Read) -> io::Result<String> {
    let mut info = String::new();
    reader.take(MAX_BYTES + 1).read_to_string(&mut info)?;
    if info.len() as u64 > MAX_BYTES {
        return Err(io::Error::other("namespace mountinfo exceeds 8 MiB"));
    }
    Ok(info)
}

struct Entry<'a> {
    id: u64,
    parent: u64,
    point: &'a [u8],
    shared: bool,
}

fn malformed() -> io::Error {
    io::Error::other("malformed namespace mountinfo")
}

fn escaped(path: &Path) -> Vec<u8> {
    let mut result = Vec::new();
    for byte in path.as_os_str().as_bytes() {
        match byte {
            b' ' => result.extend_from_slice(b"\\040"),
            b'\t' => result.extend_from_slice(b"\\011"),
            b'\n' => result.extend_from_slice(b"\\012"),
            b'\\' => result.extend_from_slice(b"\\134"),
            byte => result.push(*byte),
        }
    }
    result
}

/// Count the mount-on-mount chain reachable at an absolute, resolved path.
/// Propagated copies below shadowed ancestors are excluded. At each component,
/// descend through the topmost mount and its same-path children before proceeding.
///
/// # Errors
/// Rejects malformed records, duplicate IDs, cycles and a missing ancestor mount.
pub fn count(info: &str, path: &Path) -> io::Result<usize> {
    Ok(inspect(info, path)?.0)
}

/// Whether the visible mount containing `path` belongs to a shared peer group.
/// This only reads propagation; it never prepares or changes a mount.
///
/// # Errors
/// Rejects the same malformed mount trees as [`count`].
pub fn is_shared(info: &str, path: &Path) -> io::Result<bool> {
    Ok(inspect(info, path)?.1)
}

fn inspect(info: &str, path: &Path) -> io::Result<(usize, bool)> {
    if !path.is_absolute() {
        return Err(malformed());
    }
    let mut entries = Vec::new();
    let mut ids = BTreeSet::new();
    for line in info.lines() {
        let (fields, tail) = line.split_once(" - ").ok_or_else(malformed)?;
        if tail.split_whitespace().count() < 3 {
            return Err(malformed());
        }
        let mut fields = fields.split_whitespace();
        let id = fields
            .next()
            .ok_or_else(malformed)?
            .parse()
            .map_err(|_| malformed())?;
        let parent = fields
            .next()
            .ok_or_else(malformed)?
            .parse()
            .map_err(|_| malformed())?;
        let point = fields.nth(2).ok_or_else(malformed)?.as_bytes();
        if fields.next().is_none() || !point.starts_with(b"/") || !ids.insert(id) {
            return Err(malformed());
        }
        let shared = fields.any(|field| {
            field
                .strip_prefix("shared:")
                .is_some_and(|group| group.parse::<u64>().is_ok_and(|group| group > 0))
        });
        entries.push(Entry {
            id,
            parent,
            point,
            shared,
        });
    }
    let mut current = None;
    let mut visited = BTreeSet::new();
    let mut ancestors: Vec<_> = path.ancestors().collect();
    ancestors.reverse();
    let mut count = 0;
    let mut shared = false;
    for ancestor in ancestors {
        let point = escaped(ancestor);
        let mut depth = 0;
        loop {
            // Kernel output can contain same-parent siblings; the last is on top.
            let next = entries.iter().rev().find(|entry| {
                entry.point == point
                    && match current {
                        Some(parent) => entry.parent == parent && entry.id != parent,
                        None => entry.id == entry.parent || !ids.contains(&entry.parent),
                    }
            });
            let Some(next) = next else { break };
            if !visited.insert(next.id) {
                return Err(malformed());
            }
            current = Some(next.id);
            shared = next.shared;
            depth += 1;
        }
        if ancestor == path {
            count = depth;
        }
    }
    if current.is_none() {
        return Err(malformed());
    }
    Ok((count, shared))
}

#[cfg(test)]
mod tests {
    use super::*;

    // Host evidence: the copy parented by /run (35) is hidden by /run/netns (59).
    const HOST: &str = "35 1 0:29 / /run rw shared:12 - tmpfs tmpfs rw\n\
        59 35 0:29 /netns /run/netns rw,nosuid,nodev shared:12 - tmpfs tmpfs rw,size=1624600k,nr_inodes=819200,mode=755,inode64\n\
        229 59 0:5 net:[4026532276] /run/netns/wan rw shared:324 - nsfs nsfs rw\n\
        230 35 0:5 net:[4026532276] /run/netns/wan rw shared:324 - nsfs nsfs rw\n\
        479 59 0:5 net:[4026532579] /run/netns/scupper rw shared:418 - nsfs nsfs rw\n\
        480 35 0:5 net:[4026532579] /run/netns/scupper rw shared:418 - nsfs nsfs rw\n";

    #[test]
    fn propagated_peers_are_one_mount_but_mount_on_mount_is_two() -> io::Result<()> {
        let path = Path::new("/run/netns/scupper");
        assert_eq!(count(HOST, path)?, 1);
        assert_eq!(count(HOST, Path::new("/run/netns/wan"))?, 1);
        let stacked = format!("{HOST}481 479 0:5 net:[43] /run/netns/scupper rw - nsfs nsfs rw\n");
        assert_eq!(count(&stacked, path)?, 2);
        let siblings = format!("{HOST}481 59 0:5 net:[43] /run/netns/scupper rw - nsfs nsfs rw\n");
        assert_eq!(count(&siblings, path)?, 1);
        // A stack on the hidden peer is unreachable.
        let hidden = format!("{HOST}481 480 0:5 net:[43] /run/netns/scupper rw - nsfs nsfs rw\n");
        assert_eq!(count(&hidden, path)?, 1);
        // The restored host excerpt has the same shape and count.
        let restored = HOST.replace("479 59", "480 59").replace("480 35", "482 35");
        assert_eq!(count(&restored, path)?, 1);
        Ok(())
    }

    #[test]
    fn visible_parent_chain_excludes_overmounted_ancestors() -> io::Result<()> {
        let path = Path::new("/run/netns/scupper");
        let info = format!("{HOST}600 59 0:1 / /run/netns rw - tmpfs tmpfs rw\n");
        assert_eq!(count(&info, path)?, 0);
        let info = format!(
            "{info}601 600 0:1 / /run/netns rw - tmpfs tmpfs rw\n\
            602 601 0:5 net:[42] /run/netns/scupper rw - nsfs nsfs rw\n"
        );
        assert_eq!(count(&info, path)?, 1);
        // Record order cannot change a parent/child stack.
        let reversed = info.lines().rev().collect::<Vec<_>>().join("\n");
        assert_eq!(count(&reversed, path)?, 1);
        Ok(())
    }

    #[test]
    fn exact_escaped_paths_and_malformed_input() -> io::Result<()> {
        let info = format!(
            "{HOST}500 59 0:5 net:[42] /run/netns/a\\040b\\011c\\012d\\134e rw - nsfs nsfs rw\n"
        );
        assert_eq!(count(&info, Path::new("/run/netns/a b\tc\nd\\e"))?, 1);
        assert_eq!(count(HOST, Path::new("/run/netns/scupper-other"))?, 0);
        for info in [
            "",
            "invalid",
            "x 1 0:1 / / rw - tmpfs tmpfs rw",
            &format!("{HOST}{HOST}"),
        ] {
            assert!(count(info, Path::new("/run/netns/scupper")).is_err());
        }
        Ok(())
    }

    #[test]
    fn mountinfo_read_rejects_oversize_instead_of_truncating() -> io::Result<()> {
        assert_eq!(read_capped(&b"small"[..])?, "small");
        assert!(read_capped(io::repeat(b'x').take(MAX_BYTES + 1)).is_err());
        assert_eq!(
            read_capped(io::repeat(b'x').take(MAX_BYTES))?.len() as u64,
            MAX_BYTES
        );
        Ok(())
    }
}
