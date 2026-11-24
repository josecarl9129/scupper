//! The one production executable path allowed for the disposable Q-E2E fixture.
use serde::{Deserialize, Serialize};
use std::{
    fs,
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    path::Path,
};

pub(super) const CHILD: &str = "/opt/scupper/wireguard-go";
const PARENTS: [&str; 2] = ["/opt", "/opt/scupper"];

#[derive(Clone, Debug, Deserialize, Serialize)]
pub(super) struct Record {
    pub kind: String,
    pub path: String,
    pub dev: u64,
    pub ino: u64,
}
impl Record {
    fn new(kind: &str, path: &Path, metadata: Option<&fs::Metadata>) -> Self {
        Self {
            kind: kind.into(),
            path: path.to_string_lossy().into_owned(),
            dev: metadata.map_or(0, MetadataExt::dev),
            ino: metadata.map_or(0, MetadataExt::ino),
        }
    }
}
pub(super) fn absent(path: &Path) -> io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(false),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(true),
        Err(error) => Err(io::Error::new(
            error.kind(),
            format!("{}: inspection failed: {error}", path.display()),
        )),
    }
}

#[cfg(target_os = "macos")]
pub(super) fn stage(
    bytes: &[u8],
    journal: impl FnMut(&Record) -> io::Result<()>,
) -> io::Result<()> {
    stage_at(
        Path::new(CHILD),
        &PARENTS.map(Path::new),
        bytes,
        journal,
        |path| super::evidence_path::protected_path(path, true),
    )
}
fn stage_at(
    target: &Path,
    parents: &[&Path],
    bytes: &[u8],
    mut journal: impl FnMut(&Record) -> io::Result<()>,
    mut protect: impl FnMut(&Path) -> io::Result<()>,
) -> io::Result<()> {
    if !absent(target)? {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("pinned child path already exists: {}", target.display()),
        ));
    }
    for parent in parents {
        if absent(parent)? {
            protect(
                parent
                    .parent()
                    .ok_or_else(|| io::Error::other("parent missing"))?,
            )?;
            journal(&Record::new("r7-child-dir-intent", parent, None))?;
            fs::DirBuilder::new().mode(0o755).create(parent)?;
            journal(&Record::new(
                "r7-child-dir-created",
                parent,
                Some(&fs::symlink_metadata(parent)?),
            ))?;
        }
        protect(parent)?;
    }
    protect(
        target
            .parent()
            .ok_or_else(|| io::Error::other("child parent missing"))?,
    )?;
    journal(&Record::new("r7-child-intent", target, None))?;
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o755)
        .open(target)?;
    journal(&Record::new(
        "r7-child-created",
        target,
        Some(&file.metadata()?),
    ))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

/// Restore only entries whose recorded creation identity still matches. Intent
/// alone grants no deletion authority; empty directories are removed last.
#[cfg(target_os = "macos")]
pub(super) fn restore(records: &[Record]) -> io::Result<()> {
    restore_at(records, Path::new(CHILD), &PARENTS.map(Path::new))
}
fn restore_at(records: &[Record], target: &Path, parents: &[&Path]) -> io::Result<()> {
    let mut failures = Vec::new();
    for row in records
        .iter()
        .rev()
        .filter(|r| matches!(r.kind.as_str(), "r7-child-created" | "r7-child-dir-created"))
    {
        let path = Path::new(&row.path);
        let directory = row.kind == "r7-child-dir-created";
        if (directory && !parents.contains(&path)) || (!directory && path != target) {
            failures.push(format!("refused child restore path: {}", path.display()));
            continue;
        }
        let result = (|| -> io::Result<()> {
            let metadata = match fs::symlink_metadata(path) {
                Ok(metadata) => metadata,
                Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(()),
                Err(e) => return Err(e),
            };
            if metadata.dev() != row.dev
                || metadata.ino() != row.ino
                || (directory && !metadata.is_dir())
                || (!directory && !metadata.is_file())
            {
                return Err(io::Error::other("creation identity changed; retained"));
            }
            if directory {
                fs::remove_dir(path)
            } else {
                fs::remove_file(path)
            }
        })();
        if let Err(error) = result {
            failures.push(format!("{}: {error}", path.display()));
        }
    }
    // An intent without a creation record may mean a crash after creation.
    // Retain it as unresolved instead of deleting an unproven entry.
    for row in records
        .iter()
        .filter(|r| matches!(r.kind.as_str(), "r7-child-intent" | "r7-child-dir-intent"))
    {
        if !absent(Path::new(&row.path))?
            && !records
                .iter()
                .any(|r| r.path == row.path && r.kind.ends_with("-created"))
        {
            failures.push(format!("unresolved creation intent: {}", row.path));
        }
    }
    if failures.is_empty() {
        Ok(())
    } else {
        Err(io::Error::other(failures.join("; ")))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::symlink;
    #[test]
    fn engine_child_path_and_only_its_parents_are_pinned() {
        assert_eq!(CHILD, crate::engine::CHILD_PATH);
        assert_eq!(PARENTS, ["/opt", "/opt/scupper"]);
    }
    #[test]
    fn staging_never_overwrites_an_existing_entry() -> io::Result<()> {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("CARGO_TARGET_DIR")
                    .map(|path| std::path::PathBuf::from(path).join("tmp"))
            })
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("child-existing-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        let target = root.join("child");
        for dangling in [false, true] {
            if dangling {
                symlink("missing", &target)?;
            } else {
                fs::write(&target, b"foreign")?;
            }
            let mut journal = Vec::new();
            let result = stage_at(
                &target,
                &[],
                b"replacement",
                |row| {
                    journal.push(row.clone());
                    Ok(())
                },
                |_| Ok(()),
            );
            assert!(result.is_err());
            assert!(journal.is_empty());
            if dangling {
                assert_eq!(fs::read_link(&target)?, Path::new("missing"));
            } else {
                assert_eq!(fs::read(&target)?, b"foreign");
            }
            fs::remove_file(&target)?;
        }
        fs::remove_dir(root)?;
        Ok(())
    }
    #[test]
    fn exclusive_create_closes_precheck_race_and_journals_before_mutation() -> io::Result<()> {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("CARGO_TARGET_DIR")
                    .map(|path| std::path::PathBuf::from(path).join("tmp"))
            })
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("child-race-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        let target = root.join("child");
        let result = stage_at(
            &target,
            &[],
            b"replacement",
            |row| {
                assert_eq!(row.kind, "r7-child-intent");
                assert!(absent(&target)?);
                fs::write(&target, b"racing foreign")
            },
            |_| Ok(()),
        );
        assert!(result.is_err());
        assert_eq!(fs::read(&target)?, b"racing foreign");
        fs::remove_dir_all(root)?;
        Ok(())
    }
    #[test]
    fn restore_only_removes_created_file_and_empty_created_directories() -> io::Result<()> {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("CARGO_TARGET_DIR")
                    .map(|path| std::path::PathBuf::from(path).join("tmp"))
            })
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("child-restore-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        let parent = root.join("scupper");
        let target = parent.join("child");
        let mut records = Vec::new();
        stage_at(
            &target,
            &[&parent],
            b"fixture",
            |row| {
                records.push(row.clone());
                Ok(())
            },
            |_| Ok(()),
        )?;
        assert_eq!(fs::read(&target)?, b"fixture");
        fs::write(parent.join("foreign"), b"retained")?;
        assert!(restore_at(&records, &target, &[&parent]).is_err());
        assert!(absent(&target)?);
        assert!(parent.join("foreign").is_file());
        fs::remove_file(parent.join("foreign"))?;
        restore_at(&records, &target, &[&parent])?;
        restore_at(&records, &target, &[&parent])?;
        assert!(absent(&parent)?);
        fs::remove_dir(root)?;
        Ok(())
    }
    #[test]
    fn inspection_failure_is_not_absence() -> io::Result<()> {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("CARGO_TARGET_DIR")
                    .map(|path| std::path::PathBuf::from(path).join("tmp"))
            })
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("child-inspect-{}", std::process::id()));
        fs::create_dir_all(
            root.parent()
                .ok_or_else(|| io::Error::other("test parent"))?,
        )?;
        fs::write(&root, b"not a directory")?;
        assert!(absent(&root.join("child")).is_err());
        fs::remove_file(root)?;
        Ok(())
    }
}
