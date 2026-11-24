//! Protection of evidence paths shared by every qualification subcommand.
use std::{fs, io, os::unix::fs::MetadataExt, path::Path};

fn metadata(path: &Path) -> io::Result<fs::Metadata> {
    fs::symlink_metadata(path)
        .map_err(|error| io::Error::new(error.kind(), format!("{}: {error}", path.display())))
}

pub(super) fn protected_path(path: &Path, directory: bool) -> io::Result<()> {
    if !path.is_absolute()
        || path.components().any(|component| {
            matches!(
                component,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(io::Error::other(format!(
            "{}: protected paths must be absolute without dot components",
            path.display()
        )));
    }
    for component in path.ancestors() {
        let meta = metadata(component)?;
        validate(component, &meta, component != path || directory)?;
    }
    Ok(())
}
fn validate(path: &Path, meta: &fs::Metadata, directory: bool) -> io::Result<()> {
    validate_owner(path, meta.uid())?;
    if meta.uid() != 0
        || meta.mode() & 0o022 != 0
        || (directory && !meta.is_dir())
        || (!directory && !meta.is_file())
    {
        return Err(io::Error::other(format!(
            "{} must be root-owned, non-writable by other users, and a regular {}",
            path.display(),
            if directory { "directory" } else { "file" }
        )));
    }
    Ok(())
}

fn validate_owner(path: &Path, uid: u32) -> io::Result<()> {
    if uid == 0 {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{}: non-root owner", path.display()),
        ))
    }
}

pub(super) fn sweep(out: &Path) -> io::Result<()> {
    sweep_with(out, |path| {
        let meta = metadata(path)?;
        // The mount root has filesystem-selected metadata; its parent is protected.
        if path.file_name().is_some_and(|name| name == "storage-mount") && meta.is_dir() {
            return Ok(());
        }
        protected_path(path, meta.is_dir())
    })
}
fn sweep_with(out: &Path, mut inspect: impl FnMut(&Path) -> io::Result<()>) -> io::Result<()> {
    for entry in fs::read_dir(out)
        .map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", out.display())))?
    {
        let entry =
            entry.map_err(|e| io::Error::new(e.kind(), format!("{}: {e}", out.display())))?;
        let path = entry.path();
        match inspect(&path) {
            Ok(()) => (),
            Err(error) if error.kind() == io::ErrorKind::NotFound => (),
            Err(error) => {
                return Err(io::Error::new(
                    error.kind(),
                    format!("{}: {error}", path.display()),
                ));
            }
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    #[test]
    fn sweep_skips_vanished_entries_but_refuses_other_errors() -> io::Result<()> {
        let root = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map(std::path::PathBuf::from)
            .or_else(|| {
                std::env::var_os("CARGO_TARGET_DIR")
                    .map(|path| std::path::PathBuf::from(path).join("tmp"))
            })
            .unwrap_or_else(std::env::temp_dir)
            .join(format!("sweep-{}", std::process::id()));
        fs::create_dir_all(&root)?;
        let vanished = root.join("bootstrap.tmp");
        fs::write(&vanished, b"temporary")?;
        let result = sweep_with(&root, |path| {
            fs::remove_file(path)?; // Inject after readdir, before lstat.
            metadata(path).map(|_| ())
        });
        assert!(
            result.is_ok(),
            "assertion: vanished entry must be skipped: {result:?}"
        );
        fs::write(root.join("planted"), b"untrusted")?;
        let result = sweep_with(&root, |path| validate_owner(path, 501));
        assert!(result.unwrap_err().to_string().contains("planted"));
        let result = sweep_with(&root, |path| validate(path, &metadata(path)?, false));
        // A writable planted entry is refused even when the tests run as root.
        fs::set_permissions(root.join("planted"), fs::Permissions::from_mode(0o666))?;
        assert!(sweep_with(&root, |path| validate(path, &metadata(path)?, false)).is_err());
        drop(result);
        assert!(sweep(&root).is_err());
        fs::remove_dir_all(root)?;
        Ok(())
    }
}
