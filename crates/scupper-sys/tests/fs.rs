//! Shared filesystem protections retained after retiring the v1 apply driver.
use scupper_sys::fs::{Fs, RealFs};
use std::{
    fs, io,
    os::unix::fs::symlink,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
struct Directory(PathBuf);
impl Directory {
    fn new() -> io::Result<Self> {
        static NEXT: AtomicU64 = AtomicU64::new(0);
        let directory = Self(
            std::env::var_os("CARGO_TARGET_TMPDIR")
                .map_or_else(
                    || {
                        std::path::PathBuf::from(concat!(
                            env!("CARGO_MANIFEST_DIR"),
                            "/../../target/tmp"
                        ))
                    },
                    std::path::PathBuf::from,
                )
                .join(format!(
                    "scupper-fs-{}-{}",
                    std::process::id(),
                    NEXT.fetch_add(1, Ordering::Relaxed)
                )),
        );
        fs::create_dir(&directory.0)?;
        Ok(directory)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn real_fs_refuses_symlinked_target_without_following_or_replacing_it() -> io::Result<()> {
    for dangling in [false, true] {
        let disk = Directory::new()?;
        let victim = disk.0.join("victim");
        if !dangling {
            fs::write(&victim, "keep this file")?;
        }
        let destination = disk.0.join("state.json");
        symlink(&victim, &destination)?;
        assert!(RealFs.read(&destination).is_err());
        assert!(RealFs.check_target(&destination).is_err());
        let (source, file) = RealFs.create_temp(&disk.0)?;
        drop(file);
        assert!(RealFs.rename(&source, &destination).is_err());
        assert!(source.exists());
        assert_eq!(fs::read_link(destination)?, victim);
        if dangling {
            assert!(!victim.exists());
        } else {
            assert_eq!(fs::read_to_string(victim)?, "keep this file");
        }
    }
    Ok(())
}
#[test]
fn real_fs_cleans_only_matching_regular_stale_files() -> io::Result<()> {
    let disk = Directory::new()?;
    for name in [".scupper-123-0.tmp", ".scupper-456-987.tmp"] {
        fs::write(disk.0.join(name), "stale")?;
    }
    let preserved = [
        "other.tmp",
        ".scupper-.tmp",
        ".scupper-1.tmp",
        ".scupper-1-.tmp",
        ".scupper--2.tmp",
        ".scupper-one-2.tmp",
        ".scupper-1-2.tmp.bak",
        ".scupper-1-2-3.tmp",
    ];
    for name in preserved {
        fs::write(disk.0.join(name), "keep")?;
    }
    let subdir = disk.0.join(".scupper-789-0.tmp");
    fs::create_dir(&subdir)?;
    let link = disk.0.join(".scupper-789-1.tmp");
    symlink(disk.0.join("other.tmp"), &link)?;
    RealFs.cleanup_stale(&disk.0)?;
    assert!(!disk.0.join(".scupper-123-0.tmp").exists());
    assert!(!disk.0.join(".scupper-456-987.tmp").exists());
    for name in preserved {
        assert_eq!(fs::read_to_string(disk.0.join(name))?, "keep");
    }
    assert!(subdir.is_dir());
    assert!(fs::symlink_metadata(link)?.is_symlink());
    Ok(())
}
