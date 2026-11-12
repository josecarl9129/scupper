//! Deterministic, allow-listed ustar config bundles with validation before restore.
use crate::{
    fs::{Fs, RealFs},
    store::{Meta, VersionStore},
};
use scupper_core::config::{parse_site, validate};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs,
    io::{self, Read, Write},
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::atomic::{AtomicU64, Ordering},
};

/// Maximum sum of uncompressed member sizes.
pub const MAX_TOTAL: usize = 16 * 1024 * 1024;
/// Maximum size of a single archive member.
pub const MAX_MEMBER: usize = 1024 * 1024;
/// Maximum archive encoding size, including headers and padding.
pub const MAX_ARCHIVE: usize = 18 * 1024 * 1024;
type Members = BTreeMap<String, Vec<u8>>;
fn refused(message: &'static str) -> io::Error {
    io::Error::other(message)
}
fn hash(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}

/// Whether a member is in the exact bundle namespace. No normalization is used.
#[must_use]
pub fn allowed_member(name: &str) -> bool {
    if matches!(name, "MANIFEST" | "head" | "state.json") {
        return true;
    }
    name.strip_prefix("versions/")
        .and_then(|s| {
            s.strip_suffix(".toml")
                .or_else(|| s.strip_suffix(".meta.json"))
        })
        .is_some_and(|s| s.len() == 6 && s.bytes().all(|b| b.is_ascii_digit()) && s != "000000")
}
fn regular_read(path: &Path, limit: usize) -> io::Result<Vec<u8>> {
    use rustix::fs::{FileType, Mode, OFlags, fstat, open};
    check_directories(path.parent().ok_or_else(|| refused("missing parent"))?)?;
    let fd = open(
        path,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )?;
    let stat = fstat(&fd)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile
        || stat.st_size < 0
        || u64::try_from(stat.st_size).map_err(io::Error::other)? > limit as u64
    {
        return Err(refused("not a bounded regular file"));
    }
    let mut bytes = Vec::new();
    fs::File::from(fd)
        .take((limit + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        return Err(refused("file size limit"));
    }
    Ok(bytes)
}
fn check_directories(path: &Path) -> io::Result<()> {
    for parent in path.ancestors().filter(|p| !p.as_os_str().is_empty()) {
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.is_dir() || metadata.is_symlink() {
            return Err(refused("symlink or non-directory in path"));
        }
    }
    Ok(())
}

/// Reads a bounded regular bundle file without following symlinks.
/// # Errors
/// Refuses nonregular, symlinked, or oversized files.
pub fn read_bundle(path: &Path) -> io::Result<Vec<u8>> {
    regular_read(path, MAX_ARCHIVE)
}

/// Exports the committed store using only explicitly requested allow-listed files.
/// `None` exports the entire committed history; subsets must still be complete.
/// # Errors
/// Refuses unknown members, corrupt/incomplete history, or unsafe files.
pub fn export(root: &Path, requested: Option<&[String]>) -> io::Result<Vec<u8>> {
    if requested.is_some_and(|names| names.iter().any(|n| !allowed_member(n))) {
        return Err(refused("member outside bundle allow-list"));
    }
    check_directories(root)?;
    check_directories(&root.join("config/versions"))?;
    let store = VersionStore::read_only(root, root);
    let head = store
        .head()
        .map_err(io::Error::other)?
        .ok_or_else(|| refused("missing head"))?;
    if head > 999_999 {
        return Err(refused("version exceeds bundle namespace"));
    }
    let mut names = vec!["head".to_owned(), "state.json".to_owned()];
    for n in 1..=head {
        names.extend([
            format!("versions/{n:06}.toml"),
            format!("versions/{n:06}.meta.json"),
        ]);
    }
    if let Some(requested) = requested {
        let mut requested = requested.to_vec();
        requested.sort();
        requested.dedup();
        names.sort();
        if requested != names {
            return Err(refused("bundle must contain complete committed history"));
        }
    }
    let mut members = Members::new();
    let mut total = 0;
    for name in names {
        let path = if name == "state.json" {
            root.join(&name)
        } else {
            root.join("config").join(&name)
        };
        let bytes = regular_read(&path, MAX_MEMBER)?;
        total += bytes.len();
        if total > MAX_TOTAL {
            return Err(refused("total size limit"));
        }
        members.insert(name, bytes);
    }
    validate_members(&members)?;
    let mut manifest = String::new();
    for (name, bytes) in &members {
        manifest.push_str(&hash(bytes));
        manifest.push_str("  ");
        manifest.push_str(name);
        manifest.push('\n');
    }
    members.insert("MANIFEST".into(), manifest.into_bytes());
    encode(&members)
}

fn octal(field: &mut [u8], n: usize) -> io::Result<()> {
    let value = format!("{n:0width$o}", width = field.len() - 1);
    if value.len() >= field.len() {
        return Err(refused("tar numeric overflow"));
    }
    field.fill(0);
    field[..value.len()].copy_from_slice(value.as_bytes());
    Ok(())
}
fn encode(members: &Members) -> io::Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut total = 0;
    for (name, bytes) in members {
        total += bytes.len();
        if !allowed_member(name) || bytes.len() > MAX_MEMBER || total > MAX_TOTAL {
            return Err(refused("bundle member or size refused"));
        }
        let mut header = [0_u8; 512];
        header[..name.len()].copy_from_slice(name.as_bytes());
        octal(&mut header[100..108], 0o640)?;
        octal(&mut header[108..116], 0)?;
        octal(&mut header[116..124], 0)?;
        octal(&mut header[124..136], bytes.len())?;
        octal(&mut header[136..148], 0)?;
        header[148..156].fill(b' ');
        header[156] = b'0';
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        let sum: usize = header.iter().map(|b| usize::from(*b)).sum();
        let checksum = format!("{sum:06o}\0 ");
        header[148..156].copy_from_slice(checksum.as_bytes());
        out.extend(header);
        out.extend(bytes);
        out.resize(out.len().next_multiple_of(512), 0);
    }
    out.resize(out.len() + 1024, 0);
    if out.len() > MAX_ARCHIVE {
        return Err(refused("archive size limit"));
    }
    Ok(out)
}
fn number(field: &[u8]) -> io::Result<usize> {
    let text = std::str::from_utf8(field)
        .map_err(|_| refused("invalid tar number"))?
        .trim_matches(['\0', ' ']);
    if text.is_empty() || !text.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
        return Err(refused("invalid tar number"));
    }
    usize::from_str_radix(text, 8).map_err(|_| refused("invalid tar number"))
}
fn decode(bytes: &[u8]) -> io::Result<Members> {
    if bytes.len() > MAX_ARCHIVE || !bytes.len().is_multiple_of(512) {
        return Err(refused("invalid archive size"));
    }
    let mut members = Members::new();
    let mut cursor = 0;
    let mut total = 0_usize;
    while let Some(header) = bytes.get(cursor..cursor + 512) {
        if header.iter().all(|b| *b == 0) {
            if bytes.len() - cursor < 1024 || bytes[cursor..].iter().any(|b| *b != 0) {
                return Err(refused("invalid tar trailer"));
            }
            return Ok(members);
        }
        let expected = number(&header[148..156])?;
        let sum: usize = header
            .iter()
            .enumerate()
            .map(|(i, b)| {
                if (148..156).contains(&i) {
                    usize::from(b' ')
                } else {
                    usize::from(*b)
                }
            })
            .sum();
        if expected != sum || &header[257..263] != b"ustar\0" || &header[263..265] != b"00" {
            return Err(refused("invalid ustar header"));
        }
        if !matches!(header[156], b'0' | 0)
            || header[157..257].iter().any(|b| *b != 0)
            || header[345..500].iter().any(|b| *b != 0)
        {
            return Err(refused("only regular unprefixed files allowed"));
        }
        let end = header[..100].iter().position(|b| *b == 0).unwrap_or(100);
        if header[end..100].iter().any(|b| *b != 0) {
            return Err(refused("invalid member name padding"));
        }
        let name =
            std::str::from_utf8(&header[..end]).map_err(|_| refused("invalid member name"))?;
        if !allowed_member(name) || members.contains_key(name) {
            return Err(refused("unknown or duplicate member"));
        }
        let size = number(&header[124..136])?;
        total = total
            .checked_add(size)
            .ok_or_else(|| refused("total size overflow"))?;
        if size > MAX_MEMBER || total > MAX_TOTAL {
            return Err(refused("bundle size limit"));
        }
        cursor += 512;
        let padded = size.next_multiple_of(512);
        let data = bytes
            .get(cursor..cursor + padded)
            .ok_or_else(|| refused("truncated member"))?;
        if data[size..].iter().any(|b| *b != 0) {
            return Err(refused("invalid member padding"));
        }
        members.insert(name.into(), data[..size].to_vec());
        cursor += padded;
    }
    Err(refused("missing tar trailer"))
}
fn text<'a>(members: &'a Members, name: &str) -> io::Result<&'a str> {
    std::str::from_utf8(members.get(name).ok_or_else(|| refused("missing member"))?)
        .map_err(|_| refused("member must be UTF-8"))
}
fn validate_members(members: &Members) -> io::Result<()> {
    let raw_head = text(members, "head")?;
    let raw_head = raw_head.strip_suffix('\n').unwrap_or(raw_head);
    let head = raw_head
        .parse::<u64>()
        .map_err(|_| refused("invalid head"))?;
    if head == 0 || head > 999_999 || raw_head != head.to_string() {
        return Err(refused("invalid head"));
    }
    let expected = usize::try_from(head).map_err(io::Error::other)? * 2
        + 2
        + usize::from(members.contains_key("MANIFEST"));
    if members.len() != expected {
        return Err(refused(
            "head must name last version, complete history required",
        ));
    }
    let state: crate::state::State =
        serde_json::from_str(text(members, "state.json")?).map_err(|_| refused("invalid state"))?;
    if state.schema != 1 || state.applied_version.is_some_and(|n| n == 0 || n > head) {
        return Err(refused("invalid state schema or applied version"));
    }
    for n in 1..=head {
        let toml = text(members, &format!("versions/{n:06}.toml"))?;
        validate(parse_site(toml).map_err(|_| refused("invalid version schema"))?)
            .map_err(|_| refused("invalid version configuration"))?;
        let meta: Meta =
            serde_json::from_str(text(members, &format!("versions/{n:06}.meta.json"))?)
                .map_err(|_| refused("invalid version metadata"))?;
        if meta.parent != n.checked_sub(1).filter(|n| *n > 0)
            || meta.sha256 != hash(toml.as_bytes())
        {
            return Err(refused("nonlinear history or invalid version hash"));
        }
    }
    Ok(())
}
fn checked(bytes: &[u8]) -> io::Result<Members> {
    let members = decode(bytes)?;
    let mut manifest = BTreeMap::new();
    for line in text(&members, "MANIFEST")?.lines() {
        let (digest, name) = line
            .split_once("  ")
            .ok_or_else(|| refused("invalid manifest"))?;
        if !allowed_member(name)
            || name == "MANIFEST"
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            || manifest.insert(name, digest).is_some()
        {
            return Err(refused("invalid manifest entry"));
        }
    }
    if manifest.len() + 1 != members.len() {
        return Err(refused("manifest member mismatch"));
    }
    for (name, bytes) in &members {
        if name != "MANIFEST" && manifest.get(name.as_str()).copied() != Some(hash(bytes).as_str())
        {
            return Err(refused("manifest hash mismatch"));
        }
    }
    validate_members(&members)?;
    Ok(members)
}

/// Checks hashes, schema, state, linear history and the complete archive namespace.
/// Does not write any files.
/// # Errors
/// Refuses malformed or unsafe bundles.
pub fn verify(bytes: &[u8]) -> io::Result<()> {
    checked(bytes).map(|_| ())
}

fn empty_target(target: &Path) -> io::Result<()> {
    let parent = target
        .parent()
        .ok_or_else(|| refused("missing target parent"))?;
    check_directories(if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    })?;
    match fs::symlink_metadata(target) {
        Ok(metadata) if metadata.is_dir() && !metadata.is_symlink() => {
            if fs::read_dir(target)?.next().is_some() {
                return Err(refused("restore target is not empty"));
            }
            Ok(())
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        _ => Err(refused(
            "restore target must be an absent or empty directory",
        )),
    }
}

struct Staging(PathBuf);
impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
/// Restores a validated bundle into an absent or empty store root by atomic rename.
/// All content is synchronized in a fresh sibling staging directory first.
/// # Errors
/// Refuses any invalid bundle, nonempty/symlinked target, or filesystem failure.
pub fn restore(bytes: &[u8], target: &Path) -> io::Result<()> {
    static NEXT: AtomicU64 = AtomicU64::new(0);
    let members = checked(bytes)?;
    empty_target(target)?;
    let parent = target
        .parent()
        .ok_or_else(|| refused("missing target parent"))?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let stage = loop {
        let path = parent.join(format!(
            ".scupper-bundle-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => break Staging(path),
            Err(e) if e.kind() == io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e),
        }
    };
    fs::create_dir(stage.0.join("config"))?;
    fs::create_dir(stage.0.join("config/versions"))?;
    for (name, content) in members {
        if name == "MANIFEST" {
            continue;
        }
        let path = if name == "state.json" {
            stage.0.join(name)
        } else {
            stage.0.join("config").join(name)
        };
        let mut file = fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o640)
            .open(path)?;
        file.write_all(&content)?;
        file.set_permissions(fs::Permissions::from_mode(0o640))?;
        file.sync_all()?;
    }
    for path in [
        stage.0.join("config/versions"),
        stage.0.join("config"),
        stage.0.clone(),
    ] {
        RealFs.sync_dir(&path)?;
    }
    empty_target(target)?;
    fs::rename(&stage.0, target)?;
    RealFs.sync_dir(parent)
}

use std::os::unix::fs::DirBuilderExt;
