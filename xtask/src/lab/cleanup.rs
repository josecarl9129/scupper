//! Ownership registry. Register only successful, exclusive creations.
use super::{
    Result,
    command::{Invocation, Runner},
};
use std::{
    fs,
    path::PathBuf,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Resource {
    Namespace(String),
    User(String),
    Link(String),
    Directory(PathBuf),
}
#[derive(Default)]
pub(super) struct Registry {
    resources: Vec<Resource>,
}
impl Registry {
    // Call immediately after successful exclusive creation. A failed create never grants ownership.
    pub fn register(&mut self, resource: Resource) {
        if !self.resources.contains(&resource) {
            self.resources.push(resource);
        }
    }
    pub fn unregister(&mut self, resource: &Resource) {
        self.resources.retain(|owned| owned != resource);
    }
    pub fn cleanup(&mut self, runner: &mut Runner) -> Result<Vec<String>> {
        runner.cleanup = true;
        runner.whole = Instant::now() + Duration::from_secs(90);
        runner.phase = runner.whole;
        let mut failures = Vec::new();
        let mut reports = Vec::new();
        while let Some(resource) = self.resources.pop() {
            let outcome: Result<()> = (|| {
                match &resource {
                    Resource::User(user) => {
                        runner.run(&Invocation::new("", "userdel", &[user]))?;
                        if fs::read_to_string("/etc/group")?
                            .lines()
                            .any(|line| line.split(':').next() == Some(user.as_str()))
                        {
                            runner.run(&Invocation::new("", "groupdel", &[user]))?;
                        }
                    }
                    Resource::Namespace(ns) => {
                        let path = format!("/run/netns/{ns}");
                        let mounts = || -> Result<usize> {
                            Ok(super::mounts::count(
                                &scupper_sys::netns::mountinfo::read("/proc/self/mountinfo")?,
                                &path,
                            )?)
                        };
                        let count = mounts()?;
                        if count > 1 {
                            reports.push(format!("{path}: tolerated {count} stacked mounts"));
                            let detached = drain_mounts(mounts, || {
                                runner.run(&Invocation::new("", "umount", &["--lazy", &path]))?;
                                Ok(())
                            })?;
                            reports
                                .push(format!("{path}: detached {detached} mounts before delete"));
                        }
                        if PathBuf::from(&path).exists() {
                            runner.run(&Invocation::new("", "ip", &["netns", "delete", ns]))?;
                            if mounts()? != 0 || PathBuf::from(&path).exists() {
                                return super::fail("namespace name survived deletion");
                            }
                        }
                    }
                    Resource::Link(link) => {
                        let show = Invocation::new("", "ip", &["link", "show", "dev", link]);
                        if runner.output(&show, None)?.0.success() {
                            let deleted = runner
                                .output(
                                    &Invocation::new("", "ip", &["link", "delete", link]),
                                    None,
                                )?
                                .0
                                .success();
                            // A veth can vanish between show and delete as its peer
                            // namespace tears down. Only a still-present link fails.
                            if !deleted && runner.output(&show, None)?.0.success() {
                                return super::fail("staging veth survived deletion");
                            }
                        }
                    }
                    Resource::Directory(path) => {
                        if path.exists() {
                            fs::remove_dir_all(path)?;
                        }
                    }
                }
                Ok(())
            })();
            if let Err(error) = outcome {
                failures.push(format!("{resource:?}: {error}"));
            }
        }
        if failures.is_empty() {
            Ok(reports)
        } else {
            super::fail([reports.join("; "), failures.join("; ")].join("; "))
        }
    }
}

fn drain_mounts(
    mut count: impl FnMut() -> Result<usize>,
    mut detach: impl FnMut() -> Result<()>,
) -> Result<usize> {
    let mut detached = 0;
    while count()? != 0 {
        if detached == 64 {
            return super::fail("namespace mounts did not drain after 64 detaches");
        }
        detach()?;
        detached += 1;
    }
    Ok(detached)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicBool};

    #[test]
    fn stacked_mount_cleanup_drains_every_layer_and_bounds_nonprogress() {
        let mounts = std::cell::Cell::new(3);
        assert_eq!(
            drain_mounts(
                || Ok(mounts.get()),
                || {
                    mounts.set(mounts.get() - 1);
                    Ok(())
                }
            )
            .unwrap(),
            3
        );
        assert_eq!(
            drain_mounts(|| Ok(0), || super::super::fail("unexpected detach")).unwrap(),
            0
        );
        assert!(drain_mounts(|| Ok(2), || Ok(())).is_err());
        assert!(drain_mounts(|| Ok(2), || super::super::fail("detach failed")).is_err());
        assert!(drain_mounts(|| super::super::fail("mountinfo unreadable"), || Ok(())).is_err());
    }
    #[test]
    fn successful_creation_deduplicates_and_cleans_idempotently() {
        let dir = std::env::current_dir()
            .unwrap()
            .join(format!("target/lab-registry-test-{}", std::process::id()));
        fs::create_dir_all(dir.parent().unwrap()).unwrap();
        let mut registry = Registry::default();
        fs::create_dir(&dir).unwrap();
        registry.register(Resource::Directory(dir.clone()));
        registry.register(Resource::Directory(dir.clone()));
        assert_eq!(registry.resources.len(), 1);
        assert!(dir.exists());
        registry.unregister(&Resource::Directory(dir.clone()));
        assert_eq!(registry.resources, []);
        registry.register(Resource::Directory(dir.clone()));
        let trace = fs::File::create(dir.join("trace")).unwrap();
        let mut runner = Runner::new(trace, Arc::new(AtomicBool::new(false)));
        registry.cleanup(&mut runner).unwrap();
        registry.cleanup(&mut runner).unwrap();
        assert!(!dir.exists());
    }
}
