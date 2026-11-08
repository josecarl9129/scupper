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
    pub fn cleanup(&mut self, runner: &mut Runner) -> Result<()> {
        runner.cleanup = true;
        runner.whole = Instant::now() + Duration::from_secs(90);
        runner.phase = runner.whole;
        let mut failures = Vec::new();
        while let Some(resource) = self.resources.pop() {
            let outcome: Result<()> = (|| {
                match &resource {
                    Resource::Namespace(ns) => {
                        if PathBuf::from(format!("/run/netns/{ns}")).exists() {
                            runner.run(&Invocation::new("", "ip", &["netns", "delete", ns]))?;
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
            Ok(())
        } else {
            super::fail(failures.join("; "))
        }
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::sync::{Arc, atomic::AtomicBool};
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
