//! Namespace probe protocol and bounded parent execution.
//!
//! The request is one JSON argv argument; stdin exclusively carries a duplicated
//! held namespace descriptor. The parent uses `File::try_clone` and
//! `Stdio::from(file)`, without raw-fd ownership tricks or a request on stdin.
//!
//! The fresh executable stays synchronous throughout. Before namespace entry it
//! parses the local `scupper-probe` passwd/group entries (or accepts injected
//! numeric IDs), disables core dumps with a hard and soft `RLIMIT_CORE` of zero,
//! and verifies its task count. It then fstats stdin, checks the held device/inode
//! identity against the request and rejects caller/PID-1 namespaces. After a
//! second task-count check it calls `move_into_link_name_space` with Network
//! (`CLONE_NEWNET`), creates one IPv4 UDP socket and two unconnected IPv4 TCP
//! sockets per HTTPS target (maximum four), applying `SO_BINDTODEVICE` only when
//! requested. No name resolution is needed to create these sockets.
//!
//! Next: `set_thread_groups(&[])`, `set_thread_res_gid(g,g,g)`, then
//! `set_thread_res_uid(u,u,u)`. Rustix 1.1.6 has no safe getresuid/getresgid
//! wrappers. With unsafe code and additional crates forbidden, readback uses
//! `/proc/thread-self/status`: real, effective, saved and filesystem IDs must
//! all equal the requested nonzero IDs; groups and inheritable, permitted,
//! effective and ambient capabilities must be empty. Any failure stops before
//! network parsing. This is the explicit deviation from syscall-based readback.
//! Finally repeat `RLIMIT_CORE=0` and `set_dumpable_behavior(NotDumpable)` because
//! changing IDs can reset dumpability. Only then generate a DNS transaction ID
//! with `rustix::rand::getrandom`, parse DNS, connect the pre-created TCP sockets,
//! perform TLS with SNI/webpki roots, and parse HTTP with the M1 implementation.
//!
//! Requests allow one or two hostname HTTPS URLs, port 443 only, two A addresses
//! per target, IPv4 only for both bound and unbound probes. A zero deadline means
//! 3 seconds for Path or 8 seconds for `ExitIp`; explicit budgets may not exceed
//! 8 seconds. DNS accepts up to 512 bytes, one matching IN/A question and at most
//! eight in-response CNAME links, with no EDNS, TCP fallback or host resolver.
//! Each classified outcome is one JSON line with exit status zero; invalid
//! request JSON, output errors and other protocol errors use a nonzero status.
//! The parent permits one extra second and uses the exec layer's bounded
//! capture and process-group kill/reaping on timeout.

mod child;
mod exit_dns;

use crate::{
    netns::{NetnsHandle, NetnsId},
    probe::Target,
    rules::IfName,
    system::{ExecError, ExecOutput, RealSystem},
    verdict::{Probe, ProbeError},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::File,
    net::{IpAddr, Ipv4Addr},
    time::Duration,
};

/// Maximum JSON request size, checked before deserialization.
pub const MAX_REQUEST: usize = 16 * 1024;

/// Kind of namespace observation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProbeKind {
    /// Resolve the first target with a three-second default budget.
    Path,
    /// Resolve and fetch HTTPS targets with an eight-second default budget.
    ExitIp,
}

/// A validated HTTPS probe URL with a DNS host and the fixed TLS port 443.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "String", into = "String")]
pub struct Url(String);
impl Url {
    /// Validates URL syntax without resolving anything.
    ///
    /// # Errors
    /// Rejects non-HTTPS, credentials, fragments, invalid hosts and other ports.
    pub fn new(text: &str) -> Probe<Self> {
        let url = Self(text.into());
        url.target()?;
        Ok(url)
    }
    fn target(&self) -> Probe<Target> {
        let rest = self
            .0
            .strip_prefix("https://")
            .ok_or_else(|| ProbeError::setup("probe URL must use HTTPS"))?;
        if rest.contains('#') {
            return Err(ProbeError::setup("probe URL contains a fragment"));
        }
        let split = rest.find(['/', '?']).unwrap_or(rest.len());
        let host = rest[..split].strip_suffix(":443").unwrap_or(&rest[..split]);
        let path = &rest[split..];
        let path = if path.is_empty() {
            "/".into()
        } else if path.starts_with('?') {
            format!("/{path}")
        } else {
            path.into()
        };
        Target::new(host, &path)
    }
}
impl TryFrom<String> for Url {
    type Error = ProbeError;
    fn try_from(text: String) -> Probe<Self> {
        Self::new(&text)
    }
}
impl From<Url> for String {
    fn from(url: Url) -> Self {
        url.0
    }
}

/// One bounded, IPv4-only probe. Numeric IDs are resolved before namespace entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeRequest {
    /// DNS-only or HTTPS observation.
    pub kind: ProbeKind,
    /// Standby interface; active observations leave sockets unbound.
    #[serde(with = "optional_ifname")]
    pub bind: Option<IfName>,
    /// Device and inode of the parent's held namespace.
    pub expected_netns: NetnsId,
    /// Exit provider DNS; host resolver configuration is never consulted.
    pub dns: Ipv4Addr,
    /// One or two ordered HTTPS targets, with two IPv4 attempts each.
    pub targets: Vec<Url>,
    /// Overall budget; zero selects the kind's default. Maximum eight seconds.
    #[serde(default)]
    pub deadline_ms: u64,
    /// Optional numeric account resolved by the parent. Otherwise the child reads
    /// the local passwd/group files before entering the namespace.
    #[serde(default)]
    pub identity: Option<ProbeIdentity>,
}
impl ProbeRequest {
    fn budget(&self) -> Probe<Duration> {
        if self.targets.is_empty() || self.targets.len() > 2 || self.deadline_ms > 8000 {
            return Err(ProbeError::setup(
                "probe requires 1..=2 targets and a budget <= 8000 ms",
            ));
        }
        Ok(Duration::from_millis(if self.deadline_ms == 0 {
            match self.kind {
                ProbeKind::Path => 3000,
                ProbeKind::ExitIp => 8000,
            }
        } else {
            self.deadline_ms
        }))
    }
}

/// Numeric dedicated account, injectable for isolated child tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeIdentity {
    /// Nonzero uid.
    pub uid: u32,
    /// Nonzero primary gid.
    pub gid: u32,
}
impl ProbeIdentity {
    /// Pure local account parser, with no NSS, subprocess or host resolver.
    ///
    /// # Errors
    /// Rejects missing, duplicate, malformed, root or mismatched account entries.
    pub fn parse(passwd: &str, group: &str) -> Probe<Self> {
        fn entry(text: &str) -> Probe<Vec<&str>> {
            let mut entries = text
                .lines()
                .filter(|line| line.split(':').next() == Some("scupper-probe"));
            let fields: Vec<_> = entries
                .next()
                .ok_or_else(|| ProbeError::setup("scupper-probe account missing"))?
                .split(':')
                .collect();
            if entries.next().is_some() {
                return Err(ProbeError::setup("duplicate scupper-probe account"));
            }
            Ok(fields)
        }
        let user = entry(passwd)?;
        let group = entry(group)?;
        let number = |field: Option<&&str>| {
            field
                .and_then(|s| s.parse::<u32>().ok())
                .filter(|id| *id != 0 && *id != u32::MAX)
                .ok_or_else(|| ProbeError::setup("invalid probe account id"))
        };
        let identity = Self {
            uid: number(user.get(2))?,
            gid: number(user.get(3))?,
        };
        if user.len() != 7 || group.len() != 4 || number(group.get(2))? != identity.gid {
            return Err(ProbeError::setup("probe account/group mismatch"));
        }
        Ok(identity)
    }
    fn validate(self) -> Probe<Self> {
        if [self.uid, self.gid]
            .iter()
            .any(|id| *id == 0 || *id == u32::MAX)
        {
            return Err(ProbeError::setup("probe account must be nonroot"));
        }
        Ok(self)
    }
}

/// Credentials recorded immediately before parsing network data. Each array
/// contains real, effective, saved and filesystem IDs from procfs.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeCredentials {
    /// Four verified nonzero uid values.
    pub uids: [u32; 4],
    /// Four verified nonzero gid values.
    pub gids: [u32; 4],
}

/// A completed observation, including classified failures (child exit status 0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProbeOutcome {
    /// Result retaining the M1 setup versus path distinction.
    pub result: ProbeResult,
    /// Present only after a successful privilege drop and verification.
    pub credentials: Option<ProbeCredentials>,
    /// Task count on the original child thread, before namespace entry.
    pub threads_before_setns: Option<usize>,
}
/// JSON-safe result classes; malformed responses and implausible IPv6 replies
/// over an IPv4 connection remain path failures, as in M1.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case")]
pub enum ProbeResult {
    /// DNS succeeded; HTTPS additionally reports its observed IPv4 address.
    Success {
        /// Observed exit address, absent for DNS-only probes.
        ip: Option<IpAddr>,
    },
    /// Local setup failure.
    Setup {
        /// Bounded diagnostic.
        message: String,
    },
    /// Network, DNS, TLS or HTTP failure.
    Path {
        /// Bounded diagnostic.
        message: String,
    },
    /// Shared overall deadline expired.
    Timeout,
}
impl ProbeResult {
    fn from_probe(result: Probe<Option<IpAddr>>) -> Self {
        match result {
            Ok(ip) => Self::Success { ip },
            Err(ProbeError::Setup(message)) => Self::Setup { message },
            Err(ProbeError::Timeout) => Self::Timeout,
            Err(error) => Self::Path {
                message: error.to_string().chars().take(200).collect(),
            },
        }
    }
    /// Restores the observation class across the process boundary.
    ///
    /// # Errors
    /// Returns the child's bounded setup/path error or timeout.
    pub fn into_probe(self) -> Probe<Option<IpAddr>> {
        match self {
            Self::Success { ip } => Ok(ip),
            Self::Setup { message } => Err(ProbeError::setup(&message)),
            Self::Path { message } => Err(ProbeError::io(&message)),
            Self::Timeout => Err(ProbeError::Timeout),
        }
    }
}

/// Runs the hidden child with a single JSON argv argument and stdin netns fd.
/// This entry point must be called on the executable's original single thread.
///
/// # Errors
/// Only invalid request JSON returns an internal/protocol error. Classified
/// setup and path failures are returned as outcomes, suitable for exit status 0.
pub fn child_main(json: &str) -> Result<ProbeOutcome, String> {
    if json.len() > MAX_REQUEST {
        return Err("probe request too large".into());
    }
    let request: ProbeRequest =
        serde_json::from_str(json).map_err(|error| format!("probe request: {error}"))?;
    Ok(child::run(&request))
}

/// Injectable parent execution; implementations must bound output and kill the
/// whole process group on timeout, including descendants holding output pipes.
pub trait ProbeExec {
    /// Executes `/proc/self/exe probe <request>` with the namespace as stdin.
    ///
    /// # Errors
    /// Returns spawn, capture or process-group timeout errors.
    fn execute_probe(
        &self,
        json: &str,
        namespace: File,
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError>;
}
impl ProbeExec for RealSystem {
    fn execute_probe(
        &self,
        json: &str,
        namespace: File,
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        let mut command = std::process::Command::new("/proc/self/exe");
        command.args(["probe", json]);
        crate::system::execute_file_command(command, namespace, timeout)
    }
}

/// Verifies the held namespace, duplicates its descriptor onto child stdin and
/// captures one JSON outcome within the probe budget plus one second.
///
/// # Errors
/// Returns setup for invalid wiring, child/protocol errors and capture failures;
/// timeout remains a path timeout. Classified child failures stay in the outcome.
pub fn run_probe(
    exec: &dyn ProbeExec,
    handle: &NetnsHandle,
    request: &ProbeRequest,
) -> Probe<ProbeOutcome> {
    let budget = request.budget()?;
    handle
        .verify(request.expected_netns)
        .map_err(|error| ProbeError::setup(&error.to_string()))?;
    let file = handle
        .try_clone_file()
        .map_err(|error| ProbeError::setup(&error.to_string()))?;
    execute(exec, file, request, budget)
}
fn execute(
    exec: &dyn ProbeExec,
    file: File,
    request: &ProbeRequest,
    budget: Duration,
) -> Probe<ProbeOutcome> {
    let json =
        serde_json::to_string(request).map_err(|error| ProbeError::setup(&error.to_string()))?;
    let output = exec
        .execute_probe(&json, file, budget + Duration::from_secs(1))
        .map_err(|error| match error {
            ExecError::Timeout { .. } => ProbeError::Timeout,
            _ => ProbeError::setup(&error.to_string()),
        })?;
    if output.status != Some(0) {
        return Err(ProbeError::setup(&format!(
            "probe child failed: {}",
            output.stderr
        )));
    }
    serde_json::from_str(&output.stdout)
        .map_err(|error| ProbeError::setup(&format!("probe outcome: {error}")))
}

mod optional_ifname {
    use super::{Deserialize, IfName, Serialize};
    #[allow(clippy::ref_option)] // serde field adapter requires &Option<T>.
    pub fn serialize<S: serde::Serializer>(
        name: &Option<IfName>,
        serializer: S,
    ) -> Result<S::Ok, S::Error> {
        name.as_ref().map(IfName::as_str).serialize(serializer)
    }
    pub fn deserialize<'de, D: serde::Deserializer<'de>>(
        deserializer: D,
    ) -> Result<Option<IfName>, D::Error> {
        Option::<String>::deserialize(deserializer)?
            .map(|name| IfName::new(&name).map_err(serde::de::Error::custom))
            .transpose()
    }
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use std::{cell::RefCell, os::unix::fs::MetadataExt, process::Command, time::Instant};
    fn request() -> ProbeRequest {
        ProbeRequest {
            kind: ProbeKind::Path,
            bind: None,
            expected_netns: (1, 2),
            dns: Ipv4Addr::new(10, 2, 0, 1),
            targets: vec![Url::new("https://probe.test/").unwrap()],
            deadline_ms: 20,
            identity: Some(ProbeIdentity { uid: 99, gid: 98 }),
        }
    }
    struct Fake {
        calls: RefCell<Vec<(String, NetnsId, Duration)>>,
        output: RefCell<Option<Result<ExecOutput, ExecError>>>,
    }
    impl ProbeExec for Fake {
        fn execute_probe(
            &self,
            json: &str,
            file: File,
            timeout: Duration,
        ) -> Result<ExecOutput, ExecError> {
            let stat = file.metadata().unwrap();
            self.calls
                .borrow_mut()
                .push((json.into(), (stat.dev(), stat.ino()), timeout));
            self.output.borrow_mut().take().unwrap()
        }
    }
    #[test]
    fn parent_wires_json_and_namespace_file_and_preserves_classification() {
        let file = File::open("/proc/self/ns/net").unwrap();
        for result in [
            ProbeResult::Success { ip: None },
            ProbeResult::Setup {
                message: "bad bind".into(),
            },
            ProbeResult::Path {
                message: "bad TLS".into(),
            },
            ProbeResult::Timeout,
        ] {
            let outcome = ProbeOutcome {
                result,
                credentials: None,
                threads_before_setns: Some(1),
            };
            let fake = Fake {
                calls: RefCell::default(),
                output: RefCell::new(Some(Ok(ExecOutput {
                    status: Some(0),
                    stdout: serde_json::to_string(&outcome).unwrap(),
                    stderr: String::new(),
                }))),
            };
            assert_eq!(
                execute(
                    &fake,
                    file.try_clone().unwrap(),
                    &request(),
                    Duration::from_millis(20)
                )
                .unwrap(),
                outcome
            );
            let calls = fake.calls.borrow();
            assert_eq!(calls[0].2, Duration::from_millis(1020));
            let req: ProbeRequest = serde_json::from_str(&calls[0].0).unwrap();
            assert_eq!(req.expected_netns, (1, 2));
            assert_eq!(calls[0].1.1, file.metadata().unwrap().ino());
            let restored = outcome.result.into_probe();
            assert!(
                restored.is_ok()
                    || matches!(
                        restored,
                        Err(ProbeError::Setup(_) | ProbeError::Io(_) | ProbeError::Timeout)
                    )
            );
        }
        for output in [
            Ok(ExecOutput {
                status: Some(0),
                stdout: "{}".into(),
                stderr: String::new(),
            }),
            Ok(ExecOutput {
                status: Some(1),
                stdout: String::new(),
                stderr: "internal".into(),
            }),
        ] {
            let fake = Fake {
                calls: RefCell::default(),
                output: RefCell::new(Some(output)),
            };
            assert!(matches!(
                execute(
                    &fake,
                    file.try_clone().unwrap(),
                    &request(),
                    Duration::from_millis(20)
                ),
                Err(ProbeError::Setup(_))
            ));
        }
        let fake = Fake {
            calls: RefCell::default(),
            output: RefCell::new(Some(Err(ExecError::Timeout {
                after: Duration::from_millis(1),
            }))),
        };
        assert!(matches!(
            execute(&fake, file, &request(), Duration::from_millis(20)),
            Err(ProbeError::Timeout)
        ));
    }
    #[test]
    fn real_argv_stdin_wiring_and_process_group_timeout() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir =
            std::env::current_dir()?.join(format!("target/probe-child-{}", std::process::id()));
        std::fs::create_dir_all(&dir)?;
        let file_path = dir.join("namespace");
        std::fs::write(&file_path, b"namespace fd")?;
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "test \"$1\" = probe && test \"$2\" = '{\"kind\":\"Path\"}' && cat",
            "fixture",
            "probe",
            r#"{"kind":"Path"}"#,
        ]);
        let output = crate::system::execute_file_command(
            command,
            File::open(&file_path)?,
            Duration::from_secs(2),
        )?;
        assert_eq!(output.status, Some(0));
        assert_eq!(output.stdout, "namespace fd");
        let mut command = Command::new("/bin/sh");
        command
            .args(["-c", "sleep 1; touch \"$1\"", "fixture"])
            .arg(dir.join("survived"));
        let started = Instant::now();
        assert!(matches!(
            crate::system::execute_file_command(
                command,
                File::open(&file_path)?,
                Duration::from_millis(30)
            ),
            Err(ExecError::Timeout { .. })
        ));
        assert!(started.elapsed() < Duration::from_secs(1));
        std::thread::sleep(Duration::from_millis(1100));
        assert!(!dir.join("survived").exists());
        std::fs::remove_dir_all(dir)?;
        Ok(())
    }
    #[test]
    fn validates_local_accounts_urls_budgets_and_bind_names() {
        assert_eq!(
            ProbeIdentity::parse(
                "scupper-probe:x:99:98::/:/sbin/nologin",
                "scupper-probe:x:98:"
            )
            .unwrap(),
            ProbeIdentity { uid: 99, gid: 98 }
        );
        for passwd in [
            "",
            "scupper-probe:x:0:98::/:/sbin/nologin",
            "scupper-probe:x:99:98::/:/sbin/nologin\nscupper-probe:x:99:98::/:/sbin/nologin",
        ] {
            assert!(ProbeIdentity::parse(passwd, "scupper-probe:x:98:").is_err());
        }
        for url in [
            "http://probe.test/",
            "https://user@probe.test/",
            "https://probe.test:444/",
            "https://probe.test/#fragment",
            "https://probe.test/\r\ninjected",
        ] {
            assert!(Url::new(url).is_err());
        }
        assert!(Url::new("https://probe.test:443?query").is_ok());
        let mut req = request();
        req.targets.clear();
        assert!(req.budget().is_err());
        req = request();
        req.deadline_ms = 8001;
        assert!(req.budget().is_err());
        req = request();
        req.targets = vec![req.targets[0].clone(); 3];
        assert!(req.budget().is_err());
        let json = serde_json::to_string(&request())
            .unwrap()
            .replace("\"bind\":null", "\"bind\":\"bad name\"");
        assert!(serde_json::from_str::<ProbeRequest>(&json).is_err());
    }
}
