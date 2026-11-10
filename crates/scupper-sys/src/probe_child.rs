//! Namespace probe protocol and bounded parent execution.
//!
//! The request is one JSON argv argument; stdin exclusively carries a duplicated
//! held namespace descriptor. The parent uses `File::try_clone` and
//! `Stdio::from(file)`, without raw-fd ownership tricks or a request on stdin.
//!
//! The fresh executable stays synchronous throughout. Before namespace entry it
//! parses the local `scupper-probe` passwd/group entries (or accepts injected
//! numeric IDs in testing builds), disables core dumps with a hard and soft
//! `RLIMIT_CORE` of zero, and verifies its task count. It then fstats stdin, checks the held device/inode
//! identity against the request and rejects caller/PID-1 namespaces. After a
//! second task-count check it calls `move_into_link_name_space` with Network
//! (`CLONE_NEWNET`), creates one IPv4 UDP socket and two unconnected IPv4 TCP
//! sockets per HTTPS target (maximum four), applying `SO_BINDTODEVICE` only when
//! requested. No name resolution is needed to create these sockets.
//!
//! After setns, replace stdin with `/dev/null` and release held namespace fds.
//! After socket creation, set `no_new_privs` and clear the capability bounding set.
//! Next: `set_thread_groups(&[])`, `set_thread_res_gid(g,g,g)`, then
//! `set_thread_res_uid(u,u,u)`. Rustix 1.1.6 has no safe getresuid/getresgid
//! wrappers. With unsafe code and additional crates forbidden, readback uses
//! `/proc/thread-self/status`: real, effective, saved and filesystem IDs must
//! all equal the requested nonzero IDs; groups and inheritable, permitted,
//! effective, ambient and bounding capabilities must be empty, with NoNewPrivs=1.
//! This is the explicit deviation from syscall-based readback. Any failure stops
//! before network parsing. Set SIGKILL as the parent-death signal after dropping IDs.
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
//! Each HTTPS target gets a deadline slice; DNS retransmits once after one second.
//! This changes only the network namespace: host `/run` remains visible (the L45
//! sandbox gap after a child compromise). No `RLIMIT_NPROC` is imposed because
//! concurrent children share the dedicated uid. Inheritable caps must be empty
//! on entry; unexpected inherited caps fail credential verification closed.
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
    /// Test-only numeric account. Production always reads local passwd/group files.
    #[cfg(feature = "testing")]
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
        let probe_group = entry(group)?;
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
        if user.len() != 7 || probe_group.len() != 4 || number(probe_group.get(2))? != identity.gid
        {
            return Err(ProbeError::setup("probe account/group mismatch"));
        }
        let shared_user = passwd.lines().any(|line| {
            let fields: Vec<_> = line.split(':').collect();
            fields.first() != Some(&"scupper-probe")
                && (fields.get(2).and_then(|id| id.parse::<u32>().ok()) == Some(identity.uid)
                    || fields.get(3).and_then(|id| id.parse::<u32>().ok()) == Some(identity.gid))
        });
        let shared_group = group.lines().any(|line| {
            let fields: Vec<_> = line.split(':').collect();
            fields.get(2).and_then(|id| id.parse::<u32>().ok()) == Some(identity.gid)
                && (fields.first() != Some(&"scupper-probe")
                    || fields.get(3).is_some_and(|members| {
                        members
                            .split(',')
                            .any(|member| !member.is_empty() && member != "scupper-probe")
                    }))
        });
        if shared_user || shared_group {
            return Err(ProbeError::setup("probe account IDs or group are shared"));
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
#[serde(deny_unknown_fields)]
pub struct ProbeCredentials {
    /// Four verified nonzero uid values.
    pub uids: [u32; 4],
    /// Four verified nonzero gid values.
    pub gids: [u32; 4],
    /// Verified `PR_SET_NO_NEW_PRIVS` state.
    pub no_new_privs: bool,
    /// Verified capability bounding mask, required to be zero.
    pub cap_bnd: u64,
}

/// A completed observation, including classified failures (child exit status 0).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProbeOutcome {
    /// Result retaining the M1 setup versus path distinction.
    pub result: ProbeResult,
    /// Present only after a successful privilege drop and verification.
    pub credentials: Option<ProbeCredentials>,
    /// Task count on the original child thread, before namespace entry.
    pub threads_before_setns: Option<usize>,
}
/// JSON-safe result classes, preserving implausible addresses for the verdict.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "class", rename_all = "snake_case", deny_unknown_fields)]
pub enum ProbeResult {
    /// DNS succeeded; HTTPS additionally reports its observed IPv4 address.
    Success {
        /// Observed exit address, absent for DNS-only probes.
        ip: Option<IpAddr>,
    },
    /// An IPv6 answer received over an IPv4 connection.
    Implausible {
        /// Address retained for the parent verdict.
        ip: IpAddr,
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
            Ok(Some(ip)) if !ip.to_canonical().is_ipv4() => Self::Implausible { ip },
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
            Self::Implausible { ip } => Ok(Some(ip)),
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
    /// Permits synthetic caller-namespace descriptors for in-process fake tests.
    /// Production builds have no such bypass and always verify foreign handles.
    #[cfg(any(test, feature = "testing"))]
    fn accepts_test_namespace(&self) -> bool {
        false
    }

    /// Executes `scupper probe <request>` with the namespace as stdin.
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
    #[cfg(any(test, feature = "testing"))]
    let synthetic = exec.accepts_test_namespace() && handle.identity() == request.expected_netns;
    #[cfg(not(any(test, feature = "testing")))]
    let synthetic = false;
    if !synthetic {
        handle
            .verify(request.expected_netns)
            .map_err(|error| ProbeError::setup(&error.to_string()))?;
    }
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
    // A crash is a local implementation failure, deliberately classified Setup.
    if output.status != Some(0) {
        return Err(ProbeError::setup(&format!(
            "probe child failed: {}",
            output.stderr
        )));
    }
    let outcome: ProbeOutcome = serde_json::from_str(&output.stdout)
        .map_err(|error| ProbeError::setup(&format!("probe outcome: {error}")))?;
    if !matches!(
        outcome.result,
        ProbeResult::Setup { .. } | ProbeResult::Timeout
    ) && (outcome.threads_before_setns != Some(1)
        || !outcome.credentials.as_ref().is_some_and(|credentials| {
            let valid = |ids: [u32; 4]| ids[0] != 0 && ids[0] != u32::MAX && ids == [ids[0]; 4];
            valid(credentials.uids)
                && valid(credentials.gids)
                && credentials.no_new_privs
                && credentials.cap_bnd == 0
        }))
    {
        return Err(ProbeError::setup(
            "probe outcome lacks verified credentials or thread count",
        ));
    }
    let fits = match &outcome.result {
        ProbeResult::Success { ip } => match request.kind {
            ProbeKind::Path => ip.is_none(),
            ProbeKind::ExitIp => ip.is_some_and(|ip| ip.to_canonical().is_ipv4()),
        },
        ProbeResult::Implausible { ip } => {
            request.kind == ProbeKind::ExitIp && !ip.to_canonical().is_ipv4()
        }
        _ => true,
    };
    if !fits {
        return Err(ProbeError::setup("probe outcome does not fit request kind"));
    }
    Ok(outcome)
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
            #[cfg(feature = "testing")]
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
        for (kind, result) in [
            (ProbeKind::Path, ProbeResult::Success { ip: None }),
            (
                ProbeKind::ExitIp,
                ProbeResult::Success {
                    ip: Some("1.2.3.4".parse().unwrap()),
                },
            ),
            (
                ProbeKind::ExitIp,
                ProbeResult::Implausible {
                    ip: "2001:db8::1".parse().unwrap(),
                },
            ),
            (
                ProbeKind::Path,
                ProbeResult::Setup {
                    message: "bad bind".into(),
                },
            ),
            (
                ProbeKind::Path,
                ProbeResult::Path {
                    message: "bad TLS".into(),
                },
            ),
            (ProbeKind::Path, ProbeResult::Timeout),
        ] {
            let mut request = request();
            request.kind = kind;
            let outcome = ProbeOutcome {
                result,
                credentials: Some(ProbeCredentials {
                    uids: [99; 4],
                    gids: [98; 4],
                    no_new_privs: true,
                    cap_bnd: 0,
                }),
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
                    &request,
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
    }
    #[test]
    fn parent_rejects_protocol_and_exec_errors() {
        let file = File::open("/proc/self/ns/net").unwrap();
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
    fn identity_override_is_available_only_in_testing_builds() {
        let mut json = serde_json::to_value(request()).unwrap();
        #[cfg(not(feature = "testing"))]
        assert!(json.get("identity").is_none());
        json["identity"] = serde_json::json!({"uid": 99, "gid": 98});
        assert_eq!(
            serde_json::from_value::<ProbeRequest>(json).is_ok(),
            cfg!(feature = "testing")
        );
    }
    #[test]
    fn ipv6_classification_survives_serialization_and_parent_conversion() {
        let ip = "2001:db8::1".parse().unwrap();
        let result = ProbeResult::from_probe(Ok(Some(ip)));
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("implausible"));
        assert_eq!(
            serde_json::from_str::<ProbeResult>(&json)
                .unwrap()
                .into_probe(),
            Ok(Some(ip))
        );
    }
    #[test]
    fn rejects_shared_probe_accounts_and_group_members() {
        let passwd = "scupper-probe:x:99:98::/:/sbin/nologin";
        let group = "scupper-probe:x:98:";
        for bad in [
            format!("{passwd}\nother:x:99:97::/:/bin/sh"),
            format!("{passwd}\nother:x:100:98::/:/bin/sh"),
        ] {
            assert!(ProbeIdentity::parse(&bad, group).is_err());
        }
        for bad in [format!("{group}other"), format!("{group}\nother:x:98:")] {
            assert!(ProbeIdentity::parse(passwd, &bad).is_err());
        }
    }
    #[test]
    fn parent_rejects_inconsistent_outcomes() {
        let base = serde_json::json!({
            "result": {"class": "success", "ip": null},
            "credentials": {"uids": [99,99,99,99], "gids": [98,98,98,98], "no_new_privs": true, "cap_bnd": 0},
            "threads_before_setns": 1
        });
        let mut cases = Vec::new();
        let mut value = base.clone();
        value["credentials"] = serde_json::Value::Null;
        cases.push(value);
        let mut value = base.clone();
        value["credentials"]["uids"][0] = 0.into();
        cases.push(value);
        let mut value = base.clone();
        value["credentials"]["gids"][3] = 97.into();
        cases.push(value);
        let mut value = base.clone();
        value["threads_before_setns"] = serde_json::Value::Null;
        cases.push(value);
        let mut value = base.clone();
        value["result"]["ip"] = "1.2.3.4".into();
        cases.push(value);
        let mut value = base.clone();
        value["unknown"] = true.into();
        cases.push(value);
        let mut value = base.clone();
        value["credentials"]["no_new_privs"] = false.into();
        cases.push(value);
        let mut value = base.clone();
        value["credentials"]["cap_bnd"] = 1.into();
        cases.push(value);
        let mut value = base.clone();
        value["threads_before_setns"] = 2.into();
        cases.push(value);
        let mut value = base.clone();
        value["result"] =
            serde_json::json!({"class": "path", "message": "failure", "ip": "1.2.3.4"});
        cases.push(value);
        let mut value = base.clone();
        value["result"] = serde_json::json!({"class": "implausible", "ip": "2001:db8::1"});
        cases.push(value);
        let mut cases: Vec<_> = cases
            .into_iter()
            .map(|value| (ProbeKind::Path, value))
            .collect();
        cases.push((ProbeKind::ExitIp, base.clone()));
        let mut value = base.clone();
        value["result"] = serde_json::json!({"class": "success", "ip": "2001:db8::1"});
        cases.push((ProbeKind::ExitIp, value));
        let mut value = base;
        value["result"] = serde_json::json!({"class": "implausible", "ip": "1.2.3.4"});
        cases.push((ProbeKind::ExitIp, value));
        for (kind, value) in cases {
            let mut request = request();
            request.kind = kind;
            let fake = Fake {
                calls: RefCell::default(),
                output: RefCell::new(Some(Ok(ExecOutput {
                    status: Some(0),
                    stdout: value.to_string(),
                    stderr: String::new(),
                }))),
            };
            assert!(
                matches!(
                    execute(
                        &fake,
                        File::open("/proc/self/ns/net").unwrap(),
                        &request,
                        Duration::from_millis(20)
                    ),
                    Err(ProbeError::Setup(_))
                ),
                "{kind:?}: {value}"
            );
        }
    }
    #[test]
    fn real_argv_stdin_wiring_and_process_group_timeout() -> Result<(), Box<dyn std::error::Error>>
    {
        let dir = std::env::var_os("CARGO_TARGET_TMPDIR")
            .map_or_else(
                || {
                    std::path::PathBuf::from(concat!(
                        env!("CARGO_MANIFEST_DIR"),
                        "/../../target/tmp"
                    ))
                },
                std::path::PathBuf::from,
            )
            .join(format!("probe-child-{}", std::process::id()));
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
