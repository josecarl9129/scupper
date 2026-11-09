//! Single-threaded namespace entry and permanent privilege drop.
use super::{
    ProbeCredentials, ProbeIdentity, ProbeKind, ProbeOutcome, ProbeRequest, ProbeResult,
    exit_dns::ExitDns,
};
use crate::{
    netns::NetnsHandle,
    probe::{
        IoOperation, Target, io_failure, linux::exchange_socket, parse_ip_response, remaining,
    },
    verdict::{Probe, ProbeError},
};
use rustix::{
    process::{self, Gid, Uid},
    thread,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    fs,
    net::{IpAddr, UdpSocket},
    os::fd::AsFd,
    time::Instant,
};

fn setup(error: impl std::fmt::Display) -> ProbeError {
    ProbeError::setup(&error.to_string())
}

// The sequence is shared with the fake boundary tests. No internet bytes can be
// parsed until all calls, including the independent credential readback, pass.
trait Syscalls {
    type Sockets;
    fn verify_namespace(&mut self, request: &ProbeRequest) -> Probe<()>;
    fn thread_count(&mut self) -> Probe<usize>;
    fn setns(&mut self) -> Probe<()>;
    fn sockets(&mut self, request: &ProbeRequest) -> Probe<Self::Sockets>;
    fn groups(&mut self) -> Probe<()>;
    fn gid(&mut self, identity: ProbeIdentity) -> Probe<()>;
    fn uid(&mut self, identity: ProbeIdentity) -> Probe<()>;
    fn credentials(&mut self) -> Probe<ProbeCredentials>;
    fn no_core(&mut self) -> Probe<()>;
}
fn prepare<S: Syscalls>(
    sys: &mut S,
    request: &ProbeRequest,
    identity: ProbeIdentity,
) -> Probe<(S::Sockets, ProbeCredentials)> {
    identity.validate()?;
    sys.verify_namespace(request)?;
    if sys.thread_count()? != 1 {
        return Err(setup("probe must have exactly one thread before setns"));
    }
    sys.setns()?;
    let sockets = sys.sockets(request)?;
    sys.groups()?;
    sys.gid(identity)?;
    sys.uid(identity)?;
    let credentials = sys.credentials()?;
    if credentials.uids != [identity.uid; 4] || credentials.gids != [identity.gid; 4] {
        return Err(setup("probe credential verification failed"));
    }
    sys.no_core()?;
    Ok((sockets, credentials))
}
struct Real {
    namespace: Option<NetnsHandle>,
}
struct Sockets {
    dns: UdpSocket,
    tcp: Vec<Socket>,
}
impl Syscalls for Real {
    type Sockets = Sockets;
    fn verify_namespace(&mut self, request: &ProbeRequest) -> Probe<()> {
        let file = rustix::io::dup(std::io::stdin()).map_err(setup)?.into();
        self.namespace = Some(NetnsHandle::from_file(file, request.expected_netns).map_err(setup)?);
        Ok(())
    }
    fn thread_count(&mut self) -> Probe<usize> {
        count_threads()
    }
    fn setns(&mut self) -> Probe<()> {
        let file = self
            .namespace
            .as_ref()
            .ok_or_else(|| setup("namespace not verified"))?
            .try_clone_file()
            .map_err(setup)?;
        thread::move_into_link_name_space(file.as_fd(), Some(thread::LinkNameSpaceType::Network))
            .map_err(setup)
    }
    fn sockets(&mut self, request: &ProbeRequest) -> Probe<Sockets> {
        let create = |kind, protocol| {
            let socket = Socket::new(Domain::IPV4, kind, Some(protocol))
                .map_err(|error| io_failure(IoOperation::Socket, &error))?;
            if let Some(iface) = &request.bind {
                socket
                    .bind_device(Some(iface.as_str().as_bytes()))
                    .map_err(|error| io_failure(IoOperation::BindDevice, &error))?;
            }
            Ok(socket)
        };
        let socket: Socket = create(Type::DGRAM, Protocol::UDP)?;
        socket
            .bind(&std::net::SocketAddr::from(([0, 0, 0, 0], 0)).into())
            .map_err(setup)?;
        let count = if request.kind == ProbeKind::ExitIp {
            request.targets.len() * 2
        } else {
            0
        };
        let tcp = (0..count)
            .map(|_| create(Type::STREAM, Protocol::TCP))
            .collect::<Probe<_>>()?;
        Ok(Sockets {
            dns: socket.into(),
            tcp,
        })
    }
    fn groups(&mut self) -> Probe<()> {
        thread::set_thread_groups(&[]).map_err(setup)
    }
    fn gid(&mut self, identity: ProbeIdentity) -> Probe<()> {
        let gid = Gid::from_raw(identity.gid);
        thread::set_thread_res_gid(gid, gid, gid).map_err(setup)
    }
    fn uid(&mut self, identity: ProbeIdentity) -> Probe<()> {
        let uid = Uid::from_raw(identity.uid);
        thread::set_thread_res_uid(uid, uid, uid).map_err(setup)
    }
    fn credentials(&mut self) -> Probe<ProbeCredentials> {
        credentials(&fs::read_to_string("/proc/thread-self/status").map_err(setup)?)
    }
    fn no_core(&mut self) -> Probe<()> {
        disable_core()
    }
}
fn disable_core() -> Probe<()> {
    process::setrlimit(
        process::Resource::Core,
        process::Rlimit {
            current: Some(0),
            maximum: Some(0),
        },
    )
    .map_err(setup)?;
    process::set_dumpable_behavior(process::DumpableBehavior::NotDumpable).map_err(setup)
}
fn count_threads() -> Probe<usize> {
    fs::read_dir("/proc/self/task")
        .map_err(setup)?
        .try_fold(0, |count, entry| entry.map(|_| count + 1).map_err(setup))
}
fn credentials(status: &str) -> Probe<ProbeCredentials> {
    let field = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .ok_or_else(|| setup("credential status field missing"))
    };
    let ids = |key| -> Probe<[u32; 4]> {
        field(key)?
            .split_whitespace()
            .map(|id| id.parse::<u32>().map_err(setup))
            .collect::<Probe<Vec<_>>>()?
            .try_into()
            .map_err(|_| setup("invalid credential status"))
    };
    if !field("Groups:")?.trim().is_empty() {
        return Err(setup("probe retained supplementary groups"));
    }
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:"] {
        if u64::from_str_radix(field(key)?.trim(), 16).map_err(setup)? != 0 {
            return Err(setup("probe retained capabilities"));
        }
    }
    Ok(ProbeCredentials {
        uids: ids("Uid:")?,
        gids: ids("Gid:")?,
    })
}

pub(super) fn run(request: &ProbeRequest) -> ProbeOutcome {
    let mut credentials = None;
    let threads_before_setns = count_threads().ok();
    let result = (|| {
        // Disable core dumps even for failed setup, before reading account data.
        disable_core()?;
        if threads_before_setns != Some(1) {
            return Err(setup("probe must start single-threaded"));
        }
        let deadline = Instant::now() + request.budget()?;
        let targets = request
            .targets
            .iter()
            .map(super::Url::target)
            .collect::<Probe<Vec<_>>>()?;
        let identity = match request.identity {
            Some(identity) => identity.validate()?,
            None => ProbeIdentity::parse(
                &fs::read_to_string("/etc/passwd").map_err(setup)?,
                &fs::read_to_string("/etc/group").map_err(setup)?,
            )?,
        };
        let (sockets, verified) = prepare(&mut Real { namespace: None }, request, identity)?;
        credentials = Some(verified);
        observe(request, &targets, sockets, deadline)
    })();
    ProbeOutcome {
        result: ProbeResult::from_probe(result),
        credentials,
        threads_before_setns,
    }
}
fn observe(
    request: &ProbeRequest,
    targets: &[Target],
    sockets: Sockets,
    deadline: Instant,
) -> Probe<Option<IpAddr>> {
    let resolver = ExitDns::new(sockets.dns, request.dns);
    let mut sockets = sockets.tcp.into_iter();
    let mut last = ProbeError::io("no IPv4 probe addresses");
    for target in targets {
        remaining(deadline)?;
        let addresses = match resolver.resolve(target.host(), deadline) {
            Ok(addresses) => addresses,
            Err(error @ ProbeError::Setup(_)) => return Err(error),
            Err(error) => {
                // Reserve exactly two sockets for every HTTPS target, even when
                // DNS fails. Never create replacement sockets after dropping uid.
                if request.kind == ProbeKind::ExitIp {
                    let _ = sockets.next();
                    let _ = sockets.next();
                }
                last = error;
                if request.kind == ProbeKind::Path {
                    return Err(last);
                }
                continue;
            }
        };
        if request.kind == ProbeKind::Path {
            return Ok(None);
        }
        let reserved: Vec<_> = sockets.by_ref().take(2).collect();
        for (address, socket) in addresses.into_iter().zip(reserved) {
            let result = exchange_socket(socket, target, address, deadline).and_then(|bytes| {
                let ip = parse_ip_response(&bytes)
                    .map_err(|error| ProbeError::io(&error.to_string()))?
                    .to_canonical();
                if ip.is_ipv4() {
                    Ok(Some(ip))
                } else {
                    Err(ProbeError::io(
                        "probe answered with IPv6 over an IPv4 connection",
                    ))
                }
            });
            match result {
                Ok(ip) => {
                    remaining(deadline)?;
                    return Ok(ip);
                }
                Err(error @ ProbeError::Setup(_)) => return Err(error),
                Err(error) => last = error,
            }
        }
    }
    remaining(deadline)?;
    Err(last)
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct Fake {
        calls: Vec<&'static str>,
        bad_ns: bool,
        ids: [u32; 4],
        gids: [u32; 4],
        threads: usize,
    }
    impl Syscalls for Fake {
        type Sockets = ();
        fn verify_namespace(&mut self, _: &ProbeRequest) -> Probe<()> {
            self.calls.push("verify namespace");
            if self.bad_ns {
                Err(setup("wrong namespace"))
            } else {
                Ok(())
            }
        }
        fn thread_count(&mut self) -> Probe<usize> {
            self.calls.push("count threads");
            Ok(self.threads)
        }
        fn setns(&mut self) -> Probe<()> {
            self.calls.push("setns");
            Ok(())
        }
        fn sockets(&mut self, _: &ProbeRequest) -> Probe<()> {
            self.calls.push("sockets");
            Ok(())
        }
        fn groups(&mut self) -> Probe<()> {
            self.calls.push("setgroups");
            Ok(())
        }
        fn gid(&mut self, _: ProbeIdentity) -> Probe<()> {
            self.calls.push("setresgid");
            Ok(())
        }
        fn uid(&mut self, _: ProbeIdentity) -> Probe<()> {
            self.calls.push("setresuid");
            Ok(())
        }
        fn credentials(&mut self) -> Probe<ProbeCredentials> {
            self.calls.push("verify ids");
            Ok(ProbeCredentials {
                uids: self.ids,
                gids: self.gids,
            })
        }
        fn no_core(&mut self) -> Probe<()> {
            self.calls.push("no core");
            Ok(())
        }
    }
    fn request() -> ProbeRequest {
        serde_json::from_str(r#"{"kind":"Path","bind":null,"expected_netns":[1,2],"dns":"10.2.0.1","targets":["https://probe.test/"]}"#).unwrap()
    }
    #[test]
    fn sequence_guards_parsing_and_refuses_every_root_or_wrong_id() {
        let id = ProbeIdentity { uid: 99, gid: 99 };
        let mut sys = Fake {
            ids: [99; 4],
            gids: [99; 4],
            threads: 1,
            ..Fake::default()
        };
        prepare(&mut sys, &request(), id).unwrap();
        sys.calls.push("parse");
        assert_eq!(
            sys.calls,
            [
                "verify namespace",
                "count threads",
                "setns",
                "sockets",
                "setgroups",
                "setresgid",
                "setresuid",
                "verify ids",
                "no core",
                "parse"
            ]
        );
        for index in 0..4 {
            for bad in [0, 100] {
                let mut ids = [99; 4];
                ids[index] = bad;
                for bad_gid in [false, true] {
                    let mut sys = Fake {
                        ids: if bad_gid { [99; 4] } else { ids },
                        gids: if bad_gid { ids } else { [99; 4] },
                        threads: 1,
                        ..Fake::default()
                    };
                    assert!(prepare(&mut sys, &request(), id).is_err());
                    assert_eq!(sys.calls.last(), Some(&"verify ids"));
                }
            }
        }
        let mut sys = Fake {
            bad_ns: true,
            ..Fake::default()
        };
        assert!(prepare(&mut sys, &request(), id).is_err());
        assert_eq!(sys.calls, ["verify namespace"]);
        let mut sys = Fake {
            threads: 2,
            ..Fake::default()
        };
        assert!(prepare(&mut sys, &request(), id).is_err());
        assert_eq!(sys.calls, ["verify namespace", "count threads"]);
    }
    #[test]
    fn proc_credentials_reject_missing_groups_and_retained_caps() {
        let status = "Uid:\t99 99 99 99\nGid:\t98 98 98 98\nGroups:\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\n";
        assert_eq!(credentials(status).unwrap().gids, [98; 4]);
        assert!(credentials(&status.replace("Groups:", "Groups: 98")).is_err());
        assert!(credentials(&status.replace("CapEff:\t0", "CapEff:\t1")).is_err());
        assert!(credentials("").is_err());
    }
}
