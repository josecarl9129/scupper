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
    net::{IpAddr, Ipv4Addr, UdpSocket},
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
    fn close_namespace(&mut self) -> Probe<()>;
    fn no_new_privs(&mut self) -> Probe<()>;
    fn clear_bounding_set(&mut self) -> Probe<()>;
    fn parent_death_signal(&mut self) -> Probe<()>;
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
    sys.close_namespace()?;
    let sockets = sys.sockets(request)?;
    sys.no_new_privs()?;
    sys.clear_bounding_set()?;
    sys.groups()?;
    sys.gid(identity)?;
    sys.uid(identity)?;
    sys.parent_death_signal()?;
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
    fn close_namespace(&mut self) -> Probe<()> {
        rustix::stdio::dup2_stdin(fs::File::open("/dev/null").map_err(setup)?).map_err(setup)?;
        self.namespace = None;
        Ok(())
    }
    fn no_new_privs(&mut self) -> Probe<()> {
        thread::set_no_new_privs(true).map_err(setup)
    }
    fn clear_bounding_set(&mut self) -> Probe<()> {
        // Cover every bit in the procfs mask, including capabilities newer than
        // this rustix version. EINVAL means the kernel does not support that bit.
        for bit in 0..64 {
            let capability = thread::CapabilitySet::from_bits_retain(1 << bit);
            match thread::remove_capability_from_bounding_set(capability) {
                Ok(()) | Err(rustix::io::Errno::INVAL) => {}
                Err(error) => return Err(setup(error)),
            }
        }
        Ok(())
    }
    fn parent_death_signal(&mut self) -> Probe<()> {
        // Credential changes clear PDEATHSIG; install it only after the drop.
        process::set_parent_process_death_signal(Some(process::Signal::KILL)).map_err(setup)
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
    for key in ["CapInh:", "CapPrm:", "CapEff:", "CapAmb:", "CapBnd:"] {
        if u64::from_str_radix(field(key)?.trim(), 16).map_err(setup)? != 0 {
            return Err(setup("probe retained capabilities"));
        }
    }
    if field("NoNewPrivs:")?.trim() != "1" {
        return Err(setup("probe can gain new privileges"));
    }
    Ok(ProbeCredentials {
        no_new_privs: true,
        cap_bnd: 0,
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
        #[cfg(feature = "testing")]
        let override_identity = request.identity;
        #[cfg(not(feature = "testing"))]
        let override_identity: Option<ProbeIdentity> = None;
        let identity = match override_identity {
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
    observe_targets(
        request.kind,
        targets,
        sockets.tcp,
        deadline,
        |host, deadline| resolver.resolve(host, deadline),
        exchange_socket,
    )
}
pub(super) fn observe_targets<S>(
    kind: ProbeKind,
    targets: &[Target],
    sockets: Vec<S>,
    deadline: Instant,
    mut resolve: impl FnMut(&str, Instant) -> Probe<Vec<Ipv4Addr>>,
    mut exchange: impl FnMut(S, &Target, Ipv4Addr, Instant) -> Probe<Vec<u8>>,
) -> Probe<Option<IpAddr>> {
    let mut sockets = sockets.into_iter();
    let mut last = ProbeError::io("no IPv4 probe addresses");
    let mut implausible = None;
    for (index, target) in targets.iter().enumerate() {
        let left = remaining(deadline)?;
        // DNS and HTTPS share this target's slice. Early failures leave extra
        // time for the remaining targets; a stalled target cannot consume it.
        let count = if kind == ProbeKind::Path {
            1
        } else {
            targets.len() - index
        };
        let target_deadline = Instant::now() + left / u32::try_from(count).map_err(setup)?;
        let target_deadline = target_deadline.min(deadline);
        let addresses = match resolve(target.host(), target_deadline) {
            Ok(addresses) => addresses,
            Err(error @ ProbeError::Setup(_)) => return Err(error),
            Err(error) => {
                // Reserve exactly two sockets for every HTTPS target, even when
                // DNS fails. Never create replacement sockets after dropping uid.
                if kind == ProbeKind::ExitIp {
                    let _ = sockets.next();
                    let _ = sockets.next();
                }
                last = error;
                if kind == ProbeKind::Path {
                    return Err(last);
                }
                continue;
            }
        };
        if kind == ProbeKind::Path {
            return Ok(None);
        }
        let reserved: Vec<_> = sockets.by_ref().take(2).collect();
        for (address, socket) in addresses.into_iter().zip(reserved) {
            let result = exchange(socket, target, address, target_deadline).and_then(|bytes| {
                let ip = parse_ip_response(&bytes)
                    .map_err(|error| ProbeError::io(&error.to_string()))?
                    .to_canonical();
                // IPv6 is retained as an implausible observation for the parent
                // verdict. IPv4 values, including uplink-shaped ones, stay intact.
                remaining(target_deadline)?;
                Ok(Some(ip))
            });
            match result {
                Ok(Some(ip)) if ip.is_ipv6() => implausible = Some(ip),
                Ok(ip) => return Ok(ip),
                Err(error @ ProbeError::Setup(_)) => return Err(error),
                Err(error) => last = error,
            }
        }
    }
    implausible.map_or(Err(last), |ip| Ok(Some(ip)))
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
        fn close_namespace(&mut self) -> Probe<()> {
            self.calls.push("close namespace");
            Ok(())
        }
        fn no_new_privs(&mut self) -> Probe<()> {
            self.calls.push("no new privs");
            Ok(())
        }
        fn clear_bounding_set(&mut self) -> Probe<()> {
            self.calls.push("clear bounding set");
            Ok(())
        }
        fn parent_death_signal(&mut self) -> Probe<()> {
            self.calls.push("parent death signal");
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
                no_new_privs: true,
                cap_bnd: 0,
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
                "close namespace",
                "sockets",
                "no new privs",
                "clear bounding set",
                "setgroups",
                "setresgid",
                "setresuid",
                "parent death signal",
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
    fn target_slices_allow_fallback_after_dns_or_https_failure() {
        use std::{cell::RefCell, time::Duration};
        let targets = [
            Target::new("first.test", "/").unwrap(),
            Target::new("second.test", "/").unwrap(),
        ];
        for fail_dns in [false, true] {
            let deadlines = RefCell::new(Vec::new());
            let exchanges = RefCell::new(Vec::new());
            let started = Instant::now();
            let overall = started + Duration::from_secs(8);
            let result = observe_targets(
                ProbeKind::ExitIp,
                &targets,
                vec![0, 1, 2, 3],
                overall,
                |host, end| {
                    deadlines.borrow_mut().push((host.to_owned(), end));
                    if fail_dns && host == "first.test" {
                        Err(ProbeError::io("DNS rcode 3"))
                    } else {
                        Ok(vec![Ipv4Addr::LOCALHOST])
                    }
                },
                |socket, target, _, end| {
                    exchanges.borrow_mut().push(socket);
                    if target.host() == "first.test" {
                        assert!(end < overall);
                        Err(ProbeError::Timeout)
                    } else {
                        Ok(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n1.2.3.4".to_vec())
                    }
                },
            );
            assert_eq!(result, Ok(Some("1.2.3.4".parse().unwrap())));
            let deadlines = deadlines.borrow();
            assert_eq!(deadlines.len(), 2);
            assert!(deadlines[0].1 <= started + Duration::from_secs(5));
            assert_eq!(deadlines[1].1, overall);
            assert_eq!(exchanges.borrow().last(), Some(&2));
        }
    }
    #[test]
    fn ipv6_over_ipv4_is_implausible_and_ipv4_is_left_for_the_verdict() {
        let target = Target::new("probe.test", "/").unwrap();
        for address in ["2001:db8::1", "192.0.2.1"] {
            let result = observe_targets(
                ProbeKind::ExitIp,
                std::slice::from_ref(&target),
                vec![()],
                Instant::now() + std::time::Duration::from_secs(1),
                |_, _| Ok(vec![Ipv4Addr::LOCALHOST]),
                |(), _, _, _| {
                    Ok(format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{address}",
                        address.len()
                    )
                    .into_bytes())
                },
            );
            let ip: IpAddr = address.parse().unwrap();
            let result = ProbeResult::from_probe(result);
            if ip.is_ipv6() {
                assert_eq!(result, ProbeResult::Implausible { ip });
            } else {
                assert_eq!(result, ProbeResult::Success { ip: Some(ip) });
            }
        }
    }
    #[test]
    fn implausible_answer_preserves_fallback_to_a_usable_target() {
        let targets = [
            Target::new("first.test", "/").unwrap(),
            Target::new("second.test", "/").unwrap(),
        ];
        let result = observe_targets(
            ProbeKind::ExitIp,
            &targets,
            vec![(), (), (), ()],
            Instant::now() + std::time::Duration::from_secs(8),
            |_, _| Ok(vec![Ipv4Addr::LOCALHOST]),
            |(), target, _, _| {
                let address = if target.host() == "first.test" {
                    "2001:db8::1"
                } else {
                    "1.2.3.4"
                };
                Ok(format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{address}",
                    address.len()
                )
                .into_bytes())
            },
        );
        assert_eq!(result, Ok(Some("1.2.3.4".parse().unwrap())));
    }
    #[test]
    fn proc_credentials_reject_missing_groups_and_retained_caps() {
        let status = "Uid:\t99 99 99 99\nGid:\t98 98 98 98\nGroups:\nCapInh:\t0\nCapPrm:\t0\nCapEff:\t0\nCapAmb:\t0\nCapBnd:\t0\nNoNewPrivs:\t1\n";
        assert_eq!(credentials(status).unwrap().gids, [98; 4]);
        assert!(credentials(&status.replace("Groups:", "Groups: 98")).is_err());
        assert!(credentials(&status.replace("CapEff:\t0", "CapEff:\t1")).is_err());
        assert!(credentials(&status.replace("NoNewPrivs:\t1", "NoNewPrivs:\t0")).is_err());
        assert!(credentials(&status.replace("CapBnd:\t0", "CapBnd:\t1")).is_err());
        for missing in ["CapBnd:", "NoNewPrivs:"] {
            let incomplete = status
                .lines()
                .filter(|line| !line.starts_with(missing))
                .collect::<Vec<_>>()
                .join("\n");
            assert!(credentials(&incomplete).is_err());
        }
        assert!(credentials("").is_err());
    }
}
