use super::*;
use crate::system::ExecOutput;
use std::{cell::RefCell, collections::VecDeque, time::Duration};
struct Script(
    RefCell<VecDeque<Result<ExecOutput, ExecError>>>,
    RefCell<Vec<Vec<String>>>,
);
impl Script {
    fn new(responses: VecDeque<Result<ExecOutput, ExecError>>) -> Self {
        Self(RefCell::new(responses), RefCell::default())
    }
}
impl System for Script {
    fn now_unix_secs(&self) -> u64 {
        0
    }
    fn run(
        &self,
        program: Program,
        args: &[String],
        timeout: Duration,
    ) -> Result<ExecOutput, ExecError> {
        self.1.borrow_mut().push(args.to_vec());
        assert_eq!(program, Program::Ufw);
        assert_eq!(timeout, EXEC_TIMEOUT);
        let mut queue = self.0.borrow_mut();
        if queue.len() == 2 {
            assert_eq!(args, ["status"]);
        } else {
            assert!(args == ["status"] || args == ["status", "verbose"]);
        }
        queue.pop_front().unwrap()
    }
}

const INACTIVE: &str = include_str!("../../../tests/fixtures/firewall/ufw-status-inactive.txt");
const DEFAULT: &str = include_str!("../../../tests/fixtures/firewall/ufw-status-default.txt");
const UPLINK: &str = include_str!("../../../tests/fixtures/firewall/ufw-status-uplink-allow.txt");
const ANY: &str = include_str!("../../../tests/fixtures/firewall/ufw-status-any-allow.txt");

fn packet(hook: &str) -> Packet<'_> {
    Packet {
        hook,
        uplink: "up0",
        port: 51820,
        destination: "198.51.100.2".parse().unwrap(),
    }
}

#[test]
fn real_status_inactive_default_and_both_allow_forms() {
    assert!(!active(INACTIVE));
    assert!(parse(INACTIVE).is_none());
    let status = parse(DEFAULT).unwrap();
    assert!(status.may_block(packet("input")));
    assert!(!status.may_block(packet("output")));
    for text in [UPLINK, ANY] {
        let status = parse(text).unwrap();
        for destination in ["198.51.100.2", "2001:db8::2"] {
            assert!(!status.may_block(Packet {
                destination: destination.parse().unwrap(),
                ..packet("input")
            }));
        }
        assert!(!status.may_block(packet("output")));
    }
    assert!(parse(UPLINK).unwrap().may_block(Packet {
        uplink: "other0",
        ..packet("input")
    }));
    assert!(!parse(ANY).unwrap().may_block(Packet {
        uplink: "other0",
        ..packet("input")
    }));
}

#[test]
fn stable_fields_only_and_family_scoped_rules() {
    assert!(parse("Status: active\n").is_none());
    assert!(parse(&DEFAULT.replace("deny (incoming)", "unknown (incoming)")).is_none());
    assert!(
        !parse(&DEFAULT.replace("deny (incoming)", "allow (incoming)"))
            .unwrap()
            .may_block(packet("input"))
    );
    for row in [
        "51820/udp on other0   ALLOW IN    Anywhere",
        "51820/tcp            ALLOW IN    Anywhere",
        "53/udp               ALLOW IN    Anywhere",
        "51820/udp            ALLOW OUT   Anywhere",
        "51820/udp            DENY IN     Anywhere",
        "51820/udp            ALLOW IN    192.0.2.0/24",
        "198.51.100.3 51820/udp ALLOW IN   Anywhere",
        "51820/udp (v6)       ALLOW IN    Anywhere (v6)",
    ] {
        assert!(!allows(row, packet("input")), "{row}");
    }
    assert!(!allows(
        "51820/udp ALLOW IN Anywhere",
        Packet {
            destination: "2001:db8::2".parse().unwrap(),
            ..packet("input")
        }
    ));
}

#[test]
fn outgoing_default_block_requires_matching_udp_allow() {
    for policy in ["deny", "reject"] {
        let text = DEFAULT.replace("allow (outgoing)", &format!("{policy} (outgoing)"));
        assert!(parse(&text).unwrap().may_block(packet("output")));
        for row in [
            "51820/udp          ALLOW OUT   Anywhere on up0",
            "51820/udp          ALLOW OUT   Anywhere on up0 # exit transport",
            "198.51.100.2 51820/udp ALLOW OUT Anywhere",
            "51820             ALLOW OUT   Anywhere",
        ] {
            let rules = format!(
                "{text}\nTo                         Action      From\n--                         ------      ----\n{row}\n"
            );
            assert!(!parse(&rules).unwrap().may_block(packet("output")), "{row}");
        }
    }
    for row in [
        "51820/udp ALLOW IN Anywhere",
        "51821/udp ALLOW OUT Anywhere",
        "51820/tcp ALLOW OUT Anywhere",
        "203.0.113.3 51820/udp ALLOW OUT Anywhere",
        "51820/udp ALLOW OUT Anywhere on other0",
    ] {
        assert!(!allows(row, packet("output")), "{row}");
    }
    // A matching deny also overrides the default allow policy.
    let text = format!("{ANY}\n51820/udp DENY OUT Anywhere\n");
    assert!(parse(&text).unwrap().may_block(packet("output")));
}

#[test]
fn queries_use_only_constant_argv_and_bounded_system_calls() {
    let output = |text: &str| {
        Ok(ExecOutput {
            status: Some(0),
            stdout: text.into(),
            stderr: String::new(),
        })
    };
    let script = Script::new(VecDeque::from([output("Status: active\n"), output(ANY)]));
    assert!(
        !observe(&script)
            .unwrap()
            .unwrap()
            .may_block(packet("input"))
    );
    assert!(script.0.borrow().is_empty());
    assert_eq!(
        *script.1.borrow(),
        [vec!["status"], vec!["status", "verbose"]]
    );
    for response in [
        output(INACTIVE),
        Err(ExecError::NotFound {
            program: Program::Ufw,
        }),
    ] {
        let script = Script::new(VecDeque::from([response]));
        assert!(observe(&script).unwrap().is_none());
        assert!(script.0.borrow().is_empty());
        assert_eq!(*script.1.borrow(), [vec!["status"]]);
    }
    for failure in [
        Err(ExecError::spawn("permission denied while spawning ufw")),
        Err(ExecError::Timeout {
            after: EXEC_TIMEOUT,
        }),
        output("Status: unknown\n"),
        Ok(ExecOutput {
            status: Some(1),
            stdout: String::new(),
            stderr: "discard this diagnostic".into(),
        }),
    ] {
        assert!(observe(&Script::new(VecDeque::from([failure]))).is_err());
    }
    for failure in [
        Err(ExecError::Timeout {
            after: EXEC_TIMEOUT,
        }),
        output("Status: active\n"),
    ] {
        let script = Script::new(VecDeque::from([output("Status: active\n"), failure]));
        assert!(observe(&script).is_err());
    }
}

#[test]
fn verbose_exit_rules_use_from_column_for_interface_in_both_families() {
    let status = parse(include_str!(
        "../../../tests/fixtures/firewall/ufw-status-exit-allow.txt"
    ))
    .unwrap();
    for destination in ["203.0.113.2", "2001:db8::2"] {
        let packet = Packet {
            port: 443,
            destination: destination.parse().unwrap(),
            ..packet("output")
        };
        assert!(!status.may_block(packet));
        assert!(status.may_block(Packet {
            port: 51820,
            ..packet
        }));
        assert!(status.may_block(Packet {
            uplink: "other0",
            ..packet
        }));
    }
    assert!(allows(
        "51820/udp ALLOW IN Anywhere # public UDP (v6) text is only a comment",
        packet("input")
    ));
}

#[test]
fn deny_before_allow_remains_uncertain() {
    for action in ["DENY", "REJECT", "LIMIT"] {
        for hook in ["input", "output"] {
            let direction = if hook == "input" { "IN" } else { "OUT" };
            let deny = format!("51820/udp {action} {direction} Anywhere");
            let allow = format!("51820/udp ALLOW {direction} Anywhere");
            let text = format!("{DEFAULT}\nTo Action From\n{deny}\n{allow}\n");
            assert!(parse(&text).unwrap().may_block(packet(hook)));
            let text = format!("{DEFAULT}\nTo Action From\n{allow}\n{deny}\n");
            assert!(!parse(&text).unwrap().may_block(packet(hook)));
        }
    }
}
