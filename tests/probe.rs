//! Pure response and error contracts, with network-free connector scenarios.

use std::{error::Error, io, net::IpAddr};

use scupper::probe::{
    IoOperation, MAX_RESPONSE_BYTES, Target, default_targets, is_setup_error, parse_ip_response,
};

#[test]
fn parse_ip_response_cases() -> Result<(), Box<dyn Error>> {
    for ip in ["192.0.2.10", "2001:db8::10"] {
        for suffix in ["", "\n", "\r\n", " \t\n"] {
            let body = format!("{ip}{suffix}");
            for version in ["HTTP/1.0", "HTTP/1.1"] {
                let plain = format!("{version} 200 OK\r\n\r\n{body}");
                let length = format!(
                    "{version} 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                let chunked = format!(
                    "{version} 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{:x}\r\n{body}\r\n0\r\n\r\n",
                    body.len()
                );
                for response in [plain, length, chunked] {
                    assert_eq!(
                        parse_ip_response(response.as_bytes())?,
                        ip.parse::<IpAddr>()?
                    );
                }
            }
        }
    }
    assert_eq!(
        parse_ip_response(b"HTTP/1.1 200 OK\r\ntRaNsFeR-EnCoDiNg: ChUnKeD\r\n\r\n4\r\n192.\r\n6\r\n0.2.10\r\n0\r\n\r\n")?,
        "192.0.2.10".parse::<IpAddr>()?
    );
    for status in [
        "301 Moved",
        "404 Not Found",
        "500 Server Error",
        "2000 Bogus",
        "200OK",
    ] {
        assert!(
            parse_ip_response(format!("HTTP/1.1 {status}\r\n\r\n192.0.2.10").as_bytes()).is_err()
        );
    }
    for body in [
        "<html>192.0.2.10</html>",
        "192.0.2.10 192.0.2.11",
        "",
        " \t\r\n",
        "192.0.2.10\n2001:db8::1",
        "192.0.2.10\0",
    ] {
        assert!(parse_ip_response(format!("HTTP/1.1 200 OK\r\n\r\n{body}").as_bytes()).is_err());
    }
    for response in [
        "HTTP/1.1 200 OK\r\n192.0.2.10",
        "HTTP/2 200 OK\r\n\r\n192.0.2.10",
        "HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\n192.0.2.10",
        "HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n192.0.2.10",
        "HTTP/1.1 200 OK\r\nContent-Length: +10\r\n\r\n192.0.2.10",
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nContent-Length: 10\r\n\r\n192.0.2.10",
        "HTTP/1.1 200 OK\r\nContent-Length: 10\r\nTransfer-Encoding: chunked\r\n\r\n192.0.2.10",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip, chunked\r\n\r\n192.0.2.10",
        "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        "HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\n\r\n192.0.2.10",
        "HTTP/1.1 200 OK\r\n Content-Length: 10\r\n\r\n192.0.2.10",
        "HTTP/1.1 200 OK\r\nX-Invalid\r\n\r\n192.0.2.10",
        "HTTP/1.1 200 OK\r\nX-Invalid: yes\nno\r\n\r\n192.0.2.10",
    ] {
        assert!(
            parse_ip_response(response.as_bytes()).is_err(),
            "{response:?}"
        );
    }
    for chunks in [
        "",
        "0\r\n",
        "a\r\n192.0.2.10\r\n",
        "a\r\n192.0.2.10XX0\r\n\r\n",
        "b\r\n192.0.2.10\r\n0\r\n\r\n",
        "+a\r\n192.0.2.10\r\n0\r\n\r\n",
        "a;ext=1\r\n192.0.2.10\r\n0\r\n\r\n",
        "0\r\nX-Trailer: value\r\n\r\n",
        "a\r\n192.0.2.10\r\n0\r\n\r\nextra",
        "ffffffffffffffffffffffffffffffff\r\n",
        "4001\r\n",
        "a\n192.0.2.10\r\n0\r\n\r\n",
    ] {
        let response = format!("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n{chunks}");
        assert!(
            parse_ip_response(response.as_bytes()).is_err(),
            "{chunks:?}"
        );
    }
    let oversized = format!("HTTP/1.1 200 OK\r\n\r\n{}", " ".repeat(MAX_RESPONSE_BYTES));
    assert!(parse_ip_response(oversized.as_bytes()).is_err());
    assert!(parse_ip_response(b"HTTP/1.1 200 OK\r\nContent-Length: 16385\r\n\r\n").is_err());
    let invalid = b"HTTP/1.1 200 OK\r\n\r\n\xff";
    assert!(parse_ip_response(invalid).is_err());
    Ok(())
}

#[test]
fn request_bytes_exact() {
    let targets = default_targets();
    for (target, (host, path)) in targets
        .iter()
        .zip([("ifconfig.me", "/ip"), ("icanhazip.com", "/")])
    {
        let expected = format!(
            "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: scupper/{}\r\nAccept: text/plain\r\nConnection: close\r\n\r\n",
            env!("CARGO_PKG_VERSION")
        );
        assert_eq!(target.host(), host);
        assert_eq!(target.request_bytes(), expected.as_bytes());
    }
}

#[test]
fn invalid_targets_cannot_inject_requests() {
    for (host, path) in [
        ("example.com\r\nInjected: yes", "/"),
        ("example.com", "/\r\nInjected: yes"),
        ("example.com", "https://example.com/"),
        ("example.com:443", "/"),
        ("", "/"),
        ("-example.com", "/"),
        ("example.com", "/a b"),
    ] {
        assert!(Target::new(host, path).is_err());
    }
}

#[test]
fn error_classification_table() {
    use IoOperation::{BindDevice, Path, Resolve, Socket};
    use io::ErrorKind::{ConnectionRefused, NotFound, Other, PermissionDenied, TimedOut};
    for (operation, kind, raw, setup) in [
        (BindDevice, PermissionDenied, Some(1), true),  // EPERM
        (BindDevice, PermissionDenied, Some(13), true), // EACCES
        (BindDevice, Other, Some(19), true),            // ENODEV
        (Path, ConnectionRefused, Some(111), false),    // ECONNREFUSED
        (Path, TimedOut, Some(110), false),             // ETIMEDOUT
        (Path, Other, Some(113), false),                // EHOSTUNREACH
        (Path, Other, Some(101), false),                // ENETUNREACH
        (Path, io::ErrorKind::InvalidData, None, false), // TLS error
        (Path, io::ErrorKind::InvalidData, None, false), // HTTP error
        (BindDevice, Other, Some(101), false),
        (Socket, Other, None, true),
        (Socket, PermissionDenied, Some(13), true),
        (Resolve, NotFound, Some(2), true), // no resolver configuration
        (Resolve, Other, None, false),
        (Resolve, TimedOut, None, false),
        (Path, PermissionDenied, Some(13), false),
    ] {
        assert_eq!(
            is_setup_error(operation, kind, raw),
            setup,
            "{operation:?}, {kind:?}, {raw:?}"
        );
    }
}

#[cfg(target_os = "linux")]
mod injected {
    use std::{
        collections::VecDeque,
        error::Error,
        net::{IpAddr, Ipv4Addr},
        sync::{Arc, Mutex},
        thread,
        time::{Duration, Instant},
    };

    use scupper::{
        check::ExitProbe,
        probe::{BoundHttpsProbe, Connector, PROBE_TIMEOUT, Target, default_targets},
        rules::{IfName, V1Config},
        verdict::{Probe, ProbeError},
    };

    const FIRST: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 1);
    const SECOND: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 2);

    #[derive(Default)]
    struct FakeConnector {
        resolutions: Mutex<VecDeque<Probe<Vec<Ipv4Addr>>>>,
        exchanges: Mutex<VecDeque<Probe<Vec<u8>>>>,
        calls: Mutex<Vec<String>>,
        resolve_delay: Duration,
        exchange_delay: Duration,
    }

    impl FakeConnector {
        fn log(&self, call: String) -> Probe<()> {
            self.calls
                .lock()
                .map_err(|_| ProbeError::setup("poisoned calls"))?
                .push(call);
            Ok(())
        }
    }

    impl Connector for FakeConnector {
        fn resolve(&self, target: &Target, _deadline: Instant) -> Probe<Vec<Ipv4Addr>> {
            self.log(format!("resolve {}", target.host()))?;
            thread::sleep(self.resolve_delay);
            self.resolutions
                .lock()
                .map_err(|_| ProbeError::setup("poisoned resolutions"))?
                .pop_front()
                .unwrap_or_else(|| Err(ProbeError::setup("unexpected resolution")))
        }

        fn exchange(
            &self,
            iface: &IfName,
            target: &Target,
            address: Ipv4Addr,
            _deadline: Instant,
        ) -> Probe<Vec<u8>> {
            self.log(format!("exchange {iface} {} {address}", target.host()))?;
            thread::sleep(self.exchange_delay);
            self.exchanges
                .lock()
                .map_err(|_| ProbeError::setup("poisoned exchanges"))?
                .pop_front()
                .unwrap_or_else(|| Err(ProbeError::setup("unexpected exchange")))
        }
    }

    fn probe(connector: Arc<FakeConnector>) -> Probe<IpAddr> {
        let cfg = V1Config::default();
        BoundHttpsProbe::from(&cfg)
            .with_connector(connector)
            .probe(&cfg)
    }

    fn answer() -> Vec<u8> {
        b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n192.0.2.10".to_vec()
    }

    #[test]
    fn targets_in_order_first_success_wins() -> Result<(), Box<dyn Error>> {
        let connector = Arc::new(FakeConnector {
            resolutions: Mutex::new(VecDeque::from([Ok(vec![FIRST]), Ok(vec![SECOND])])),
            exchanges: Mutex::new(VecDeque::from([
                Err(ProbeError::io("TLS failed")),
                Ok(answer()),
            ])),
            ..FakeConnector::default()
        });
        assert_eq!(probe(connector.clone())?, "192.0.2.10".parse::<IpAddr>()?);
        assert_eq!(
            *connector.calls.lock().map_err(|_| "poisoned calls")?,
            [
                "resolve ifconfig.me",
                "exchange proton0 ifconfig.me 192.0.2.1",
                "resolve icanhazip.com",
                "exchange proton0 icanhazip.com 192.0.2.2",
            ]
        );
        let connector = Arc::new(FakeConnector {
            resolutions: Mutex::new(VecDeque::from([Ok(vec![FIRST, SECOND])])),
            exchanges: Mutex::new(VecDeque::from([Ok(answer())])),
            ..FakeConnector::default()
        });
        assert_eq!(probe(connector.clone())?, "192.0.2.10".parse::<IpAddr>()?);
        assert_eq!(
            connector.calls.lock().map_err(|_| "poisoned calls")?.len(),
            2
        );
        Ok(())
    }

    #[test]
    fn all_targets_fail_reports_last() -> Result<(), Box<dyn Error>> {
        for (last, setup) in [
            (ProbeError::io("last HTTP failure"), false),
            (ProbeError::setup("last device failure"), true),
        ] {
            let connector = Arc::new(FakeConnector {
                resolutions: Mutex::new(VecDeque::from([Ok(vec![FIRST]), Ok(vec![SECOND])])),
                exchanges: Mutex::new(VecDeque::from([
                    Err(ProbeError::io("first TLS failure")),
                    Err(last.clone()),
                ])),
                ..FakeConnector::default()
            });
            let error = probe(connector).err().ok_or("expected failure")?;
            assert_eq!(matches!(error, ProbeError::Setup(_)), setup);
            let text = error.to_string();
            assert!(text.contains("ifconfig.me"));
            assert!(text.contains("first TLS failure"));
            assert!(text.contains("icanhazip.com"));
            assert!(text.contains(if setup {
                "last device failure"
            } else {
                "last HTTP failure"
            }));
            assert!(text.find("ifconfig.me") < text.find("icanhazip.com"));
        }
        Ok(())
    }

    #[test]
    fn tries_addresses_until_a_valid_answer() -> Result<(), Box<dyn Error>> {
        let connector = Arc::new(FakeConnector {
            resolutions: Mutex::new(VecDeque::from([Ok(vec![FIRST, SECOND])])),
            exchanges: Mutex::new(VecDeque::from([
                Ok(b"HTTP/1.1 200 OK\r\n\r\n<html>bad</html>".to_vec()),
                Ok(answer()),
            ])),
            ..FakeConnector::default()
        });
        assert_eq!(probe(connector.clone())?, "192.0.2.10".parse::<IpAddr>()?);
        assert_eq!(
            connector.calls.lock().map_err(|_| "poisoned calls")?.len(),
            3
        );
        Ok(())
    }

    #[test]
    fn resolution_failures_and_no_ipv4_are_path_errors() -> Result<(), Box<dyn Error>> {
        let connector = Arc::new(FakeConnector {
            resolutions: Mutex::new(VecDeque::from([
                Err(ProbeError::io("DNS unavailable")),
                Ok(vec![]),
            ])),
            ..FakeConnector::default()
        });
        let error = probe(connector).err().ok_or("expected failure")?;
        assert!(matches!(error, ProbeError::Io(_)));
        assert!(error.to_string().contains("DNS returned no IPv4"));
        assert!(error.to_string().contains("DNS unavailable"));
        Ok(())
    }

    #[test]
    fn failure_history_is_bounded() -> Result<(), Box<dyn Error>> {
        let connector = Arc::new(FakeConnector {
            resolutions: Mutex::new(VecDeque::from(vec![
                Err(ProbeError::io(&"界".repeat(1000)));
                8
            ])),
            ..FakeConnector::default()
        });
        let cfg = V1Config::default();
        let targets = default_targets().into_iter().cycle().take(8).collect();
        let error = BoundHttpsProbe::new(cfg.exit_iface.clone(), targets)
            .with_connector(connector)
            .probe(&cfg)
            .err()
            .ok_or("expected failure")?;
        if let ProbeError::Io(text) = error {
            assert!(text.chars().count() <= 200);
            assert!(text.contains("icanhazip.com"));
        } else {
            return Err("expected path failure".into());
        }
        Ok(())
    }

    #[test]
    fn budget_is_bounded() -> Result<(), Box<dyn Error>> {
        let connector = Arc::new(FakeConnector {
            resolutions: Mutex::new(VecDeque::from([
                Ok(vec![FIRST, SECOND]),
                Ok(vec![FIRST, SECOND]),
            ])),
            exchanges: Mutex::new(VecDeque::from([
                Ok(answer()),
                Ok(answer()),
                Ok(answer()),
                Ok(answer()),
            ])),
            exchange_delay: PROBE_TIMEOUT + Duration::from_secs(2),
            ..FakeConnector::default()
        });
        let start = Instant::now();
        let error = probe(connector.clone()).err().ok_or("expected timeout")?;
        assert!(start.elapsed() < PROBE_TIMEOUT + Duration::from_secs(1));
        assert!(!matches!(error, ProbeError::Setup(_)));
        assert!(error.to_string().contains("timed out"));
        assert_eq!(
            connector.calls.lock().map_err(|_| "poisoned calls")?.len(),
            2
        );
        Ok(())
    }

    #[test]
    fn dns_counts_against_budget() -> Result<(), Box<dyn Error>> {
        let connector = Arc::new(FakeConnector {
            resolutions: Mutex::new(VecDeque::from([Ok(vec![FIRST])])),
            resolve_delay: PROBE_TIMEOUT + Duration::from_secs(2),
            ..FakeConnector::default()
        });
        let start = Instant::now();
        let error = probe(connector).err().ok_or("expected timeout")?;
        assert!(start.elapsed() < PROBE_TIMEOUT + Duration::from_secs(1));
        assert!(!matches!(error, ProbeError::Setup(_)));
        assert!(error.to_string().contains("timed out"));
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
#[test]
fn unsupported_platform_is_setup() {
    use scupper::{check::ExitProbe, probe::BoundHttpsProbe, rules::V1Config, verdict::ProbeError};
    let cfg = V1Config::default();
    assert_eq!(
        BoundHttpsProbe::from(&cfg).probe(&cfg),
        Err(ProbeError::setup("exit probe needs Linux"))
    );
}
