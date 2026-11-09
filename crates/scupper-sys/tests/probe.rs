//! Pure response and error contracts, with network-free connector scenarios.

use std::{error::Error, io, net::IpAddr};

use scupper_sys::probe::{
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
        (Path, io::ErrorKind::InvalidData, None, false), // TLS/HTTP error
        (BindDevice, Other, Some(101), false),
        (Socket, Other, None, true),
        (Socket, PermissionDenied, Some(13), true),
        (Resolve, NotFound, Some(2), false), // ambiguous resolver failure
        (Resolve, NotFound, None, false),
        (Resolve, Other, Some(2), false),
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
