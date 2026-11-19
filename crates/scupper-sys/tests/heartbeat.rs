//! Value-free protocol, reference confinement and retry tests.
#![allow(clippy::unwrap_used)]
use scupper_sys::heartbeat::{Failure, Request, account, monotonic_ns, resolve, retry};
use std::{
    fs,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
    sync::atomic::{AtomicUsize, Ordering},
};
static NEXT: AtomicUsize = AtomicUsize::new(0);
struct Temp(PathBuf);
impl Temp {
    fn new() -> Self {
        let root = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join(format!(
            "heartbeat-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir_all(root.join("secrets/url")).unwrap();
        for path in ["", "secrets", "secrets/url"] {
            fs::set_permissions(root.join(path), fs::Permissions::from_mode(0o700)).unwrap();
        }
        Self(root)
    }
    fn write(&self, bytes: &str) {
        let path = self.0.join("secrets/url/check");
        fs::write(&path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
}
impl Drop for Temp {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn reference() -> scupper_core::config::SecretName {
    scupper_core::config::SecretName::new(scupper_core::config::SecretKind::Url, "check").unwrap()
}
#[test]
fn stdin_protocol_and_deadline_do_not_reset() {
    let request = Request::new(
        "https://heartbeat.invalid/private-check",
        monotonic_ns() + 1_000_000_000,
    )
    .unwrap();
    let encoded = request.encode().unwrap();
    let decoded = Request::read(encoded.as_slice()).unwrap();
    assert_eq!(decoded.encode().unwrap().as_slice(), encoded.as_slice());
    for bytes in [
        b"bad".as_slice(),
        b"{}",
        b"[]",
        b"{\"url\":\"http://heartbeat.invalid/private\",\"deadline_ns\":0}",
        b"{\"url\":\"https://heartbeat.invalid/private\",\"deadline_ns\":0,\"extra\":1}",
    ] {
        assert_eq!(Request::read(bytes).unwrap_err(), Failure::Internal);
    }
    assert!(Request::read(vec![b'x'; 8193].as_slice()).is_err());
    assert!(Request::new("https://heartbeat.invalid/check", u64::MAX).is_err());
    let expired = Request::new("https://heartbeat.invalid/check", 0).unwrap();
    let mut calls = 0;
    assert_eq!(
        retry(&expired, || {
            calls += 1;
            Ok(())
        }),
        Err(Failure::Deadline)
    );
    assert_eq!(calls, 0);
}
#[test]
fn retries_once_and_preserves_final_reason() {
    let request = Request::new(
        "https://heartbeat.invalid/check",
        monotonic_ns() + 1_000_000_000,
    )
    .unwrap();
    let mut calls = 0;
    assert_eq!(
        retry(&request, || {
            calls += 1;
            Err(Failure::Http)
        }),
        Err(Failure::Http)
    );
    assert_eq!(calls, 2);
    calls = 0;
    assert_eq!(
        retry(&request, || {
            calls += 1;
            if calls == 1 {
                Err(Failure::Http)
            } else {
                Ok(())
            }
        }),
        Ok(())
    );
    assert_eq!(calls, 2);
    calls = 0;
    retry(&request, || {
        calls += 1;
        Ok(())
    })
    .unwrap();
    assert_eq!(calls, 1);
    let request = Request::new(
        "https://heartbeat.invalid/check",
        monotonic_ns() + 20_000_000,
    )
    .unwrap();
    calls = 0;
    assert!(
        retry(&request, || {
            calls += 1;
            std::thread::sleep(std::time::Duration::from_millis(30));
            Err(Failure::Deadline)
        })
        .is_err()
    );
    assert_eq!(calls, 1);
}
#[test]
fn secret_permissions_ownership_and_https() {
    let temp = Temp::new();
    let uid = rustix::process::geteuid().as_raw();
    assert!(matches!(
        resolve(&temp.0, &reference(), "", uid),
        Err(Failure::Secret)
    ));
    for url in [
        "http://heartbeat.invalid/check",
        "https://user@heartbeat.invalid/check",
        "https://heartbeat.invalid/#bad",
        "https://heartbeat.invalid/check\n\n",
        "https://heartbeat.invalid/check\r\n",
    ] {
        temp.write(url);
        assert!(matches!(
            resolve(&temp.0, &reference(), "", uid),
            Err(Failure::Secret)
        ));
    }
    temp.write("https://heartbeat.invalid/check?key=private\n");
    let url = resolve(&temp.0, &reference(), "/3", uid).unwrap();
    assert_eq!(
        url.expose(),
        "https://heartbeat.invalid/check/3?key=private"
    );
    assert!(matches!(
        resolve(&temp.0, &reference(), "/5", uid),
        Err(Failure::Internal)
    ));
    assert!(matches!(
        resolve(&temp.0, &reference(), "", uid.wrapping_add(1)),
        Err(Failure::Secret)
    ));
    for mode in [0o644, 0o400, 0o660, 0o1600] {
        fs::set_permissions(
            temp.0.join("secrets/url/check"),
            fs::Permissions::from_mode(mode),
        )
        .unwrap();
        assert!(matches!(
            resolve(&temp.0, &reference(), "", uid),
            Err(Failure::Secret)
        ));
    }
    fs::remove_file(temp.0.join("secrets/url/check")).unwrap();
    symlink("missing", temp.0.join("secrets/url/check")).unwrap();
    assert!(matches!(
        resolve(&temp.0, &reference(), "", uid),
        Err(Failure::Secret)
    ));
}
#[test]
fn account_and_exit_codes() {
    let valid = "scupper-alert:x:99:98::/:/sbin/nologin";
    let group = "scupper-alert:x:98:";
    let ids = account(valid, group).unwrap();
    assert_eq!((ids.uid, ids.gid), (99, 98));
    for passwd in [
        String::new(),
        valid.replace(":99:", ":0:"),
        format!("{valid}\n{valid}"),
        format!("{valid}\nother:x:99:97::/:/bin/false"),
    ] {
        assert_eq!(account(&passwd, group), Err(Failure::Account));
    }
    assert_eq!(Failure::Http.exit_code(), 20);
    assert_eq!(Failure::Deadline.exit_code(), 21);
    assert_eq!(Failure::Internal.exit_code(), 22);
}
proptest::proptest! {
    #[test]
    fn formatting_and_errors_never_contain_secret(path in "[a-zA-Z0-9]{16,64}") {
        let url = format!("https://heartbeat.invalid/{path}");
        let request = Request::new(&url, monotonic_ns() + 1_000_000_000).unwrap();
        let temp = Temp::new();
        temp.write(&url);
        let secret = resolve(&temp.0, &reference(), "", rustix::process::geteuid().as_raw()).unwrap();
        let debug = format!("{request:?} {secret:?}");
        proptest::prop_assert!(!debug.contains(&url));
        proptest::prop_assert!(!debug.contains(&path));
        let malformed = format!("{{\"url\":{url:?},\"deadline_ns\":\"{path}\"}}");
        let error = Request::read(malformed.as_bytes()).unwrap_err();
        for error in [error, Failure::Http, Failure::Deadline, Failure::Secret, Failure::Internal, Failure::Account] {
            let message = format!("{error}: {error:?}");
            proptest::prop_assert!(!message.contains(&url));
            proptest::prop_assert!(!message.contains(&path));
        }
    }
}

#[test]
fn bounded_secret_pipe_delivery_and_group_timeout() {
    use std::{
        process::Command,
        time::{Duration, Instant},
    };
    let secret = b"https://heartbeat.invalid/private-check";
    let mut command = Command::new("/bin/sh");
    command.args([
        "-c",
        "test \"$#\" = 2 && test \"$1\" = deliver && test \"$2\" = heartbeat && cat >/dev/null",
        "fixture",
        "deliver",
        "heartbeat",
    ]);
    let output =
        scupper_sys::system::execute_input_command(command, secret, Duration::from_secs(2))
            .unwrap();
    assert_eq!(output.status, Some(0));
    let temp = Temp::new();
    let mut command = Command::new("/bin/sh");
    command
        .args([
            "-c",
            "cat >/dev/null; (sleep 1; touch \"$1\") & wait",
            "fixture",
        ])
        .arg(temp.0.join("survived"));
    let started = Instant::now();
    let result =
        scupper_sys::system::execute_input_command(command, secret, Duration::from_millis(30));
    assert!(matches!(
        result,
        Err(scupper_sys::system::ExecError::Timeout { .. })
    ));
    assert!(started.elapsed() < Duration::from_secs(1));
    std::thread::sleep(Duration::from_millis(1100));
    assert!(!temp.0.join("survived").exists());
}

#[test]
fn log_suffix_and_body_preserve_secret_url_confinement() {
    let temp = Temp::new();
    let uid = rustix::process::geteuid().as_raw();
    for base in [
        "https://heartbeat.invalid/private",
        "https://heartbeat.invalid/private/",
    ] {
        temp.write(&format!("{base}?key=secret\n"));
        let url = resolve(&temp.0, &reference(), "/log", uid).unwrap();
        assert_eq!(
            url.expose(),
            "https://heartbeat.invalid/private/log?key=secret"
        );
        let request = Request::log(url.expose(), monotonic_ns() + 1_000_000_000).unwrap();
        let encoded = request.encode().unwrap();
        let decoded: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decoded["url"], url.expose());
        assert_eq!(
            decoded["payload"]["content_type"],
            "text/plain; charset=utf-8"
        );
        assert_eq!(
            decoded["payload"]["body"],
            "code=3 reason=ClientSessionsPending\n"
        );
        assert_eq!(decoded["payload"]["headers"], serde_json::json!({}));
        assert_eq!(
            Request::read(encoded.as_slice())
                .unwrap()
                .encode()
                .unwrap()
                .as_slice(),
            encoded.as_slice()
        );
        assert!(!format!("{url:?} {request:?}").contains("private"));
        assert!(!format!("{url:?} {request:?}").contains("secret"));
    }
    for suffix in ["/log/0", "/logs", "/log?secret", "/log\r\n"] {
        assert!(matches!(
            resolve(&temp.0, &reference(), suffix, uid),
            Err(Failure::Internal)
        ));
    }
}

#[test]
fn non_log_request_keeps_the_012_wire_format() {
    let request = Request::new("https://heartbeat.invalid/check/0", 0).unwrap();
    assert_eq!(
        request.encode().unwrap().as_slice(),
        br#"{"url":"https://heartbeat.invalid/check/0","deadline_ns":0,"form_credentials":false}"#
    );
    let payload = scupper_core::alerts::Payload {
        content_type: "text/plain; charset=utf-8".into(),
        headers: std::collections::BTreeMap::new(),
        body: "test alert".into(),
    };
    let request = Request::alert("https://heartbeat.invalid/alert", 0, payload).unwrap();
    assert_eq!(request.encode().unwrap().as_slice(), br#"{"url":"https://heartbeat.invalid/alert","deadline_ns":0,"payload":{"content_type":"text/plain; charset=utf-8","headers":{},"body":"test alert"},"form_credentials":false}"#);
}

#[test]
fn stored_012_urls_remain_readable_with_log_falling_back_to_status() {
    let temp = Temp::new();
    let uid = rustix::process::geteuid().as_raw();
    for target_len in [2044, 2045, 2046] {
        // Include a query to exercise the actual request-target byte limit.
        let path = format!("/{}?q=x", "x".repeat(target_len - 5));
        let original = format!("https://heartbeat.invalid{path}");
        temp.write(&original);
        assert_eq!(
            resolve(&temp.0, &reference(), "", uid).unwrap().expose(),
            original
        );
        for suffix in ["/0", "/3", "/log"] {
            let resolved = resolve(&temp.0, &reference(), suffix, uid).unwrap();
            let selected = if suffix == "/log" && target_len > 2044 {
                "/3"
            } else {
                suffix
            };
            assert_eq!(
                resolved.expose(),
                original.replace("?q=x", &format!("{selected}?q=x"))
            );
            assert_eq!(resolved.is_log(), selected == "/log");
            let request = if resolved.is_log() {
                Request::log(resolved.expose(), 0).unwrap()
            } else {
                Request::new(resolved.expose(), 0).unwrap()
            };
            assert!(Request::read(request.encode().unwrap().as_slice()).is_ok());
        }
    }
}
