#![allow(clippy::unwrap_used, clippy::panic)]
use super::*;
use std::collections::VecDeque;

#[test]
fn paths_accept_exactly_two_safe_components() {
    for path in ["com.apple/scupper", "scupper-qual/scupper", "A_1/B.2-3"] {
        assert_eq!(AnchorPath::new(path).unwrap().as_str(), path);
    }
    for path in [
        "", "a", "/a", "a/", "a/b/c", "a/*", "./a", "a/..", "a/.", "a//b", "a/b\n", "a/b\0",
        "a/b c", "a/é",
    ] {
        assert!(AnchorPath::new(path).is_err(), "{path:?}");
    }
}
#[test]
fn every_proposed_row_is_build_pinned_and_unreviewed() {
    for build in pftext::BUILDS {
        let build = Build::fixture(build);
        let rows = [
            (Operation::Load, 0, b"".as_slice(), b"".as_slice()),
            (Operation::Load, 0, b"", LOAD_WARNING),
            (Operation::Inventory, 0, b"  scupper\n  foreign\n", b""),
            (Operation::Inventory, 0, b"", b""),
            (Operation::Inventory, 0, b"  scupper-qual/scupper\n", b""),
            (
                Operation::Inventory,
                0,
                b"",
                b"Anchor 'com.apple' not found.\n",
            ),
            (
                Operation::Inventory,
                0,
                b"",
                b"Anchor 'scupper-qual' not found.\n",
            ),
            (Operation::Filter, 0, b"block drop all\n", b""),
            (Operation::Filter, 0, b"", b""),
            (
                Operation::Filter,
                0,
                b"",
                b"pfctl: DIOCGETRULES: Invalid argument\n",
            ),
            (Operation::Extra, 0, b"", b""),
            (Operation::Rules, 0, b"", b"rules cleared\n"),
            (Operation::Nat, 0, b"", b"nat cleared\n"),
            (Operation::Dummynet, 0, b"", b"dummynet cleared\n"),
            (Operation::Tables, 0, b"", b"0 tables deleted.\n"),
            (Operation::Tables, 0, b"", b"4294967295 tables deleted.\n"),
            (Operation::States, 0, b"", b"0 states cleared\n"),
            (Operation::States, 0, b"", b"65535 states cleared\n"),
        ];
        for (op, rc, out, err) in rows {
            for err in [err.to_vec(), [pftext::ALTQ_PREAMBLE, err].concat()] {
                assert!(
                    proposed(&build, op, rc, out, &err).is_ok(),
                    "{op:?} {err:?}"
                );
                assert_eq!(qualified(&build, op, rc, out, &err), Err(UNREVIEWED));
                assert!(proposed(&Build::fixture("unknown"), op, rc, out, &err).is_err());
                for extra in [b"unexpected\n".as_slice(), b"\0", b"\n"] {
                    assert!(
                        proposed(&build, op, rc, out, &[err.as_slice(), extra].concat()).is_err()
                    );
                }
                if !err.is_empty() {
                    assert!(proposed(&build, op, rc, out, &err[..err.len() - 1]).is_err());
                }
                if !out.is_empty() {
                    assert!(proposed(&build, op, rc, &out[..out.len() - 1], &err).is_err());
                }
                assert!(proposed(&build, op, 2, out, &err).is_err());
            }
        }
    }
}
#[test]
fn unknown_counts_inventories_and_foreign_classes_fail() {
    let b = Build::fixture("24H232");
    for count in ["", "-1", "+1", " 1", "1 ", "4294967296", "1.0", "1\n2"] {
        assert!(
            proposed(
                &b,
                Operation::States,
                0,
                b"",
                format!("{count} states cleared\n").as_bytes()
            )
            .is_err()
        );
    }
    for text in [
        "scupper\n",
        "  a\n  a\n",
        "  a/b/c\n",
        "  *\n",
        "  ..\n",
        "  a\n\n",
        "    a\n",
        "  a\0\n",
    ] {
        assert!(proposed(&b, Operation::Inventory, 0, text.as_bytes(), b"").is_err());
    }
    for text in ["nat on en0\n", "foreign\n", "  child\n", "\n"] {
        assert_eq!(
            proposed(&b, Operation::Extra, 0, text.as_bytes(), b""),
            Err(SysError::Failed("foreign content in owned anchor"))
        );
    }
    assert!(source("block all\n").is_ok());
    for text in ["", "block all", "block\0all\n"] {
        assert!(source(text).is_err());
    }
    assert_eq!(selective(true), Ok(()));
    assert_eq!(selective(false), Err(SELECTIVE_UNQUALIFIED));
}
struct Script {
    rows: VecDeque<(Vec<String>, Result<Text, SysError>)>,
}
impl Script {
    fn new(rows: Vec<(&[&str], Result<Text, SysError>)>) -> Self {
        Self {
            rows: rows
                .into_iter()
                .map(|(a, r)| (a.iter().map(|s| (*s).into()).collect(), r))
                .collect(),
        }
    }
    fn done(&self) {
        assert_eq!(
            self.rows.len(),
            0,
            "skipped required subread/flush: {:?}",
            self.rows
        );
    }
}
impl Commands for Script {
    fn call(&mut self, _: Operation, args: &[&str], input: &[u8]) -> Result<Text, SysError> {
        assert_eq!(input, &[] as &[u8]);
        assert!(!self.rows.is_empty());
        let (expected, result) = self
            .rows
            .pop_front()
            .expect("asserted a required command row");
        assert_eq!(args, expected);
        result
    }
}
#[allow(clippy::unnecessary_wraps)] // Fixture rows use the same Result type for success and injected errors.
fn text(s: &str) -> Result<Text, SysError> {
    Ok(Text::Present(s.into()))
}
fn path() -> AnchorPath {
    AnchorPath::new("scupper-qual/scupper").unwrap()
}
#[test]
fn absence_needs_parent_then_nonexistent_rules_agreement() {
    for filter in [
        Ok(Text::Missing),
        text(""),
        text("block all\n"),
        Err(SysError::Unknown),
    ] {
        let absent = filter == Ok(Text::Missing);
        let mut io = Script::new(vec![
            (
                &["-a", "scupper-qual", "-sA"],
                text("  scupper-qual/other\n"),
            ),
            (&["-a", "scupper-qual/scupper", "-sr"], filter),
        ]);
        assert_eq!(read(&mut io, &path()).is_ok(), absent);
        io.done();
    }
    let mut io = Script::new(vec![(
        &["-a", "scupper-qual", "-sA"],
        Err(SysError::Unknown),
    )]);
    assert!(read(&mut io, &path()).is_err());
    io.done();
}
#[test]
fn missing_parent_requires_complete_root_lacking_parent() {
    for root in [
        text("  com.apple\n"),
        text("  scupper-qual\n"),
        Err(SysError::Unknown),
        Ok(Text::Missing),
    ] {
        let absent = root == text("  com.apple\n");
        let mut rows = vec![
            (
                &["-a", "scupper-qual", "-sA"][..],
                Ok(Text::MissingParent("scupper-qual".into())),
            ),
            (&["-sA"][..], root),
        ];
        if absent {
            rows.push((&["-a", "scupper-qual/scupper", "-sr"], Ok(Text::Missing)));
        }
        let mut io = Script::new(rows);
        assert_eq!(read(&mut io, &path()).is_ok(), absent);
        io.done();
    }
}
fn present_rows(filter: &str) -> Vec<(&'static [&'static str], Result<Text, SysError>)> {
    vec![
        (
            &["-a", "scupper-qual", "-sA"],
            text("  scupper-qual/scupper\n"),
        ),
        (&["-a", "scupper-qual/scupper", "-sr"], text(filter)),
        (&["-a", "scupper-qual/scupper", "-sn"], text("")),
        (&["-a", "scupper-qual/scupper", "-sT"], text("")),
        (&["-a", "scupper-qual/scupper", "-sA"], text("")),
        (&["-a", "scupper-qual/scupper", "-sd"], text("")),
    ]
}
#[test]
fn present_empty_is_some_and_every_extra_class_is_checked() {
    for filter in ["", "block all\n"] {
        let mut io = Script::new(present_rows(filter));
        assert_eq!(read(&mut io, &path()), Ok(Some(filter.into())));
        io.done();
    }
    for index in 2..6 {
        for bad in [text("foreign\n"), Err(SysError::Unknown), Ok(Text::Missing)] {
            let mut rows = present_rows("block all\n");
            rows.truncate(index + 1);
            rows[index].1 = bad;
            let mut io = Script::new(rows);
            assert!(read(&mut io, &path()).is_err());
            io.done();
        }
    }
}
#[test]
fn removal_uses_only_scoped_flushes_and_proves_absence() {
    for persists in [false, true] {
        let mut rows = present_rows("block all\n");
        for class in ["rules", "nat", "Tables", "dummynet"] {
            let args: &'static [&'static str] = match class {
                "rules" => &["-a", "scupper-qual/scupper", "-F", "rules"],
                "nat" => &["-a", "scupper-qual/scupper", "-F", "nat"],
                "Tables" => &["-a", "scupper-qual/scupper", "-F", "Tables"],
                _ => &["-a", "scupper-qual/scupper", "-F", "dummynet"],
            };
            rows.push((args, text("")));
        }
        if persists {
            rows.extend(present_rows(""));
        } else {
            rows.extend([
                (&["-a", "scupper-qual", "-sA"][..], text("")),
                (
                    &["-a", "scupper-qual/scupper", "-sr"][..],
                    Ok(Text::Missing),
                ),
            ]);
        }
        let mut io = Script::new(rows);
        assert_eq!(remove(&mut io, &path()).is_ok(), !persists);
        io.done();
    }
    let mut io = Script::new(vec![
        (&["-a", "scupper-qual", "-sA"], text("")),
        (&["-a", "scupper-qual/scupper", "-sr"], Ok(Text::Missing)),
    ]);
    assert_eq!(remove(&mut io, &path()), Ok(()));
    io.done();
}

#[test]
fn load_notices_each_occur_at_most_once_in_either_proposed_order() {
    for name in pftext::BUILDS {
        let build = Build::fixture(name);
        let reversed = [LOAD_WARNING, pftext::ALTQ_PREAMBLE].concat();
        assert_eq!(
            proposed(&build, Operation::Load, 0, b"", &reversed),
            text("")
        );
        for duplicate in [
            [LOAD_WARNING, LOAD_WARNING].concat(),
            [pftext::ALTQ_PREAMBLE, pftext::ALTQ_PREAMBLE].concat(),
            [pftext::ALTQ_PREAMBLE, LOAD_WARNING, pftext::ALTQ_PREAMBLE].concat(),
        ] {
            assert!(proposed(&build, Operation::Load, 0, b"", &duplicate).is_err());
        }
        assert!(proposed(&build, Operation::Filter, 0, b"unexpected\n", b"").is_err());
        assert!(
            proposed(
                &build,
                Operation::Filter,
                0,
                b"block all\n# unexpected\n",
                b""
            )
            .is_err()
        );
        assert!(proposed(&build, Operation::Filter, 0, b"block all\n\n", b"").is_err());
    }
}

#[test]
fn parent_scope_and_named_absence_must_agree() {
    for observed in [
        text("  com.apple/scupper\n"),
        text("  scupper\n"),
        Ok(Text::MissingParent("com.apple".into())),
        Ok(Text::Missing),
    ] {
        let mut io = Script::new(vec![(&["-a", "scupper-qual", "-sA"], observed)]);
        assert!(read(&mut io, &path()).is_err());
        io.done();
    }
    let build = Build::fixture("24H232");
    for parent in ["com.apple", "scupper-qual"] {
        assert_eq!(
            proposed(
                &build,
                Operation::Inventory,
                0,
                b"",
                format!("Anchor '{parent}' not found.\n").as_bytes()
            ),
            Ok(Text::MissingParent(parent.into()))
        );
    }
    assert!(
        proposed(
            &build,
            Operation::Filter,
            1,
            b"",
            b"pfctl: DIOCGETRULES: Invalid argument\n"
        )
        .is_err()
    );
}

#[test]
fn production_grammar_excludes_harness_syntax() {
    let build = Build::fixture("24H232");
    for row in [
        "pass quick on lo0 inet proto udp from 127.0.0.1 to 127.0.0.1 port = 45678 keep state label \"scupper-qual\"\n",
        "anchor \"child\" all\n",
        "pass quick on lo0 inet proto udp from 127.0.0.1 to 127.0.0.1 port = 45678 keep state\n",
    ] {
        assert!(
            proposed(&build, Operation::Filter, 0, row.as_bytes(), b"").is_err(),
            "{row}"
        );
        assert!(
            proposed(&build, Operation::HarnessFilter, 0, row.as_bytes(), b"").is_ok(),
            "{row}"
        );
    }
}
