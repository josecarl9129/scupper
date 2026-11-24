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
#[allow(clippy::too_many_lines)] // Keep the reviewed operation rows and their common rejection checks together.
fn every_proposed_row_is_build_pinned_and_reviewed() {
    for name in pftext::BUILDS {
        let build = Build::fixture(name);
        let rows = [
            (
                Operation::Load,
                b"".as_slice(),
                [LOAD_WARNING, pftext::ALTQ_PREAMBLE].concat(),
            ),
            (
                Operation::Inventory,
                b"  scupper-qual/scupper\n",
                pftext::ALTQ_PREAMBLE.to_vec(),
            ),
            (
                Operation::Inventory,
                b"  com.apple\n",
                pftext::ALTQ_PREAMBLE.to_vec(),
            ),
            (
                Operation::Inventory,
                b"  com.apple/child\n",
                pftext::ALTQ_PREAMBLE.to_vec(),
            ),
            (
                Operation::Inventory,
                b"",
                [pftext::ALTQ_PREAMBLE, b"Anchor 'scupper-qual' not found.\n"].concat(),
            ),
            (
                Operation::Filter,
                b"block drop all\n",
                pftext::ALTQ_PREAMBLE.to_vec(),
            ),
            (
                Operation::Filter,
                b"",
                [
                    pftext::ALTQ_PREAMBLE,
                    b"pfctl: DIOCGETRULES: Invalid argument\n",
                ]
                .concat(),
            ),
            (
                Operation::Rules,
                b"",
                [pftext::ALTQ_PREAMBLE, b"rules cleared\n"].concat(),
            ),
            (
                Operation::Nat,
                b"",
                [pftext::ALTQ_PREAMBLE, b"nat cleared\n"].concat(),
            ),
            (
                Operation::Dummynet,
                b"",
                [pftext::ALTQ_PREAMBLE, b"dummynet cleared\n"].concat(),
            ),
            (
                Operation::Tables,
                b"",
                [pftext::ALTQ_PREAMBLE, b"0 tables deleted.\n"].concat(),
            ),
            (
                Operation::Tables,
                b"",
                [pftext::ALTQ_PREAMBLE, b"4294967295 tables deleted.\n"].concat(),
            ),
            (
                Operation::States,
                b"",
                [pftext::ALTQ_PREAMBLE, b"0 states cleared\n"].concat(),
            ),
            (
                Operation::States,
                b"",
                [pftext::ALTQ_PREAMBLE, b"65535 states cleared\n"].concat(),
            ),
            (Operation::Filter, b"", pftext::ALTQ_PREAMBLE.to_vec()),
            (Operation::DummynetShow, b"", pftext::ALTQ_PREAMBLE.to_vec()),
            (
                Operation::DummynetShow,
                b"",
                [
                    pftext::ALTQ_PREAMBLE,
                    b"pfctl: DIOCGETRULES: Invalid argument\n",
                ]
                .concat(),
            ),
            (Operation::Extra, b"", pftext::ALTQ_PREAMBLE.to_vec()),
            (Operation::Inventory, b"", pftext::ALTQ_PREAMBLE.to_vec()),
        ];
        for (op, out, err) in rows {
            assert!(
                qualified(&build, op, 0, out, &err).is_ok(),
                "{op:?} {err:?}"
            );
            assert!(qualified(&Build::fixture("unknown"), op, 0, out, &err).is_err());
            assert!(qualified(&build, op, 1, out, &err).is_err());
            assert!(qualified(&build, op, 0, out, b"").is_err());
            assert!(qualified(&build, op, 0, out, &err[..err.len() - 1]).is_err());
            for extra in [b"unexpected\n".as_slice(), b"\0", b"\n"] {
                assert!(qualified(&build, op, 0, out, &[err.as_slice(), extra].concat()).is_err());
            }
            if !out.is_empty() {
                assert!(qualified(&build, op, 0, &out[..out.len() - 1], &err).is_err());
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
                [
                    pftext::ALTQ_PREAMBLE,
                    format!("{count} states cleared\n").as_bytes()
                ]
                .concat()
                .as_slice()
            )
            .is_err()
        );
    }
    for text in [
        "scupper\n",
        "  a\n  a\n",
        "  a/b/c/d/e/f/g/h/i/j/k\n",
        "  *\n",
        "  ..\n",
        "  a\n\n",
        "    a\n",
        "  a\0\n",
    ] {
        assert!(
            proposed(
                &b,
                Operation::Inventory,
                0,
                text.as_bytes(),
                pftext::ALTQ_PREAMBLE
            )
            .is_err()
        );
    }
    for text in ["nat on en0\n", "foreign\n", "  child\n", "\n"] {
        assert_eq!(
            proposed(
                &b,
                Operation::Extra,
                0,
                text.as_bytes(),
                pftext::ALTQ_PREAMBLE
            ),
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
    recursive: bool,
    build: &'static str,
    rows: VecDeque<(Vec<String>, Result<Text, SysError>)>,
}
impl Script {
    fn new(rows: Vec<(&[&str], Result<Text, SysError>)>) -> Self {
        Self {
            recursive: false,
            build: "24H232",
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
    fn build(&self) -> Result<Build, SysError> {
        Ok(Build::fixture(self.build))
    }
    fn descendants_reviewed(&self) -> Result<bool, SysError> {
        Ok(self.recursive)
    }

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
fn present_empty_is_none_and_every_extra_class_is_checked() {
    for filter in ["", "block all\n"] {
        let mut io = Script::new(present_rows(filter));
        assert_eq!(
            read(&mut io, &path()),
            Ok((!filter.is_empty()).then(|| filter.into()))
        );
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
        assert_eq!(remove(&mut io, &path()), Ok(()));
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
fn load_requires_exact_warning_then_altq_and_optimizer_none() {
    assert_eq!(
        load_args(&path()).as_slice(),
        ["-o", "none", "-a", "scupper-qual/scupper", "-f", "-"]
    );
    for name in pftext::BUILDS {
        let build = Build::fixture(name);
        assert_eq!(
            qualified(
                &build,
                Operation::Load,
                0,
                b"",
                &[LOAD_WARNING, pftext::ALTQ_PREAMBLE].concat()
            ),
            text("")
        );
        for bad in [
            vec![],
            LOAD_WARNING.to_vec(),
            pftext::ALTQ_PREAMBLE.to_vec(),
            [pftext::ALTQ_PREAMBLE, LOAD_WARNING].concat(),
            [LOAD_WARNING, LOAD_WARNING, pftext::ALTQ_PREAMBLE].concat(),
        ] {
            assert!(qualified(&build, Operation::Load, 0, b"", &bad).is_err());
        }
    }
}

#[test]
fn removal_skips_flush_only_after_complete_configuration_absence() {
    let mut io = Script::new(present_rows(""));
    assert_eq!(remove(&mut io, &path()), Ok(()));
    io.done();
    for first in [
        Err(SysError::Unknown),
        Err(SysError::Failed("foreign content in owned anchor")),
    ] {
        let mut rows = vec![(&["-a", "scupper-qual", "-sA"][..], first)];
        for args in [
            &["-a", "scupper-qual/scupper", "-F", "rules"][..],
            &["-a", "scupper-qual/scupper", "-F", "nat"],
            &["-a", "scupper-qual/scupper", "-F", "Tables"],
            &["-a", "scupper-qual/scupper", "-F", "dummynet"],
        ] {
            rows.push((args, text("")));
        }
        rows.extend(present_rows(""));
        let mut io = Script::new(rows);
        assert_eq!(remove(&mut io, &path()), Ok(()));
        io.done();
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
                [
                    pftext::ALTQ_PREAMBLE,
                    format!("Anchor '{parent}' not found.\n").as_bytes()
                ]
                .concat()
                .as_slice()
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
            proposed(
                &build,
                Operation::Filter,
                0,
                row.as_bytes(),
                pftext::ALTQ_PREAMBLE
            )
            .is_err(),
            "{row}"
        );
        assert!(
            proposed(
                &build,
                Operation::HarnessFilter,
                0,
                row.as_bytes(),
                pftext::ALTQ_PREAMBLE
            )
            .is_ok(),
            "{row}"
        );
    }
}

#[test]
fn filter_foreign_classes_have_exact_error() {
    for name in pftext::BUILDS {
        for line in [
            "scrub in all\n",
            "scrub-anchor \"x\" all\n",
            "anchor \"x\" all\n",
            "block from <q> to any\n",
        ] {
            assert_eq!(
                proposed(
                    &Build::fixture(name),
                    Operation::Filter,
                    0,
                    line.as_bytes(),
                    pftext::ALTQ_PREAMBLE
                ),
                Err(SysError::Failed("foreign content in owned anchor"))
            );
        }
    }
}

#[test]
fn unsupported_build_load_and_remove_spawn_no_commands() {
    let mut io = Script::new(vec![]);
    io.build = "unreviewed";
    assert_eq!(
        load(&mut io, &path(), "block all\n"),
        Err(UNSUPPORTED_BUILD)
    );
    assert_eq!(remove(&mut io, &path()), Err(UNSUPPORTED_BUILD));
    io.done();
    for name in pftext::BUILDS {
        assert!(reviewed(&Build::fixture(name)));
        assert!(!descendants_reviewed(&Build::fixture(name)));
    }
}

#[derive(Default)]
struct Tree {
    recursive: bool,
    nodes: std::collections::BTreeMap<String, (String, Vec<String>)>,
    calls: Vec<Vec<String>>,
    bad: Option<(&'static str, Result<Text, SysError>)>,
}
impl Commands for Tree {
    fn build(&self) -> Result<Build, SysError> {
        Ok(Build::fixture("24H232"))
    }
    fn descendants_reviewed(&self) -> Result<bool, SysError> {
        Ok(self.recursive)
    }
    fn call(&mut self, op: Operation, args: &[&str], _: &[u8]) -> Result<Text, SysError> {
        self.calls.push(args.iter().map(|s| (*s).into()).collect());
        let path = args[1];
        let flag = args[2];
        if path == "scupper-qual" {
            return text("  scupper-qual/scupper\n");
        }
        if path.ends_with("/child")
            && let Some((bad_flag, result)) = &self.bad
            && flag == *bad_flag
        {
            return result.clone();
        }
        let (filter, children) = self.nodes.get(path).cloned().unwrap_or_default();
        let out = match flag {
            "-sA" => children.iter().fold(String::new(), |mut text, child| {
                text.push_str("  ");
                text.push_str(child);
                text.push('\n');
                text
            }),
            "-sr" => filter,
            "-F" => {
                self.nodes.entry(path.into()).or_default().0.clear();
                return text("");
            }
            _ => String::new(),
        };
        proposed(
            &Build::fixture("24H232"),
            op,
            0,
            out.as_bytes(),
            pftext::ALTQ_PREAMBLE,
        )
    }
}
fn tree(recursive: bool, chain: usize) -> Tree {
    let mut io = Tree {
        recursive,
        ..Tree::default()
    };
    let mut parent = path().as_str().to_owned();
    for _ in 0..chain {
        let child = format!("{parent}/child");
        io.nodes.entry(parent).or_default().1.push(child.clone());
        parent = child;
    }
    io
}
#[test]
fn descendant_absence_requires_review_and_complete_empty_subtree() {
    for recursive in [false, true] {
        for length in [1, 2, 8] {
            let mut io = tree(recursive, length);
            assert_eq!(read(&mut io, &path()).is_ok(), recursive);
            io.nodes.entry(path().as_str().into()).or_default().0 = "block all\n".into();
            assert_eq!(
                read(&mut io, &path()).is_ok(),
                recursive,
                "own policy also checks children"
            );
        }
        let mut io = tree(recursive, 2);
        io.nodes
            .entry("scupper-qual/scupper/child/child".into())
            .or_default()
            .0 = "block all\n".into();
        assert!(read(&mut io, &path()).is_err());
        assert!(remove(&mut io, &path()).is_err());
        assert!(
            io.calls
                .iter()
                .filter(|a| a.contains(&"-F".into()))
                .all(|a| a[1] == path().as_str())
        );
        for escape in [
            "scupper-qual/scupper2/child",
            "scupper-qual/foreign",
            "scupper-qual/scupper/../escape",
            "scupper-qual/scupper/child/grandchild",
        ] {
            let mut io = tree(recursive, 0);
            io.nodes
                .entry(path().as_str().into())
                .or_default()
                .1
                .push(escape.into());
            assert!(read(&mut io, &path()).is_err());
            assert!(!io.calls.iter().any(|a| a[1] == escape));
        }
        let mut io = tree(recursive, 9);
        assert!(read(&mut io, &path()).is_err());
        for count in [63, 64] {
            let mut io = tree(recursive, 0);
            io.nodes.entry(path().as_str().into()).or_default().1 = (0..count)
                .map(|n| format!("scupper-qual/scupper/c{n}"))
                .collect();
            assert_eq!(read(&mut io, &path()).is_ok(), recursive && count == 63);
        }
    }
    for policy in ["", "block all\n"] {
        let mut io = tree(true, 2);
        io.nodes.entry(path().as_str().into()).or_default().0 = policy.into();
        assert_eq!(remove(&mut io, &path()), Ok(()));
        let flushes = io
            .calls
            .iter()
            .filter(|a| a.contains(&"-F".into()))
            .collect::<Vec<_>>();
        assert_eq!(flushes.len(), if policy.is_empty() { 0 } else { 4 });
        assert!(flushes.iter().all(|a| a[1] == path().as_str()));
    }
    for flag in ["-sr", "-sn", "-sd", "-sT", "-sA"] {
        for bad in [
            text("foreign\n"),
            Err(SysError::TimedOut),
            Err(SysError::Unknown),
            Ok(Text::Missing),
        ] {
            let mut io = tree(true, 1);
            io.bad = Some((flag, bad));
            assert!(read(&mut io, &path()).is_err(), "{flag}");
        }
    }
}

#[test]
fn unsupported_build_only_canonical_owned_lockdown_attempts_one_load() {
    struct LoadIo {
        calls: usize,
        status: Result<i32, SysError>,
    }
    impl Commands for LoadIo {
        fn build(&self) -> Result<Build, SysError> {
            Ok(Build::fixture("unreviewed"))
        }
        fn call(&mut self, _: Operation, _: &[&str], _: &[u8]) -> Result<Text, SysError> {
            panic!("unexpected qualified command");
        }
        fn emergency_load(&mut self, args: &[&str], input: &[u8]) -> Result<i32, SysError> {
            self.calls += 1;
            assert_eq!(
                args,
                ["-o", "none", "-a", "scupper-qual/scupper", "-f", "-"]
            );
            assert_eq!(
                input,
                scupper_core::mac::policy::render_lockdown()
                    .as_str()
                    .as_bytes()
            );
            self.status.clone()
        }
    }
    for status in [
        Ok(0),
        Ok(1),
        Err(SysError::Unknown),
        Err(SysError::TimedOut),
    ] {
        let mut io = LoadIo { calls: 0, status };
        assert_eq!(
            load(
                &mut io,
                &path(),
                scupper_core::mac::policy::render_lockdown().as_str()
            ),
            Err(SysError::Unknown)
        );
        assert_eq!(io.calls, 1);
        assert_eq!(
            load(
                &mut io,
                &path(),
                crate::platform::tests::pretunnel_fixture()
                    .unwrap()
                    .as_str()
            ),
            Err(UNSUPPORTED_BUILD)
        );
        assert_eq!(
            load(
                &mut io,
                &AnchorPath::new("other/anchor").unwrap(),
                scupper_core::mac::policy::render_lockdown().as_str()
            ),
            Err(UNSUPPORTED_BUILD)
        );
        assert_eq!(remove(&mut io, &path()), Err(UNSUPPORTED_BUILD));
        assert_eq!(io.calls, 1);
    }
}

#[test]
fn descendant_depth_bound_precedes_component_limit() {
    // Start at depth eight on a short path: the inventory parser accepts every
    // component, so only the recursion bound can reject this next child.
    let mut io = tree(true, 1);
    let mut count = 1;
    assert_eq!(
        empty_classes(&mut io, path().as_str(), 8, &mut count, true),
        Err(SysError::Failed("descendant bound exceeded"))
    );
    assert!(!io.calls.iter().any(|args| args[1].ends_with("/child")));
}

#[test]
fn nonempty_descendant_each_configuration_class_is_err_with_review_flag_true() {
    for (flag, value) in [
        ("-sr", "pass quick on lo0 all no state\n"),
        ("-sn", "nat on lo0 from any to any -> 127.0.0.1\n"),
        ("-sT", "qtable\n"),
        ("-sd", "dummynet in all pipe 1\n"),
    ] {
        let mut io = tree(true, 1);
        io.bad = Some((flag, Ok(Text::Present(value.into()))));
        assert!(read(&mut io, &path()).is_err(), "{flag}");
        assert!(remove(&mut io, &path()).is_err(), "{flag}");
    }
}
