//! Stable case catalog and longest-first duration balancing (one-based shards).
use super::{Result, evidence::Case, fail};
use std::{fmt::Write as _, str::FromStr};

/// A one-based shard selection, parsed from `I/N`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shard {
    index: usize,
    count: usize,
}
impl Default for Shard {
    fn default() -> Self {
        Self { index: 1, count: 1 }
    }
}
impl FromStr for Shard {
    type Err = String;
    fn from_str(text: &str) -> std::result::Result<Self, Self::Err> {
        let invalid = || "shard must be I/N with 1 <= I <= N <= 64".to_owned();
        let (index, count) = text.split_once('/').ok_or_else(invalid)?;
        let index = index.parse::<usize>().map_err(|_| invalid())?;
        let count = count.parse::<usize>().map_err(|_| invalid())?;
        if index == 0 || index > count || count > 64 {
            return Err(invalid());
        }
        Ok(Self { index, count })
    }
}
#[derive(Clone, Debug)]
pub(super) struct Spec {
    pub id: String,
    pub seconds: u64,
    pub kind: Kind,
}
#[derive(Clone, Copy, Debug)]
pub(super) enum Kind {
    Daemon,
    Legacy(Case),
}
/// Conservative estimates until per-case results from CI replace them. L3/L16
/// include the real 175-second handshake-staleness window.
pub(super) fn catalog() -> Vec<Spec> {
    let mut cases = Vec::new();
    for id in super::daemon::CASES {
        let seconds = match id {
            "L3" | "L16" | "L9-host-link" | "L10" => 240,
            "L9" => 900,
            "L9b" => 720,
            "L44" | "L50" | "L11" | "L53" => 180,
            "L43" => 150,
            "L20" | "heartbeat" => 120,
            _ => 60,
        };
        cases.push(Spec {
            id: format!("daemon-{id}"),
            seconds,
            kind: Kind::Daemon,
        });
    }
    for case in Case::ALL {
        if case != Case::Daemon {
            cases.push(Spec {
                id: case.name().into(),
                seconds: 60,
                kind: Kind::Legacy(case),
            });
        }
    }
    cases
}
fn assignments(cases: &[Spec], count: usize) -> Vec<usize> {
    let mut order: Vec<_> = (0..cases.len()).collect();
    order.sort_by(|&a, &b| {
        cases[b]
            .seconds
            .cmp(&cases[a].seconds)
            .then_with(|| cases[a].id.cmp(&cases[b].id))
    });
    let mut totals = vec![0; count];
    let mut assigned = vec![0; cases.len()];
    for i in order {
        let shard = (0..count).min_by_key(|&n| (totals[n], n)).unwrap_or(0);
        totals[shard] += cases[i].seconds;
        assigned[i] = shard + 1;
    }
    assigned
}
fn select(shard: Shard, cases: Vec<Spec>) -> Vec<Spec> {
    let assigned = assignments(&cases, shard.count);
    cases
        .into_iter()
        .zip(assigned)
        .filter_map(|(case, n)| (n == shard.index).then_some(case))
        .collect()
}
#[cfg(test)]
fn selected(shard: Shard) -> Vec<Spec> {
    select(shard, catalog())
}
pub(super) fn selected_recorded(shard: Shard, path: Option<&std::path::Path>) -> Result<Vec<Spec>> {
    Ok(select(shard, recorded_catalog(path)?))
}
fn recorded_catalog(path: Option<&std::path::Path>) -> Result<Vec<Spec>> {
    let mut cases = catalog();
    let default = std::path::Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/lab/results.tsv"));
    if let Some(path) = path.or_else(|| default.exists().then_some(default)) {
        apply_durations(&mut cases, &std::fs::read_to_string(path)?)?;
    }
    Ok(cases)
}
fn apply_durations(cases: &mut [Spec], text: &str) -> Result<()> {
    let mut lines = text.lines();
    let header: Vec<_> = lines
        .next()
        .ok_or("empty duration results")?
        .split('\t')
        .collect();
    let column = |key| {
        header
            .iter()
            .position(|v| *v == key)
            .ok_or("duration results missing column")
    };
    let (name, got) = (column("name")?, column("got")?);
    let elapsed = header.iter().position(|v| *v == "elapsed_ms");
    let detail = column("detail")?;
    for line in lines {
        let cells: Vec<_> = line.split('\t').collect();
        if cells.get(got) != Some(&"passed") {
            continue;
        }
        let raw = elapsed.and_then(|i| cells.get(i).copied()).or_else(|| {
            cells
                .get(detail)?
                .split(';')
                .find_map(|v| v.trim().strip_prefix("elapsed_ms="))
        });
        let Some(ms) = raw.and_then(|v| v.parse::<u64>().ok()).filter(|v| *v > 0) else {
            continue;
        };
        if let Some(case) = cases
            .iter_mut()
            .find(|c| cells.get(name) == Some(&c.id.as_str()))
        {
            // Retain a 25% allowance and five seconds of scheduling slack.
            case.seconds = (ms.saturating_mul(5) / 4).div_ceil(1000).saturating_add(5);
        }
    }
    Ok(())
}
/// Lists all cases with their deterministic shard and expected duration. `None`
/// uses the four-shard CI layout; a selection prints just that shard.
///
/// # Errors
/// Returns an error if the catalog has duplicate identifiers.
pub fn list(shard: Option<Shard>) -> Result<String> {
    list_with_durations(shard, None)
}
/// List using a shared previous results.tsv for duration balancing.
///
/// # Errors
/// Returns an error for unreadable or malformed duration results.
pub fn list_with_durations(
    shard: Option<Shard>,
    durations: Option<&std::path::Path>,
) -> Result<String> {
    let cases = recorded_catalog(durations)?;
    let count = shard.map_or(4, |s| s.count);
    let assigned = assignments(&cases, count);
    let mut seen = std::collections::BTreeSet::new();
    let mut text = "case\tshard\texpected_seconds\n".to_owned();
    for (case, n) in cases.iter().zip(assigned) {
        if !seen.insert(&case.id) {
            return fail("duplicate case id");
        }
        if shard.is_none_or(|s| n == s.index) {
            writeln!(text, "{}\t{n}/{count}\t{}", case.id, case.seconds)?;
        }
    }
    Ok(text)
}
#[cfg(test)]
mod tests {
    use super::*;
    // CI has no committed successful durations yet: always check the built-in
    // estimates, with 300 seconds reserved for setup/cleanup in the 30-minute budget.
    fn check_four_shard_budget(cases: &[Spec]) -> Result<()> {
        if cases.is_empty() {
            return fail("empty shard catalog");
        }
        for index in 1..=4 {
            let seconds: u64 = select(Shard { index, count: 4 }, cases.to_vec())
                .iter()
                .map(|case| case.seconds)
                .sum();
            if seconds + 300 > 30 * 60 {
                return fail(format!(
                    "shard {index}: {seconds}s plus 300s exceeds 1800s budget"
                ));
            }
        }
        Ok(())
    }
    #[test]
    fn ci_shard_budget_uses_builtin_estimates_and_rejects_over_budget() {
        check_four_shard_budget(&catalog()).unwrap();
        let mut over_budget = catalog();
        over_budget[0].seconds = 30 * 60;
        assert!(
            check_four_shard_budget(&over_budget)
                .unwrap_err()
                .to_string()
                .contains("exceeds")
        );
        assert!(check_four_shard_budget(&[]).is_err());
    }

    #[test]
    fn deterministic_complete_disjoint_balanced_and_order_independent() {
        let cases = catalog();
        for count in 1..=8 {
            let a = assignments(&cases, count);
            assert_eq!(a, assignments(&cases, count));
            let mut reverse = cases.clone();
            reverse.reverse();
            let mut reversed = assignments(&reverse, count);
            reversed.reverse();
            assert_eq!(a, reversed);
            let mut seen = std::collections::BTreeSet::new();
            let mut totals = vec![0; count];
            for index in 1..=count {
                for case in selected(Shard { index, count }) {
                    assert!(seen.insert(case.id));
                    totals[index - 1] += case.seconds;
                }
            }
            assert_eq!(seen.len(), cases.len());
            assert!(totals.iter().max().unwrap() - totals.iter().min().unwrap() <= 900);
            if count == 4 {
                assert!(totals.iter().all(|s| *s + 300 <= 30 * 60));
            }
        }
    }
    #[test]
    fn design_m2_rows_and_explicit_extras_are_complete() {
        let design = include_str!("../../../docs/DESIGN.md");
        let mut expected = std::collections::BTreeSet::new();
        let mut rows = std::collections::BTreeSet::new();
        for line in design.lines().filter(|line| line.starts_with("| L")) {
            let id = line.split('|').nth(1).unwrap().trim();
            if let Some(n) = id.strip_prefix('L').and_then(|v| v.parse::<u8>().ok())
                && (1..=20).contains(&n)
            {
                rows.insert(n);
                expected.insert(if n == 19 {
                    "L19".into()
                } else {
                    format!("daemon-{}", if n == 17 { "L17-V14" } else { id })
                });
            }
        }
        assert_eq!(rows, (1..=20).collect());
        for extra in [
            "daemon-L9b",
            "daemon-L9-host-link",
            "daemon-L17-rebuild",
            "daemon-L43",
            "daemon-L44",
            "daemon-L50",
            "daemon-L52",
            "daemon-L52b",
            "daemon-L53",
            "daemon-heartbeat",
            "daemon-V03",
            "baseline",
            "probe-child",
            "check-v2",
            "client-v6-dropped",
            "bridged-real-ruleset",
            "positive-control-permissive",
            "positive-control-uplink",
        ] {
            assert!(expected.insert(extra.into()));
        }
        assert_eq!(expected, catalog().into_iter().map(|c| c.id).collect());
    }
    #[test]
    fn ci_matrix_covers_the_default_list_exactly() {
        let ci = include_str!("../../../.github/workflows/ci.yml");
        let matrix = ci
            .lines()
            .find_map(|line| line.trim().strip_prefix("shard: ["))
            .unwrap()
            .trim_end_matches(']');
        let shards: Vec<usize> = matrix
            .split(',')
            .map(|s| s.trim().parse().unwrap())
            .collect();
        let count = shards.len();
        assert_eq!(shards, (1..=count).collect::<Vec<_>>());
        let listed = list(None).unwrap();
        assert!(listed.lines().skip(1).all(|line| {
            line.split('\t')
                .nth(1)
                .unwrap()
                .ends_with(&format!("/{count}"))
        }));
        assert!(ci.contains(&format!("--shard ${{{{ matrix.shard }}}}/{count}")));
    }
    #[test]
    fn recorded_durations_ignore_failed_and_accept_old_and_new_results() {
        let mut cases = catalog();
        apply_durations(&mut cases, "name\twanted\tgot\tdetail\ndaemon-L9\ttrial\tpassed\telapsed_ms=800000; measured\ndaemon-L9b\ttrial\tfailed\telapsed_ms=1\n").unwrap();
        assert_eq!(
            cases.iter().find(|c| c.id == "daemon-L9").unwrap().seconds,
            1005
        );
        assert_eq!(
            cases.iter().find(|c| c.id == "daemon-L9b").unwrap().seconds,
            720
        );
        apply_durations(
            &mut cases,
            "name\tgot\telapsed_ms\tdetail\ndaemon-L9\tpassed\t600000\twindow_ms=3\n",
        )
        .unwrap();
        assert_eq!(
            cases.iter().find(|c| c.id == "daemon-L9").unwrap().seconds,
            755
        );
    }
    #[test]
    fn list_and_selection_agree_and_invalid_shards_fail() {
        let all = list(None).unwrap();
        assert_eq!(all.lines().count(), catalog().len() + 1);
        let cases = recorded_catalog(None).unwrap();
        for index in 1..=4 {
            let shard = Shard { index, count: 4 };
            let text = list(Some(shard)).unwrap();
            assert_eq!(text.lines().count(), select(shard, cases.clone()).len() + 1);
            for case in select(shard, cases.clone()) {
                assert!(text.contains(&format!("{}\t{index}/4\t{}\n", case.id, case.seconds)));
            }
        }
        for index in 1..=4 {
            let seconds: u64 = select(Shard { index, count: 4 }, cases.clone())
                .iter()
                .map(|case| case.seconds)
                .sum();
            assert!(
                seconds + 300 <= 30 * 60,
                "recorded shard {index}: {seconds}s"
            );
        }
        for invalid in ["", "1", "0/4", "5/4", "1/0", "1/65", "1/2/3", "x/4"] {
            assert!(invalid.parse::<Shard>().is_err());
        }
    }
}

#[cfg(test)]
#[test]
fn l19_detectors_remain_in_regular_shards() {
    let catalog = catalog();
    assert!(
        catalog
            .iter()
            .any(|s| s.id == "L19" && matches!(s.kind, Kind::Legacy(Case::Meta)))
    );
    let count: usize = (1..=4)
        .map(|index| {
            select(Shard { index, count: 4 }, catalog.clone())
                .iter()
                .filter(|s| s.id == "L19")
                .count()
        })
        .sum();
    assert_eq!(
        count, 1,
        "R1 isolation leaves only L19 detecting bugs 2 and 3"
    );
}
