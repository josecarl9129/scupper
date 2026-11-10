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
            "L3" | "L16" => 240,
            "L9" => 360,
            "L9b" => 270,
            "L44" | "L50" => 180,
            "L43" => 150,
            "L20" | "L11" | "L9-host-link" => 120,
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
pub(super) fn selected(shard: Shard) -> Vec<Spec> {
    let cases = catalog();
    let assigned = assignments(&cases, shard.count);
    cases
        .into_iter()
        .zip(assigned)
        .filter_map(|(case, n)| (n == shard.index).then_some(case))
        .collect()
}
/// Lists all cases with their deterministic shard and expected duration. `None`
/// uses the four-shard CI layout; a selection prints just that shard.
///
/// # Errors
/// Returns an error if the catalog has duplicate identifiers.
pub fn list(shard: Option<Shard>) -> Result<String> {
    let cases = catalog();
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
            assert!(totals.iter().max().unwrap() - totals.iter().min().unwrap() <= 360);
            if count == 4 {
                assert!(totals.iter().all(|s| *s + 300 <= 25 * 60));
            }
        }
    }
    #[test]
    fn list_and_selection_agree_and_invalid_shards_fail() {
        let all = list(None).unwrap();
        assert_eq!(all.lines().count(), catalog().len() + 1);
        for index in 1..=4 {
            let shard = Shard { index, count: 4 };
            let text = list(Some(shard)).unwrap();
            assert_eq!(text.lines().count(), selected(shard).len() + 1);
            for case in selected(shard) {
                assert!(text.contains(&format!("{}\t{index}/4\t{}\n", case.id, case.seconds)));
            }
        }
        for invalid in ["", "1", "0/4", "5/4", "1/0", "1/65", "1/2/3", "x/4"] {
            assert!(invalid.parse::<Shard>().is_err());
        }
    }
}
