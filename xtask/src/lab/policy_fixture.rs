//! Bug-1 symptom oracle control in a lab-only routing layout.
use scupper_core::lab_mutation::{Mutation, active};

/// Render the lab-only policy rule.
#[must_use]
pub fn policy_rule(subnet: &str) -> Vec<String> {
    policy_rule_for(active(), subnet)
}
fn policy_rule_for(mutation: Option<Mutation>, subnet: &str) -> Vec<String> {
    let selector = if cfg!(feature = "lab-mutation") && mutation == Some(Mutation::Src) {
        vec!["from", subnet]
    } else {
        vec!["iif", "wg0"]
    };
    [
        vec!["rule", "add", "pref", "191"],
        selector,
        vec!["lookup", "191"],
    ]
    .concat()
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[cfg(all(test, feature = "lab-mutation"))]
mod tests {
    use super::*;
    #[test]
    #[cfg(feature = "lab-mutation")]
    fn bug1_symptom_oracle_fixture_diff_is_golden() {
        let before = policy_rule_for(None, "10.99.0.0/24").join(" ");
        let after = policy_rule_for(Some(Mutation::Src), "10.99.0.0/24").join(" ");
        assert_eq!(
            format!("-{before}\n+{after}\n"),
            include_str!("../../../tests/golden/M-src.diff")
        );
    }
}
