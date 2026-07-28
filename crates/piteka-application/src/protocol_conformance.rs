//! Product-state mapping for SDK-owned conflict and reorganization fixtures.

use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct Manifest {
    cases: Vec<Case>,
}

#[derive(Debug, Deserialize)]
struct Case {
    id: String,
    expected_reason_code: String,
}

/// Product response to a protocol fixture. Neither response is success.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MandateReviewState {
    ConflictReview,
    ReorganizationReconciliation,
}

/// Runs the two execution-path adversarial cases from the pinned SDK package.
pub fn execution_fixture_states() -> Result<Vec<(String, MandateReviewState)>, String> {
    let manifest: Manifest =
        serde_json::from_slice(piteka_parwana::closure::conformance_manifest())
            .map_err(|error| format!("invalid SDK conformance manifest: {error}"))?;
    ["losing-conflict", "reorganization"]
        .into_iter()
        .map(|id| {
            let case = manifest
                .cases
                .iter()
                .find(|case| case.id == id)
                .ok_or_else(|| format!("SDK fixture {id} is missing"))?;
            let state = match case.expected_reason_code.as_str() {
                "ACCEPT.V2.CONFLICT" => MandateReviewState::ConflictReview,
                "STORAGE.CHECKPOINT.ORPHANED" => {
                    MandateReviewState::ReorganizationReconciliation
                }
                other => return Err(format!("fixture {id} has unexpected reason {other}")),
            };
            Ok((id.to_string(), state))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn losing_conflict_and_reorg_never_map_to_success() {
        let states = execution_fixture_states().expect("pinned SDK fixtures must be consumable");
        assert_eq!(
            states,
            vec![
                ("losing-conflict".into(), MandateReviewState::ConflictReview),
                (
                    "reorganization".into(),
                    MandateReviewState::ReorganizationReconciliation
                ),
            ]
        );
    }
}
