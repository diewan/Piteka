#![forbid(unsafe_code)]
#![warn(missing_docs)]

//! Explicit worker entry point for ambiguous GitHub deployment outcomes.
//!
//! This crate deliberately contains no timer, retry loop, or release action.
//! Queue/API assembly submits one [`ReconciliationJob`] and [`run_job`] invokes
//! the application use case once. Provider absence therefore leaves the
//! mandate quarantined; only an explicit `Abandon` job can permanently close
//! an unresolved case.

use piteka_application::{
    ReconciliationError, ReconciliationOutcome, ReconciliationPorts, ReconciliationUseCase,
};

/// A single, explicitly authorized reconciliation operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReconciliationJob {
    /// Query GitHub for a deployment carrying the attempt's correlation data.
    Reconcile {
        /// Quarantined mandate identifier.
        mandate_id_hex: String,
        /// Authenticated worker or operator identity.
        operator_identity: String,
        /// Mandate projection version used by compare-and-swap.
        expected_mandate_version: i64,
    },
    /// Permanently close an ambiguity after an explicit investigation decision.
    Abandon {
        /// Quarantined mandate identifier.
        mandate_id_hex: String,
        /// Authenticated operator identity.
        operator_identity: String,
        /// Mandate projection version used by compare-and-swap.
        expected_mandate_version: i64,
        /// Non-empty investigation reason retained in the audit event.
        reason: String,
    },
}

/// Executes exactly one reconciliation job.
///
/// There is intentionally no automatic retry here. An unresolved result is a
/// successful, uncertainty-preserving outcome and remains quarantined until a
/// later explicit job is submitted.
pub async fn run_job<P: ReconciliationPorts>(
    use_case: &ReconciliationUseCase<P>,
    job: ReconciliationJob,
) -> Result<ReconciliationOutcome, ReconciliationError> {
    match job {
        ReconciliationJob::Reconcile {
            mandate_id_hex,
            operator_identity,
            expected_mandate_version,
        } => {
            use_case
                .reconcile(
                    &mandate_id_hex,
                    &operator_identity,
                    expected_mandate_version,
                )
                .await
        }
        ReconciliationJob::Abandon {
            mandate_id_hex,
            operator_identity,
            expected_mandate_version,
            reason,
        } => {
            use_case
                .abandon_unresolved(
                    &mandate_id_hex,
                    &operator_identity,
                    expected_mandate_version,
                    &reason,
                )
                .await
        }
    }
}
