#![forbid(unsafe_code)]

pub mod action_request;
pub mod authz;
pub mod bundle_export;
pub mod dispatch;
pub mod mcp;
pub mod observation;
pub mod receipt_production;
pub mod reconciliation;
pub mod session;
pub mod webhook_ingestion;

#[cfg(test)]
mod action_request_tests;
#[cfg(test)]
mod authz_tests;
#[cfg(test)]
mod bundle_export_tests;
#[cfg(test)]
mod dispatch_tests;
#[cfg(test)]
mod receipt_production_tests;
#[cfg(test)]
mod reconciliation_tests;
#[cfg(test)]
mod session_tests;

pub use action_request::{
    ActionRequestPorts, ActionRequestUseCase, ActionRequestUseCaseError, Approved, Proposed,
    Rejected, Revoked,
};
pub use authz::{ActionSensitivity, AuthorizationRequest, Denial, ReauthPolicy};
pub use dispatch::{
    DispatchError, DispatchOutcome, DispatchPorts, DispatchUseCase, Dispatched, ReservationFailed,
};
pub use observation::{
    EvidenceGap, Observation, ObservationError, ObservationPort, ObservationQuery,
    ObservationQueryResult, ObservationUseCase, SourceHealth,
};
pub use receipt_production::{
    DeploymentStatusEvent, ReceiptProducingProcessor, ReceiptProductionError,
    ReceiptProductionResult, map_github_state_to_outcome, parse_deployment_status,
    produce_receipt_from_webhook,
};
pub use reconciliation::{
    CorrelatedDeployment, DeploymentStatusProvider, ReconciliationError, ReconciliationOutcome,
    ReconciliationPorts, ReconciliationUseCase,
};
pub use session::{
    AuthError, AuthenticatedSession, SessionAuthority, SessionSigner, Signature,
    SignatureAlgorithm, SignedSession,
};
pub use webhook_ingestion::{
    IngestionOutcome, WebhookEventProcessor, WebhookIngestionPorts, WebhookIngestionUseCase,
};

use piteka_domain::{Health, ServiceStatus};

/// A clock trait for time-dependent operations.
pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> u64;
}

/// System clock that returns the current time from the OS.
#[derive(Clone)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
    }
}

pub struct HealthQuery<C> {
    clock: C,
}

impl<C: Clock> HealthQuery<C> {
    pub const fn new(clock: C) -> Self {
        Self { clock }
    }

    pub fn execute(&self) -> Health {
        Health {
            status: ServiceStatus::Ready,
            observed_at_unix_seconds: self.clock.unix_seconds(),
        }
    }
}
