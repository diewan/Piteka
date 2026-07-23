//! Positive and adversarial coverage for the demo authorization boundary.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use piteka_application::{
    AuthenticatedSession, AuthorizationRequest, Clock, Denial, ReauthPolicy, SessionAuthority,
    SessionSigner, Signature, SignatureAlgorithm,
};
use piteka_domain::{Capability, ConfiguredOrganization, SessionId, UserId};
use piteka_storage::memory::InMemoryAuditLog;
use piteka_storage::ports::AuditLog;

use super::{DemoAuthorizationBoundary, NON_PRODUCTION_IDENTITY_WARNING};

/// Deterministic test signer (a keyed fold, not cryptography).
struct FoldSigner;

impl SessionSigner for FoldSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::DemoLocalV1
    }
    fn sign(&self, message: &[u8]) -> Signature {
        let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
        for &byte in message {
            acc = (acc ^ u64::from(byte)).wrapping_mul(0x0100_0000_01b3);
        }
        Signature::new(SignatureAlgorithm::DemoLocalV1, acc.to_be_bytes().to_vec())
    }
    fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        signature.algorithm() == self.algorithm() && self.sign(message).bytes() == signature.bytes()
    }
}

#[derive(Clone)]
struct StepClock {
    now: Arc<AtomicU64>,
}
impl StepClock {
    fn at(now: u64) -> Self {
        Self {
            now: Arc::new(AtomicU64::new(now)),
        }
    }
    fn set(&self, now: u64) {
        self.now.store(now, Ordering::SeqCst);
    }
}
impl Clock for StepClock {
    fn unix_seconds(&self) -> u64 {
        self.now.load(Ordering::SeqCst)
    }
}

/// Issues and authenticates a session for `user` at the clock's current time.
fn session_for(user: &str, clock: &StepClock) -> AuthenticatedSession {
    let authority =
        SessionAuthority::new(FoldSigner, clock.clone(), ConfiguredOrganization::demo());
    let signed = authority
        .issue(
            &UserId::new(user).unwrap(),
            SessionId::from_bytes([1; 16]),
            3_600,
        )
        .unwrap();
    authority.authenticate(&signed).unwrap()
}

fn boundary(clock: &StepClock) -> DemoAuthorizationBoundary<InMemoryAuditLog, StepClock> {
    DemoAuthorizationBoundary::new(
        piteka_storage::TenantScope::new("demo-org").unwrap(),
        InMemoryAuditLog::default(),
        clock.clone(),
        ReauthPolicy::new(300),
    )
}

#[tokio::test]
async fn approver_may_approve_a_standard_action_without_audit_noise() {
    let clock = StepClock::at(1_000);
    let boundary = boundary(&clock);
    let session = session_for("approver", &clock);

    let outcome = boundary
        .authorize(
            &session,
            &AuthorizationRequest::standard(Capability::ApproveAction),
            "approve intent aa",
        )
        .await
        .unwrap();
    let grant = outcome.expect("approver is authorized");
    assert_eq!(grant.identity_warning(), NON_PRODUCTION_IDENTITY_WARNING);

    // Standard grants are not audited (only denials and production grants are).
    assert!(
        boundary
            .audit()
            .recent(&piteka_storage::TenantScope::new("demo-org").unwrap(), 10)
            .await
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn requester_is_denied_approval_and_the_denial_is_audited() {
    let clock = StepClock::at(1_000);
    let boundary = boundary(&clock);
    let session = session_for("requester", &clock);

    let outcome = boundary
        .authorize(
            &session,
            &AuthorizationRequest::standard(Capability::ApproveAction),
            "approve intent aa",
        )
        .await
        .unwrap();

    let denied = outcome.expect_err("requester cannot approve");
    assert_eq!(
        denied.denial(),
        Denial::Unauthorized(Capability::ApproveAction)
    );

    let events = boundary
        .audit()
        .recent(&piteka_storage::TenantScope::new("demo-org").unwrap(), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].decision, "denied");
    assert_eq!(events[0].actor.as_deref(), Some("requester"));
    assert_eq!(events[0].action, "approve intent aa");
}

#[tokio::test]
async fn production_approval_requires_recent_reauthentication() {
    let clock = StepClock::at(1_000);
    let boundary = boundary(&clock);
    // Session authenticated at t=1000; still valid but not fresh.
    let session = session_for("approver", &clock);

    // Advance beyond the re-auth window (300s) but within session lifetime.
    clock.set(1_400);
    let outcome = boundary
        .authorize(
            &session,
            &AuthorizationRequest::production_approval(Capability::ApproveAction),
            "approve production intent aa",
        )
        .await
        .unwrap();

    let denied = outcome.expect_err("stale session cannot production-approve");
    assert!(matches!(
        denied.denial(),
        Denial::ReconfirmationRequired { .. }
    ));
    let events = boundary
        .audit()
        .recent(&piteka_storage::TenantScope::new("demo-org").unwrap(), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].decision, "denied");
}

#[tokio::test]
async fn production_approval_succeeds_after_reauthentication_and_is_audited() {
    let clock = StepClock::at(1_000);
    let boundary = boundary(&clock);

    // Advance the clock, then re-authenticate (fresh session at the new time).
    clock.set(5_000);
    let fresh = session_for("approver", &clock);

    let outcome = boundary
        .authorize(
            &fresh,
            &AuthorizationRequest::production_approval(Capability::ApproveAction),
            "approve production intent aa",
        )
        .await
        .unwrap();
    assert!(outcome.is_ok());

    // Production-approval grants are audited too.
    let events = boundary
        .audit()
        .recent(&piteka_storage::TenantScope::new("demo-org").unwrap(), 10)
        .await
        .unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].decision, "granted");
    assert_eq!(events[0].actor.as_deref(), Some("approver"));
}
