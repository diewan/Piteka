//! Unit coverage for the pure authorization policy.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use piteka_domain::{Capability, ConfiguredOrganization, SessionId, UserId};

use crate::authz::{AuthorizationRequest, Denial, ReauthPolicy};
use crate::session::{AuthenticatedSession, SessionAuthority, SessionSigner, Signature, SignatureAlgorithm};
use crate::Clock;

struct FoldSigner;
impl SessionSigner for FoldSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::DemoLocalV1
    }
    fn sign(&self, message: &[u8]) -> Signature {
        let mut acc: u64 = 1469598103934665603;
        for &b in message {
            acc = (acc ^ u64::from(b)).wrapping_mul(1099511628211);
        }
        Signature::new(SignatureAlgorithm::DemoLocalV1, acc.to_be_bytes().to_vec())
    }
    fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        signature.algorithm() == self.algorithm() && self.sign(message).bytes() == signature.bytes()
    }
}

#[derive(Clone)]
struct FixedClock(Arc<AtomicU64>);
impl FixedClock {
    fn at(now: u64) -> Self {
        Self(Arc::new(AtomicU64::new(now)))
    }
    fn set(&self, now: u64) {
        self.0.store(now, Ordering::SeqCst);
    }
}
impl Clock for FixedClock {
    fn unix_seconds(&self) -> u64 {
        self.0.load(Ordering::SeqCst)
    }
}

fn session(user: &str, clock: &FixedClock) -> AuthenticatedSession {
    let authority = SessionAuthority::new(FoldSigner, clock.clone(), ConfiguredOrganization::demo());
    let signed = authority
        .issue(&UserId::new(user).unwrap(), SessionId::from_bytes([9; 16]), 10_000)
        .unwrap();
    authority.authenticate(&signed).unwrap()
}

#[test]
fn role_enforcement_denies_missing_capability() {
    let clock = FixedClock::at(1_000);
    let requester = session("requester", &clock);
    let policy = ReauthPolicy::new(300);
    assert_eq!(
        policy.evaluate(
            &requester,
            &AuthorizationRequest::standard(Capability::ApproveAction),
            1_000,
        ),
        Err(Denial::Unauthorized(Capability::ApproveAction))
    );
    // The requester's own capability is granted.
    assert!(policy
        .evaluate(
            &requester,
            &AuthorizationRequest::standard(Capability::ProposeAction),
            1_000,
        )
        .is_ok());
}

#[test]
fn production_reauth_window_is_inclusive_at_the_boundary() {
    let clock = FixedClock::at(1_000);
    let approver = session("approver", &clock);
    let policy = ReauthPolicy::new(300);
    let request = AuthorizationRequest::production_approval(Capability::ApproveAction);

    // Age exactly at the window is still accepted.
    assert!(policy.evaluate(&approver, &request, 1_300).is_ok());
    // One second past the window is denied.
    assert!(matches!(
        policy.evaluate(&approver, &request, 1_301),
        Err(Denial::ReconfirmationRequired { .. })
    ));
}

#[test]
fn standard_actions_ignore_session_age() {
    let clock = FixedClock::at(1_000);
    let approver = session("approver", &clock);
    clock.set(9_000); // far past any re-auth window, but still valid
    let policy = ReauthPolicy::new(300);
    assert!(policy
        .evaluate(
            &approver,
            &AuthorizationRequest::standard(Capability::ApproveAction),
            9_000,
        )
        .is_ok());
}
