//! Positive and adversarial coverage for signed local sessions.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use piteka_domain::{
    Capability, ConfiguredOrganization, OrganizationId, Role, SessionClaims, SessionId, UserId,
};

use crate::Clock;
use crate::session::{
    AuthError, SessionAuthority, SessionSigner, Signature, SignatureAlgorithm, SignedSession,
};

/// A deterministic test signer. It is a **test double**, not cryptography: the
/// "signature" is a keyed fold, sufficient to prove the authority verifies,
/// rejects forgeries, and rejects tampered claims. The production/demo signer is
/// an infrastructure adapter wired by ticket D-04.
struct FoldSigner {
    key: u8,
}

impl SessionSigner for FoldSigner {
    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::DemoLocalV1
    }

    fn sign(&self, message: &[u8]) -> Signature {
        let mut acc: u64 = 0xcbf2_9ce4_8422_2325;
        for &byte in message {
            acc = (acc ^ u64::from(byte ^ self.key)).wrapping_mul(0x0100_0000_01b3);
        }
        Signature::new(SignatureAlgorithm::DemoLocalV1, acc.to_be_bytes().to_vec())
    }

    fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        signature.algorithm() == self.algorithm() && self.sign(message).bytes() == signature.bytes()
    }
}

/// A clock whose time the test can advance; shared via `Arc` so a clone handed
/// to the authority observes updates made through the retained handle.
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

fn authority(clock: &StepClock, key: u8) -> SessionAuthority<FoldSigner, StepClock> {
    SessionAuthority::new(
        FoldSigner { key },
        clock.clone(),
        ConfiguredOrganization::demo(),
    )
}

fn requester() -> UserId {
    UserId::new("requester").unwrap()
}

fn sid() -> SessionId {
    SessionId::from_bytes([1; 16])
}

#[test]
fn issue_then_authenticate_and_authorize_succeeds() {
    let clock = StepClock::at(1_000);
    let authority = authority(&clock, 0x5a);
    let session = authority.issue(&requester(), sid(), 3_600).unwrap();

    let authenticated = authority.authenticate(&session).unwrap();
    assert_eq!(authenticated.role(), Role::Requester);
    assert_eq!(authenticated.identity().user_id(), &requester());

    assert!(
        authority
            .authorize(&authenticated, Capability::ProposeAction)
            .is_ok()
    );
    assert_eq!(
        authority.authorize(&authenticated, Capability::ApproveAction),
        Err(AuthError::Unauthorized(Capability::ApproveAction))
    );
}

#[test]
fn issue_binds_role_from_directory_not_caller() {
    let clock = StepClock::at(1_000);
    let authority = authority(&clock, 1);
    for (user, role) in [
        ("requester", Role::Requester),
        ("approver", Role::Approver),
        ("auditor", Role::Auditor),
    ] {
        let session = authority
            .issue(&UserId::new(user).unwrap(), sid(), 60)
            .unwrap();
        assert_eq!(session.claims().role(), role);
    }
}

#[test]
fn issue_rejects_unknown_subject() {
    let clock = StepClock::at(1_000);
    let authority = authority(&clock, 1);
    assert_eq!(
        authority
            .issue(&UserId::new("intruder").unwrap(), sid(), 60)
            .unwrap_err(),
        AuthError::UnknownSubject(UserId::new("intruder").unwrap())
    );
}

#[test]
fn authenticate_rejects_a_forged_signature() {
    let clock = StepClock::at(1_000);
    let issuer = authority(&clock, 0x11);
    let genuine = issuer.issue(&requester(), sid(), 3_600).unwrap();

    // Attacker signs the same claims with a different key.
    let forger = FoldSigner { key: 0x22 };
    let forged = SignedSession::from_parts(
        genuine.claims().clone(),
        forger.sign(&genuine.claims().signing_bytes()),
    );
    assert_eq!(
        issuer.authenticate(&forged),
        Err(AuthError::InvalidSignature)
    );
}

#[test]
fn authenticate_rejects_tampered_claims() {
    // Keep a genuine signature but splice in different (elevated) claims.
    let clock = StepClock::at(1_000);
    let authority = authority(&clock, 0x33);
    let requester_session = authority.issue(&requester(), sid(), 3_600).unwrap();
    let approver_session = authority
        .issue(&UserId::new("approver").unwrap(), sid(), 3_600)
        .unwrap();

    let spliced = SignedSession::from_parts(
        approver_session.claims().clone(),
        requester_session.signature().clone(),
    );
    assert_eq!(
        authority.authenticate(&spliced),
        Err(AuthError::InvalidSignature)
    );
}

#[test]
fn authenticate_rejects_expired_and_not_yet_valid_sessions() {
    let clock = StepClock::at(1_000);
    let authority = authority(&clock, 7);
    let session = authority.issue(&requester(), sid(), 100).unwrap(); // valid [1000, 1100)

    clock.set(1_100);
    assert!(matches!(
        authority.authenticate(&session),
        Err(AuthError::Expired { .. })
    ));

    clock.set(999);
    assert!(matches!(
        authority.authenticate(&session),
        Err(AuthError::NotYetValid { .. })
    ));

    clock.set(1_050);
    assert!(authority.authenticate(&session).is_ok());
}

#[test]
fn authenticate_rejects_role_tamper_that_keeps_a_valid_signature() {
    // Sign claims whose role disagrees with the directory (as if a signing key
    // were misused). The directory cross-check still denies.
    let clock = StepClock::at(1_000);
    let authority = authority(&clock, 4);
    let forged_claims = SessionClaims::new(
        sid(),
        requester(),
        OrganizationId::new("diewan-demo").unwrap(),
        Role::Approver, // requester is not an approver in the directory
        1_000,
        4_600,
    )
    .unwrap();
    let signer = FoldSigner { key: 4 };
    let signed = SignedSession::from_parts(
        forged_claims.clone(),
        signer.sign(&forged_claims.signing_bytes()),
    );

    assert_eq!(
        authority.authenticate(&signed),
        Err(AuthError::RoleMismatch {
            configured: Role::Requester,
            claimed: Role::Approver,
        })
    );
}

#[test]
fn authenticate_rejects_cross_organization_claims() {
    let clock = StepClock::at(1_000);
    let authority = authority(&clock, 4);
    let cross_org = SessionClaims::new(
        sid(),
        requester(),
        OrganizationId::new("other-tenant").unwrap(),
        Role::Requester,
        1_000,
        4_600,
    )
    .unwrap();
    let signer = FoldSigner { key: 4 };
    let signed =
        SignedSession::from_parts(cross_org.clone(), signer.sign(&cross_org.signing_bytes()));

    assert_eq!(
        authority.authenticate(&signed),
        Err(AuthError::CrossOrganization)
    );
}
