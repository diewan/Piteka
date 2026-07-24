//! Coverage for session claim construction and signing bytes.

use crate::identity::{OrganizationId, Role, UserId};
use crate::session::{SessionClaims, SessionError, SessionId};

fn claims(role: Role, issued: u64, expires: u64) -> Result<SessionClaims, SessionError> {
    SessionClaims::new(
        SessionId::from_bytes([7; 16]),
        UserId::new("requester").unwrap(),
        OrganizationId::new("diewan-demo").unwrap(),
        role,
        issued,
        expires,
    )
}

#[test]
fn claims_require_a_positive_lifetime() {
    assert_eq!(
        claims(Role::Requester, 100, 100),
        Err(SessionError::NonPositiveLifetime {
            issued_at_unix_seconds: 100,
            expires_at_unix_seconds: 100,
        })
    );
    assert!(matches!(
        claims(Role::Requester, 100, 50),
        Err(SessionError::NonPositiveLifetime { .. })
    ));
    assert!(claims(Role::Requester, 100, 101).is_ok());
}

#[test]
fn active_window_is_half_open() {
    let session = claims(Role::Approver, 100, 200).unwrap();
    assert!(!session.is_active_at(99));
    assert!(session.is_active_at(100));
    assert!(session.is_active_at(199));
    assert!(!session.is_active_at(200), "expiry is exclusive");
    assert!(!session.is_active_at(201));
}

#[test]
fn signing_bytes_change_with_every_field() {
    let base = claims(Role::Requester, 100, 200).unwrap().signing_bytes();

    // Different role -> different bytes (a role-elevation tamper is not silent).
    assert_ne!(
        base,
        claims(Role::Approver, 100, 200).unwrap().signing_bytes()
    );
    // Different window -> different bytes.
    assert_ne!(
        base,
        claims(Role::Requester, 101, 200).unwrap().signing_bytes()
    );
    assert_ne!(
        base,
        claims(Role::Requester, 100, 201).unwrap().signing_bytes()
    );

    // Different subject -> different bytes.
    let other_subject = SessionClaims::new(
        SessionId::from_bytes([7; 16]),
        UserId::new("approver").unwrap(),
        OrganizationId::new("diewan-demo").unwrap(),
        Role::Requester,
        100,
        200,
    )
    .unwrap();
    assert_ne!(base, other_subject.signing_bytes());

    // Different organization -> different bytes (cross-tenant tamper is visible).
    let other_org = SessionClaims::new(
        SessionId::from_bytes([7; 16]),
        UserId::new("requester").unwrap(),
        OrganizationId::new("other-tenant").unwrap(),
        Role::Requester,
        100,
        200,
    )
    .unwrap();
    assert_ne!(base, other_org.signing_bytes());
}

#[test]
fn signing_bytes_are_deterministic() {
    let a = claims(Role::Auditor, 100, 200).unwrap().signing_bytes();
    let b = claims(Role::Auditor, 100, 200).unwrap().signing_bytes();
    assert_eq!(a, b);
}
