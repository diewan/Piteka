use super::portable_execution::{
    ClosureRecoveryState, PortableExclusivity, PortableExecutionGrounding, RecoveryAction,
    ground_execution,
};

#[test]
fn ungrounded_profile_declares_its_limitation() {
    let result = ground_execution(PortableExclusivity::NotRequired, None, None)
        .expect("explicitly ungrounded profile is valid");
    assert!(matches!(
        result,
        PortableExecutionGrounding::Ungrounded { limitation }
            if limitation.contains("not required")
    ));
}

#[test]
fn portable_profile_fails_before_dispatch_without_verified_closure() {
    assert!(ground_execution(PortableExclusivity::Required, None, None).is_err());
    assert!(
        ground_execution(PortableExclusivity::Required, Some(&[0xff]), Some("satisfied")).is_err()
    );
    assert!(
        ground_execution(PortableExclusivity::Required, Some(&[0xff]), Some("indeterminate"))
            .is_err()
    );
}

#[test]
fn recovery_never_releases_after_source_closure() {
    assert_eq!(
        ClosureRecoveryState::PreClosureFailure.action(),
        RecoveryAction::ReleaseReservation
    );
    assert_eq!(
        ClosureRecoveryState::ClosedBeforeDispatch.action(),
        RecoveryAction::Quarantine
    );
    assert_eq!(
        ClosureRecoveryState::DispatchOutcomeUnknown.action(),
        RecoveryAction::Quarantine
    );
    assert_eq!(
        ClosureRecoveryState::Complete.action(),
        RecoveryAction::Consume
    );
}
