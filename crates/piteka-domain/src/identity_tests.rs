//! Positive and adversarial coverage for identities and roles.

use crate::identity::{
    Capability, ConfiguredOrganization, Identity, IdentityError, Organization, OrganizationId, Role,
    UserId,
};

fn org_id() -> OrganizationId {
    OrganizationId::new("diewan-demo").unwrap()
}

#[test]
fn demo_organization_has_one_identity_per_role() {
    let configured = ConfiguredOrganization::demo();
    assert_eq!(configured.members().len(), 3);

    let roles: Vec<Role> = configured.members().iter().map(Identity::role).collect();
    assert!(roles.contains(&Role::Requester));
    assert!(roles.contains(&Role::Approver));
    assert!(roles.contains(&Role::Auditor));

    // Every member belongs to the single configured organization.
    for member in configured.members() {
        assert_eq!(member.organization(), configured.organization().id());
    }
}

#[test]
fn member_lookup_returns_the_configured_identity() {
    let configured = ConfiguredOrganization::demo();
    let requester = UserId::new("requester").unwrap();
    let found = configured.member(&requester).expect("requester configured");
    assert_eq!(found.role(), Role::Requester);

    let stranger = UserId::new("intruder").unwrap();
    assert!(configured.member(&stranger).is_none());
}

#[test]
fn role_capabilities_are_separated() {
    // Requester proposes and executes but cannot approve or verify.
    assert!(Role::Requester.grants(Capability::ProposeAction));
    assert!(Role::Requester.grants(Capability::ExecuteApprovedMandate));
    assert!(!Role::Requester.grants(Capability::ApproveAction));
    assert!(!Role::Requester.grants(Capability::VerifyBundle));

    // Approver decides but cannot propose or execute.
    assert!(Role::Approver.grants(Capability::ApproveAction));
    assert!(Role::Approver.grants(Capability::RevokeMandate));
    assert!(!Role::Approver.grants(Capability::ProposeAction));
    assert!(!Role::Approver.grants(Capability::ExecuteApprovedMandate));

    // Auditor reads and verifies but cannot approve or execute.
    assert!(Role::Auditor.grants(Capability::VerifyBundle));
    assert!(Role::Auditor.grants(Capability::ReadScopedRecords));
    assert!(!Role::Auditor.grants(Capability::ApproveAction));
    assert!(!Role::Auditor.grants(Capability::ExecuteApprovedMandate));
}

#[test]
fn role_tags_are_distinct() {
    let tags = [
        Role::Requester.tag(),
        Role::Approver.tag(),
        Role::Auditor.tag(),
    ];
    assert_eq!(tags[0], 1);
    let mut unique = tags.to_vec();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), 3, "role tags must be unique");
}

#[test]
fn empty_identifiers_are_rejected() {
    assert_eq!(
        OrganizationId::new(""),
        Err(IdentityError::EmptyField("organization_id"))
    );
    assert_eq!(
        UserId::new("   "),
        Err(IdentityError::EmptyField("user_id"))
    );
}

#[test]
fn configured_organization_rejects_a_cross_organization_member() {
    let organization = Organization::new(org_id(), "DieWan Demo").unwrap();
    let foreign = Identity::new(
        UserId::new("mallory").unwrap(),
        OrganizationId::new("other-tenant").unwrap(),
        "Foreign Member",
        Role::Auditor,
    )
    .unwrap();

    match ConfiguredOrganization::new(organization, vec![foreign]) {
        Err(IdentityError::CrossOrganizationMember { organization, member }) => {
            assert_eq!(organization.as_str(), "diewan-demo");
            assert_eq!(member.as_str(), "other-tenant");
        }
        other => panic!("expected CrossOrganizationMember, got {other:?}"),
    }
}

#[test]
fn configured_organization_rejects_duplicate_members() {
    let organization = Organization::new(org_id(), "DieWan Demo").unwrap();
    let make = |role| {
        Identity::new(UserId::new("shared").unwrap(), org_id(), "Shared", role).unwrap()
    };
    assert_eq!(
        ConfiguredOrganization::new(organization, vec![make(Role::Requester), make(Role::Approver)]),
        Err(IdentityError::DuplicateMember(UserId::new("shared").unwrap()))
    );
}

#[test]
fn configured_organization_rejects_no_members() {
    let organization = Organization::new(org_id(), "DieWan Demo").unwrap();
    assert_eq!(
        ConfiguredOrganization::new(organization, vec![]),
        Err(IdentityError::NoMembers)
    );
}
