//! Configured-organization identities and roles for the first demo slice.
//!
//! The demo operates as **one configured organization** with three local roles
//! (Master Plan §15, §21 "one configured organization with three local roles").
//! Full tenants, memberships, service-identity administration, and KMS-backed
//! credentials are post-slice hardening — see the demo-identity ADR under
//! `docs/adr/`. Nothing here is a production identity provider.

use std::fmt;

/// A validation failure while constructing an identity or organization.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum IdentityError {
    /// A required identifier or name was empty or whitespace-only.
    EmptyField(&'static str),
    /// A member's organization did not match the configured organization.
    CrossOrganizationMember {
        /// The configured organization.
        organization: OrganizationId,
        /// The member's declared organization.
        member: OrganizationId,
    },
    /// Two members shared the same stable user identifier.
    DuplicateMember(UserId),
    /// The configured organization declared no members.
    NoMembers,
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyField(field) => write!(f, "identity field `{field}` must not be empty"),
            Self::CrossOrganizationMember {
                organization,
                member,
            } => write!(
                f,
                "member organization `{}` does not belong to configured organization `{}`",
                member.as_str(),
                organization.as_str()
            ),
            Self::DuplicateMember(user) => {
                write!(f, "duplicate member identity `{}`", user.as_str())
            }
            Self::NoMembers => f.write_str("configured organization must have at least one member"),
        }
    }
}

impl std::error::Error for IdentityError {}

fn require_nonempty(field: &'static str, value: &str) -> Result<(), IdentityError> {
    if value.trim().is_empty() {
        Err(IdentityError::EmptyField(field))
    } else {
        Ok(())
    }
}

/// A stable organization identifier.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct OrganizationId(String);

impl OrganizationId {
    /// Constructs an organization identifier, rejecting empty values.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::EmptyField`] when `value` is empty or blank.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        require_nonempty("organization_id", &value)?;
        Ok(Self(value))
    }

    /// Borrows the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A stable user identifier within an organization.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct UserId(String);

impl UserId {
    /// Constructs a user identifier, rejecting empty values.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::EmptyField`] when `value` is empty or blank.
    pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
        let value = value.into();
        require_nonempty("user_id", &value)?;
        Ok(Self(value))
    }

    /// Borrows the identifier text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A discrete permission a role may grant.
///
/// Deliberately there is **no** capability that edits a canonical signed object:
/// Master Plan §15 requires corrections to be append-only superseding records,
/// so no role can mutate authority, receipts, or evidence in place.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Capability {
    /// Propose an action for approval.
    ProposeAction,
    /// Receive status of a proposed or approved action.
    ReceiveActionStatus,
    /// Execute an already-approved mandate through a constrained tool.
    ExecuteApprovedMandate,
    /// Review a human-readable action intent.
    ReviewIntent,
    /// Approve a reviewed action.
    ApproveAction,
    /// Reject a reviewed action.
    RejectAction,
    /// Attach conditions required for approval.
    RequireConditions,
    /// Revoke a mandate before dispatch.
    RevokeMandate,
    /// Read scoped accountability records.
    ReadScopedRecords,
    /// Verify an exported dispute bundle.
    VerifyBundle,
    /// Inspect assurance dimensions and stated limitations.
    InspectAssurance,
    /// Create and append to tenant-scoped investigator cases.
    ManageInvestigatorCases,
}

/// A demo role. The first slice ships exactly these three local roles.
///
/// Investigator, Security operator, and Tenant administrator (Master Plan §15)
/// are post-demo roles and are intentionally absent here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Role {
    /// Proposes actions and executes approved mandates through a constrained tool.
    Requester,
    /// Reviews intents and approves, rejects, conditions, or revokes them.
    Approver,
    /// Reads scoped records, verifies bundles, and inspects assurance.
    Auditor,
}

impl Role {
    /// The exact capabilities this role grants.
    #[must_use]
    pub fn capabilities(self) -> &'static [Capability] {
        match self {
            Self::Requester => &[
                Capability::ProposeAction,
                Capability::ReceiveActionStatus,
                Capability::ExecuteApprovedMandate,
            ],
            Self::Approver => &[
                Capability::ReviewIntent,
                Capability::ApproveAction,
                Capability::RejectAction,
                Capability::RequireConditions,
                Capability::RevokeMandate,
            ],
            Self::Auditor => &[
                Capability::ReadScopedRecords,
                Capability::VerifyBundle,
                Capability::InspectAssurance,
                Capability::ManageInvestigatorCases,
            ],
        }
    }

    /// Whether this role grants `capability`.
    #[must_use]
    pub fn grants(self, capability: Capability) -> bool {
        self.capabilities().contains(&capability)
    }

    /// The stable wire tag used when a role is committed to signed session bytes.
    #[must_use]
    pub const fn tag(self) -> u8 {
        match self {
            Self::Requester => 1,
            Self::Approver => 2,
            Self::Auditor => 3,
        }
    }
}

/// The configured organization itself.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Organization {
    id: OrganizationId,
    display_name: String,
}

impl Organization {
    /// Constructs an organization, rejecting an empty display name.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::EmptyField`] when the display name is blank.
    pub fn new(id: OrganizationId, display_name: impl Into<String>) -> Result<Self, IdentityError> {
        let display_name = display_name.into();
        require_nonempty("organization_display_name", &display_name)?;
        Ok(Self { id, display_name })
    }

    /// The organization identifier.
    #[must_use]
    pub fn id(&self) -> &OrganizationId {
        &self.id
    }

    /// The presentation display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }
}

/// A member identity bound to an organization and a single role.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Identity {
    user_id: UserId,
    organization: OrganizationId,
    display_name: String,
    role: Role,
}

impl Identity {
    /// Constructs a member identity, rejecting an empty display name.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::EmptyField`] when the display name is blank.
    pub fn new(
        user_id: UserId,
        organization: OrganizationId,
        display_name: impl Into<String>,
        role: Role,
    ) -> Result<Self, IdentityError> {
        let display_name = display_name.into();
        require_nonempty("identity_display_name", &display_name)?;
        Ok(Self {
            user_id,
            organization,
            display_name,
            role,
        })
    }

    /// The stable user identifier.
    #[must_use]
    pub fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// The organization this identity belongs to.
    #[must_use]
    pub fn organization(&self) -> &OrganizationId {
        &self.organization
    }

    /// The presentation display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.display_name
    }

    /// The single role this identity holds.
    #[must_use]
    pub fn role(&self) -> Role {
        self.role
    }
}

/// One configured organization and its member identities.
///
/// Construction fails closed: every member must belong to the configured
/// organization and no two members may share a user identifier. This is the
/// enforcement point that keeps a cross-tenant identity out of the demo.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfiguredOrganization {
    organization: Organization,
    members: Vec<Identity>,
}

impl ConfiguredOrganization {
    /// Assembles the configured organization from its members.
    ///
    /// # Errors
    ///
    /// Returns [`IdentityError::NoMembers`] when `members` is empty,
    /// [`IdentityError::CrossOrganizationMember`] when a member belongs to a
    /// different organization, or [`IdentityError::DuplicateMember`] when two
    /// members share a user identifier.
    pub fn new(organization: Organization, members: Vec<Identity>) -> Result<Self, IdentityError> {
        if members.is_empty() {
            return Err(IdentityError::NoMembers);
        }
        for (index, member) in members.iter().enumerate() {
            if member.organization() != organization.id() {
                return Err(IdentityError::CrossOrganizationMember {
                    organization: organization.id().clone(),
                    member: member.organization().clone(),
                });
            }
            if members[..index]
                .iter()
                .any(|other| other.user_id() == member.user_id())
            {
                return Err(IdentityError::DuplicateMember(member.user_id().clone()));
            }
        }
        Ok(Self {
            organization,
            members,
        })
    }

    /// The configured organization.
    #[must_use]
    pub fn organization(&self) -> &Organization {
        &self.organization
    }

    /// The configured member identities.
    #[must_use]
    pub fn members(&self) -> &[Identity] {
        &self.members
    }

    /// Looks up a member by stable user identifier.
    #[must_use]
    pub fn member(&self, user_id: &UserId) -> Option<&Identity> {
        self.members
            .iter()
            .find(|member| member.user_id() == user_id)
    }

    /// Builds the single demo organization with one identity per demo role.
    ///
    /// Demo scaffolding only. A production deployment loads its organization and
    /// members from configuration and an identity provider, never from this
    /// hard-coded fixture.
    #[must_use]
    pub fn demo() -> Self {
        let organization_id =
            OrganizationId::new("diewan-demo").expect("static demo organization id is non-empty");
        let organization = Organization::new(organization_id.clone(), "DieWan Demo Organization")
            .expect("static demo organization name is non-empty");
        let members = [
            ("requester", "Demo Requester", Role::Requester),
            ("approver", "Demo Approver", Role::Approver),
            ("auditor", "Demo Auditor", Role::Auditor),
        ]
        .into_iter()
        .map(|(user, display, role)| {
            Identity::new(
                UserId::new(user).expect("static demo user id is non-empty"),
                organization_id.clone(),
                display,
                role,
            )
            .expect("static demo identity display name is non-empty")
        })
        .collect();
        Self::new(organization, members).expect("static demo organization is well-formed")
    }
}
