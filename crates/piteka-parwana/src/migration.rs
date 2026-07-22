//! Piteka adapter: normalize raw database-migration input to the registered
//! `DbMigrationIntentV1` profile (PROFILE-02).
//!
//! This is the concrete consumer-side adapter proving the profile model is not
//! GitHub-specific: it takes untrusted provider input, computes the exact
//! migration-plan digest itself (the agent never supplies a free-form digest),
//! builds the profile, and constructs a canonical [`ActionIntent`] through the
//! generic registry path. Security-relevant fields are bound into the parameters
//! commitment; presentation names never displace the stable database/environment
//! ids.

use sha2::{Digest, Sha256};

use crate::protocol::{
    ActionIntent, DB_MIGRATION_PROFILE_ID, DbMigrationIntentV1, IntentError, MigrationDirection,
    ProfileId, ProfileRegistry,
};

/// Raw, untrusted database-migration request as a provider/agent supplies it.
///
/// Note the caller supplies the migration **plan bytes**, not a digest: the
/// adapter derives the digest so the agent cannot bind the mandate to a plan it
/// did not disclose.
#[derive(Clone, Debug)]
pub struct MigrationInput {
    /// Stable provider database identifier.
    pub database_id: u64,
    /// Presentation-only database name.
    pub database_name: String,
    /// Stable provider environment identifier.
    pub environment_id: u64,
    /// Presentation-only environment name.
    pub environment_name: String,
    /// Stable migration identifier (version/name).
    pub migration_id: String,
    /// The exact migration plan/script bytes; the adapter hashes these.
    pub migration_plan: Vec<u8>,
    /// Migration direction (forward or rollback).
    pub direction: MigrationDirection,
    /// Whether destructive statements are permitted by this authorization.
    pub allow_destructive: bool,
    /// Number of statements in the plan.
    pub statement_count: u32,
    /// Presentation-only change-ticket reference.
    pub change_ticket: String,
}

/// Derives the exact migration-plan digest committed into the intent.
///
/// This is an opaque, domain-tagged commitment to the plan bytes the caller
/// discloses — application input, not a canonical protocol-object hash (those
/// stay in Parwana). The adapter computing it is what stops an agent binding a
/// mandate to a plan it never disclosed.
#[must_use]
pub fn migration_plan_digest(plan: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"db-migration-plan-v1");
    hasher.update(plan);
    hasher.finalize().into()
}

/// Normalizes untrusted input into the canonical `DbMigrationIntentV1` profile.
///
/// # Errors
///
/// Returns an [`IntentError`] if the input fails the profile's canonical
/// validation (zero stable ids, empty/over-long fields, a zero-statement plan,
/// and so on).
pub fn normalize_migration_profile(
    input: &MigrationInput,
) -> Result<DbMigrationIntentV1, IntentError> {
    let profile = DbMigrationIntentV1 {
        database_id: input.database_id,
        database_name: input.database_name.clone(),
        environment_id: input.environment_id,
        environment_name: input.environment_name.clone(),
        migration_id: input.migration_id.clone(),
        migration_digest: migration_plan_digest(&input.migration_plan),
        direction: input.direction,
        allow_destructive: input.allow_destructive,
        statement_count: input.statement_count,
        change_ticket: input.change_ticket.clone(),
    };
    // Validate now so a bad input fails at normalization, not later at dispatch.
    profile.validate()?;
    Ok(profile)
}

/// Builds a canonical [`ActionIntent`] for the database-migration profile through
/// the generic registry path.
///
/// # Errors
///
/// Returns an [`IntentError`] if the profile is unregistered or the input fails
/// canonical validation.
pub fn build_migration_action_intent(
    registry: &ProfileRegistry,
    input: &MigrationInput,
    requested_by: Vec<u8>,
    requested_at: u64,
    request_nonce: [u8; 32],
    context_commitments: Vec<[u8; 32]>,
) -> Result<ActionIntent, IntentError> {
    let profile = normalize_migration_profile(input)?;
    let profile_id = ProfileId::new(DB_MIGRATION_PROFILE_ID)?;
    let descriptor = registry
        .descriptor(&profile_id)
        .ok_or(IntentError::UnregisteredProfile)?;
    let codec = registry
        .codec(&profile_id)
        .ok_or(IntentError::UnregisteredProfile)?;
    let profile_bytes = profile.canonical_bytes()?;
    ActionIntent::new(
        descriptor,
        codec,
        profile_bytes,
        requested_by,
        requested_at,
        request_nonce,
        context_commitments,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::{DB_MIGRATION_ACTION_TYPE, default_registry};

    fn input() -> MigrationInput {
        MigrationInput {
            database_id: 42,
            database_name: "orders-prod".to_string(),
            environment_id: 7,
            environment_name: "production".to_string(),
            migration_id: "2026_07_22_add_index".to_string(),
            migration_plan: b"CREATE INDEX CONCURRENTLY ...".to_vec(),
            direction: MigrationDirection::Forward,
            allow_destructive: false,
            statement_count: 1,
            change_ticket: "CHG-1024".to_string(),
        }
    }

    #[test]
    fn normalizes_and_builds_a_registered_intent() {
        let registry = default_registry();
        let intent =
            build_migration_action_intent(&registry, &input(), b"svc:migrator".to_vec(), 1, [9u8; 32], vec![])
                .expect("builds");
        assert_eq!(intent.action_type, DB_MIGRATION_ACTION_TYPE);
        // The stable target is the ids only, derived by the codec.
        assert_eq!(intent.target, {
            let mut t = 42u64.to_be_bytes().to_vec();
            t.extend_from_slice(&7u64.to_be_bytes());
            t
        });
    }

    #[test]
    fn the_agent_cannot_forge_the_plan_digest_a_changed_plan_changes_the_commitment() {
        let registry = default_registry();
        let base = build_migration_action_intent(&registry, &input(), b"svc".to_vec(), 1, [9u8; 32], vec![])
            .unwrap()
            .parameters_commitment;
        let mut tampered = input();
        tampered.migration_plan = b"DROP TABLE orders;".to_vec();
        let changed =
            build_migration_action_intent(&registry, &tampered, b"svc".to_vec(), 1, [9u8; 32], vec![])
                .unwrap()
                .parameters_commitment;
        assert_ne!(base, changed, "a different plan must change the commitment");
    }

    #[test]
    fn display_names_do_not_change_the_stable_target() {
        let registry = default_registry();
        let target = |i: &MigrationInput| {
            build_migration_action_intent(&registry, i, b"svc".to_vec(), 1, [9u8; 32], vec![])
                .unwrap()
                .target
        };
        let mut renamed = input();
        renamed.database_name = "totally-different".to_string();
        renamed.environment_name = "prod-us-east".to_string();
        renamed.change_ticket = "CHG-9999".to_string();
        assert_eq!(target(&input()), target(&renamed));
    }

    #[test]
    fn invalid_input_fails_closed_at_normalization() {
        let mut bad = input();
        bad.database_id = 0;
        assert_eq!(
            normalize_migration_profile(&bad),
            Err(IntentError::InvalidStableId)
        );
        let mut bad = input();
        bad.statement_count = 0;
        assert_eq!(
            normalize_migration_profile(&bad),
            Err(IntentError::EmptyField("statement_count"))
        );
    }
}
