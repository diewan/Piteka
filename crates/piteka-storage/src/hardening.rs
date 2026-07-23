//! Immutable evidence, durable outbox, and retention primitives.
//!
//! These in-memory implementations specify adapter semantics and power
//! adversarial tests. PostgreSQL/S3 adapters must preserve the same tenant,
//! conditional-write, leasing, idempotency, and tombstone invariants.

use sha2::{Digest, Sha256};
use std::collections::{HashMap, HashSet};
use std::sync::Mutex;

/// Object storage failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ObjectStoreError {
    /// Adapter is unavailable; callers must not report completion.
    Unavailable,
    /// An immutable key already exists with different bytes.
    OverwriteAttempt,
    /// Stored bytes no longer match their content address.
    IntegrityViolation,
    /// Object was not found.
    NotFound,
}

/// Immutable, version-addressed evidence.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VersionedEvidence {
    /// Tenant scope embedded in the object key.
    pub tenant_id: String,
    /// SHA-256 content address.
    pub digest_hex: String,
    /// Provider version id (opaque).
    pub version_id: String,
    /// Immutable payload.
    pub bytes: Vec<u8>,
    /// Retention-until time enforced by object lock.
    pub retain_until_unix_seconds: u64,
}

/// S3-compatible immutable semantics with conditional create and integrity reads.
#[derive(Default)]
pub struct ImmutableEvidenceStore {
    objects: Mutex<HashMap<(String, String), VersionedEvidence>>,
    unavailable: Mutex<bool>,
}

impl ImmutableEvidenceStore {
    /// Simulates provider availability for fail-closed tests.
    pub fn set_unavailable(&self, unavailable: bool) {
        *self.unavailable.lock().unwrap() = unavailable;
    }

    /// Creates an object once. Identical retries are idempotent.
    pub fn put_once(
        &self,
        tenant_id: &str,
        bytes: &[u8],
        retain_until_unix_seconds: u64,
    ) -> Result<VersionedEvidence, ObjectStoreError> {
        self.available()?;
        let digest_hex = hex::encode(Sha256::digest(bytes));
        let key = (tenant_id.to_string(), digest_hex.clone());
        let mut objects = self.objects.lock().unwrap();
        if let Some(existing) = objects.get(&key) {
            if existing.bytes == bytes {
                return Ok(existing.clone());
            }
            return Err(ObjectStoreError::OverwriteAttempt);
        }
        let object = VersionedEvidence {
            tenant_id: tenant_id.to_string(),
            version_id: format!("sha256:{digest_hex}"),
            digest_hex,
            bytes: bytes.to_vec(),
            retain_until_unix_seconds,
        };
        objects.insert(key, object.clone());
        Ok(object)
    }

    /// Reads and verifies content integrity.
    pub fn get(
        &self,
        tenant_id: &str,
        digest_hex: &str,
    ) -> Result<VersionedEvidence, ObjectStoreError> {
        self.available()?;
        let object = self
            .objects
            .lock()
            .unwrap()
            .get(&(tenant_id.to_string(), digest_hex.to_string()))
            .cloned()
            .ok_or(ObjectStoreError::NotFound)?;
        if hex::encode(Sha256::digest(&object.bytes)) != object.digest_hex {
            return Err(ObjectStoreError::IntegrityViolation);
        }
        Ok(object)
    }

    /// Test/support hook representing out-of-band provider corruption.
    pub fn corrupt_for_test(&self, tenant_id: &str, digest_hex: &str) {
        if let Some(object) = self
            .objects
            .lock()
            .unwrap()
            .get_mut(&(tenant_id.to_string(), digest_hex.to_string()))
        {
            object.bytes.push(0xff);
        }
    }

    fn available(&self) -> Result<(), ObjectStoreError> {
        if *self.unavailable.lock().unwrap() {
            Err(ObjectStoreError::Unavailable)
        } else {
            Ok(())
        }
    }
}

/// Outbox delivery status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum OutboxStatus {
    /// Committed with domain state but not published.
    Pending,
    /// Leased by one publisher.
    Leased,
    /// Successfully published.
    Published,
    /// Exhausted retries and isolated from the normal queue.
    Quarantined,
}

/// Durable publication record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxEvent {
    /// Globally stable idempotency key.
    pub event_id: String,
    /// Tenant scope.
    pub tenant_id: String,
    /// Stable event kind.
    pub kind: String,
    /// Content-addressed payload digest.
    pub payload_digest_hex: String,
    /// State.
    pub status: OutboxStatus,
    /// Delivery attempts.
    pub attempts: u32,
}

#[derive(Clone, Debug)]
struct StoredOutbox {
    event: OutboxEvent,
    lease_owner: Option<String>,
    lease_expires_at: u64,
}

/// Lease returned to one publisher.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutboxLease {
    /// Event to publish.
    pub event: OutboxEvent,
    /// Lease owner required for acknowledgement.
    pub owner: String,
    /// Expiration.
    pub expires_at_unix_seconds: u64,
}

/// Outbox failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutboxError {
    /// Same event id was reused for different content or tenant.
    IdempotencyConflict,
    /// Lease is absent, expired, or belongs to another worker.
    InvalidLease,
    /// Event not found in tenant.
    NotFound,
}

/// Transactional outbox state machine.
#[derive(Default)]
pub struct DurableOutbox {
    events: Mutex<HashMap<(String, String), StoredOutbox>>,
}

impl DurableOutbox {
    /// Enqueues the event idempotently. Database adapters call this in the same
    /// transaction as the authoritative domain mutation.
    pub fn enqueue(&self, event: OutboxEvent) -> Result<(), OutboxError> {
        let key = (event.tenant_id.clone(), event.event_id.clone());
        let mut events = self.events.lock().unwrap();
        if let Some(existing) = events.get(&key) {
            if existing.event.kind == event.kind
                && existing.event.payload_digest_hex == event.payload_digest_hex
            {
                return Ok(());
            }
            return Err(OutboxError::IdempotencyConflict);
        }
        events.insert(
            key,
            StoredOutbox {
                event: OutboxEvent {
                    status: OutboxStatus::Pending,
                    attempts: 0,
                    ..event
                },
                lease_owner: None,
                lease_expires_at: 0,
            },
        );
        Ok(())
    }

    /// Leases pending work; expired leases are crash-recoverable.
    pub fn lease(
        &self,
        tenant_id: &str,
        owner: &str,
        now_unix_seconds: u64,
        lease_seconds: u64,
    ) -> Option<OutboxLease> {
        let mut events = self.events.lock().unwrap();
        let stored = events.values_mut().find(|stored| {
            stored.event.tenant_id == tenant_id
                && (stored.event.status == OutboxStatus::Pending
                    || (stored.event.status == OutboxStatus::Leased
                        && stored.lease_expires_at <= now_unix_seconds))
        })?;
        stored.event.status = OutboxStatus::Leased;
        stored.lease_owner = Some(owner.to_string());
        stored.lease_expires_at = now_unix_seconds.saturating_add(lease_seconds);
        Some(OutboxLease {
            event: stored.event.clone(),
            owner: owner.to_string(),
            expires_at_unix_seconds: stored.lease_expires_at,
        })
    }

    /// Marks one leased event published. Duplicate downstream delivery is
    /// harmless because `event_id` is the consumer idempotency key.
    pub fn acknowledge(
        &self,
        lease: &OutboxLease,
        now_unix_seconds: u64,
    ) -> Result<(), OutboxError> {
        let mut events = self.events.lock().unwrap();
        let stored = events
            .get_mut(&(lease.event.tenant_id.clone(), lease.event.event_id.clone()))
            .ok_or(OutboxError::NotFound)?;
        validate_lease(stored, lease, now_unix_seconds)?;
        stored.event.status = OutboxStatus::Published;
        stored.lease_owner = None;
        Ok(())
    }

    /// Releases for retry or quarantines a poison message.
    pub fn fail(
        &self,
        lease: &OutboxLease,
        now_unix_seconds: u64,
        max_attempts: u32,
    ) -> Result<OutboxStatus, OutboxError> {
        let mut events = self.events.lock().unwrap();
        let stored = events
            .get_mut(&(lease.event.tenant_id.clone(), lease.event.event_id.clone()))
            .ok_or(OutboxError::NotFound)?;
        validate_lease(stored, lease, now_unix_seconds)?;
        stored.event.attempts = stored.event.attempts.saturating_add(1);
        stored.event.status = if stored.event.attempts >= max_attempts {
            OutboxStatus::Quarantined
        } else {
            OutboxStatus::Pending
        };
        stored.lease_owner = None;
        Ok(stored.event.status)
    }

    /// Returns a snapshot for operations/metrics.
    pub fn get(&self, tenant_id: &str, event_id: &str) -> Option<OutboxEvent> {
        self.events
            .lock()
            .unwrap()
            .get(&(tenant_id.to_string(), event_id.to_string()))
            .map(|stored| stored.event.clone())
    }
}

fn validate_lease(stored: &StoredOutbox, lease: &OutboxLease, now: u64) -> Result<(), OutboxError> {
    if stored.event.status != OutboxStatus::Leased
        || stored.lease_owner.as_deref() != Some(&lease.owner)
        || stored.lease_expires_at != lease.expires_at_unix_seconds
        || stored.lease_expires_at <= now
    {
        Err(OutboxError::InvalidLease)
    } else {
        Ok(())
    }
}

/// Purpose-limited retention classes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionClass {
    /// Short-lived operational telemetry.
    Operational { retain_seconds: u64 },
    /// Accountability evidence.
    Evidence { retain_seconds: u64 },
}

/// Active legal hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegalHold {
    /// Tenant.
    pub tenant_id: String,
    /// Evidence digest.
    pub digest_hex: String,
    /// Case/reason reference.
    pub reason: String,
}

/// Commitment retained after payload deletion. It explicitly says the payload
/// is unavailable and never claims the evidenced action did not occur.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Tombstone {
    /// Tenant.
    pub tenant_id: String,
    /// Original content commitment.
    pub digest_hex: String,
    /// Deletion time.
    pub deleted_at_unix_seconds: u64,
    /// Stable absence semantics.
    pub meaning: &'static str,
}

/// Retention failures.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RetentionError {
    /// Active hold prevents deletion.
    LegalHoldActive,
    /// Retention period has not elapsed.
    RetentionActive,
    /// DB/object transaction or publication did not complete.
    Incomplete,
}

/// Coordinates retention metadata and legal holds.
#[derive(Default)]
pub struct EvidenceRetention {
    holds: Mutex<HashSet<(String, String)>>,
    tombstones: Mutex<HashMap<(String, String), Tombstone>>,
}

impl EvidenceRetention {
    /// Places an idempotent legal hold.
    pub fn place_hold(&self, hold: LegalHold) -> Result<(), RetentionError> {
        if hold.reason.trim().is_empty() {
            return Err(RetentionError::Incomplete);
        }
        self.holds
            .lock()
            .unwrap()
            .insert((hold.tenant_id, hold.digest_hex));
        Ok(())
    }

    /// Releases a hold after an authorized case decision.
    pub fn release_hold(&self, tenant_id: &str, digest_hex: &str) {
        self.holds
            .lock()
            .unwrap()
            .remove(&(tenant_id.to_string(), digest_hex.to_string()));
    }

    /// Records coherent deletion only after both object and database adapters
    /// confirm removal and the durable deletion event is committed.
    pub fn confirm_deletion(
        &self,
        object: &VersionedEvidence,
        now_unix_seconds: u64,
        database_deleted: bool,
        object_deleted: bool,
        outbox_committed: bool,
    ) -> Result<Tombstone, RetentionError> {
        let key = (object.tenant_id.clone(), object.digest_hex.clone());
        if self.holds.lock().unwrap().contains(&key) {
            return Err(RetentionError::LegalHoldActive);
        }
        if now_unix_seconds < object.retain_until_unix_seconds {
            return Err(RetentionError::RetentionActive);
        }
        if !(database_deleted && object_deleted && outbox_committed) {
            return Err(RetentionError::Incomplete);
        }
        let tombstone = Tombstone {
            tenant_id: object.tenant_id.clone(),
            digest_hex: object.digest_hex.clone(),
            deleted_at_unix_seconds: now_unix_seconds,
            meaning: "payload deleted; commitment retained; occurrence is not determined",
        };
        self.tombstones
            .lock()
            .unwrap()
            .insert(key, tombstone.clone());
        Ok(tombstone)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn immutable_store_detects_tamper_and_unavailability() {
        let store = ImmutableEvidenceStore::default();
        let object = store.put_once("tenant-a", b"evidence", 100).unwrap();
        assert_eq!(store.get("tenant-a", &object.digest_hex).unwrap(), object);
        store.corrupt_for_test("tenant-a", &object.digest_hex);
        assert_eq!(
            store.get("tenant-a", &object.digest_hex),
            Err(ObjectStoreError::IntegrityViolation)
        );
        store.set_unavailable(true);
        assert_eq!(
            store.put_once("tenant-a", b"other", 100),
            Err(ObjectStoreError::Unavailable)
        );
    }

    #[test]
    fn crash_releases_lease_duplicates_are_idempotent_and_poison_is_quarantined() {
        let outbox = DurableOutbox::default();
        let event = OutboxEvent {
            event_id: "event-1".into(),
            tenant_id: "tenant-a".into(),
            kind: "evidence.created".into(),
            payload_digest_hex: "abc".into(),
            status: OutboxStatus::Published,
            attempts: 99,
        };
        outbox.enqueue(event.clone()).unwrap();
        outbox.enqueue(event).unwrap();
        let crashed = outbox.lease("tenant-a", "worker-1", 10, 5).unwrap();
        assert_eq!(
            outbox.acknowledge(&crashed, 16),
            Err(OutboxError::InvalidLease)
        );
        let retry = outbox.lease("tenant-a", "worker-2", 16, 5).unwrap();
        assert_eq!(
            outbox.fail(&retry, 17, 1).unwrap(),
            OutboxStatus::Quarantined
        );
    }

    #[test]
    fn legal_hold_blocks_deletion_and_tombstone_preserves_absence_semantics() {
        let store = ImmutableEvidenceStore::default();
        let object = store.put_once("tenant-a", b"evidence", 100).unwrap();
        let retention = EvidenceRetention::default();
        retention
            .place_hold(LegalHold {
                tenant_id: "tenant-a".into(),
                digest_hex: object.digest_hex.clone(),
                reason: "case-1".into(),
            })
            .unwrap();
        assert_eq!(
            retention.confirm_deletion(&object, 101, true, true, true),
            Err(RetentionError::LegalHoldActive)
        );
        retention.release_hold("tenant-a", &object.digest_hex);
        let tombstone = retention
            .confirm_deletion(&object, 101, true, true, true)
            .unwrap();
        assert!(tombstone.meaning.contains("not determined"));
    }
}
