//! PostgreSQL adapters (feature `postgres`).
//!
//! Uses sqlx runtime queries, so this crate compiles without a live database.
//! The database is the sole live-state authority: the mandate CAS is a single
//! conditional `UPDATE`, webhook deliveries are a unique key, protocol objects
//! are immutable, and audit events are append-only.

use async_trait::async_trait;
use sqlx::Row;
use sqlx::postgres::{PgPool, PgPoolOptions};

use crate::error::{StorageError, StorageResult};
use crate::model::{
    AuditEvent, CasOutcome, MandateProjection, ProtocolObjectRecord, WebhookReceipt,
    WebhookRecordOutcome,
};
use crate::ports::{AuditLog, MandateProjectionStore, ProtocolObjectStore, WebhookReceiptStore};

fn backend(error: sqlx::Error) -> StorageError {
    StorageError::Backend(error.to_string())
}

/// Opens a connection pool.
///
/// # Errors
///
/// Returns a backend error if the pool cannot be established.
pub async fn connect(database_url: &str) -> StorageResult<PgPool> {
    PgPoolOptions::new()
        .max_connections(8)
        .connect(database_url)
        .await
        .map_err(backend)
}

/// Applies the embedded migrations.
///
/// # Errors
///
/// Returns a backend error if a migration fails.
pub async fn run_migrations(pool: &PgPool) -> StorageResult<()> {
    sqlx::migrate!("../../migrations")
        .run(pool)
        .await
        .map_err(|error| StorageError::Backend(error.to_string()))
}

/// Postgres immutable protocol-object store.
#[derive(Clone)]
pub struct PgProtocolObjectStore {
    pool: PgPool,
}

impl PgProtocolObjectStore {
    /// Wraps a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ProtocolObjectStore for PgProtocolObjectStore {
    async fn put(&self, record: ProtocolObjectRecord) -> StorageResult<()> {
        if record.object_id_hex.is_empty() {
            return Err(StorageError::EmptyField("object_id_hex"));
        }
        let inserted = sqlx::query(
            "INSERT INTO protocol_objects (object_id_hex, kind, bytes) VALUES ($1, $2, $3) \
             ON CONFLICT (object_id_hex) DO NOTHING",
        )
        .bind(&record.object_id_hex)
        .bind(&record.kind)
        .bind(&record.bytes)
        .execute(&self.pool)
        .await
        .map_err(backend)?;

        if inserted.rows_affected() == 1 {
            return Ok(());
        }
        // Row already existed: enforce immutability by comparing bytes.
        let existing: Vec<u8> = sqlx::query("SELECT bytes FROM protocol_objects WHERE object_id_hex = $1")
            .bind(&record.object_id_hex)
            .fetch_one(&self.pool)
            .await
            .map_err(backend)?
            .try_get("bytes")
            .map_err(backend)?;
        if existing == record.bytes {
            Ok(())
        } else {
            Err(StorageError::ImmutableViolation {
                object_id_hex: record.object_id_hex,
            })
        }
    }

    async fn get(&self, object_id_hex: &str) -> StorageResult<Option<ProtocolObjectRecord>> {
        let row = sqlx::query("SELECT kind, bytes FROM protocol_objects WHERE object_id_hex = $1")
            .bind(object_id_hex)
            .fetch_optional(&self.pool)
            .await
            .map_err(backend)?;
        row.map(|row| {
            Ok(ProtocolObjectRecord {
                kind: row.try_get("kind").map_err(backend)?,
                object_id_hex: object_id_hex.to_string(),
                bytes: row.try_get("bytes").map_err(backend)?,
            })
        })
        .transpose()
    }
}

/// Postgres mandate projection store with a conditional-update CAS.
#[derive(Clone)]
pub struct PgMandateProjectionStore {
    pool: PgPool,
}

impl PgMandateProjectionStore {
    /// Wraps a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl MandateProjectionStore for PgMandateProjectionStore {
    async fn insert(&self, mandate_id_hex: &str, state: &str) -> StorageResult<()> {
        if mandate_id_hex.is_empty() {
            return Err(StorageError::EmptyField("mandate_id_hex"));
        }
        sqlx::query(
            "INSERT INTO mandate_projections (mandate_id_hex, version, state) VALUES ($1, 1, $2)",
        )
        .bind(mandate_id_hex)
        .bind(state)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn get(&self, mandate_id_hex: &str) -> StorageResult<Option<MandateProjection>> {
        let row =
            sqlx::query("SELECT version, state FROM mandate_projections WHERE mandate_id_hex = $1")
                .bind(mandate_id_hex)
                .fetch_optional(&self.pool)
                .await
                .map_err(backend)?;
        row.map(|row| {
            Ok(MandateProjection {
                mandate_id_hex: mandate_id_hex.to_string(),
                version: row.try_get("version").map_err(backend)?,
                state: row.try_get("state").map_err(backend)?,
            })
        })
        .transpose()
    }

    async fn compare_and_swap(
        &self,
        mandate_id_hex: &str,
        expected_version: i64,
        new_state: &str,
    ) -> StorageResult<CasOutcome> {
        // Exactly one caller with the matching version wins the conditional update.
        let updated = sqlx::query(
            "UPDATE mandate_projections SET version = version + 1, state = $3, \
             updated_at = extract(epoch from now())::bigint \
             WHERE mandate_id_hex = $1 AND version = $2 RETURNING version",
        )
        .bind(mandate_id_hex)
        .bind(expected_version)
        .bind(new_state)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;

        if let Some(row) = updated {
            return Ok(CasOutcome::Applied {
                new_version: row.try_get("version").map_err(backend)?,
            });
        }
        // No update: distinguish a version conflict from a missing projection.
        match self.get(mandate_id_hex).await? {
            Some(current) => Ok(CasOutcome::Conflict {
                current_version: current.version,
            }),
            None => Ok(CasOutcome::Missing),
        }
    }
}

/// Postgres webhook receipt store keyed by unique delivery id.
#[derive(Clone)]
pub struct PgWebhookReceiptStore {
    pool: PgPool,
}

impl PgWebhookReceiptStore {
    /// Wraps a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WebhookReceiptStore for PgWebhookReceiptStore {
    async fn record(&self, receipt: WebhookReceipt) -> StorageResult<WebhookRecordOutcome> {
        if receipt.delivery_id.is_empty() {
            return Err(StorageError::EmptyField("delivery_id"));
        }
        let inserted = sqlx::query(
            "INSERT INTO webhook_receipts (delivery_id, source, raw_digest, received_at) \
             VALUES ($1, $2, $3, $4) ON CONFLICT (delivery_id) DO NOTHING",
        )
        .bind(&receipt.delivery_id)
        .bind(&receipt.source)
        .bind(receipt.raw_digest.to_hex())
        .bind(receipt.received_at_unix_seconds)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if inserted.rows_affected() == 1 {
            Ok(WebhookRecordOutcome::Recorded)
        } else {
            Ok(WebhookRecordOutcome::Duplicate)
        }
    }

    async fn get(&self, delivery_id: &str) -> StorageResult<Option<WebhookReceipt>> {
        let row = sqlx::query(
            "SELECT source, raw_digest, received_at FROM webhook_receipts WHERE delivery_id = $1",
        )
        .bind(delivery_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            let raw_hex: String = row.try_get("raw_digest").map_err(backend)?;
            let raw_digest = crate::digest::ContentDigest::from_hex(&raw_hex).ok_or_else(|| {
                StorageError::Backend("stored webhook raw_digest is not valid hex".to_string())
            })?;
            Ok(WebhookReceipt {
                delivery_id: delivery_id.to_string(),
                source: row.try_get("source").map_err(backend)?,
                raw_digest,
                received_at_unix_seconds: row.try_get("received_at").map_err(backend)?,
            })
        })
        .transpose()
    }
}

/// Postgres append-only audit log.
#[derive(Clone)]
pub struct PgAuditLog {
    pool: PgPool,
}

impl PgAuditLog {
    /// Wraps a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl AuditLog for PgAuditLog {
    async fn append(&self, event: AuditEvent) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO audit_events (occurred_at, actor, action, decision, detail) \
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(event.occurred_at_unix_seconds)
        .bind(event.actor.as_deref())
        .bind(&event.action)
        .bind(&event.decision)
        .bind(&event.detail)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn recent(&self, limit: usize) -> StorageResult<Vec<AuditEvent>> {
        let rows = sqlx::query(
            "SELECT occurred_at, actor, action, decision, detail FROM audit_events \
             ORDER BY id DESC LIMIT $1",
        )
        .bind(i64::try_from(limit).unwrap_or(i64::MAX))
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        let mut events = Vec::with_capacity(rows.len());
        for row in rows {
            events.push(AuditEvent {
                occurred_at_unix_seconds: row.try_get("occurred_at").map_err(backend)?,
                actor: row.try_get("actor").map_err(backend)?,
                action: row.try_get("action").map_err(backend)?,
                decision: row.try_get("decision").map_err(backend)?,
                detail: row.try_get("detail").map_err(backend)?,
            });
        }
        events.reverse(); // insertion order
        Ok(events)
    }
}
