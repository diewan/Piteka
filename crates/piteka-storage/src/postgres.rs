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
    ActionRequest, ActionRequestStatus, ApprovalDecision, AuditEvent, CasOutcome,
    CaseAppendOutcome, CaseEvent, EvidenceNodeRecord, EvidenceSource, ExecutionAttempt,
    ExecutionAttemptState, InvestigatorCase, MandateProjection, ProtocolObjectRecord,
    ReceiptOutcome, ReceiptProjection, SealConsumptionProofRecord, TenantScope,
    WebhookDeliveryRecord, WebhookRecordOutcome,
};
use crate::ports::{
    ActionRequestStore, ApprovalDecisionStore, AuditLog, EvidenceNodeStore, ExecutionAttemptStore,
    InvestigatorCaseStore, MandateProjectionStore, ProtocolObjectStore, ReceiptProjectionStore,
    SealConsumptionStore, WebhookDeliveryStore,
};

fn backend(error: sqlx::Error) -> StorageError {
    StorageError::Backend(error.to_string())
}

/// PostgreSQL tenant-scoped investigator-case store.
#[derive(Clone)]
pub struct PgInvestigatorCaseStore {
    pool: PgPool,
}

impl PgInvestigatorCaseStore {
    /// Wraps a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl InvestigatorCaseStore for PgInvestigatorCaseStore {
    async fn create(&self, tenant: &TenantScope, case: InvestigatorCase) -> StorageResult<()> {
        if case.tenant_id != tenant.as_str()
            || case.case_id.trim().is_empty()
            || case.title.trim().is_empty()
        {
            return Err(StorageError::EmptyField("investigator_case"));
        }
        if case.version != 0 {
            return Err(StorageError::Backend(
                "new investigator case must start at version zero".into(),
            ));
        }
        sqlx::query("INSERT INTO investigator_cases (tenant_id, case_id, version, title, opened_by, created_at) VALUES ($1, $2, 0, $3, $4, $5)")
            .bind(&case.tenant_id).bind(&case.case_id).bind(&case.title)
            .bind(&case.opened_by).bind(case.created_at_unix_seconds)
            .execute(&self.pool).await.map_err(backend)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        case_id: &str,
    ) -> StorageResult<Option<InvestigatorCase>> {
        let row = sqlx::query("SELECT version, title, opened_by, created_at FROM investigator_cases WHERE tenant_id = $1 AND case_id = $2")
            .bind(tenant.as_str()).bind(case_id).fetch_optional(&self.pool).await.map_err(backend)?;
        row.map(|row| {
            Ok(InvestigatorCase {
                tenant_id: tenant.as_str().into(),
                case_id: case_id.into(),
                version: row.try_get("version").map_err(backend)?,
                title: row.try_get("title").map_err(backend)?,
                opened_by: row.try_get("opened_by").map_err(backend)?,
                created_at_unix_seconds: row.try_get("created_at").map_err(backend)?,
            })
        })
        .transpose()
    }

    async fn list(&self, tenant: &TenantScope) -> StorageResult<Vec<InvestigatorCase>> {
        let rows = sqlx::query("SELECT case_id, version, title, opened_by, created_at FROM investigator_cases WHERE tenant_id = $1 ORDER BY case_id")
            .bind(tenant.as_str()).fetch_all(&self.pool).await.map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                Ok(InvestigatorCase {
                    tenant_id: tenant.as_str().into(),
                    case_id: row.try_get("case_id").map_err(backend)?,
                    version: row.try_get("version").map_err(backend)?,
                    title: row.try_get("title").map_err(backend)?,
                    opened_by: row.try_get("opened_by").map_err(backend)?,
                    created_at_unix_seconds: row.try_get("created_at").map_err(backend)?,
                })
            })
            .collect()
    }

    async fn append(
        &self,
        tenant: &TenantScope,
        case_id: &str,
        expected_version: i64,
        event: CaseEvent,
    ) -> StorageResult<CaseAppendOutcome> {
        if event.tenant_id != tenant.as_str() || event.case_id != case_id {
            return Err(StorageError::Backend("case event scope mismatch".into()));
        }
        let mut tx = self.pool.begin().await.map_err(backend)?;
        let current = sqlx::query("SELECT version FROM investigator_cases WHERE tenant_id = $1 AND case_id = $2 FOR UPDATE")
            .bind(tenant.as_str()).bind(case_id).fetch_optional(&mut *tx).await.map_err(backend)?;
        let Some(current) = current else {
            return Ok(CaseAppendOutcome::Missing);
        };
        let current_version: i64 = current.try_get("version").map_err(backend)?;
        if current_version != expected_version {
            return Ok(CaseAppendOutcome::Conflict { current_version });
        }
        let new_version = current_version + 1;
        sqlx::query("INSERT INTO investigator_case_events (tenant_id, case_id, sequence, event_id, actor, kind, detail, evidence_digest_hex, occurred_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
            .bind(tenant.as_str()).bind(case_id).bind(new_version).bind(&event.event_id).bind(&event.actor)
            .bind(&event.kind).bind(&event.detail).bind(&event.evidence_digest_hex).bind(event.occurred_at_unix_seconds)
            .execute(&mut *tx).await.map_err(backend)?;
        sqlx::query(
            "UPDATE investigator_cases SET version = $3 WHERE tenant_id = $1 AND case_id = $2",
        )
        .bind(tenant.as_str())
        .bind(case_id)
        .bind(new_version)
        .execute(&mut *tx)
        .await
        .map_err(backend)?;
        tx.commit().await.map_err(backend)?;
        Ok(CaseAppendOutcome::Applied { new_version })
    }

    async fn history(&self, tenant: &TenantScope, case_id: &str) -> StorageResult<Vec<CaseEvent>> {
        let rows = sqlx::query("SELECT sequence, event_id, actor, kind, detail, evidence_digest_hex, occurred_at FROM investigator_case_events WHERE tenant_id = $1 AND case_id = $2 ORDER BY sequence")
            .bind(tenant.as_str()).bind(case_id).fetch_all(&self.pool).await.map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                Ok(CaseEvent {
                    event_id: row.try_get("event_id").map_err(backend)?,
                    tenant_id: tenant.as_str().into(),
                    case_id: case_id.into(),
                    sequence: row.try_get("sequence").map_err(backend)?,
                    actor: row.try_get("actor").map_err(backend)?,
                    kind: row.try_get("kind").map_err(backend)?,
                    detail: row.try_get("detail").map_err(backend)?,
                    evidence_digest_hex: row.try_get("evidence_digest_hex").map_err(backend)?,
                    occurred_at_unix_seconds: row.try_get("occurred_at").map_err(backend)?,
                })
            })
            .collect()
    }
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
    async fn put(&self, tenant: &TenantScope, record: ProtocolObjectRecord) -> StorageResult<()> {
        if record.object_id_hex.is_empty() {
            return Err(StorageError::EmptyField("object_id_hex"));
        }
        let inserted = sqlx::query(
            "INSERT INTO protocol_objects (tenant_id, object_id_hex, kind, bytes) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id, object_id_hex) DO NOTHING",
        )
        .bind(tenant.as_str())
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
        let existing: Vec<u8> = sqlx::query(
            "SELECT bytes FROM protocol_objects WHERE tenant_id = $1 AND object_id_hex = $2",
        )
        .bind(tenant.as_str())
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

    async fn get(
        &self,
        tenant: &TenantScope,
        object_id_hex: &str,
    ) -> StorageResult<Option<ProtocolObjectRecord>> {
        let row = sqlx::query(
            "SELECT kind, bytes FROM protocol_objects WHERE tenant_id = $1 AND object_id_hex = $2",
        )
        .bind(tenant.as_str())
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

/// Postgres immutable seal-consumption proof store (§5.9).
#[derive(Clone)]
pub struct PgSealConsumptionStore {
    pool: PgPool,
}

impl PgSealConsumptionStore {
    /// Wraps a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl SealConsumptionStore for PgSealConsumptionStore {
    async fn put(
        &self,
        tenant: &TenantScope,
        record: SealConsumptionProofRecord,
    ) -> StorageResult<()> {
        if record.mandate_id_hex.is_empty() {
            return Err(StorageError::EmptyField("mandate_id_hex"));
        }
        let inserted = sqlx::query(
            "INSERT INTO seal_consumption_proofs \
             (tenant_id, mandate_id_hex, seal_id_hex, nullifier_hex, commitment_hex, anchor_backend) \
             VALUES ($1, $2, $3, $4, $5, $6) ON CONFLICT (tenant_id, mandate_id_hex) DO NOTHING",
        )
        .bind(tenant.as_str())
        .bind(&record.mandate_id_hex)
        .bind(&record.seal_id_hex)
        .bind(&record.nullifier_hex)
        .bind(&record.commitment_hex)
        .bind(&record.anchor_backend)
        .execute(&self.pool)
        .await
        .map_err(backend)?;

        if inserted.rows_affected() == 1 {
            return Ok(());
        }
        // Row already existed: enforce immutability by comparing the stored proof.
        match self.get(tenant, &record.mandate_id_hex).await? {
            Some(existing) if existing == record => Ok(()),
            _ => Err(StorageError::ImmutableViolation {
                object_id_hex: record.mandate_id_hex,
            }),
        }
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Option<SealConsumptionProofRecord>> {
        let row = sqlx::query(
            "SELECT seal_id_hex, nullifier_hex, commitment_hex, anchor_backend \
             FROM seal_consumption_proofs WHERE tenant_id = $1 AND mandate_id_hex = $2",
        )
        .bind(tenant.as_str())
        .bind(mandate_id_hex)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            Ok(SealConsumptionProofRecord {
                mandate_id_hex: mandate_id_hex.to_string(),
                seal_id_hex: row.try_get("seal_id_hex").map_err(backend)?,
                nullifier_hex: row.try_get("nullifier_hex").map_err(backend)?,
                commitment_hex: row.try_get("commitment_hex").map_err(backend)?,
                anchor_backend: row.try_get("anchor_backend").map_err(backend)?,
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
    async fn insert(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
        state: &str,
    ) -> StorageResult<()> {
        if mandate_id_hex.is_empty() {
            return Err(StorageError::EmptyField("mandate_id_hex"));
        }
        sqlx::query(
            "INSERT INTO mandate_projections (tenant_id, mandate_id_hex, version, state) VALUES ($1, $2, 1, $3)",
        )
        .bind(tenant.as_str())
        .bind(mandate_id_hex)
        .bind(state)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Option<MandateProjection>> {
        let row =
            sqlx::query("SELECT version, state FROM mandate_projections WHERE tenant_id = $1 AND mandate_id_hex = $2")
                .bind(tenant.as_str())
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
        tenant: &TenantScope,
        mandate_id_hex: &str,
        expected_version: i64,
        new_state: &str,
    ) -> StorageResult<CasOutcome> {
        // Exactly one caller with the matching version wins the conditional update.
        let updated = sqlx::query(
            "UPDATE mandate_projections SET version = version + 1, state = $4, \
             updated_at = extract(epoch from now())::bigint \
             WHERE tenant_id = $1 AND mandate_id_hex = $2 AND version = $3 RETURNING version",
        )
        .bind(tenant.as_str())
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
        match self.get(tenant, mandate_id_hex).await? {
            Some(current) => Ok(CasOutcome::Conflict {
                current_version: current.version,
            }),
            None => Ok(CasOutcome::Missing),
        }
    }
}

/// Postgres webhook receipt store keyed by unique delivery id.
#[derive(Clone)]
pub struct PgWebhookDeliveryStore {
    pool: PgPool,
}

impl PgWebhookDeliveryStore {
    /// Wraps a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl WebhookDeliveryStore for PgWebhookDeliveryStore {
    async fn record(
        &self,
        tenant: &TenantScope,
        receipt: WebhookDeliveryRecord,
    ) -> StorageResult<WebhookRecordOutcome> {
        if receipt.delivery_id.is_empty() {
            return Err(StorageError::EmptyField("delivery_id"));
        }
        let inserted = sqlx::query(
            "INSERT INTO webhook_receipts (tenant_id, delivery_id, source, raw_digest, received_at) \
             VALUES ($1, $2, $3, $4, $5) ON CONFLICT (tenant_id, delivery_id) DO NOTHING",
        )
        .bind(tenant.as_str())
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

    async fn get(
        &self,
        tenant: &TenantScope,
        delivery_id: &str,
    ) -> StorageResult<Option<WebhookDeliveryRecord>> {
        let row = sqlx::query(
            "SELECT source, raw_digest, received_at FROM webhook_receipts WHERE tenant_id = $1 AND delivery_id = $2",
        )
        .bind(tenant.as_str())
        .bind(delivery_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            let raw_hex: String = row.try_get("raw_digest").map_err(backend)?;
            let raw_digest = crate::digest::ContentDigest::from_hex(&raw_hex).ok_or_else(|| {
                StorageError::Backend("stored webhook raw_digest is not valid hex".to_string())
            })?;
            Ok(WebhookDeliveryRecord {
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
    async fn append(&self, tenant: &TenantScope, event: AuditEvent) -> StorageResult<()> {
        sqlx::query(
            "INSERT INTO audit_events (tenant_id, occurred_at, actor, action, decision, detail) \
             VALUES ($1, $2, $3, $4, $5, $6)",
        )
        .bind(tenant.as_str())
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

    async fn recent(&self, tenant: &TenantScope, limit: usize) -> StorageResult<Vec<AuditEvent>> {
        let rows = sqlx::query(
            "SELECT occurred_at, actor, action, decision, detail FROM audit_events \
             WHERE tenant_id = $1 ORDER BY id DESC LIMIT $2",
        )
        .bind(tenant.as_str())
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

/// Postgres execution attempt store.
#[derive(Clone)]
pub struct PgExecutionAttemptStore {
    pool: PgPool,
}

impl PgExecutionAttemptStore {
    /// Wraps a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ExecutionAttemptStore for PgExecutionAttemptStore {
    async fn insert(&self, tenant: &TenantScope, attempt: ExecutionAttempt) -> StorageResult<()> {
        if attempt.attempt_id_hex.is_empty() {
            return Err(StorageError::EmptyField("attempt_id_hex"));
        }
        sqlx::query(
            "INSERT INTO execution_attempts \
             (tenant_id, attempt_id_hex, mandate_id_hex, state, created_at, intent_id_hex, \
              reservation_token_digest, executor_identity, correlation_key, github_deployment_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(tenant.as_str())
        .bind(&attempt.attempt_id_hex)
        .bind(&attempt.mandate_id_hex)
        .bind(state_to_str(&attempt.state))
        .bind(attempt.started_at_unix_seconds)
        .bind(&attempt.intent_id_hex)
        .bind(&attempt.reservation_token_digest)
        .bind(&attempt.executor_identity)
        .bind(&attempt.correlation_key)
        .bind(attempt.github_deployment_id.map(|value| value as i64))
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        attempt_id_hex: &str,
    ) -> StorageResult<Option<ExecutionAttempt>> {
        let row = sqlx::query(
            "SELECT mandate_id_hex, state, created_at, github_deployment_id, intent_id_hex, \
             reservation_token_digest, executor_identity, correlation_key \
             FROM execution_attempts WHERE tenant_id = $1 AND attempt_id_hex = $2",
        )
        .bind(tenant.as_str())
        .bind(attempt_id_hex)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            Ok(ExecutionAttempt {
                attempt_id_hex: attempt_id_hex.to_string(),
                mandate_id_hex: row.try_get("mandate_id_hex").map_err(backend)?,
                intent_id_hex: row.try_get("intent_id_hex").map_err(backend)?,
                reservation_token_digest: row
                    .try_get("reservation_token_digest")
                    .map_err(backend)?,
                executor_identity: row.try_get("executor_identity").map_err(backend)?,
                correlation_key: row.try_get("correlation_key").map_err(backend)?,
                started_at_unix_seconds: row.try_get("created_at").map_err(backend)?,
                dispatch_boundary_at_unix_seconds: None,
                state: str_to_state(row.try_get::<String, _>("state").map_err(backend)?),
                github_deployment_id: row
                    .try_get::<Option<i64>, _>("github_deployment_id")
                    .map_err(backend)?
                    .map(|v| v as u64),
            })
        })
        .transpose()
    }

    async fn update_state(
        &self,
        tenant: &TenantScope,
        attempt_id_hex: &str,
        new_state: ExecutionAttemptState,
    ) -> StorageResult<()> {
        let updated = sqlx::query(
            "UPDATE execution_attempts SET state = $3 WHERE tenant_id = $1 AND attempt_id_hex = $2",
        )
        .bind(tenant.as_str())
        .bind(attempt_id_hex)
        .bind(state_to_str(&new_state))
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if updated.rows_affected() == 0 {
            return Err(StorageError::Backend(format!(
                "execution attempt `{attempt_id_hex}` not found"
            )));
        }
        Ok(())
    }

    async fn update_deployment_id(
        &self,
        tenant: &TenantScope,
        attempt_id_hex: &str,
        deployment_id: u64,
    ) -> StorageResult<()> {
        let updated = sqlx::query(
            "UPDATE execution_attempts SET github_deployment_id = $3 WHERE tenant_id = $1 AND attempt_id_hex = $2",
        )
        .bind(tenant.as_str())
        .bind(attempt_id_hex)
        .bind(deployment_id as i64)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        if updated.rows_affected() == 0 {
            return Err(StorageError::Backend(format!(
                "execution attempt `{attempt_id_hex}` not found"
            )));
        }
        Ok(())
    }

    async fn by_mandate(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Vec<ExecutionAttempt>> {
        let rows = sqlx::query(
            "SELECT attempt_id_hex, state, created_at, github_deployment_id, intent_id_hex, \
             reservation_token_digest, executor_identity, correlation_key \
             FROM execution_attempts WHERE tenant_id = $1 AND mandate_id_hex = $2 ORDER BY created_at",
        )
        .bind(tenant.as_str())
        .bind(mandate_id_hex)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                Ok(ExecutionAttempt {
                    attempt_id_hex: row.try_get("attempt_id_hex").map_err(backend)?,
                    mandate_id_hex: mandate_id_hex.to_string(),
                    intent_id_hex: row.try_get("intent_id_hex").map_err(backend)?,
                    reservation_token_digest: row
                        .try_get("reservation_token_digest")
                        .map_err(backend)?,
                    executor_identity: row.try_get("executor_identity").map_err(backend)?,
                    correlation_key: row.try_get("correlation_key").map_err(backend)?,
                    started_at_unix_seconds: row.try_get("created_at").map_err(backend)?,
                    dispatch_boundary_at_unix_seconds: None,
                    state: str_to_state(row.try_get::<String, _>("state").map_err(backend)?),
                    github_deployment_id: row
                        .try_get::<Option<i64>, _>("github_deployment_id")
                        .map_err(backend)?
                        .map(|v| v as u64),
                })
            })
            .collect()
    }

    async fn by_deployment_id(
        &self,
        tenant: &TenantScope,
        deployment_id: u64,
    ) -> StorageResult<Option<ExecutionAttempt>> {
        let row = sqlx::query(
            "SELECT attempt_id_hex, mandate_id_hex, state, created_at, github_deployment_id, \
             intent_id_hex, reservation_token_digest, executor_identity, correlation_key \
             FROM execution_attempts WHERE tenant_id = $1 AND github_deployment_id = $2",
        )
        .bind(tenant.as_str())
        .bind(deployment_id as i64)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            Ok(ExecutionAttempt {
                attempt_id_hex: row.try_get("attempt_id_hex").map_err(backend)?,
                mandate_id_hex: row.try_get("mandate_id_hex").map_err(backend)?,
                intent_id_hex: row.try_get("intent_id_hex").map_err(backend)?,
                reservation_token_digest: row
                    .try_get("reservation_token_digest")
                    .map_err(backend)?,
                executor_identity: row.try_get("executor_identity").map_err(backend)?,
                correlation_key: row.try_get("correlation_key").map_err(backend)?,
                started_at_unix_seconds: row.try_get("created_at").map_err(backend)?,
                dispatch_boundary_at_unix_seconds: None,
                state: str_to_state(row.try_get::<String, _>("state").map_err(backend)?),
                github_deployment_id: Some(deployment_id),
            })
        })
        .transpose()
    }
}

/// Postgres receipt projection store.
#[derive(Clone)]
pub struct PgReceiptProjectionStore {
    pool: PgPool,
}

impl PgReceiptProjectionStore {
    /// Wraps a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }

    /// Lists every receipt id with its creation time, ordered oldest-first.
    ///
    /// Used by the evidence-export feed to publish receipts as they are
    /// produced. Ordering is deterministic (`created_at`, then id) so feed
    /// sequence numbers and emission clocks stay stable as new receipts append.
    pub async fn list_ids_ordered(
        &self,
        tenant: &TenantScope,
    ) -> StorageResult<Vec<(String, i64)>> {
        let rows = sqlx::query(
            "SELECT receipt_id_hex, created_at FROM receipt_projections \
             WHERE tenant_id = $1 ORDER BY created_at, receipt_id_hex",
        )
        .bind(tenant.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                Ok((
                    row.try_get("receipt_id_hex").map_err(backend)?,
                    row.try_get("created_at").map_err(backend)?,
                ))
            })
            .collect()
    }
}

#[async_trait]
impl ReceiptProjectionStore for PgReceiptProjectionStore {
    async fn insert(&self, tenant: &TenantScope, receipt: ReceiptProjection) -> StorageResult<()> {
        if receipt.receipt_id_hex.is_empty() {
            return Err(StorageError::EmptyField("receipt_id_hex"));
        }
        sqlx::query(
            "INSERT INTO receipt_projections \
             (tenant_id, receipt_id_hex, mandate_id_hex, outcome, created_at, intent_id_hex, attempt_id_hex, \
              dispatch_evidence_refs, target_evidence_refs, evidence_gaps, canonical_bytes) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(tenant.as_str())
        .bind(&receipt.receipt_id_hex)
        .bind(&receipt.mandate_id_hex)
        .bind(outcome_to_str(&receipt.outcome))
        .bind(receipt.created_at_unix_seconds)
        .bind(&receipt.intent_id_hex)
        .bind(&receipt.attempt_id_hex)
        .bind(
            serde_json::to_string(&receipt.dispatch_evidence_refs)
                .map_err(|error| StorageError::Backend(error.to_string()))?,
        )
        .bind(
            serde_json::to_string(&receipt.target_evidence_refs)
                .map_err(|error| StorageError::Backend(error.to_string()))?,
        )
        .bind(
            serde_json::to_string(&receipt.evidence_gaps)
                .map_err(|error| StorageError::Backend(error.to_string()))?,
        )
        .bind(&receipt.canonical_bytes)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        receipt_id_hex: &str,
    ) -> StorageResult<Option<ReceiptProjection>> {
        let row = sqlx::query(
            "SELECT mandate_id_hex, outcome, created_at, intent_id_hex, attempt_id_hex, \
             dispatch_evidence_refs, target_evidence_refs, evidence_gaps, canonical_bytes \
             FROM receipt_projections WHERE tenant_id = $1 AND receipt_id_hex = $2",
        )
        .bind(tenant.as_str())
        .bind(receipt_id_hex)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            let dispatch_refs_str: String =
                row.try_get("dispatch_evidence_refs").map_err(backend)?;
            let dispatch_evidence_refs: Vec<String> =
                serde_json::from_str(&dispatch_refs_str).unwrap_or_default();
            let target_refs_str: String = row.try_get("target_evidence_refs").map_err(backend)?;
            let target_evidence_refs: Vec<String> =
                serde_json::from_str(&target_refs_str).unwrap_or_default();
            let gaps_str: String = row.try_get("evidence_gaps").map_err(backend)?;
            let evidence_gaps: Vec<String> = serde_json::from_str(&gaps_str).unwrap_or_default();
            let canonical_bytes: Option<Vec<u8>> =
                row.try_get("canonical_bytes").map_err(backend)?;
            Ok(ReceiptProjection {
                receipt_id_hex: receipt_id_hex.to_string(),
                mandate_id_hex: row.try_get("mandate_id_hex").map_err(backend)?,
                // Some historical receipts predate intent/attempt binding and
                // store NULL here; treat that as an empty binding rather than a
                // decode failure so read paths and the feed stay resilient.
                intent_id_hex: row
                    .try_get::<Option<String>, _>("intent_id_hex")
                    .map_err(backend)?
                    .unwrap_or_default(),
                attempt_id_hex: row
                    .try_get::<Option<String>, _>("attempt_id_hex")
                    .map_err(backend)?
                    .unwrap_or_default(),
                outcome: str_to_outcome(row.try_get::<String, _>("outcome").map_err(backend)?),
                created_at_unix_seconds: row.try_get("created_at").map_err(backend)?,
                dispatch_evidence_refs,
                target_evidence_refs,
                evidence_gaps,
                canonical_bytes,
            })
        })
        .transpose()
    }

    async fn by_mandate(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Vec<ReceiptProjection>> {
        let rows = sqlx::query(
            "SELECT receipt_id_hex, outcome, created_at, intent_id_hex, attempt_id_hex, \
             dispatch_evidence_refs, target_evidence_refs, evidence_gaps, canonical_bytes \
             FROM receipt_projections WHERE tenant_id = $1 AND mandate_id_hex = $2 ORDER BY created_at",
        )
        .bind(tenant.as_str())
        .bind(mandate_id_hex)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                let dispatch_refs_str: String =
                    row.try_get("dispatch_evidence_refs").map_err(backend)?;
                let dispatch_evidence_refs: Vec<String> =
                    serde_json::from_str(&dispatch_refs_str).unwrap_or_default();
                let target_refs_str: String =
                    row.try_get("target_evidence_refs").map_err(backend)?;
                let target_evidence_refs: Vec<String> =
                    serde_json::from_str(&target_refs_str).unwrap_or_default();
                let gaps_str: String = row.try_get("evidence_gaps").map_err(backend)?;
                let evidence_gaps: Vec<String> =
                    serde_json::from_str(&gaps_str).unwrap_or_default();
                let canonical_bytes: Option<Vec<u8>> =
                    row.try_get("canonical_bytes").map_err(backend)?;
                Ok(ReceiptProjection {
                    receipt_id_hex: row.try_get("receipt_id_hex").map_err(backend)?,
                    mandate_id_hex: mandate_id_hex.to_string(),
                    intent_id_hex: row
                        .try_get::<Option<String>, _>("intent_id_hex")
                        .map_err(backend)?
                        .unwrap_or_default(),
                    attempt_id_hex: row
                        .try_get::<Option<String>, _>("attempt_id_hex")
                        .map_err(backend)?
                        .unwrap_or_default(),
                    outcome: str_to_outcome(row.try_get::<String, _>("outcome").map_err(backend)?),
                    created_at_unix_seconds: row.try_get("created_at").map_err(backend)?,
                    dispatch_evidence_refs,
                    target_evidence_refs,
                    evidence_gaps,
                    canonical_bytes,
                })
            })
            .collect()
    }
}

/// Postgres structured evidence node store.
#[derive(Clone)]
pub struct PgEvidenceNodeStore {
    pool: PgPool,
}

impl PgEvidenceNodeStore {
    /// Wraps a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl EvidenceNodeStore for PgEvidenceNodeStore {
    async fn insert(&self, tenant: &TenantScope, node: EvidenceNodeRecord) -> StorageResult<()> {
        if node.node_id_hex.is_empty() {
            return Err(StorageError::EmptyField("node_id_hex"));
        }
        let source_str = match &node.source {
            EvidenceSource::Piteka => "piteka",
            EvidenceSource::Provider(_) => "provider",
            EvidenceSource::Verifier => "verifier",
        };
        let asserted_at = node.asserted_event_at_unix_seconds;
        let relationships = serde_json::to_string(&node.relationships).map_err(|e| {
            StorageError::Backend(format!("failed to serialize relationships: {e}"))
        })?;
        sqlx::query(
            "INSERT INTO evidence_nodes \
             (tenant_id, node_id_hex, registry_id, source, producer_identity, collected_at, \
              asserted_event_at, content_digest, media_type, disclosure_classification, relationships) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)",
        )
        .bind(tenant.as_str())
        .bind(&node.node_id_hex)
        .bind(&node.registry_id)
        .bind(source_str)
        .bind(&node.producer_identity)
        .bind(node.collected_at_unix_seconds)
        .bind(asserted_at)
        .bind(node.content_digest.to_hex())
        .bind(&node.media_type)
        .bind(&node.disclosure_classification)
        .bind(relationships)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        node_id_hex: &str,
    ) -> StorageResult<Option<EvidenceNodeRecord>> {
        let row = sqlx::query(
            "SELECT registry_id, source, producer_identity, collected_at, asserted_event_at, \
             content_digest, media_type, disclosure_classification, relationships \
             FROM evidence_nodes WHERE tenant_id = $1 AND node_id_hex = $2",
        )
        .bind(tenant.as_str())
        .bind(node_id_hex)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            let content_hex: String = row.try_get("content_digest").map_err(backend)?;
            let content_digest =
                crate::digest::ContentDigest::from_hex(&content_hex).ok_or_else(|| {
                    StorageError::Backend("stored content_digest is not valid hex".to_string())
                })?;
            let relationships_str: String = row.try_get("relationships").map_err(backend)?;
            let relationships: Vec<String> =
                serde_json::from_str(&relationships_str).map_err(|e| {
                    StorageError::Backend(format!("failed to deserialize relationships: {e}"))
                })?;
            let source_str: String = row.try_get("source").map_err(backend)?;
            let source = match source_str.as_str() {
                "piteka" => EvidenceSource::Piteka,
                "verifier" => EvidenceSource::Verifier,
                _ => EvidenceSource::Provider(source_str),
            };
            Ok(EvidenceNodeRecord {
                node_id_hex: node_id_hex.to_string(),
                registry_id: row.try_get("registry_id").map_err(backend)?,
                source,
                producer_identity: row.try_get("producer_identity").map_err(backend)?,
                collected_at_unix_seconds: row.try_get("collected_at").map_err(backend)?,
                asserted_event_at_unix_seconds: row
                    .try_get("asserted_event_at")
                    .map_err(backend)?,
                content_digest,
                media_type: row.try_get("media_type").map_err(backend)?,
                disclosure_classification: row
                    .try_get("disclosure_classification")
                    .map_err(backend)?,
                relationships,
            })
        })
        .transpose()
    }

    async fn by_mandate(
        &self,
        tenant: &TenantScope,
        mandate_id_hex: &str,
    ) -> StorageResult<Vec<EvidenceNodeRecord>> {
        let rows = sqlx::query(
            "SELECT node_id_hex, registry_id, source, producer_identity, collected_at, \
             asserted_event_at, content_digest, media_type, disclosure_classification, relationships \
             FROM evidence_nodes WHERE tenant_id = $1 AND node_id_hex LIKE $2 ORDER BY collected_at",
        )
        .bind(tenant.as_str())
        .bind(format!("{mandate_id_hex}%"))
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                let node_id_hex: String = row.try_get("node_id_hex").map_err(backend)?;
                let content_hex: String = row.try_get("content_digest").map_err(backend)?;
                let content_digest = crate::digest::ContentDigest::from_hex(&content_hex)
                    .ok_or_else(|| {
                        StorageError::Backend("stored content_digest is not valid hex".to_string())
                    })?;
                let relationships_str: String = row.try_get("relationships").map_err(backend)?;
                let relationships: Vec<String> =
                    serde_json::from_str(&relationships_str).map_err(|e| {
                        StorageError::Backend(format!("failed to deserialize relationships: {e}"))
                    })?;
                let source_str: String = row.try_get("source").map_err(backend)?;
                let source = match source_str.as_str() {
                    "piteka" => EvidenceSource::Piteka,
                    "verifier" => EvidenceSource::Verifier,
                    _ => EvidenceSource::Provider(source_str),
                };
                Ok(EvidenceNodeRecord {
                    node_id_hex,
                    registry_id: row.try_get("registry_id").map_err(backend)?,
                    source,
                    producer_identity: row.try_get("producer_identity").map_err(backend)?,
                    collected_at_unix_seconds: row.try_get("collected_at").map_err(backend)?,
                    asserted_event_at_unix_seconds: row
                        .try_get("asserted_event_at")
                        .map_err(backend)?,
                    content_digest,
                    media_type: row.try_get("media_type").map_err(backend)?,
                    disclosure_classification: row
                        .try_get("disclosure_classification")
                        .map_err(backend)?,
                    relationships,
                })
            })
            .collect()
    }
}

// ---------------------------------------------------------------------------
// Helper functions for state/outcome string conversion
// ---------------------------------------------------------------------------

fn state_to_str(state: &ExecutionAttemptState) -> &'static str {
    match state {
        ExecutionAttemptState::Prepared => "prepared",
        ExecutionAttemptState::Dispatching => "dispatching",
        ExecutionAttemptState::Accepted => "accepted",
        ExecutionAttemptState::Rejected => "rejected",
        ExecutionAttemptState::OutcomeAmbiguous => "outcome_ambiguous",
        ExecutionAttemptState::ReconciledAccepted => "reconciled_accepted",
        ExecutionAttemptState::ReconciledNotAccepted => "reconciled_not_accepted",
        ExecutionAttemptState::AbandonedAmbiguous => "abandoned_ambiguous",
    }
}

fn str_to_state(s: String) -> ExecutionAttemptState {
    match s.as_str() {
        "prepared" => ExecutionAttemptState::Prepared,
        "dispatching" => ExecutionAttemptState::Dispatching,
        "accepted" => ExecutionAttemptState::Accepted,
        "rejected" => ExecutionAttemptState::Rejected,
        "outcome_ambiguous" => ExecutionAttemptState::OutcomeAmbiguous,
        "reconciled_accepted" => ExecutionAttemptState::ReconciledAccepted,
        "reconciled_not_accepted" => ExecutionAttemptState::ReconciledNotAccepted,
        "abandoned_ambiguous" => ExecutionAttemptState::AbandonedAmbiguous,
        _ => ExecutionAttemptState::OutcomeAmbiguous,
    }
}

fn outcome_to_str(outcome: &ReceiptOutcome) -> &'static str {
    match outcome {
        ReceiptOutcome::Succeeded => "succeeded",
        ReceiptOutcome::Failed => "failed",
        ReceiptOutcome::Rejected => "rejected",
        ReceiptOutcome::Unknown => "unknown",
    }
}

fn str_to_outcome(s: String) -> ReceiptOutcome {
    match s.as_str() {
        "succeeded" => ReceiptOutcome::Succeeded,
        "failed" => ReceiptOutcome::Failed,
        "rejected" => ReceiptOutcome::Rejected,
        "unknown" => ReceiptOutcome::Unknown,
        _ => ReceiptOutcome::Unknown,
    }
}

fn action_request_status_to_str(status: &ActionRequestStatus) -> &'static str {
    match status {
        ActionRequestStatus::Pending => "pending",
        ActionRequestStatus::Approved => "approved",
        ActionRequestStatus::Rejected => "rejected",
        ActionRequestStatus::Revoked => "revoked",
    }
}

fn str_to_action_request_status(s: &str) -> StorageResult<ActionRequestStatus> {
    match s {
        "pending" => Ok(ActionRequestStatus::Pending),
        "approved" => Ok(ActionRequestStatus::Approved),
        "rejected" => Ok(ActionRequestStatus::Rejected),
        "revoked" => Ok(ActionRequestStatus::Revoked),
        other => Err(StorageError::Backend(format!(
            "unknown action-request status `{other}` in database"
        ))),
    }
}

/// Postgres action-request store with a `version` compare-and-swap on status
/// transitions (mirrors [`PgMandateProjectionStore`]; Master Plan §6). Postgres
/// is the sole live-state authority, so exactly one concurrent approver with the
/// matching version wins the conditional `UPDATE`.
#[derive(Clone)]
pub struct PgActionRequestStore {
    pool: PgPool,
}

impl PgActionRequestStore {
    /// Wraps a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ActionRequestStore for PgActionRequestStore {
    async fn insert(&self, tenant: &TenantScope, request: ActionRequest) -> StorageResult<()> {
        if request.request_id.is_empty() {
            return Err(StorageError::EmptyField("request_id"));
        }
        // Fresh requests start at version 1 (the column default), matching the
        // in-memory store. A duplicate id violates the primary key.
        sqlx::query(
            "INSERT INTO action_requests \
             (tenant_id, request_id, requested_by, intent_id_hex, status, version, created_at) \
             VALUES ($1, $2, $3, $4, $5, 1, $6)",
        )
        .bind(tenant.as_str())
        .bind(&request.request_id)
        .bind(&request.requested_by)
        .bind(&request.intent_id_hex)
        .bind(action_request_status_to_str(&request.status))
        .bind(request.created_at_unix_seconds)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        request_id: &str,
    ) -> StorageResult<Option<ActionRequest>> {
        let row = sqlx::query(
            "SELECT requested_by, intent_id_hex, status, created_at \
             FROM action_requests WHERE tenant_id = $1 AND request_id = $2",
        )
        .bind(tenant.as_str())
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            let status: String = row.try_get("status").map_err(backend)?;
            Ok(ActionRequest {
                request_id: request_id.to_string(),
                requested_by: row.try_get("requested_by").map_err(backend)?,
                intent_id_hex: row.try_get("intent_id_hex").map_err(backend)?,
                status: str_to_action_request_status(&status)?,
                created_at_unix_seconds: row.try_get("created_at").map_err(backend)?,
            })
        })
        .transpose()
    }

    async fn list(&self, tenant: &TenantScope) -> StorageResult<Vec<ActionRequest>> {
        // Insertion order (created_at, then id for a stable tiebreak).
        let rows = sqlx::query(
            "SELECT request_id, requested_by, intent_id_hex, status, created_at \
             FROM action_requests WHERE tenant_id = $1 ORDER BY created_at ASC, request_id ASC",
        )
        .bind(tenant.as_str())
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                let status: String = row.try_get("status").map_err(backend)?;
                Ok(ActionRequest {
                    request_id: row.try_get("request_id").map_err(backend)?,
                    requested_by: row.try_get("requested_by").map_err(backend)?,
                    intent_id_hex: row.try_get("intent_id_hex").map_err(backend)?,
                    status: str_to_action_request_status(&status)?,
                    created_at_unix_seconds: row.try_get("created_at").map_err(backend)?,
                })
            })
            .collect()
    }

    async fn compare_and_swap(
        &self,
        tenant: &TenantScope,
        request_id: &str,
        expected_version: i64,
        new_status: ActionRequestStatus,
    ) -> StorageResult<CasOutcome> {
        // Exactly one caller with the matching version wins the conditional update.
        let updated = sqlx::query(
            "UPDATE action_requests SET version = version + 1, status = $4 \
             WHERE tenant_id = $1 AND request_id = $2 AND version = $3 RETURNING version",
        )
        .bind(tenant.as_str())
        .bind(request_id)
        .bind(expected_version)
        .bind(action_request_status_to_str(&new_status))
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;

        if let Some(row) = updated {
            return Ok(CasOutcome::Applied {
                new_version: row.try_get("version").map_err(backend)?,
            });
        }
        // No row updated: distinguish a version conflict from a missing request.
        let current = sqlx::query(
            "SELECT version FROM action_requests WHERE tenant_id = $1 AND request_id = $2",
        )
        .bind(tenant.as_str())
        .bind(request_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        match current {
            Some(row) => Ok(CasOutcome::Conflict {
                current_version: row.try_get("version").map_err(backend)?,
            }),
            None => Ok(CasOutcome::Missing),
        }
    }
}

/// Postgres approval-decision store. Decisions are immutable once recorded;
/// corrections are append-only superseding records (Master Plan §59 D-06).
#[derive(Clone)]
pub struct PgApprovalDecisionStore {
    pool: PgPool,
}

impl PgApprovalDecisionStore {
    /// Wraps a pool.
    #[must_use]
    pub fn new(pool: PgPool) -> Self {
        Self { pool }
    }
}

#[async_trait]
impl ApprovalDecisionStore for PgApprovalDecisionStore {
    async fn insert(&self, tenant: &TenantScope, decision: ApprovalDecision) -> StorageResult<()> {
        if decision.decision_id.is_empty() {
            return Err(StorageError::EmptyField("decision_id"));
        }
        sqlx::query(
            "INSERT INTO approval_decisions \
             (tenant_id, decision_id, request_id, decided_by, decision, intent_id_hex, decided_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
        )
        .bind(tenant.as_str())
        .bind(&decision.decision_id)
        .bind(&decision.request_id)
        .bind(&decision.decided_by)
        .bind(&decision.decision)
        .bind(&decision.intent_id_hex)
        .bind(decision.decided_at_unix_seconds)
        .execute(&self.pool)
        .await
        .map_err(backend)?;
        Ok(())
    }

    async fn get(
        &self,
        tenant: &TenantScope,
        decision_id: &str,
    ) -> StorageResult<Option<ApprovalDecision>> {
        let row = sqlx::query(
            "SELECT request_id, decided_by, decision, intent_id_hex, decided_at \
             FROM approval_decisions WHERE tenant_id = $1 AND decision_id = $2",
        )
        .bind(tenant.as_str())
        .bind(decision_id)
        .fetch_optional(&self.pool)
        .await
        .map_err(backend)?;
        row.map(|row| {
            Ok(ApprovalDecision {
                decision_id: decision_id.to_string(),
                request_id: row.try_get("request_id").map_err(backend)?,
                decided_by: row.try_get("decided_by").map_err(backend)?,
                decision: row.try_get("decision").map_err(backend)?,
                intent_id_hex: row.try_get("intent_id_hex").map_err(backend)?,
                decided_at_unix_seconds: row.try_get("decided_at").map_err(backend)?,
            })
        })
        .transpose()
    }

    async fn by_request(
        &self,
        tenant: &TenantScope,
        request_id: &str,
    ) -> StorageResult<Vec<ApprovalDecision>> {
        let rows = sqlx::query(
            "SELECT decision_id, decided_by, decision, intent_id_hex, decided_at \
             FROM approval_decisions WHERE tenant_id = $1 AND request_id = $2 ORDER BY decided_at ASC, decision_id ASC",
        )
        .bind(tenant.as_str())
        .bind(request_id)
        .fetch_all(&self.pool)
        .await
        .map_err(backend)?;
        rows.into_iter()
            .map(|row| {
                Ok(ApprovalDecision {
                    decision_id: row.try_get("decision_id").map_err(backend)?,
                    request_id: request_id.to_string(),
                    decided_by: row.try_get("decided_by").map_err(backend)?,
                    decision: row.try_get("decision").map_err(backend)?,
                    intent_id_hex: row.try_get("intent_id_hex").map_err(backend)?,
                    decided_at_unix_seconds: row.try_get("decided_at").map_err(backend)?,
                })
            })
            .collect()
    }
}
