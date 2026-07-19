# Runbook — PostgreSQL backup and restore

Piteka's PostgreSQL database is the sole live-state authority for the mandate
reservation CAS (Master Plan §6, §18). This runbook covers the first-slice
backup/restore and recovery validation. The local evidence-object directory is
a separate consistency unit and must be captured at the same recovery point.

## Prerequisites

- A running PostgreSQL instance.
- libpq client tools: `psql`, `pg_dump`, `pg_restore`, `createdb`, `dropdb`.
- Standard `PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD` environment as needed.

## Automated smoke test

```bash
piteka/scripts/pg_backup_restore_smoke.sh
```

It creates a disposable source database, applies every ordered migration,
inserts canonical protocol and evidence records, backs up with
`pg_dump --format=custom`, restores into a fresh database, and checks both
records. It cleans up both databases on exit.

This smoke test is necessary but insufficient for pilot use. Before a pilot,
the platform owner must document encrypted backup storage, retention, restore
credentials, off-site copies, and a measured recovery-point objective (RPO)
and recovery-time objective (RTO). Those are release blockers in the readiness
manifest until exercised in the target environment.

## Manual backup

```bash
pg_dump --format=custom --file=piteka-$(date +%F).dump "$DATABASE_URL"
```

Quiesce dispatch first and record the latest audit sequence. Snapshot the
configured evidence-object root after the database dump begins; do not copy a
live directory while writers are active. Hash the dump and evidence snapshot,
encrypt them, and record their recovery point in the incident log. A database
dump without its referenced evidence objects is not a complete backup.

## Manual restore

```bash
createdb piteka_restored
pg_restore --no-owner --dbname=piteka_restored piteka-YYYY-MM-DD.dump
```

Restore to an isolated database and evidence root. Apply no new dispatches.
Verify schema migrations, immutable object counts, evidence digests, newest
audit sequence, and a sample bundle export. Only then switch application
configuration during an approved maintenance window. If any digest or
reference is missing, stop: absence is not evidence of non-occurrence.

## Integration tests against a live database

```bash
DATABASE_URL=postgres://localhost/piteka_test \
  cargo test -p piteka-storage --features postgres --test postgres \
  -- --ignored --test-threads=1
```

Run serially (`--test-threads=1`): the tests share one database.

These assert the Postgres adapters uphold immutability, the conditional-update
CAS (one winner), unique webhook deliveries, and append-only audit ordering.
