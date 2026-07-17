# Runbook — PostgreSQL backup and restore (demo)

Piteka's PostgreSQL database is the sole live-state authority for the mandate
reservation CAS (Master Plan §6, §18). This runbook covers the first-slice
backup/restore smoke test. S3 offloading, point-in-time recovery, and
multi-tenant isolation are Stage 8.

## Prerequisites

- A running PostgreSQL instance.
- libpq client tools: `psql`, `pg_dump`, `pg_restore`, `createdb`, `dropdb`.
- Standard `PGHOST`/`PGPORT`/`PGUSER`/`PGPASSWORD` environment as needed.

## Automated smoke test

```bash
piteka/scripts/pg_backup_restore_smoke.sh
```

It creates a disposable source database, applies `migrations/0001_init.sql`,
inserts a canonical protocol object, backs up with `pg_dump --format=custom`,
restores into a fresh database with `pg_restore`, and asserts the object
survived. It cleans up both databases on exit. A `PASS` line means the immutable
protocol object round-tripped through backup and restore.

## Manual backup

```bash
pg_dump --format=custom --file=piteka-$(date +%F).dump "$DATABASE_URL"
```

## Manual restore

```bash
createdb piteka_restored
pg_restore --no-owner --dbname=piteka_restored piteka-YYYY-MM-DD.dump
```

## Integration tests against a live database

```bash
DATABASE_URL=postgres://localhost/piteka_test \
  cargo test -p piteka-storage --features postgres --test postgres \
  -- --ignored --test-threads=1
```

Run serially (`--test-threads=1`): the tests share one database.

These assert the Postgres adapters uphold immutability, the conditional-update
CAS (one winner), unique webhook deliveries, and append-only audit ordering.
