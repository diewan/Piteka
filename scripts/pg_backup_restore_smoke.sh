#!/usr/bin/env bash
# Postgres backup/restore smoke test (Master Plan §59 D-03 acceptance).
#
# Applies migrations to a source database, inserts a canonical protocol object,
# backs the database up with pg_dump, restores it into a fresh database, and
# verifies the object survived. Requires a running PostgreSQL and the libpq
# client tools (psql, pg_dump, createdb, dropdb).
#
# Usage:
#   PGHOST=... PGPORT=... PGUSER=... \
#   scripts/pg_backup_restore_smoke.sh
set -euo pipefail

SRC_DB="piteka_smoke_src_$$"
DST_DB="piteka_smoke_dst_$$"
DUMP_FILE="$(mktemp)"
MIGRATIONS_DIR="$(dirname "$0")/../migrations"

cleanup() {
    dropdb --if-exists "$SRC_DB" >/dev/null 2>&1 || true
    dropdb --if-exists "$DST_DB" >/dev/null 2>&1 || true
    rm -f "$DUMP_FILE"
}
trap cleanup EXIT

echo "1. create source database and apply migration"
createdb "$SRC_DB"
for migration in "$MIGRATIONS_DIR"/*.sql; do
    psql -v ON_ERROR_STOP=1 -q -d "$SRC_DB" -f "$migration"
done

echo "2. insert a canonical protocol object"
psql -v ON_ERROR_STOP=1 -q -d "$SRC_DB" -c \
    "INSERT INTO protocol_objects (object_id_hex, kind, bytes) VALUES ('aa', 'action_intent', '\\x0102')"
psql -v ON_ERROR_STOP=1 -q -d "$SRC_DB" -c \
    "INSERT INTO evidence_nodes (node_id_hex, registry_id, source, producer_identity, collected_at, content_digest, media_type, disclosure_classification) VALUES ('node-aa', 'registry-v1', 'provider', 'github-app:1', 1, 'digest-aa', 'application/json', 'pilot-restricted')"

echo "3. back up with pg_dump"
pg_dump --format=custom --file="$DUMP_FILE" "$SRC_DB"

echo "4. restore into a fresh database"
createdb "$DST_DB"
pg_restore --no-owner --dbname="$DST_DB" "$DUMP_FILE"

echo "5. verify the object survived the restore"
COUNT="$(psql -tA -d "$DST_DB" -c "SELECT count(*) FROM protocol_objects WHERE object_id_hex = 'aa'")"
if [ "$COUNT" != "1" ]; then
    echo "FAIL: restored database is missing the protocol object (count=$COUNT)" >&2
    exit 1
fi

EVIDENCE_COUNT="$(psql -tA -d "$DST_DB" -c "SELECT count(*) FROM evidence_nodes WHERE node_id_hex = 'node-aa' AND disclosure_classification = 'pilot-restricted'")"
if [ "$EVIDENCE_COUNT" != "1" ]; then
    echo "FAIL: restored database is missing the evidence node (count=$EVIDENCE_COUNT)" >&2
    exit 1
fi

echo "PASS: backup/restore preserved canonical protocol and evidence records"
