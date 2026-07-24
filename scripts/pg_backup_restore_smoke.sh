#!/usr/bin/env bash
# Postgres backup/restore smoke test (Master Plan §59 D-03 acceptance).
#
# Applies migrations to a source database, inserts a canonical protocol object
# and an evidence node, backs the database up with pg_dump, restores it into a
# fresh database, and verifies both records survived.
#
# Usage:
#
#   # Against the repository's own stack (deployment/scripts/up.sh infra):
#   scripts/pg_backup_restore_smoke.sh
#
#   # Against any other server, using host libpq tools:
#   PGHOST=... PGPORT=... PGUSER=... PITEKA_PG_CONTAINER= \
#     scripts/pg_backup_restore_smoke.sh
#
# # Client/server version matching
#
# pg_dump refuses to produce a dump a *newer* server feature set can describe but
# an older server cannot restore — a dump from pg_dump 18 emits directives such as
# `SET transaction_timeout` that a PostgreSQL 16 server rejects. A developer whose
# host libpq is newer than the pinned `postgres:16-alpine` image therefore saw this
# script fail on a restore error that had nothing to do with backup integrity.
#
# So the tools are run *inside the server's own container* by default, which makes
# client and server the same build by construction. Set PITEKA_PG_CONTAINER to
# another container name, or to the empty string to force host libpq tools.
set -euo pipefail

CONTAINER="${PITEKA_PG_CONTAINER-diewan-postgres}"
PGUSER_EFFECTIVE="${PGUSER:-zorvan}"
MIGRATIONS_DIR="$(cd "$(dirname "$0")/../migrations" && pwd)"

if [ -n "$CONTAINER" ]; then
    if ! command -v docker &>/dev/null || ! docker inspect "$CONTAINER" &>/dev/null; then
        echo "Postgres container '$CONTAINER' is not running." >&2
        echo "Start it with:  deployment/scripts/up.sh infra" >&2
        echo "Or set PITEKA_PG_CONTAINER= to use host libpq tools instead." >&2
        exit 1
    fi
    # Run every client tool inside the server container.
    pg() { docker exec -i "$CONTAINER" "$@"; }
    MODE="container '$CONTAINER'"
else
    for tool in psql pg_dump pg_restore createdb dropdb; do
        command -v "$tool" &>/dev/null || {
            echo "ERROR: $tool not found on PATH." >&2
            exit 1
        }
    done
    pg() { "$@"; }
    MODE="host libpq tools"
fi

SRC_DB="piteka_smoke_src_$$"
DST_DB="piteka_smoke_dst_$$"
# The dump lives wherever the tools run, so it is never moved across a version
# boundary; it is only ever written and read by the same pg_dump/pg_restore pair.
DUMP_FILE="/tmp/piteka_smoke_$$.dump"

cleanup() {
    pg dropdb -U "$PGUSER_EFFECTIVE" --if-exists "$SRC_DB" >/dev/null 2>&1 || true
    pg dropdb -U "$PGUSER_EFFECTIVE" --if-exists "$DST_DB" >/dev/null 2>&1 || true
    if [ -n "$CONTAINER" ]; then
        docker exec "$CONTAINER" rm -f "$DUMP_FILE" >/dev/null 2>&1 || true
    else
        rm -f "$DUMP_FILE"
    fi
}
trap cleanup EXIT

echo "Running with $MODE"
CLIENT_VERSION="$(pg pg_dump --version | grep -oE '[0-9]+' | head -n1)"
SERVER_VERSION="$(pg psql -U "$PGUSER_EFFECTIVE" -tA -d postgres \
    -c 'SHOW server_version_num' | cut -c1-2)"
if [ "$CLIENT_VERSION" != "$SERVER_VERSION" ]; then
    echo "ERROR: pg_dump major version ($CLIENT_VERSION) does not match the server ($SERVER_VERSION)." >&2
    echo "A dump taken by a newer client can emit directives an older server rejects." >&2
    echo "Unset PITEKA_PG_CONTAINER to use the server container's own tools." >&2
    exit 1
fi
echo "   client and server are both PostgreSQL $SERVER_VERSION"

echo "1. create source database and apply migrations"
pg createdb -U "$PGUSER_EFFECTIVE" "$SRC_DB"
for migration in "$MIGRATIONS_DIR"/*.sql; do
    pg psql -U "$PGUSER_EFFECTIVE" -v ON_ERROR_STOP=1 -q -d "$SRC_DB" < "$migration"
done

echo "2. insert a canonical protocol object and an evidence node"
pg psql -U "$PGUSER_EFFECTIVE" -v ON_ERROR_STOP=1 -q -d "$SRC_DB" -c \
    "INSERT INTO protocol_objects (tenant_id, object_id_hex, kind, bytes) VALUES ('backup-smoke', 'aa', 'action_intent', '\\x0102')"
pg psql -U "$PGUSER_EFFECTIVE" -v ON_ERROR_STOP=1 -q -d "$SRC_DB" -c \
    "INSERT INTO evidence_nodes (tenant_id, node_id_hex, registry_id, source, producer_identity, collected_at, content_digest, media_type, disclosure_classification) VALUES ('backup-smoke', 'node-aa', 'registry-v1', 'provider', 'github-app:1', 1, 'digest-aa', 'application/json', 'pilot-restricted')"

echo "3. back up with pg_dump"
pg pg_dump -U "$PGUSER_EFFECTIVE" --format=custom --file="$DUMP_FILE" "$SRC_DB"

echo "4. restore into a fresh database"
pg createdb -U "$PGUSER_EFFECTIVE" "$DST_DB"
# No error is tolerated here: a restore that partially failed is not a restore.
pg pg_restore -U "$PGUSER_EFFECTIVE" --exit-on-error --no-owner --dbname="$DST_DB" "$DUMP_FILE"

echo "5. verify the records survived the restore"
COUNT="$(pg psql -U "$PGUSER_EFFECTIVE" -tA -d "$DST_DB" -c \
    "SELECT count(*) FROM protocol_objects WHERE tenant_id = 'backup-smoke' AND object_id_hex = 'aa'" | tr -d '[:space:]')"
if [ "$COUNT" != "1" ]; then
    echo "FAIL: restored database is missing the protocol object (count=$COUNT)" >&2
    exit 1
fi

# The canonical bytes must survive byte-for-byte: a backup that preserves the row
# but not its exact bytes would silently break offline verification.
BYTES="$(pg psql -U "$PGUSER_EFFECTIVE" -tA -d "$DST_DB" -c \
    "SELECT encode(bytes, 'hex') FROM protocol_objects WHERE tenant_id = 'backup-smoke' AND object_id_hex = 'aa'" | tr -d '[:space:]')"
if [ "$BYTES" != "0102" ]; then
    echo "FAIL: canonical bytes changed across backup/restore (got '$BYTES', want '0102')" >&2
    exit 1
fi

EVIDENCE_COUNT="$(pg psql -U "$PGUSER_EFFECTIVE" -tA -d "$DST_DB" -c \
    "SELECT count(*) FROM evidence_nodes WHERE tenant_id = 'backup-smoke' AND node_id_hex = 'node-aa' AND disclosure_classification = 'pilot-restricted'" | tr -d '[:space:]')"
if [ "$EVIDENCE_COUNT" != "1" ]; then
    echo "FAIL: restored database is missing the evidence node (count=$EVIDENCE_COUNT)" >&2
    exit 1
fi

echo "PASS: backup/restore preserved canonical protocol and evidence records"
