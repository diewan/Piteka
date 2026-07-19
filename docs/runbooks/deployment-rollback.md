# Runbook — deployment and rollback

Deploy Parwana contract artifacts first, then the exactly pinned Piteka build.
Record image/revision digests and retain the immediately previous compatible
artifact. Back up PostgreSQL and the evidence-object store at one documented
recovery point before migrations.

For an application-only fault, stop new dispatch, drain workers, preserve
quarantined attempts, and restore the prior build only when it supports the
current schema and exact contract pin. Verify health, read paths, bundle export,
and offline verification before resuming.

Database migrations are forward-only unless a migration includes and tests an
explicit reverse operation. Never restore an older database over newer live
evidence. For a data fault, isolate the service and restore database plus
evidence objects into a new environment using the backup runbook. Compare
audit sequence and content digests before cutover.

Rollback never changes consumed to executable, releases quarantine, deletes
audit/evidence records, reserializes canonical bytes, or retries an ambiguous
provider call. If compatibility or provider acceptance is uncertain, remain
stopped and escalate.
