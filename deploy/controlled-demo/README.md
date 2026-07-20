# Controlled deployment demo environment

This directory is the reproducible specification for H-01. Install the
consumer workflow and validation script in a **dedicated repository containing
no customer production data**. The environment name is
`piteka-demo-production`; despite GitHub's production classification it is a
disposable test target only.

## Provisioning and credentials

1. Create a private, dedicated GitHub repository and the named environment.
2. Configure no required reviewers, wait timer, branch policy, or custom
   deployment-protection rules. Piteka is the single approval authority.
3. Copy `piteka-deployment-consumer.yml` to
   `.github/workflows/piteka-deployment-consumer.yml`, and keep this directory
   at the same commit. Do not replace the pinned action SHA with a tag.
4. Install the Piteka GitHub App on this repository only. It needs Deployments
   read/write and Contents read. The workflow's token gets Contents read,
   Deployments write, and OIDC identity-token write.
5. Run `capture_environment_snapshot.sh evidence/environment.json` before a
   demo. Retain the JSON, its SHA-256 sidecar, workflow file digest, repository
   and environment stable IDs, `github.workflow_ref`, `github.workflow_sha`,
   run ID/attempt, logs, and the controlled action digest as evidence.

GitHub-hosted runners and repository/environment configuration have no
incremental software cost on GitHub plans that include the required private
repository Actions allowance; usage beyond the plan is billed by GitHub.
Piteka infrastructure and secret-manager costs remain deployment-specific.
Check the account's current billing limits before each run.

Secrets are never committed. Operators use a short-lived GitHub App
installation token as `GITHUB_TOKEN`; `PITEKA_DEMO_REPOSITORY` contains only
the `owner/repository` name. The Piteka App private key stays in the configured
secret manager and is never available to this consumer workflow.

## Dispatch contract

The Deployments API request must set the exact 40-character commit SHA as both
`ref` and resolved `sha`, `task=deploy`, `auto_merge=false`, environment
`piteka-demo-production`, and payload:

```json
{"schema_version":1,"piteka_attempt_digest":"<64 lowercase hex characters>"}
```

Any missing, changed, ambiguous, or additional payload input fails closed. The
workflow writes `in_progress` and exactly one terminal state (`success`,
`failure`, or `error`) against the original event deployment ID. It does not
make an authorization decision.

## Reset and rollback

`reset.sh --confirm-demo-only` removes only terminal deployments from the named
demo environment in deterministic ID order. It refuses active or unknown
states. Rollback is removal of the consumer workflow and GitHub App
installation; no protocol or database migration is involved. Existing
evidence remains immutable and must be retained per the demo evidence policy.

Run the offline checks from the Piteka repository root:

```bash
python3 -m unittest discover -s tests/e2e -p 'test_*.py'
```

## Guarded live transport check

`controlled_demo_dispatch` exercises real GitHub App JWT authentication,
installation-token exchange, and the Deployments API. It refuses to run unless
`PITEKA_CONFIRM_LIVE_DEMO` exactly names the disposable repository. Supply the
private key by file path; never put its contents in an environment variable or
commit it. The remaining required variables are listed by running the binary
without arguments:

```bash
cargo run -p piteka-github --bin controlled_demo_dispatch
```

This utility validates the provider transport only. It does not manufacture a
mandate or approval and must not be represented as H-02 evidence. A qualifying
H-02 run must enter through Piteka's persisted approval/reservation path and
retain authenticated webhook and receipt evidence.

`controlled_demo_flow` exercises the demo application state machine before
crossing the provider boundary: propose, approve the exact intent, insert an
issued mandate, reserve it with CAS, dispatch, and consume only after GitHub
acceptance. It requires the same provider variables plus
`PITEKA_DEMO_JOURNAL`, an absolute output path for its run journal:

```bash
cargo run -p piteka --bin controlled_demo_flow
```

The flow uses the repository's documented demo identity and in-memory stores;
the journal makes the observed run durable, but does not turn those stores into
production persistence. Authenticated webhook receipt evidence remains a
separate required artifact.
