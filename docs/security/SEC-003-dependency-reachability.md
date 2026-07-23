# SEC-003 dependency reachability evidence

Date: 2026-07-23  
Base revision: `f6aa81a600aac640eff2c6bddcccc727b7d60198`

## Selected feature graph

`piteka-storage` disables SQLx default features and selects only `postgres`,
`runtime-tokio`, `tls-rustls`, `migrate`, and `macros`. The following audit
command prints no dependency tree, including when all targets are considered:

```text
cargo tree --target all -e features -i sqlx-mysql
warning: nothing to print.
```

The lockfile still records `sqlx-mysql` and `sqlx-sqlite` because the SQLx
facade's optional dependency inventory is retained by Cargo lock resolution.
This is not selected executable reachability, but feature-insensitive scanners
will report it. PostgreSQL remains Piteka's only selected database backend.

## RSA reachability and minimization

RSA cannot be removed from the current GitHub adapter: GitHub App JWTs require
RS256 signing. The selected path is exactly `piteka-github -> rsa 0.9.10`, now
with only `pem` and `std`; RSA default features and Piteka's redundant direct
`pkcs8` dependency were removed. Tests cover a known-good RS256 signature,
claim binding, malformed-key failure, and secret redaction.

`cargo audit --no-fetch` continues to report `RUSTSEC-2023-0071` for RSA
0.9.10, for which no fixed release is available. The private operation is
reachable while creating GitHub App JWTs, so this is a real residual risk, not
an ignored false positive. Private keys remain process-local and are resolved
by reference, but network timing noise is only mitigation. Production removal
of in-process signing belongs to `HARD-02` (KMS/HSM signing adapter and key
lifecycle). SEC-003 must not be marked complete until a risk owner approves
that interim exposure or `HARD-02` removes it.

## Verification

- `cargo test -p piteka-github --locked`: 51 passed.
- `cargo test --workspace`: passed; seven PostgreSQL integration tests were
  ignored because no `DATABASE_URL` was supplied.
- 2026-07-23 revalidation: both `cargo tree --target all -e features -i sqlx-mysql`
  and the corresponding `sqlx-sqlite` command printed no selected dependency
  tree. `cargo tree -e features -i rsa` showed only `pem` and `std` selected by
  `piteka-github`. `cargo test --workspace` passed outside the restricted
  sandbox so the two loopback-socket Tuppira tests could bind.
- 2026-07-23 migration revalidation: with the repository PostgreSQL 16 container
  and a disposable `piteka_test` database,
  `DATABASE_URL=postgres://zorvan@127.0.0.1:55432/piteka_test cargo test
  -p piteka-storage --features postgres --test postgres -- --ignored
  --test-threads=1` passed all seven tests. This runs every migration, including
  `0006_tenant_isolation.sql`, before exercising immutability, CAS,
  append-only ordering, webhook uniqueness, and cross-tenant isolation.
- `cargo audit --no-fetch`: reports the retained RSA advisory above and the
  unrelated transitive `bincode` maintenance warning.
- Independent security review approved the feature-minimization diff and
  rejected unconditional closure without explicit residual-risk approval.

Migration compatibility is unchanged. Rolling back the manifest/import change
restores the broader RSA defaults and direct `pkcs8` dependency; it is not
needed for runtime compatibility.
