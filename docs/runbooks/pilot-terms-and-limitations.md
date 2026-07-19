# Pilot terms and known limitations

These are the minimum design-partner terms to complete before launch. Legal and
commercial owners must turn them into accepted terms; this file is not a signed
agreement.

The pilot covers one named organization, dedicated non-production repository,
one GitHub deployment profile, named users, fixed duration, and bounded usage.
It excludes customer production, additional deployment providers, public SaaS,
autonomous approval, and claims of protocol v1 stability. GitHub credentials
remain server-side. Optional anchoring is not required for correctness.

The agreement identifies data controller/processor roles; allowed evidence and
purposes; regions; access roles; encryption; retention and deletion windows;
legal hold; incident notification; subprocessors; export/return at exit; support
hours and severity objectives; maintenance; suspension; feedback; liability;
and termination. It names support and security contacts and requires consent
before capturing personal or repository-sensitive evidence.

Known limitations are user-visible: the current build uses demo local identity
rather than OIDC, lacks a production tenant boundary and KMS/Vault-backed
secret lifecycle, uses local evidence storage, and has only a liveness health
endpoint. Real H-02 execution evidence, independent handoff, product-owner
language approval, production alert drills, and measured restore objectives are
absent. Integrity does not establish truth; missing evidence does not establish
non-occurrence; outcomes may remain indeterminate; quarantine is not retryable.

Any unresolved Critical or High finding, readiness blocker, contract-pin
mismatch, failed restore/alert drill, or unsigned term is a no-go. Exceptions
may not waive tenant isolation, credential security, canonical integrity,
single-use enforcement, or quarantine semantics.
