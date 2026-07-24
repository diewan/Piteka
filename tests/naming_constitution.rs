//! NAM-02: mechanical guards for the semantic naming constitution.
//!
//! Authority: `development/CANONICAL-NAMING.md` (ADR-0015).
//!
//! These checks enforce only *declared spellings* — where a reserved suffix may
//! and may not appear. They cannot certify that a name is semantically right;
//! §2.6 of the constitution says as much. They exist so that the specific
//! confusions NAM-02 removed cannot silently return: a rendered table item
//! reacquiring the persistence `Row` suffix, a product type re-borrowing the
//! protocol's `Receipt`/`Canonical` vocabulary, or an `/api/v1` boundary shape
//! losing its version.

use std::{
    fs,
    path::{Path, PathBuf},
};

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// Returns `(path, source)` for every non-test Rust file under `dir`.
fn sources(dir: &Path) -> Vec<(PathBuf, String)> {
    let mut found = Vec::new();
    let Ok(entries) = fs::read_dir(dir) else {
        return found;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            if path.file_name().is_some_and(|name| name == "target") {
                continue;
            }
            found.extend(sources(&path));
        } else if path.extension().is_some_and(|ext| ext == "rs") {
            let name = path.file_name().unwrap().to_string_lossy().to_string();
            if name.ends_with("_tests.rs") || name == "tests.rs" {
                continue;
            }
            if let Ok(text) = fs::read_to_string(&path) {
                found.push((path, text));
            }
        }
    }
    found
}

/// Returns every `pub struct`/`pub enum`/`pub trait`/`pub type` name declared in
/// `source`.
fn public_type_names(source: &str) -> Vec<String> {
    source
        .lines()
        .filter_map(|line| {
            let line = line.trim_start();
            let rest = ["pub struct ", "pub enum ", "pub trait ", "pub type "]
                .iter()
                .find_map(|prefix| line.strip_prefix(*prefix))?;
            let name: String = rest
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_')
                .collect();
            (!name.is_empty()).then_some(name)
        })
        .collect()
}

/// `Row` is reserved for one relational persistence mapping. The UI crates must
/// not use it: their values are formatted, presentation-only state that is never
/// stored and never authoritative.
#[test]
fn ui_crates_do_not_use_the_reserved_row_suffix() {
    for crate_dir in ["crates/piteka-ui/src", "apps/piteka-web/src"] {
        for (path, source) in sources(&root().join(crate_dir)) {
            for name in public_type_names(&source) {
                assert!(
                    !name.ends_with("Row"),
                    "{}: `{name}` uses the persistence-reserved `Row` suffix. \
                     UI-ready state is a `ViewModel`.",
                    path.display()
                );
            }
        }
    }
}

/// `Data`, `Info`, `Item`, and `Object` are prohibited as public top-level names
/// or trailing qualifiers (§2.2): they say nothing about domain, authority, or
/// representation.
#[test]
fn public_types_avoid_context_free_suffixes() {
    for crate_dir in ["crates", "apps"] {
        for (path, source) in sources(&root().join(crate_dir)) {
            for name in public_type_names(&source) {
                for banned in ["Data", "Info"] {
                    assert!(
                        name != banned && !name.ends_with(banned),
                        "{}: `{name}` ends in the context-free noun `{banned}`.",
                        path.display()
                    );
                }
            }
        }
    }
}

/// Every public boundary shape on the `/api/v1` surface carries an explicit
/// version, so a future v2 shape can exist beside it and a reader can tell the
/// external contract from an internal projection.
#[test]
fn api_boundary_shapes_are_versioned() {
    for file in [
        "apps/piteka-api/src/models.rs",
        "apps/piteka-api/src/error.rs",
    ] {
        let source = fs::read_to_string(root().join(file)).unwrap();
        for name in public_type_names(&source) {
            // `ApiError` is the internal error enum, not a serialized shape.
            if name == "ApiError" {
                continue;
            }
            assert!(
                name.ends_with("V1"),
                "{file}: `{name}` is an /api/v1 boundary shape and must end in a \
                 version (`RequestV1`, `ResponseV1`, or `DtoV1`)."
            );
        }
    }
}

/// The OpenAPI contract and the Rust types name the same schemas (§4:
/// "Schema titles and generated type names agree").
#[test]
fn openapi_schema_names_match_declared_rust_types() {
    let spec = fs::read_to_string(root().join("openapi/openapi.yaml")).unwrap();
    let models = fs::read_to_string(root().join("apps/piteka-api/src/models.rs")).unwrap();
    let errors = fs::read_to_string(root().join("apps/piteka-api/src/error.rs")).unwrap();

    let declared: Vec<String> = public_type_names(&models)
        .into_iter()
        .chain(public_type_names(&errors))
        .collect();

    // Every schema the spec defines must be a type Rust actually declares.
    for line in spec.lines() {
        let Some(name) = line.strip_prefix("    ").and_then(|l| l.strip_suffix(':')) else {
            continue;
        };
        if !name.ends_with("V1") {
            continue;
        }
        assert!(
            declared.iter().any(|d| d == name),
            "openapi.yaml declares schema `{name}` with no matching Rust type"
        );
    }
}

/// Constitutional protocol vocabulary is not re-used for product-local values.
///
/// `Receipt`, `Mandate`, `Observation`, `Assurance`, and `Verification` carry
/// fixed meanings owned by Parwana. A Piteka type may *hold* one of these
/// (`ReceiptProjection`, `MandateProjection`) or *qualify* it by owner
/// (`TuppiraObservation`), but a bare protocol noun in product code claims
/// authority Piteka does not have.
#[test]
fn protocol_vocabulary_is_not_redefined_by_product_types() {
    // Bare protocol nouns that must never be declared as a Piteka public type.
    let reserved = [
        "Receipt",
        "Mandate",
        "Observation",
        "Assurance",
        "Verification",
        "Evidence",
    ];

    for crate_dir in ["crates", "apps"] {
        for (path, source) in sources(&root().join(crate_dir)) {
            for name in public_type_names(&source) {
                assert!(
                    !reserved.contains(&name.as_str()),
                    "{}: `{name}` re-declares protocol-owned vocabulary. Qualify it \
                     with its owner or representation.",
                    path.display()
                );
            }
        }
    }
}

/// `Canonical` names Parwana's single serializer. A Piteka type that computes its
/// own digest must not borrow it — that was exactly the `CanonicalIntent`
/// confusion NAM-02 removed, where an approval-display digest read as a protocol
/// intent id.
///
/// `piteka-parwana` is exempt by design: it is the one adapter crate that holds
/// Parwana's canonical bytes unchanged, so `CanonicalObject` there names exactly
/// what it is. The exemption is the crate boundary, not a per-type allowance —
/// which is what keeps "who may say canonical" answerable in one place.
#[test]
fn product_types_do_not_claim_canonical_protocol_authority() {
    for crate_dir in ["crates", "apps"] {
        for (path, source) in sources(&root().join(crate_dir)) {
            if path.components().any(|c| c.as_os_str() == "piteka-parwana") {
                continue;
            }
            for name in public_type_names(&source) {
                assert!(
                    !name.starts_with("Canonical"),
                    "{}: `{name}` claims canonical protocol authority, which only \
                     Parwana holds (and only `piteka-parwana` may relay).",
                    path.display()
                );
            }
        }
    }
}

/// `Wire` is reserved for representations whose field layout participates in the
/// versioned Parwana contract. Piteka owns no such contract, so it declares no
/// `Wire` type of its own — only re-exports of Parwana's.
#[test]
fn piteka_declares_no_wire_types_of_its_own() {
    for crate_dir in ["crates", "apps"] {
        for (path, source) in sources(&root().join(crate_dir)) {
            for name in public_type_names(&source) {
                assert!(
                    !name.ends_with("Wire") && !name.contains("WireV"),
                    "{}: `{name}` uses the protocol-reserved `Wire` suffix. A \
                     Piteka boundary shape is a `Dto`.",
                    path.display()
                );
            }
        }
    }
}

/// The newcomer walkthrough names real types.
///
/// `docs/naming-walkthrough.md` is the ticket's "same terms as the code and UI"
/// deliverable, which is only true while every type it names still exists. A doc
/// that quietly drifts from the code teaches the wrong vocabulary, so this test
/// fails rather than letting that happen silently.
#[test]
fn naming_walkthrough_names_types_that_exist() {
    let doc = fs::read_to_string(root().join("docs/naming-walkthrough.md")).unwrap();

    let mut declared: Vec<String> = Vec::new();
    for crate_dir in ["crates", "apps"] {
        for (_, source) in sources(&root().join(crate_dir)) {
            declared.extend(public_type_names(&source));
        }
    }

    for name in [
        "RequestDeploymentInput",
        "GitHubDeploymentInput",
        "NormalizedGitHubDeploymentIntent",
        "NormalizedGitHubDeploymentIntentDtoV1",
        "ApprovalCeremonyIntent",
        "ApproveActionRequestResult",
        "DispatchedExecution",
        "ReservationConflict",
        "ReplayRejection",
        "DeploymentCreationResponse",
        "WebhookDeliveryRecord",
        "ReceiptProjection",
        "MandateProjection",
        "ReceiptResponseV1",
        "MandateChainResponseV1",
        "WorkQueueItemViewModel",
        "IntentPanelViewModel",
        "TuppiraObservation",
        "ObservationQueryResult",
        "InMemoryCsvSealAnchor",
        "InMemoryChainAnchor",
        "ActionRequestResponseV1",
        "ApprovalDecisionDtoV1",
    ] {
        assert!(
            doc.contains(name),
            "docs/naming-walkthrough.md no longer mentions `{name}`"
        );
        assert!(
            declared.iter().any(|d| d == name),
            "docs/naming-walkthrough.md names `{name}`, which no type declares"
        );
    }

    // The walkthrough must not teach a name NAM-02 removed.
    for stale in [
        "`CanonicalIntent`",
        "`WebhookReceipt`",
        "`WorkQueueRow`",
        "`RequestDetailRow`",
        "`IntentPanelData`",
        "`NormalizedIntent`",
    ] {
        let bare = stale.trim_matches('`');
        assert!(
            !declared.iter().any(|d| d == bare),
            "`{bare}` was reintroduced as a public type after NAM-02 removed it"
        );
    }
}

/// The OpenAPI contract is consistent with the routes actually served.
///
/// `openapi/openapi.yaml` is hand-maintained — there are no `utoipa` annotations
/// to generate it from — so nothing keeps it honest except a check that runs.
/// The former `scripts/regenerate_openapi.sh` called a `piteka_api::ApiDoc` that
/// does not exist, so the gate it advertised never ran and the spec silently
/// drifted (five undocumented read-model endpoints, and a file that was not even
/// valid YAML). Running the check from the test suite means it cannot be
/// forgotten.
#[test]
fn openapi_contract_matches_the_served_routes() {
    let script = root().join("scripts/check_openapi.sh");
    assert!(script.exists(), "scripts/check_openapi.sh is missing");

    let output = std::process::Command::new("bash")
        .arg(&script)
        .current_dir(root())
        .output()
        .expect("failed to run scripts/check_openapi.sh");

    assert!(
        output.status.success(),
        "OpenAPI contract check failed:\n{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
}
