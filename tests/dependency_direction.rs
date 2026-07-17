use std::{fs, path::Path};

#[test]
fn workspace_dependencies_point_inward() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let domain = fs::read_to_string(root.join("crates/piteka-domain/Cargo.toml")).unwrap();
    let application =
        fs::read_to_string(root.join("crates/piteka-application/Cargo.toml")).unwrap();
    let infra = fs::read_to_string(root.join("crates/piteka-infra/Cargo.toml")).unwrap();

    assert!(!domain.contains("piteka-application"));
    assert!(!domain.contains("piteka-infra"));
    assert!(application.contains("piteka-domain.workspace = true"));
    assert!(!application.contains("piteka-infra"));
    assert!(infra.contains("piteka-application.workspace = true"));
}

/// The Parwana contract has exactly one dependency edge into Piteka: the
/// `piteka-parwana` adapter, which links only the public `csv-sdk` facade at an
/// exact pinned version. No other crate touches a `csv-*` protocol crate.
/// Enforces ARCHITECTURE.md §5.1 (no product-local protocol copies) and §7
/// (exact pin, no `latest`).
#[test]
fn only_the_adapter_links_the_parwana_contract() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    let crates = root.join("crates");

    let adapter = fs::read_to_string(crates.join("piteka-parwana/Cargo.toml")).unwrap();
    assert!(
        adapter.contains(r#"csv-sdk = { version = "=0.1.5""#),
        "adapter must pin csv-sdk to an exact contract version"
    );
    assert!(
        !adapter.contains("csv-accountability") && !adapter.contains("csv-wire"),
        "adapter must reach the protocol only through the public csv-sdk facade"
    );

    // Every other workspace crate, plus the root binary, must stay free of any
    // direct `csv-*` protocol dependency.
    let mut manifests = vec![fs::read_to_string(root.join("Cargo.toml")).unwrap()];
    for entry in fs::read_dir(&crates).unwrap() {
        let dir = entry.unwrap().path();
        if dir.file_name().and_then(|name| name.to_str()) == Some("piteka-parwana") {
            continue;
        }
        let manifest = dir.join("Cargo.toml");
        if manifest.exists() {
            manifests.push(fs::read_to_string(manifest).unwrap());
        }
    }
    for manifest in manifests {
        assert!(
            !manifest.contains("csv-"),
            "only piteka-parwana may depend on a csv-* protocol crate:\n{manifest}"
        );
    }
}
