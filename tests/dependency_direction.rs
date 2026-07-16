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
