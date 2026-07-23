use piteka::demo::cross_entity::CrossEntityHandoff;
use piteka_storage::{EvidenceObjectStore, InMemoryEvidenceStore, TenantScope};

#[test]
fn receiver_reverifies_without_trusting_sender_infrastructure() {
    let package = CrossEntityHandoff::disclosed().unwrap();
    let transported = package.canonical_bytes().unwrap();
    assert!(!transported.is_empty());

    let trace = package.verify_at_receiver().unwrap();
    assert_eq!(trace.sender_tenant, "org-a");
    assert_eq!(trace.receiver_tenant, "org-b");
    assert_eq!(trace.conclusion, "Compatible");
    assert_eq!(trace.withheld_branches, 0);
    assert!(!trace.custody_node_id.is_empty());
    assert!(
        !serde_json::to_string(&trace)
            .unwrap()
            .contains("Authorized")
    );
}

#[test]
fn undisclosed_branch_is_indeterminate_and_committed() {
    let package = CrossEntityHandoff::with_withheld_branch().unwrap();
    let trace = package.verify_at_receiver().unwrap();
    assert_eq!(trace.conclusion, "Indeterminate");
    assert_eq!(trace.withheld_branches, 1);
    assert_eq!(
        package.bundle().withheld_objects[0].reason_code,
        "purpose-limited-third-party-identity"
    );
}

#[test]
fn custody_and_bundle_tampering_fail_closed() {
    let package = CrossEntityHandoff::disclosed().unwrap();
    let mut tampered = package.bundle().clone();
    let custody = tampered
        .disclosed_objects
        .iter_mut()
        .find(|object| object.registry_id == "org.diewan.evidence.custody-record.v1")
        .unwrap();
    custody.bytes[0] ^= 1;
    assert!(tampered.validate().is_err());

    let mut ambiguous = package.bundle().clone();
    ambiguous
        .withheld_objects
        .push(piteka_parwana::protocol::WithheldObject {
            registry_id: "org.diewan.evidence.claim.v1".into(),
            content_digest: ambiguous.disclosed_objects[0].content_digest,
            reason_code: "tenant-boundary-test".into(),
        });
    assert!(ambiguous.validate().is_err());
}

#[tokio::test]
async fn tenant_storage_requires_an_explicit_cross_entity_handoff() {
    let package = CrossEntityHandoff::disclosed().unwrap();
    let bytes = package.canonical_bytes().unwrap();
    let store = InMemoryEvidenceStore::default();
    let sender = TenantScope::new("org-a").unwrap();
    let receiver = TenantScope::new("org-b").unwrap();

    let digest = store.put(&sender, &bytes).await.unwrap();
    assert_eq!(store.get(&receiver, &digest).await.unwrap(), None);

    // Transport is explicit: Org B receives exact bytes, content-addresses
    // them under its own scope, and only then can access its retained copy.
    let received_digest = store.put(&receiver, &bytes).await.unwrap();
    assert_eq!(received_digest, digest);
    assert_eq!(
        store.get(&receiver, &received_digest).await.unwrap(),
        Some(bytes)
    );
}
