//! DEMO-05 — capped, recipient-bound, single-use payment mandate.
//!
//! No real funds or credentials participate. The deterministic provider records
//! calls, while canonical payment meaning comes exclusively from Parwana. Live
//! single-use state remains in Piteka's mandate CAS store.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use piteka::demo::demo_mandate_id;
use piteka_parwana::protocol::{ActionIntent, PaymentCodec, PaymentIntentV1, ProfileCodec};
use piteka_storage::model::{CasOutcome, ReceiptOutcome, ReceiptProjection};
use sha2::{Digest, Sha256};

#[allow(dead_code)]
mod common;
use common::in_memory_ports;

fn payment() -> PaymentIntentV1 {
    PaymentIntentV1 {
        payer_id: "org:payer-acme".into(),
        merchant_id: "merchant:coffee-42".into(),
        recipient_account_digest: [41; 32],
        amount_minor: 2_500,
        cap_minor: 5_000,
        currency: "USD".into(),
        expires_at: 200,
        payment_reference: "invoice:2026-0042".into(),
    }
}

fn intent(profile: &PaymentIntentV1) -> ActionIntent {
    let codec = PaymentCodec::default();
    ActionIntent::new(
        codec.descriptor(),
        &codec,
        profile.canonical_bytes().unwrap(),
        b"agent:payment".to_vec(),
        90,
        [42; 32],
        vec![[43; 32]],
    )
    .unwrap()
}

fn hex_id(intent: &ActionIntent) -> String {
    hex::encode(intent.id().unwrap().as_bytes())
}

struct FakePaymentProvider {
    calls: Arc<AtomicUsize>,
}

impl FakePaymentProvider {
    fn settle(&self, profile: &PaymentIntentV1) -> [u8; 32] {
        self.calls.fetch_add(1, Ordering::SeqCst);
        let mut digest = Sha256::new();
        digest.update(b"fake-payment-settlement-v1");
        digest.update(profile.canonical_bytes().unwrap());
        digest.finalize().into()
    }
}

async fn execute(
    approved_intent_id: &str,
    supplied: &PaymentIntentV1,
    now: u64,
    provider: &FakePaymentProvider,
    ports: &piteka::demo::DemoPorts,
) -> Result<ReceiptProjection, &'static str> {
    supplied.validate().map_err(|_| "INVALID_PAYMENT")?;
    if now > supplied.expires_at {
        return Err("PAYMENT_EXPIRED");
    }
    if hex_id(&intent(supplied)) != approved_intent_id {
        return Err("INTENT_MISMATCH");
    }
    let mandate_id = demo_mandate_id(approved_intent_id);
    match ports
        .mandates
        .compare_and_swap(&ports.tenant, &mandate_id, 1, "reserved")
        .await
        .map_err(|_| "RESERVATION_FAILED")?
    {
        CasOutcome::Applied { .. } => {}
        CasOutcome::Conflict { .. } | CasOutcome::Missing => return Err("REPLAY_REJECTED"),
    }

    let settlement = provider.settle(supplied);
    let receipt_id = hex::encode(Sha256::digest(settlement));
    let receipt = ReceiptProjection {
        receipt_id_hex: receipt_id,
        mandate_id_hex: mandate_id.clone(),
        intent_id_hex: approved_intent_id.to_owned(),
        attempt_id_hex: hex::encode(settlement),
        outcome: ReceiptOutcome::Succeeded,
        created_at_unix_seconds: now as i64,
        dispatch_evidence_refs: vec!["evidence.executor.attempt-record".into()],
        target_evidence_refs: vec!["evidence.payment.settlement-record".into()],
        evidence_gaps: vec![],
        canonical_bytes: None,
    };
    ports
        .receipts
        .insert(&ports.tenant, receipt.clone())
        .await
        .map_err(|_| "RECEIPT_FAILED")?;
    ports
        .mandates
        .compare_and_swap(&ports.tenant, &mandate_id, 2, "consumed")
        .await
        .map_err(|_| "CONSUMPTION_FAILED")?;
    Ok(receipt)
}

#[tokio::test]
async fn cap_recipient_currency_expiry_and_replay_are_enforced() {
    let ports = in_memory_ports();
    let approved = payment();
    let approved_intent_id = hex_id(&intent(&approved));
    let mandate_id = demo_mandate_id(&approved_intent_id);
    ports
        .mandates
        .insert(&ports.tenant, &mandate_id, "issued")
        .await
        .unwrap();
    let calls = Arc::new(AtomicUsize::new(0));
    let provider = FakePaymentProvider {
        calls: calls.clone(),
    };

    let mut over_cap = approved.clone();
    over_cap.amount_minor = over_cap.cap_minor + 1;
    assert_eq!(
        execute(&approved_intent_id, &over_cap, 150, &provider, &ports).await,
        Err("INVALID_PAYMENT")
    );

    for mutated in [
        PaymentIntentV1 {
            recipient_account_digest: [99; 32],
            ..approved.clone()
        },
        PaymentIntentV1 {
            currency: "EUR".into(),
            ..approved.clone()
        },
    ] {
        assert_eq!(
            execute(&approved_intent_id, &mutated, 150, &provider, &ports).await,
            Err("INTENT_MISMATCH")
        );
    }
    assert_eq!(
        execute(&approved_intent_id, &approved, 201, &provider, &ports).await,
        Err("PAYMENT_EXPIRED")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);

    let receipt = execute(&approved_intent_id, &approved, 150, &provider, &ports)
        .await
        .expect("authorized payment settles exactly once");
    assert_eq!(receipt.outcome, ReceiptOutcome::Succeeded);
    assert_eq!(calls.load(Ordering::SeqCst), 1);

    assert_eq!(
        execute(&approved_intent_id, &approved, 151, &provider, &ports).await,
        Err("REPLAY_REJECTED")
    );
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(
        ports
            .receipts
            .by_mandate(&ports.tenant, &mandate_id)
            .await
            .unwrap()
            .len(),
        1
    );
}
