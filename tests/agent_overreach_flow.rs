//! DEMO-03 (Scenario B) — agent overreach → fail-closed rejection.
//!
//! An agent that got a mandate approved for one exact deployment tries to exceed
//! it (a different commit SHA, then a different environment). Piteka must fail
//! closed: the server recompute rejects the changed parameters with an
//! intent-mismatch reason code, **no** provider dispatch happens, and the
//! mandate is never silently consumed — the honest deployment still works
//! afterward. The structured rejection returned to the agent is the Piteka-side
//! dispute record; the *independent* Parwana verdict over the mismatch bundle is
//! proven in `parwana/csv-sdk/tests/overreach_verdict.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use piteka::demo::{AgentActor, AgentDemoBackend, DeploymentPlan, human_approve};

mod common;
use common::{ENV_ID, FakeGitHub, REPO_ID, SHA, TENANT, identity, in_memory_ports};

const AUTHORIZED_SHA: &str = SHA;
const OVERREACH_SHA: &str = "ffffffffffffffffffffffffffffffffffffffff";
const OVERREACH_ENV_ID: u64 = 9;

fn plan() -> DeploymentPlan {
    DeploymentPlan {
        request_id: "req-overreach-1".into(),
        repository_id: REPO_ID,
        environment_id: ENV_ID,
        commit_sha: AUTHORIZED_SHA.into(),
    }
}

#[tokio::test]
async fn agent_overreach_is_rejected_fail_closed_and_leaves_the_mandate_usable() {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = AgentDemoBackend::new(in_memory_ports(), FakeGitHub::new(calls.clone()));
    let plan = plan();
    let mut agent = AgentActor::new(&backend, identity());

    // Propose + human-approve the exact authorized deployment.
    agent.request_deployment(&plan).await.expect("propose");
    let intent_id = plan.intent_id(TENANT);
    let mandate_id = human_approve(backend.ports(), "demo-approver", &plan.request_id, &intent_id)
        .await
        .expect("approve");

    // Overreach 1 — a commit SHA the approver never reviewed, presented under
    // the approved intent id. The server recomputes from the actual SHA and
    // rejects; nothing is dispatched.
    let wrong_sha = agent
        .execute_raw(&plan.request_id, &mandate_id, REPO_ID, OVERREACH_SHA, ENV_ID, &intent_id)
        .await
        .expect_err("wrong-sha overreach must be rejected");
    assert_eq!(wrong_sha.code, "INTENT_MISMATCH");
    // The rejection carries the dispute detail: supplied vs independently computed intent.
    let details = wrong_sha.details.expect("mismatch carries details");
    assert_eq!(details["supplied_intent_id"], intent_id);
    assert_ne!(details["computed_intent_id"], serde_json::Value::Null);
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no dispatch on sha overreach");

    // Overreach 2 — an environment outside the mandate. Environment is part of
    // the intent, so this too fails the recompute. No dispatch.
    let wrong_env = agent
        .execute_raw(
            &plan.request_id,
            &mandate_id,
            REPO_ID,
            AUTHORIZED_SHA,
            OVERREACH_ENV_ID,
            &intent_id,
        )
        .await
        .expect_err("wrong-environment overreach must be rejected");
    assert_eq!(wrong_env.code, "INTENT_MISMATCH");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no dispatch on env overreach");

    // The mandate was never consumed by the rejected overreach attempts: the
    // honest, authorized deployment still executes exactly once.
    let ok = agent.execute(&plan, &mandate_id).await.expect("honest execute still works");
    assert_eq!(ok["dispatched"], true);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one honest dispatch");
}
