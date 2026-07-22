//! DEMO-01 (Scenario A) end-to-end: an autonomous agent drives the Piteka MCP
//! tools under a single-use mandate, with a human approving out of band.
//!
//! This test runs the *real* backend ([`piteka::demo::AgentDemoBackend`]) over
//! in-memory stores and a fake GitHub port so all four acceptance criteria are
//! proven deterministically in `cargo test`:
//!
//! 1. The agent completes propose → (human approve) → execute → receipt with no
//!    human performing the execute step.
//! 2. Changed parameters after approval fail intent matching; no dispatch.
//! 3. A second execute under the same mandate is visibly rejected.
//! 4. The provider is called exactly once for the whole flow.
//!
//! The live GitHub App + Postgres wiring lives in `src/bin/agent_demo_flow.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use piteka::demo::{AgentActor, AgentDemoBackend, DeploymentPlan, human_approve};

mod common;
use common::{DEPLOYMENT_ID, ENV_ID, FakeGitHub, REPO_ID, SHA, TENANT, identity, in_memory_ports};

fn plan() -> DeploymentPlan {
    DeploymentPlan {
        request_id: "req-demo-a-1".into(),
        repository_id: REPO_ID,
        environment_id: ENV_ID,
        commit_sha: SHA.into(),
    }
}

#[tokio::test]
async fn agent_completes_propose_approve_execute_receipt_and_rejects_replay() {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = AgentDemoBackend::new(in_memory_ports(), FakeGitHub::new(calls.clone()));
    let plan = plan();
    let mut agent = AgentActor::new(&backend, identity());

    // 1. Agent proposes. No mandate exists yet.
    let proposed = agent.request_deployment(&plan).await.expect("propose");
    assert_eq!(proposed["status"], "pending");
    let status = agent.action_status(&plan.request_id).await.expect("status");
    assert_eq!(status["status"], "pending");
    assert!(status.get("mandate_id").is_none(), "no mandate before approval");

    // Human approval happens out of band — the agent cannot do this itself.
    let intent_id = plan.intent_id(TENANT);
    let mandate_id = human_approve(backend.ports(), "demo-approver", &plan.request_id, &intent_id)
        .await
        .expect("human approve");

    // 2. Agent polls and learns the mandate id, then executes — no human here.
    let learned = agent
        .wait_for_mandate(&plan.request_id, 3)
        .await
        .expect("mandate visible after approval");
    assert_eq!(learned, mandate_id);

    let executed = agent.execute(&plan, &mandate_id).await.expect("execute");
    assert_eq!(executed["dispatched"], true);
    assert_eq!(executed["github_deployment_id"], DEPLOYMENT_ID);
    assert_eq!(calls.load(Ordering::SeqCst), 1, "exactly one provider call");

    // 3. Receipt reads back the real attempt journal.
    let receipt = agent.get_receipt(&mandate_id).await.expect("receipt");
    assert_eq!(receipt["mandate_id"], mandate_id);
    assert_eq!(receipt["state"], "accepted");
    assert_eq!(receipt["github_deployment_id"], DEPLOYMENT_ID);

    // 4. A second execute under the same mandate is rejected with no new call.
    let replay = agent
        .execute(&plan, &mandate_id)
        .await
        .expect_err("replay must be rejected");
    assert_eq!(replay.code, "MANDATE.REPLAY_DETECTED");
    assert_eq!(calls.load(Ordering::SeqCst), 1, "replay makes no provider call");
}

#[tokio::test]
async fn changed_parameters_after_approval_fail_intent_matching_without_dispatch() {
    let calls = Arc::new(AtomicUsize::new(0));
    let backend = AgentDemoBackend::new(in_memory_ports(), FakeGitHub::new(calls.clone()));
    let plan = plan();
    let mut agent = AgentActor::new(&backend, identity());

    agent.request_deployment(&plan).await.expect("propose");
    let intent_id = plan.intent_id(TENANT);
    let mandate_id = human_approve(backend.ports(), "demo-approver", &plan.request_id, &intent_id)
        .await
        .expect("approve");

    // The agent tampers: it keeps the approved intent id and mandate, but
    // presents a *different* commit sha to execute. The server recomputes the
    // intent from the actual sha and the supplied approved intent no longer
    // matches → INTENT_MISMATCH, before any provider call.
    let tampered_sha = "b1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0";
    let err = agent
        .execute_raw(&plan.request_id, &mandate_id, REPO_ID, tampered_sha, ENV_ID, &intent_id)
        .await
        .expect_err("changed parameters must be rejected");
    assert_eq!(err.code, "INTENT_MISMATCH", "recompute gate must fire");
    assert_eq!(calls.load(Ordering::SeqCst), 0, "no dispatch on parameter change");

    // The mandate is still issued and unconsumed: the honest execute still works.
    let ok = agent.execute(&plan, &mandate_id).await.expect("honest execute");
    assert_eq!(ok["dispatched"], true);
    assert_eq!(calls.load(Ordering::SeqCst), 1);
}
