#![forbid(unsafe_code)]

//! Fail-closed action-binding gate for the ORG-REL-003 campaign.

use serde::Deserialize;
use serde_json::json;
use std::{env, fs};

#[derive(Deserialize)]
struct Campaign {
    schema: String,
    isolated_successors: Vec<Successor>,
    closure: Closure,
}

#[derive(Deserialize)]
struct Successor {
    txid: String,
}

#[derive(Deserialize)]
struct Closure {
    valid_successor: String,
    valid_successor_count: u64,
    losing_testmempoolaccept: Vec<MempoolReading>,
}

#[derive(Deserialize)]
struct MempoolReading {
    allowed: bool,
}

fn main() -> Result<(), String> {
    piteka_parwana::ParwanaContract::bind_or_refuse_to_start()
        .map_err(|error| format!("Parwana contract binding failed: {error}"))?;
    let path = env::args_os()
        .nth(1)
        .ok_or("usage: org-rel-003-campaign-gate RESULT")?;
    let campaign: Campaign = serde_json::from_slice(
        &fs::read(path).map_err(|error| format!("campaign result: {error}"))?,
    )
    .map_err(|error| format!("campaign result: {error}"))?;
    if campaign.schema != "diewan.org-rel-003.result.v1"
        || campaign.isolated_successors.len() != 2
        || campaign.closure.valid_successor_count != 1
        || campaign.closure.losing_testmempoolaccept.len() != 1
        || campaign.closure.losing_testmempoolaccept[0].allowed
    {
        return Err("campaign is not safe to bind to an action".into());
    }
    let transaction_ids = campaign
        .isolated_successors
        .iter()
        .map(|successor| successor.txid.clone())
        .collect::<Vec<_>>();
    if transaction_ids[0] == transaction_ids[1]
        || !transaction_ids.contains(&campaign.closure.valid_successor)
    {
        return Err("campaign winner is not exactly one declared successor".into());
    }
    let losing = transaction_ids
        .iter()
        .find(|txid| **txid != campaign.closure.valid_successor)
        .ok_or("campaign has no distinct losing successor")?;

    println!(
        "{}",
        serde_json::to_string_pretty(&json!({
            "schema": "diewan.piteka.org-rel-003.action-binding.v1",
            "action_bound_to": campaign.closure.valid_successor,
            "conflict_review": losing,
            "action_count": 1,
            "contract_bound": true
        }))
        .map_err(|error| error.to_string())?
    );
    Ok(())
}
