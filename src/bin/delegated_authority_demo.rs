#![forbid(unsafe_code)]

use piteka::demo::delegated_authority::DelegatedAuthorityDemo;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut demo = DelegatedAuthorityDemo::default();
    let traces = [
        demo.execute_valid_once().map_err(std::io::Error::other)?,
        demo.overreach().map_err(std::io::Error::other)?,
        demo.withheld_link().map_err(std::io::Error::other)?,
    ];
    let case = demo
        .investigate(&traces[1])
        .await
        .map_err(std::io::Error::other)?;
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "traces": traces,
            "investigator_case": case,
        }))?
    );
    Ok(())
}
