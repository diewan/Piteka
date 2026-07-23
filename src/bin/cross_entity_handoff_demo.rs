use piteka::demo::cross_entity::CrossEntityHandoff;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let package = CrossEntityHandoff::disclosed().map_err(std::io::Error::other)?;
    let trace = package
        .verify_at_receiver()
        .map_err(std::io::Error::other)?;
    println!("{}", serde_json::to_string_pretty(&trace)?);
    Ok(())
}
