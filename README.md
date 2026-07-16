# Piteka

Piteka is the enterprise accountability workbench. The first release is a
Rust modular monolith: one Axum process with pure domain rules, application
use cases and ports, and infrastructure adapters separated into inward-pointing
workspace crates.

Local configuration in `config/local.toml` is deliberately secret-free.
Credentials must be supplied through environment variables and must never be
committed.

