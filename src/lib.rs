#![forbid(unsafe_code)]

//! Piteka application library surface shared by the service binary, the demo
//! actors, and integration tests.
//!
//! The primary product surfaces live in the `piteka-*` workspace crates. This
//! root library hosts the cross-cutting demo actors (Master Plan §3 vertical
//! slice) so a single implementation is exercised by both the `agent_demo_flow`
//! binary and the deterministic e2e tests.

pub mod demo;
