#![forbid(unsafe_code)]

pub mod anchor;
pub mod chain_anchor;
pub mod kms;

pub use anchor::InMemoryCsvSealAnchor;

use std::time::{SystemTime, UNIX_EPOCH};

use piteka_application::Clock;

#[derive(Clone, Copy, Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn unix_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock must be after the Unix epoch")
            .as_secs()
    }
}
