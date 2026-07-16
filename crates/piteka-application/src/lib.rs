#![forbid(unsafe_code)]

use piteka_domain::{Health, ServiceStatus};

pub trait Clock: Send + Sync {
    fn unix_seconds(&self) -> u64;
}

pub struct HealthQuery<C> {
    clock: C,
}

impl<C: Clock> HealthQuery<C> {
    pub const fn new(clock: C) -> Self {
        Self { clock }
    }

    pub fn execute(&self) -> Health {
        Health {
            status: ServiceStatus::Ready,
            observed_at_unix_seconds: self.clock.unix_seconds(),
        }
    }
}
