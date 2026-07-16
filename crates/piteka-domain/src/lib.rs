#![forbid(unsafe_code)]

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceStatus {
    Ready,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Health {
    pub status: ServiceStatus,
    pub observed_at_unix_seconds: u64,
}
