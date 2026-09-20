use std::sync::Arc;

use ark_ec::CurveGroup;
use ark_ff::{FftField, PrimeField};

use crate::net::engine_config::MpcSessionConfig;

#[derive(Clone)]
pub struct AvssEngineConfig<F, G>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    pub session: MpcSessionConfig,
    pub secret_key: F,
    pub public_keys: Arc<Vec<G>>,
    /// Random shares preprocessing generates beyond the program's own pool —
    /// for example one client input mask per registered coordinator input.
    pub additional_random_shares: usize,
}

impl<F, G> AvssEngineConfig<F, G>
where
    F: FftField + PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    pub fn new(session: MpcSessionConfig, secret_key: F, public_keys: Arc<Vec<G>>) -> Self {
        Self {
            session,
            secret_key,
            public_keys,
            additional_random_shares: 0,
        }
    }

    /// Generate `count` more random shares than the default pool, so that
    /// drawing `count` of them (client input masks) leaves the program's own
    /// randomness untouched.
    pub fn with_additional_random_shares(mut self, count: usize) -> Self {
        self.additional_random_shares = count;
        self
    }
}
