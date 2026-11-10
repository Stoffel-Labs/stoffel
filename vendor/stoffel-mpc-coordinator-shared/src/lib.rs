// The coordinator is generic over the share type `S` used to represent shares in the underlying
// MPC protocol. Concretely, `S` must implement `ShareBound`, which is `stoffelcrypto`'s
// `SecretSharingScheme` plus some additional bounds to make the code work.
// Every struct and trait in this library that touches shares is parametrized as `<F: FftField, S: ShareBound<F>>`;
// the generic type `F` comes directly from the definition of `SecretSharingScheme`.
//
// Two share types are already contained and can be selected by choosing the concrete `S`
// at coordinator startup:
//
// * **`RobustShare<F>`**: the plain Shamir share used by HoneyBadger MPC.
// * **`FeldmanShamirShare<F, G>`**: a Shamir share augmented with group elements that
// enable verifiable secret sharing.

/// Self-signed certificates used for tests.
pub mod self_signed_certs;

/// Things related to JSON-RPC interfaces.
pub mod rpc;

/// Things for testing the coordinator when deployed, using Docker, for example.
pub mod tests;

use ark_ec::CurveGroup;
use ark_ff::FftField;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::str::FromStr;
use std::sync::Once;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::share::ShareError;
use stoffelmpc_mpc::common::SecretSharingScheme;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use thiserror::Error;

/// Uniquely identifies one MPC program invocation.
///
/// A program hash is deliberately not used as the execution identity: two invocations of the
/// same program must be able to overlap without sharing coordinator or node state. The all-zero
/// value is reserved and rejected by persistent/concurrent RPC paths.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ExecutionId([u8; 32]);

impl ExecutionId {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn is_zero(self) -> bool {
        self.0 == [0; 32]
    }
}

impl fmt::Display for ExecutionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&hex::encode(self.0))
    }
}

impl FromStr for ExecutionId {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() != 64 {
            return Err(format!(
                "execution ID must contain exactly 64 hexadecimal characters, got {}",
                value.len()
            ));
        }
        let bytes = hex::decode(value).map_err(|error| format!("invalid execution ID: {error}"))?;
        Ok(Self(
            bytes.try_into().expect("validated execution ID length"),
        ))
    }
}

#[cfg(test)]
mod execution_id_tests {
    use super::*;

    #[test]
    fn hex_round_trip_is_strict_and_stable() {
        let id = ExecutionId::from_bytes([0xab; 32]);
        let encoded = id.to_string();
        assert_eq!(encoded.len(), 64);
        assert_eq!(encoded.parse::<ExecutionId>().unwrap(), id);
        assert!("ab".parse::<ExecutionId>().is_err());
        assert!(format!("{}z", &encoded[..63])
            .parse::<ExecutionId>()
            .is_err());
    }
}

pub trait ShareBound<F: FftField>:
    SecretSharingScheme<F, SecretType = Self::ValueType>
    + CanonicalSerialize
    + CanonicalDeserialize
    + Clone
    + Send
    + 'static
{
    type ValueType: CanonicalSerialize + CanonicalDeserialize + Clone + Send;

    fn compute_masked_input(input: Self::ValueType, mask_share: &Self) -> Result<Self, ShareError>;

    fn min_shares(t: usize) -> usize;

    /// Validate share metadata against the authenticated sender's roster position.
    fn valid_output_sender(&self, party_index: usize, n: usize, t: usize) -> bool;

    fn recover_output(shares: &[Self], n: usize, t: usize) -> Result<Self::ValueType, Self::Error> {
        Self::recover_secret(shares, n, t).map(|(_, value)| value)
    }
}

impl<F: FftField> ShareBound<F> for RobustShare<F> {
    type ValueType = Self::SecretType;

    fn compute_masked_input(input: Self::ValueType, mask_share: &Self) -> Result<Self, ShareError> {
        Ok(RobustShare::new(
            input - mask_share.share[0],
            mask_share.id,
            mask_share.degree,
        ))
    }

    fn min_shares(t: usize) -> usize {
        2 * t + 1
    }
    fn valid_output_sender(&self, party_index: usize, n: usize, t: usize) -> bool {
        party_index < n && self.id == party_index && self.degree == t
    }
}

impl<F: FftField, G: CurveGroup<ScalarField = F>> ShareBound<F> for FeldmanShamirShare<F, G> {
    type ValueType = Self::SecretType;

    fn compute_masked_input(input: Self::ValueType, mask_share: &Self) -> Result<Self, ShareError> {
        let neg_mask_share = (mask_share.clone() * (-F::one()))?;
        neg_mask_share + input
    }

    fn min_shares(t: usize) -> usize {
        t + 1
    }
    fn valid_output_sender(&self, party_index: usize, n: usize, t: usize) -> bool {
        if party_index >= n
            || self.feldmanshare.id != party_index + 1
            || self.feldmanshare.degree != t
            || self.commitments.len() != t + 1
        {
            return false;
        }
        let x = F::from(self.feldmanshare.id as u64);
        let expected = self
            .commitments
            .iter()
            .rev()
            .fold(G::zero(), |acc, c| acc * x + c);
        G::generator() * self.feldmanshare.share[0] == expected
    }

    fn recover_output(shares: &[Self], n: usize, t: usize) -> Result<Self::ValueType, Self::Error> {
        // At most t senders are faulty. A group of t+1 identical polynomial
        // commitments therefore contains an honest sender and binds the output.
        for candidate in shares {
            let matching: Vec<_> = shares
                .iter()
                .filter(|share| {
                    share.commitments == candidate.commitments
                        && share.feldmanshare.id > 0
                        && share.valid_output_sender(share.feldmanshare.id - 1, n, t)
                })
                .cloned()
                .collect();
            if matching.len() >= t + 1 {
                return Self::recover_secret(&matching, n, t).map(|(_, value)| value);
            }
        }
        Err(ShareError::InsufficientShares)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Round {
    Idle,
    Preprocessing,
    InputMaskReservation,
    InputCollection,
    MPCExecution,
    OutputDistribution,
    ProgramFinished,
}

/// The position of a round in the fixed protocol order. Rounds only ever advance, so this
/// lets a coordinator recognise a proposal for a round it has already passed.
pub fn round_index(round: Round) -> u8 {
    match round {
        Round::Idle => 0,
        Round::Preprocessing => 1,
        Round::InputMaskReservation => 2,
        Round::InputCollection => 3,
        Round::MPCExecution => 4,
        Round::OutputDistribution => 5,
        Round::ProgramFinished => 6,
    }
}

pub fn round_before(current: Round) -> Option<Round> {
    match current {
        Round::Idle => None,
        Round::Preprocessing => Some(Round::Idle),
        Round::InputMaskReservation => Some(Round::Preprocessing),
        Round::InputCollection => Some(Round::InputMaskReservation),
        Round::MPCExecution => Some(Round::InputCollection),
        Round::OutputDistribution => Some(Round::MPCExecution),
        Round::ProgramFinished => Some(Round::OutputDistribution),
    }
}

pub trait Coordinator<F: FftField, S: ShareBound<F>> {
    type ClientIdentity;

    fn start_preprocessing(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn reserve_input_masks(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn collect_inputs(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn start_mpc(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn send_output(&self) -> impl Future<Output = Result<(), CoordinatorError>>;
    fn finalize(&self) -> impl Future<Output = Result<(), CoordinatorError>>;

    fn wait_for_round(&self, round: Round) -> impl Future<Output = Result<(), CoordinatorError>>;

    fn reserve_mask_index(&mut self, i: u64) -> impl Future<Output = Result<(), CoordinatorError>>;

    /// Reserves several input-mask indices in one call. The default implementation just calls
    /// `reserve_mask_index` in a loop, so implementors get this for free; `off-chain` overrides
    /// it with a single round trip, since reserving indices one at a time is what makes clients
    /// with many inputs blow past the RPC timeout under load.
    fn reserve_mask_indices(
        &mut self,
        indices: &[u64],
    ) -> impl Future<Output = Result<(), CoordinatorError>> {
        async move {
            for &i in indices {
                self.reserve_mask_index(i).await?;
            }
            Ok(())
        }
    }

    fn send_masked_input(
        &self,
        masked_input: S::ValueType,
        i: u64,
    ) -> impl Future<Output = Result<(), CoordinatorError>>;

    /// Submits several masked inputs in one call. The default implementation just calls
    /// `send_masked_input` in a loop, so implementors get this for free; `off-chain` overrides
    /// it with a single round trip, for the same reason `reserve_mask_indices` overrides
    /// `reserve_mask_index`: submitting inputs one at a time is what makes clients with many
    /// inputs blow past the RPC timeout under load.
    fn send_masked_inputs(
        &self,
        inputs: &[(u64, S::ValueType)],
    ) -> impl Future<Output = Result<(), CoordinatorError>> {
        async move {
            for (i, masked_input) in inputs {
                self.send_masked_input(masked_input.clone(), *i).await?;
            }
            Ok(())
        }
    }

    fn wait_for_inputs(
        &self,
        n_inputs: u64,
        mask_shares: Vec<S>,
    ) -> impl Future<Output = Result<HashMap<Self::ClientIdentity, Vec<S>>, CoordinatorError>>;

    fn wait_for_indices(
        &self,
        n_inputs: u64,
    ) -> impl Future<Output = Result<HashMap<Self::ClientIdentity, Vec<u64>>, CoordinatorError>>;

    fn obtain_outputs(&self) -> impl Future<Output = Result<Vec<S::ValueType>, CoordinatorError>>;

    fn send_output_shares(
        &self,
        client_id: Self::ClientIdentity,
        key: Vec<u8>,
        output_shares: Vec<S>,
    ) -> impl Future<Output = Result<(), CoordinatorError>>;
}

#[derive(Error, Clone, Debug, Serialize, Deserialize)]
pub enum CoordinatorError {
    #[error("The index {0:?} is already reserved.")]
    IndexAlreadyReserved(usize),
    #[error("The masked input for index {0:?} has already been sent.")]
    MaskedInputAlreadySent(usize),
    #[error("Mask reconstruction from {0:?} shares failed.")]
    MaskReconstructionFailed(usize),
    #[error("Interaction with Ethereum blockchain failed: {0}")]
    EthereumError(String),
    #[error("U256 value out of range for Fr")]
    U256ToFrError,
    #[error("U256 value out of range for u64")]
    U256ToU64Error,
    #[error("U64 value out of range for usize")]
    U64ToUsizeError,
    #[error("Parsing DER-encoded key as PKCS#8 failed")]
    ParsingDERAsPKCS8Failed,
    #[error("Parsing private key failed")]
    ParsingPrivateKeyFailed,
    #[error("Deserialization failed")]
    DeserializationError,
    #[error("Serialization failed")]
    SerializationError,
    #[error("Parsing public key failed")]
    ParsingPublicKeyFailed,
    #[error("Encryption failed")]
    EncryptionError,
    #[error("Decryption failed")]
    DecryptionError,
    #[error("JSON error: {0}")]
    JSONError(String),
    #[error("Subscription error: {0}")]
    SubscriptionError(String),
    #[error("Parsing an encapsulated key failed")]
    ParsingEncapsulatedKeyFailed,
    #[error("Cannot transition to Idle round")]
    CannotTransitionToIdle,
    #[error("Calculating a share failed")]
    ShareError,
    #[error("Failed to bind to address {0}")]
    BindError(String),
    #[error("Failed to connect: {0}")]
    ConnectError(String),
    #[error("TLS configuration error: {0}")]
    TlsConfigError(String),
}

#[derive(Error, Clone, Debug)]
pub enum NodeRPCError {
    #[error("Execution is not registered or is ambiguous")]
    ExecutionNotFound,
    #[error("Index already added")]
    IndexAlreadyAdded,
    #[error("Index not added")]
    IndexNotAdded,
    #[error("JSON error")]
    JSONError,
    #[error("Serialization error")]
    SerializationError,
    #[error("Ethereum error: {0}")]
    EthereumError(String),
    #[error("Authentication failed for client with TLS identity {0:?}")]
    AuthenticationFailed(Vec<u8>),
}

static INIT: Once = Once::new();

pub fn setup_test() {
    INIT.call_once(|| {
        // Installing a crypto provider is process-global. Another dependency may
        // have installed one before this helper runs, which is already a valid
        // test setup and must not poison the initializer.
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}

#[cfg(test)]
mod output_validation_tests {
    use super::*;
    use ark_bls12_381::{Fr, G1Projective};

    #[test]
    fn feldman_output_ignores_invalid_values_and_minority_polynomials() {
        type Share = FeldmanShamirShare<Fr, G1Projective>;
        let ids = [1, 2, 3, 4, 5];
        let mut rng = ark_std::test_rng();
        let mut shares = Share::compute_shares(Fr::from(7u64), 5, 1, Some(&ids), &mut rng).unwrap();
        shares[0].feldmanshare.share[0] += Fr::from(1u64);
        assert!(!shares[0].valid_output_sender(0, 5, 1));
        assert_eq!(
            Share::recover_output(&shares, 5, 1).unwrap(),
            Fr::from(7u64)
        );
        shares[0] = Share::compute_shares(Fr::from(99u64), 5, 1, Some(&ids), &mut rng)
            .unwrap()
            .remove(0);
        assert!(shares[0].valid_output_sender(0, 5, 1));
        assert_eq!(
            Share::recover_output(&shares, 5, 1).unwrap(),
            Fr::from(7u64)
        );
    }
}
