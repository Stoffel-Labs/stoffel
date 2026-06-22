//! On-chain coordinator SDK boundary.
//!
//! Provider-backed coordination is re-exported from `stoffel-mpc-coordinator`.
//! `OnChainCoordinatorHandle` represents the no-provider address-only case and
//! returns explicit unsupported errors for networked operations.

use std::pin::Pin;
use std::str::FromStr;
use std::task::{Context, Poll};

use alloy::{
    network::EthereumWallet,
    providers::{Provider, ProviderBuilder, WalletProvider, WsConnect},
    signers::local::PrivateKeySigner,
};
use ark_bls12_381::{Fr, G1Projective};
use serde::{Deserialize, Serialize};
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;

use crate::config::{Curve, MpcBackend};
use crate::error::{Error, Result};
use crate::types::{ClientId, FieldElement, MaskIndex, Round, Value};

pub use stoffel_mpc_coordinator_on_chain::{
    node_rpc, setup_coord, ws_connect, ClientIdentity as OnChainClientIdentity, OnChainCoordinator,
};

pub type HoneyBadgerOnChainCoordinator<P> = OnChainCoordinator<P, Fr, RobustShare<Fr>>;
pub type BlsOnChainAvssCoordinator<P> =
    OnChainCoordinator<P, Fr, FeldmanShamirShare<Fr, G1Projective>>;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CoordinatorEvent {
    RoundStarted(Round),
    OutputReady(ClientId),
}

/// Event stream returned by a no-provider [`OnChainCoordinatorHandle`].
///
/// Provider-backed event subscriptions are owned by `stoffel-mpc-coordinator`.
/// This SDK stream is intentionally empty so applications can type-check event
/// wiring without the SDK inventing blockchain behavior.
#[derive(Debug, Clone, Default)]
pub struct CoordinatorEventStream;

impl futures_core::Stream for CoordinatorEventStream {
    type Item = CoordinatorEvent;

    fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        Poll::Ready(None)
    }
}

/// Lightweight SDK handle for applications that only have a contract address.
///
/// Provider-backed on-chain coordination is exposed as the re-exported
/// [`OnChainCoordinator`] from `stoffel-mpc-coordinator`. This handle keeps the
/// no-provider case explicit and returns `Unsupported` for networked operations.
#[derive(Debug, Clone)]
pub struct OnChainCoordinatorHandle {
    contract_address: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnChainCoordinatorSummary {
    pub contract_address: String,
    pub provider_configured: bool,
    pub contract_address_well_formed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnChainCoordinatorConfig {
    pub contract_address: String,
    pub websocket_endpoint: String,
    pub wallet_private_key: String,
    pub parties: u64,
    pub threshold: u64,
    pub output_count: u64,
    pub backend: MpcBackend,
    pub output_key_der: Option<Vec<u8>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OnChainCoordinatorConfigSummary {
    pub contract_address: String,
    pub websocket_endpoint: String,
    pub parties: u64,
    pub threshold: u64,
    pub output_count: u64,
    pub backend: MpcBackend,
    pub output_key_configured: bool,
}

#[derive(Debug, Clone)]
pub struct OnChainCoordinatorConfigBuilder {
    contract_address: Option<String>,
    websocket_endpoint: Option<String>,
    wallet_private_key: Option<String>,
    parties: u64,
    threshold: u64,
    output_count: u64,
    backend: MpcBackend,
    output_key_der: Option<Vec<u8>>,
}

impl OnChainCoordinatorHandle {
    pub fn new(contract_address: impl Into<String>) -> Self {
        Self {
            contract_address: contract_address.into(),
        }
    }

    pub fn try_new(contract_address: impl Into<String>) -> Result<Self> {
        let handle = Self::new(contract_address);
        handle.validate_contract_address()?;
        Ok(handle)
    }

    pub fn contract_address(&self) -> &str {
        &self.contract_address
    }

    pub fn is_provider_configured(&self) -> bool {
        false
    }

    pub fn is_contract_address_well_formed(&self) -> bool {
        is_evm_address(&self.contract_address)
    }

    pub fn validate_contract_address(&self) -> Result<()> {
        if self.is_contract_address_well_formed() {
            return Ok(());
        }
        Err(Error::Configuration(format!(
            "contract address '{}' must be a 0x-prefixed 20-byte hex address",
            self.contract_address
        )))
    }

    pub fn summary(&self) -> OnChainCoordinatorSummary {
        OnChainCoordinatorSummary {
            contract_address: self.contract_address.clone(),
            provider_configured: self.is_provider_configured(),
            contract_address_well_formed: self.is_contract_address_well_formed(),
        }
    }

    #[tracing::instrument(skip_all, fields(contract = %self.contract_address))]
    pub async fn current_round(&self) -> Result<Round> {
        Err(Error::Unsupported(
            "on-chain coordination requires a provider-backed stoffel-mpc-coordinator instance"
                .to_owned(),
        ))
    }

    #[tracing::instrument(skip_all, fields(contract = %self.contract_address, round = ?_round))]
    pub async fn await_round(&self, _round: Round) -> Result<()> {
        Err(Error::Unsupported(
            "on-chain coordination requires a provider-backed stoffel-mpc-coordinator instance"
                .to_owned(),
        ))
    }

    #[tracing::instrument(skip_all, fields(contract = %self.contract_address, client_id = _client_id))]
    pub async fn reserve_input_mask(&self, _client_id: ClientId) -> Result<MaskIndex> {
        Err(Error::Unsupported(
            "on-chain coordination requires a provider-backed stoffel-mpc-coordinator instance"
                .to_owned(),
        ))
    }

    #[tracing::instrument(skip_all, fields(contract = %self.contract_address, mask_index = _index))]
    pub async fn submit_masked_input(
        &self,
        _index: MaskIndex,
        _masked_value: FieldElement,
    ) -> Result<()> {
        Err(Error::Unsupported(
            "on-chain coordination requires a provider-backed stoffel-mpc-coordinator instance"
                .to_owned(),
        ))
    }

    #[tracing::instrument(skip_all, fields(contract = %self.contract_address, client_id = _client_id))]
    pub async fn await_output(&self, _client_id: ClientId) -> Result<Vec<Value>> {
        Err(Error::Unsupported(
            "on-chain coordination requires a provider-backed stoffel-mpc-coordinator instance"
                .to_owned(),
        ))
    }

    pub fn subscribe_events(&self) -> CoordinatorEventStream {
        CoordinatorEventStream
    }
}

impl OnChainCoordinatorConfig {
    pub fn builder() -> OnChainCoordinatorConfigBuilder {
        OnChainCoordinatorConfigBuilder::default()
    }

    pub fn validate(&self) -> Result<()> {
        validate_contract_address(&self.contract_address)?;
        validate_ws_endpoint(&self.websocket_endpoint)?;
        validate_private_key(&self.wallet_private_key)?;
        if self.threshold == 0 {
            return Err(Error::Configuration(
                "on-chain coordinator threshold must be greater than zero".to_owned(),
            ));
        }
        match self.backend {
            MpcBackend::HoneyBadger => {}
            MpcBackend::Avss {
                curve: Curve::Bls12_381,
            } => {}
            MpcBackend::Avss { curve } => {
                return Err(Error::Unsupported(format!(
                    "on-chain AVSS coordinator connections currently support bls12-381, got {curve}"
                )));
            }
        }
        Ok(())
    }

    pub fn summary(&self) -> OnChainCoordinatorConfigSummary {
        OnChainCoordinatorConfigSummary {
            contract_address: self.contract_address.clone(),
            websocket_endpoint: self.websocket_endpoint.clone(),
            parties: self.parties,
            threshold: self.threshold,
            output_count: self.output_count,
            backend: self.backend,
            output_key_configured: self.output_key_der.is_some(),
        }
    }

    pub async fn connect_honeybadger(
        &self,
    ) -> Result<HoneyBadgerOnChainCoordinator<impl Provider + WalletProvider + Clone + 'static>>
    {
        self.validate()?;
        if self.backend != MpcBackend::HoneyBadger {
            return Err(Error::Configuration(format!(
                "connect_honeybadger requires honeybadger backend, got {}",
                self.backend
            )));
        }
        let provider = connect_provider(&self.websocket_endpoint, &self.wallet_private_key).await?;
        let contract_address = parse_contract_address(&self.contract_address)?;
        Ok(setup_coord::<_, Fr, RobustShare<Fr>>(
            provider,
            contract_address,
            self.parties,
            self.threshold,
            self.output_count,
            self.output_key_der.clone(),
        )
        .await)
    }

    pub async fn connect_avss_bls12_381(
        &self,
    ) -> Result<BlsOnChainAvssCoordinator<impl Provider + WalletProvider + Clone + 'static>> {
        self.validate()?;
        if self.backend
            != (MpcBackend::Avss {
                curve: Curve::Bls12_381,
            })
        {
            return Err(Error::Configuration(format!(
                "connect_avss_bls12_381 requires avss/bls12-381 backend, got {}",
                self.backend
            )));
        }
        let provider = connect_provider(&self.websocket_endpoint, &self.wallet_private_key).await?;
        let contract_address = parse_contract_address(&self.contract_address)?;
        Ok(setup_coord::<_, Fr, FeldmanShamirShare<Fr, G1Projective>>(
            provider,
            contract_address,
            self.parties,
            self.threshold,
            self.output_count,
            self.output_key_der.clone(),
        )
        .await)
    }
}

impl Default for OnChainCoordinatorConfigBuilder {
    fn default() -> Self {
        Self {
            contract_address: None,
            websocket_endpoint: None,
            wallet_private_key: None,
            parties: 1,
            threshold: 1,
            output_count: 0,
            backend: MpcBackend::HoneyBadger,
            output_key_der: None,
        }
    }
}

impl OnChainCoordinatorConfigBuilder {
    pub fn contract_address(mut self, address: impl Into<String>) -> Self {
        self.contract_address = Some(address.into());
        self
    }

    pub fn websocket_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.websocket_endpoint = Some(endpoint.into());
        self
    }

    pub fn wallet_private_key(mut self, private_key: impl Into<String>) -> Self {
        self.wallet_private_key = Some(private_key.into());
        self
    }

    pub fn parties(mut self, parties: u64) -> Self {
        self.parties = parties;
        self
    }

    pub fn threshold(mut self, threshold: u64) -> Self {
        self.threshold = threshold;
        self
    }

    pub fn output_count(mut self, output_count: u64) -> Self {
        self.output_count = output_count;
        self
    }

    pub fn backend(mut self, backend: MpcBackend) -> Self {
        self.backend = backend;
        self
    }

    pub fn honeybadger(self) -> Self {
        self.backend(MpcBackend::HoneyBadger)
    }

    pub fn avss_bls12_381(self) -> Self {
        self.backend(MpcBackend::Avss {
            curve: Curve::Bls12_381,
        })
    }

    pub fn output_key_der(mut self, key_der: impl Into<Vec<u8>>) -> Self {
        self.output_key_der = Some(key_der.into());
        self
    }

    pub fn build(self) -> Result<OnChainCoordinatorConfig> {
        let config = OnChainCoordinatorConfig {
            contract_address: self.contract_address.ok_or_else(|| {
                Error::Configuration("on-chain contract address is required".to_owned())
            })?,
            websocket_endpoint: self.websocket_endpoint.ok_or_else(|| {
                Error::Configuration("on-chain websocket endpoint is required".to_owned())
            })?,
            wallet_private_key: self.wallet_private_key.ok_or_else(|| {
                Error::Configuration("on-chain wallet private key is required".to_owned())
            })?,
            parties: self.parties,
            threshold: self.threshold,
            output_count: self.output_count,
            backend: self.backend,
            output_key_der: self.output_key_der,
        };
        config.validate()?;
        Ok(config)
    }
}

fn is_evm_address(address: &str) -> bool {
    let Some(hex) = address.strip_prefix("0x") else {
        return false;
    };
    hex.len() == 40 && hex.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn validate_contract_address(address: &str) -> Result<()> {
    if is_evm_address(address) {
        return Ok(());
    }
    Err(Error::Configuration(format!(
        "contract address '{address}' must be a 0x-prefixed 20-byte hex address"
    )))
}

fn validate_ws_endpoint(endpoint: &str) -> Result<()> {
    let endpoint = endpoint.trim();
    if endpoint.starts_with("ws://") || endpoint.starts_with("wss://") {
        return Ok(());
    }
    Err(Error::Configuration(
        "on-chain websocket endpoint must start with ws:// or wss://".to_owned(),
    ))
}

fn validate_private_key(private_key: &str) -> Result<()> {
    let hex = private_key
        .strip_prefix("0x")
        .or_else(|| private_key.strip_prefix("0X"))
        .unwrap_or(private_key);
    if hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Ok(());
    }
    Err(Error::Configuration(
        "on-chain wallet private key must be a 32-byte hex string".to_owned(),
    ))
}

fn parse_contract_address(address: &str) -> Result<OnChainClientIdentity> {
    OnChainClientIdentity::from_str(address).map_err(|error| {
        Error::Configuration(format!("invalid on-chain contract address: {error}"))
    })
}

async fn connect_provider(
    endpoint: &str,
    wallet_private_key: &str,
) -> Result<impl Provider + WalletProvider + Clone + 'static> {
    let signer = PrivateKeySigner::from_str(wallet_private_key).map_err(|error| {
        Error::Configuration(format!("invalid on-chain wallet private key: {error}"))
    })?;
    let wallet = EthereumWallet::from(signer);
    ProviderBuilder::new()
        .wallet(wallet)
        .connect_ws(WsConnect::new(endpoint))
        .await
        .map_err(|error| {
            Error::NetworkConnection(format!(
                "could not connect to Ethereum node at {endpoint}: {error}"
            ))
        })
}
