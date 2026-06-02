//! MPC and network configuration types.
//!
//! Builders in this module perform fail-fast validation for party counts,
//! thresholds, backend selection, network addresses, and preprocessing sizes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::Duration;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::error::{Error, Result};
use crate::types::GeneratedProgramManifest;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Curve {
    Bls12_381,
    Bn254,
    Curve25519,
    Ed25519,
    Secp256k1,
    Secp256r1,
}

impl fmt::Display for Curve {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Curve::Bls12_381 => "bls12_381",
            Curve::Bn254 => "bn254",
            Curve::Curve25519 => "curve25519",
            Curve::Ed25519 => "ed25519",
            Curve::Secp256k1 => "secp256k1",
            Curve::Secp256r1 => "p-256",
        })
    }
}

impl FromStr for Curve {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        match normalize_identifier(value).as_str() {
            "bls12381" => Ok(Curve::Bls12_381),
            "bn254" => Ok(Curve::Bn254),
            "curve25519" => Ok(Curve::Curve25519),
            "ed25519" => Ok(Curve::Ed25519),
            "secp256k1" => Ok(Curve::Secp256k1),
            "p256" | "nistp256" | "secp256r1" => Ok(Curve::Secp256r1),
            curve => Err(Error::Configuration(format!(
                "unsupported curve '{curve}'; expected one of bls12_381, bn254, curve25519, ed25519, secp256k1, p-256"
            ))),
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum MpcBackend {
    #[default]
    HoneyBadger,
    Avss {
        curve: Curve,
    },
}

impl Serialize for MpcBackend {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_string())
    }
}

impl<'de> Deserialize<'de> for MpcBackend {
    fn deserialize<D>(deserializer: D) -> std::result::Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(serde::de::Error::custom)
    }
}

impl MpcBackend {
    pub(crate) fn compiler_backend(self) -> stoffel_vm_types::compiled_binary::MpcBackend {
        match self {
            MpcBackend::HoneyBadger => stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            MpcBackend::Avss { .. } => stoffel_vm_types::compiled_binary::MpcBackend::Avss,
        }
    }

    pub(crate) fn compiler_curve(self) -> stoffel_vm_types::compiled_binary::MpcCurve {
        match self {
            MpcBackend::HoneyBadger
            | MpcBackend::Avss {
                curve: Curve::Bls12_381,
            } => stoffel_vm_types::compiled_binary::MpcCurve::Bls12_381,
            MpcBackend::Avss {
                curve: Curve::Bn254,
            } => stoffel_vm_types::compiled_binary::MpcCurve::Bn254,
            MpcBackend::Avss {
                curve: Curve::Curve25519,
            } => stoffel_vm_types::compiled_binary::MpcCurve::Curve25519,
            MpcBackend::Avss {
                curve: Curve::Ed25519,
            } => stoffel_vm_types::compiled_binary::MpcCurve::Ed25519,
            MpcBackend::Avss {
                curve: Curve::Secp256k1,
            } => stoffel_vm_types::compiled_binary::MpcCurve::Secp256k1,
            MpcBackend::Avss {
                curve: Curve::Secp256r1,
            } => stoffel_vm_types::compiled_binary::MpcCurve::Secp256r1,
        }
    }

    pub fn is_honeybadger(self) -> bool {
        matches!(self, MpcBackend::HoneyBadger)
    }

    pub fn is_avss(self) -> bool {
        matches!(self, MpcBackend::Avss { .. })
    }

    pub fn curve(self) -> Option<Curve> {
        match self {
            MpcBackend::HoneyBadger => None,
            MpcBackend::Avss { curve } => Some(curve),
        }
    }

    pub fn minimum_reconstruction_shares(self, threshold: usize) -> Result<usize> {
        match self {
            MpcBackend::HoneyBadger => checked_threshold_expression(
                threshold,
                2,
                1,
                "HoneyBadger reconstruction threshold",
            ),
            MpcBackend::Avss { .. } => {
                checked_threshold_expression(threshold, 1, 1, "AVSS reconstruction threshold")
            }
        }
    }
}

impl fmt::Display for MpcBackend {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            MpcBackend::HoneyBadger => f.write_str("honeybadger"),
            MpcBackend::Avss { curve } => write!(f, "avss:{curve}"),
        }
    }
}

impl FromStr for MpcBackend {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self> {
        let (protocol, curve) = value
            .trim()
            .split_once(':')
            .map_or((value.trim(), None), |(protocol, curve)| {
                (protocol.trim(), Some(curve.trim()))
            });

        match normalize_identifier(protocol).as_str() {
            "honeybadger" if curve.is_none() => Ok(MpcBackend::HoneyBadger),
            "honeybadger" => Err(Error::Configuration(
                "HoneyBadger does not take a curve; use 'honeybadger'".to_owned(),
            )),
            "avss" => Ok(MpcBackend::Avss {
                curve: curve
                    .map(Curve::from_str)
                    .transpose()?
                    .unwrap_or(Curve::Bls12_381),
            }),
            protocol => Err(Error::Configuration(format!(
                "unsupported MPC protocol '{protocol}'; expected 'honeybadger' or 'avss'"
            ))),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcConfig {
    pub parties: usize,
    pub threshold: usize,
    pub instance_id: u64,
    pub backend: MpcBackend,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcConfigSummary {
    pub parties: usize,
    pub threshold: usize,
    pub instance_id: u64,
    pub backend: MpcBackend,
    pub minimum_parties: usize,
    pub maximum_threshold: usize,
    pub minimum_reconstruction_shares: usize,
}

impl Default for MpcConfig {
    fn default() -> Self {
        Self {
            parties: 5,
            threshold: 1,
            instance_id: default_instance_id(),
            backend: MpcBackend::default(),
        }
    }
}

impl MpcConfig {
    pub fn builder() -> MpcConfigBuilder {
        MpcConfigBuilder::default()
    }

    pub fn minimum_parties_for_threshold(threshold: usize) -> Result<usize> {
        byzantine_minimum_parties(threshold)
    }

    pub fn maximum_threshold_for_parties(parties: usize) -> Result<usize> {
        if parties < 5 {
            return Err(Error::Configuration(
                "parties must be at least 5 for 4 * threshold + 1 Byzantine MPC".to_owned(),
            ));
        }
        Ok((parties - 1) / 4)
    }

    pub fn validate(&self) -> Result<()> {
        if self.parties < 5 {
            return Err(Error::Configuration(
                "parties must be at least 5 for 4 * threshold + 1 Byzantine MPC".to_owned(),
            ));
        }
        let minimum_parties = byzantine_minimum_parties(self.threshold)?;
        if self.parties < minimum_parties {
            return Err(Error::Configuration(format!(
                "invalid Byzantine threshold: parties ({}) must be >= 4 * threshold ({}) + 1",
                self.parties, self.threshold
            )));
        }
        Ok(())
    }

    pub fn minimum_parties(&self) -> Result<usize> {
        Self::minimum_parties_for_threshold(self.threshold)
    }

    pub fn maximum_threshold(&self) -> Result<usize> {
        Self::maximum_threshold_for_parties(self.parties)
    }

    pub fn minimum_reconstruction_shares(&self) -> Result<usize> {
        self.backend.minimum_reconstruction_shares(self.threshold)
    }

    pub fn summary(&self) -> Result<MpcConfigSummary> {
        self.validate()?;
        Ok(MpcConfigSummary {
            parties: self.parties,
            threshold: self.threshold,
            instance_id: self.instance_id,
            backend: self.backend,
            minimum_parties: self.minimum_parties()?,
            maximum_threshold: self.maximum_threshold()?,
            minimum_reconstruction_shares: self.minimum_reconstruction_shares()?,
        })
    }

    pub fn to_vm_topology(
        &self,
        party_id: usize,
    ) -> Result<stoffel_vm::net::mpc_engine::MpcSessionTopology> {
        self.validate()?;
        stoffel_vm::net::mpc_engine::MpcSessionTopology::try_new(
            self.instance_id,
            party_id,
            self.parties,
            self.threshold,
        )
        .map_err(|error| Error::Configuration(error.to_string()))
    }
}

#[derive(Debug, Clone, Default)]
pub struct MpcConfigBuilder {
    config: MpcConfig,
}

impl MpcConfigBuilder {
    pub fn parties(mut self, parties: usize) -> Self {
        self.config.parties = parties;
        self
    }

    pub fn threshold(mut self, threshold: usize) -> Self {
        self.config.threshold = threshold;
        self
    }

    pub fn instance_id(mut self, instance_id: u64) -> Self {
        self.config.instance_id = instance_id;
        self
    }

    pub fn backend(mut self, backend: MpcBackend) -> Self {
        self.config.backend = backend;
        self
    }

    pub fn manifest<M: GeneratedProgramManifest>(self) -> Self {
        self.backend(M::BACKEND)
    }

    pub fn honeybadger(mut self) -> Self {
        self.config.backend = MpcBackend::HoneyBadger;
        self
    }

    pub fn avss(mut self, curve: Curve) -> Self {
        self.config.backend = MpcBackend::Avss { curve };
        self
    }

    pub fn curve(mut self, curve: Curve) -> Self {
        self.config.backend = MpcBackend::Avss { curve };
        self
    }

    pub fn build(self) -> Result<MpcConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

fn default_instance_id() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfig {
    #[serde(default)]
    pub network: NetworkSection,
    #[serde(default)]
    pub mpc: MpcSection,
    #[serde(default)]
    pub preprocessing: PreprocessingConfig,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkConfigSummary {
    pub party_id: usize,
    pub bind_address: String,
    pub expected_parties: usize,
    pub expected_clients: usize,
    pub peer_count: usize,
    pub consensus_timeout_ms: u64,
    pub threshold: usize,
    pub backend: MpcBackend,
    pub minimum_reconstruction_shares: usize,
    pub preprocessing_triples: usize,
    pub preprocessing_random_shares: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkDeployment {
    configs: Vec<NetworkConfig>,
}

#[derive(Debug, Clone)]
pub struct NetworkDeploymentBuilder {
    addresses: Vec<String>,
    expected_clients: usize,
    consensus_timeout_ms: u64,
    threshold: usize,
    backend: MpcBackend,
    preprocessing: PreprocessingConfig,
}

impl NetworkConfig {
    pub fn builder() -> NetworkConfigBuilder {
        NetworkConfigBuilder::default()
    }

    pub fn from_toml_str(toml: &str) -> Result<Self> {
        let config: Self = toml::from_str(toml)?;
        config.validate()?;
        Ok(config)
    }

    pub fn from_toml_file(path: impl AsRef<Path>) -> Result<Self> {
        let toml = std::fs::read_to_string(path)?;
        Self::from_toml_str(&toml)
    }

    pub fn to_toml_string(&self) -> Result<String> {
        self.validate()?;
        Ok(toml::to_string_pretty(self)?)
    }

    pub fn save_toml_file(&self, path: impl AsRef<Path>) -> Result<()> {
        std::fs::write(path, self.to_toml_string()?)?;
        Ok(())
    }

    pub fn validate(&self) -> Result<()> {
        if self.network.expected_parties < 5 {
            return Err(Error::Configuration(
                "expected_parties must be at least 5 for 4 * threshold + 1 Byzantine MPC"
                    .to_owned(),
            ));
        }
        let minimum_parties = byzantine_minimum_parties(self.mpc.threshold)?;
        if self.network.expected_parties < minimum_parties {
            return Err(Error::Configuration(format!(
                "invalid Byzantine threshold: expected_parties ({}) must be >= 4 * threshold ({}) + 1",
                self.network.expected_parties, self.mpc.threshold
            )));
        }
        if self.network.party_id >= self.network.expected_parties {
            return Err(Error::Configuration(format!(
                "party_id {} must be less than expected_parties {}",
                self.network.party_id, self.network.expected_parties
            )));
        }
        if self.network.bind_address.trim().is_empty() {
            return Err(Error::Configuration(
                "bind_address must not be empty".to_owned(),
            ));
        }
        validate_socket_address("bind_address", &self.network.bind_address)?;
        for (party_id, address) in &self.network.peers {
            if *party_id >= self.network.expected_parties {
                return Err(Error::Configuration(format!(
                    "peer party_id {party_id} must be less than expected_parties {}",
                    self.network.expected_parties
                )));
            }
            if *party_id == self.network.party_id {
                return Err(Error::Configuration(format!(
                    "peer party_id {party_id} must not match this node's party_id"
                )));
            }
            if address.trim().is_empty() {
                return Err(Error::Configuration(format!(
                    "peer address for party_id {party_id} must not be empty"
                )));
            }
            validate_socket_address(&format!("peer address for party_id {party_id}"), address)?;
        }
        if self.network.consensus_timeout_ms == 0 {
            return Err(Error::Configuration(
                "consensus_timeout_ms must be greater than 0".to_owned(),
            ));
        }
        self.preprocessing.validate()?;
        self.mpc_backend()?;
        Ok(())
    }

    pub fn mpc_backend(&self) -> Result<MpcBackend> {
        self.mpc.protocol.parse()
    }

    pub fn minimum_reconstruction_shares(&self) -> Result<usize> {
        self.mpc_backend()?
            .minimum_reconstruction_shares(self.mpc.threshold)
    }

    pub fn summary(&self) -> Result<NetworkConfigSummary> {
        self.validate()?;
        Ok(NetworkConfigSummary {
            party_id: self.network.party_id,
            bind_address: self.network.bind_address.clone(),
            expected_parties: self.network.expected_parties,
            expected_clients: self.network.expected_clients,
            peer_count: self.network.peers.len(),
            consensus_timeout_ms: self.network.consensus_timeout_ms,
            threshold: self.mpc.threshold,
            backend: self.mpc_backend()?,
            minimum_reconstruction_shares: self.minimum_reconstruction_shares()?,
            preprocessing_triples: self.preprocessing.triples,
            preprocessing_random_shares: self.preprocessing.random_shares,
        })
    }

    pub fn to_mpc_config(&self, instance_id: u64) -> Result<MpcConfig> {
        self.validate()?;
        let config = MpcConfig {
            parties: self.network.expected_parties,
            threshold: self.mpc.threshold,
            instance_id,
            backend: self.mpc_backend()?,
        };
        config.validate()?;
        Ok(config)
    }

    pub fn consensus_timeout(&self) -> Duration {
        Duration::from_millis(self.network.consensus_timeout_ms)
    }

    pub fn validate_server_addresses(&self) -> Result<()> {
        self.validate()?;
        let mut addresses = self.network.peers.clone();
        addresses.insert(self.network.party_id, self.network.bind_address.clone());
        for party_id in 0..self.network.expected_parties {
            if !addresses.contains_key(&party_id) {
                return Err(Error::Configuration(format!(
                    "missing server address for party_id {party_id}"
                )));
            }
        }
        Ok(())
    }

    pub fn server_addresses(&self) -> Result<Vec<String>> {
        Ok(self.server_address_map()?.into_values().collect())
    }

    pub fn server_address_map(&self) -> Result<BTreeMap<usize, String>> {
        self.validate_server_addresses()?;
        let mut addresses = self.network.peers.clone();
        addresses.insert(self.network.party_id, self.network.bind_address.clone());
        Ok(addresses)
    }

    pub fn server_address(&self, party_id: usize) -> Result<Option<String>> {
        self.validate()?;
        if party_id >= self.network.expected_parties {
            return Err(Error::Configuration(format!(
                "party_id {party_id} must be less than expected_parties {}",
                self.network.expected_parties
            )));
        }
        if party_id == self.network.party_id {
            return Ok(Some(self.network.bind_address.clone()));
        }
        Ok(self.network.peers.get(&party_id).cloned())
    }

    pub fn bind_address(&self) -> &str {
        &self.network.bind_address
    }

    pub fn party_id(&self) -> usize {
        self.network.party_id
    }

    pub fn expected_parties(&self) -> usize {
        self.network.expected_parties
    }

    pub fn expected_clients(&self) -> usize {
        self.network.expected_clients
    }

    pub fn peer_addresses(&self) -> &BTreeMap<usize, String> {
        &self.network.peers
    }

    pub fn preprocessing(&self) -> &PreprocessingConfig {
        &self.preprocessing
    }

    pub fn threshold(&self) -> usize {
        self.mpc.threshold
    }

    pub fn protocol(&self) -> &str {
        &self.mpc.protocol
    }

    pub fn consensus_timeout_ms(&self) -> u64 {
        self.network.consensus_timeout_ms
    }

    pub fn to_quic_config(&self) -> Result<stoffelnet::transports::quic::QuicNetworkConfig> {
        self.validate()?;
        let config = stoffelnet::transports::quic::QuicNetworkConfig {
            expected_parties: Some(self.network.expected_parties),
            expected_clients: Some(self.network.expected_clients),
            consensus_timeout_ms: self.network.consensus_timeout_ms,
            ..Default::default()
        };
        config
            .validate()
            .map_err(|error| Error::Configuration(error.to_string()))?;
        Ok(config)
    }

    pub fn to_quic_manager(&self) -> Result<stoffelnet::transports::quic::QuicNetworkManager> {
        let config = self.to_quic_config()?;
        stoffelnet::transports::quic::QuicNetworkManager::try_with_config(config)
            .map_err(|error| Error::Configuration(error.to_string()))
    }
}

impl NetworkDeployment {
    pub fn builder<I, S>(addresses: I) -> NetworkDeploymentBuilder
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        NetworkDeploymentBuilder::new(addresses)
    }

    pub fn len(&self) -> usize {
        self.configs.len()
    }

    pub fn is_empty(&self) -> bool {
        self.configs.is_empty()
    }

    pub fn configs(&self) -> &[NetworkConfig] {
        &self.configs
    }

    pub fn into_configs(self) -> Vec<NetworkConfig> {
        self.configs
    }

    pub fn config(&self, party_id: usize) -> Option<&NetworkConfig> {
        self.configs.get(party_id)
    }

    pub fn server_addresses(&self) -> Vec<String> {
        self.configs
            .iter()
            .map(|config| config.network.bind_address.clone())
            .collect()
    }

    pub fn summaries(&self) -> Result<Vec<NetworkConfigSummary>> {
        self.configs.iter().map(NetworkConfig::summary).collect()
    }

    pub fn to_toml_strings(&self) -> Result<Vec<String>> {
        self.configs
            .iter()
            .map(NetworkConfig::to_toml_string)
            .collect()
    }

    pub fn save_toml_files(&self, directory: impl AsRef<Path>) -> Result<Vec<PathBuf>> {
        self.save_toml_files_with_prefix(directory, "party")
    }

    pub fn save_toml_files_with_prefix(
        &self,
        directory: impl AsRef<Path>,
        prefix: &str,
    ) -> Result<Vec<PathBuf>> {
        let directory = directory.as_ref();
        std::fs::create_dir_all(directory)?;
        let prefix = prefix.trim();
        if prefix.is_empty() {
            return Err(Error::Configuration(
                "deployment config file prefix must not be empty".to_owned(),
            ));
        }

        self.configs
            .iter()
            .map(|config| {
                let path = directory.join(format!("{prefix}-{}.toml", config.network.party_id));
                config.save_toml_file(&path)?;
                Ok(path)
            })
            .collect()
    }
}

impl NetworkDeploymentBuilder {
    pub fn new<I, S>(addresses: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        Self {
            addresses: addresses.into_iter().map(Into::into).collect(),
            expected_clients: 0,
            consensus_timeout_ms: 60_000,
            threshold: 1,
            backend: MpcBackend::HoneyBadger,
            preprocessing: PreprocessingConfig::default(),
        }
    }

    pub fn expected_clients(mut self, expected_clients: usize) -> Self {
        self.expected_clients = expected_clients;
        self
    }

    pub fn consensus_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.consensus_timeout_ms = timeout_ms;
        self
    }

    pub fn consensus_timeout(mut self, timeout: Duration) -> Self {
        self.consensus_timeout_ms = duration_to_millis(timeout);
        self
    }

    pub fn threshold(mut self, threshold: usize) -> Self {
        self.threshold = threshold;
        self
    }

    pub fn backend(mut self, backend: MpcBackend) -> Self {
        self.backend = backend;
        self
    }

    pub fn manifest<M: GeneratedProgramManifest>(self) -> Self {
        self.backend(M::BACKEND)
    }

    pub fn honeybadger(mut self) -> Self {
        self.backend = MpcBackend::HoneyBadger;
        self
    }

    pub fn avss(mut self, curve: Curve) -> Self {
        self.backend = MpcBackend::Avss { curve };
        self
    }

    pub fn preprocessing(mut self, triples: usize, random_shares: usize) -> Self {
        self.preprocessing = PreprocessingConfig {
            triples,
            random_shares,
        };
        self
    }

    pub fn build(self) -> Result<NetworkDeployment> {
        if self.addresses.len() < 5 {
            return Err(Error::Configuration(
                "network deployment requires at least 5 party addresses".to_owned(),
            ));
        }
        let mut seen = BTreeSet::new();
        for (party_id, address) in self.addresses.iter().enumerate() {
            if address.trim().is_empty() {
                return Err(Error::Configuration(format!(
                    "deployment address for party_id {party_id} must not be empty"
                )));
            }
            validate_socket_address(
                &format!("deployment address for party_id {party_id}"),
                address,
            )?;
            if !seen.insert(address.as_str()) {
                return Err(Error::Configuration(format!(
                    "duplicate deployment address '{address}'"
                )));
            }
        }

        let expected_parties = self.addresses.len();
        let configs = self
            .addresses
            .iter()
            .enumerate()
            .map(|(party_id, bind_address)| {
                let peers = self
                    .addresses
                    .iter()
                    .enumerate()
                    .filter(|(peer_id, _)| *peer_id != party_id)
                    .map(|(peer_id, address)| (peer_id, address.clone()))
                    .collect();
                let config = NetworkConfig {
                    network: NetworkSection {
                        party_id,
                        bind_address: bind_address.clone(),
                        expected_parties,
                        expected_clients: self.expected_clients,
                        consensus_timeout_ms: self.consensus_timeout_ms,
                        peers,
                    },
                    mpc: MpcSection {
                        threshold: self.threshold,
                        protocol: self.backend.to_string(),
                    },
                    preprocessing: self.preprocessing.clone(),
                };
                config.validate()?;
                Ok(config)
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(NetworkDeployment { configs })
    }
}

impl TryFrom<&NetworkConfig> for stoffelnet::transports::quic::QuicNetworkConfig {
    type Error = Error;

    fn try_from(config: &NetworkConfig) -> Result<Self> {
        config.to_quic_config()
    }
}

impl TryFrom<NetworkConfig> for stoffelnet::transports::quic::QuicNetworkConfig {
    type Error = Error;

    fn try_from(config: NetworkConfig) -> Result<Self> {
        config.to_quic_config()
    }
}

impl TryFrom<&NetworkConfig> for MpcBackend {
    type Error = Error;

    fn try_from(config: &NetworkConfig) -> Result<Self> {
        config.mpc_backend()
    }
}

impl TryFrom<NetworkConfig> for MpcBackend {
    type Error = Error;

    fn try_from(config: NetworkConfig) -> Result<Self> {
        config.mpc_backend()
    }
}

#[derive(Debug, Clone, Default)]
pub struct NetworkConfigBuilder {
    config: NetworkConfig,
}

impl NetworkConfigBuilder {
    pub fn party_id(mut self, party_id: usize) -> Self {
        self.config.network.party_id = party_id;
        self
    }

    pub fn bind_address(mut self, bind_address: impl Into<String>) -> Self {
        self.config.network.bind_address = bind_address.into();
        self
    }

    pub fn expected_parties(mut self, expected_parties: usize) -> Self {
        self.config.network.expected_parties = expected_parties;
        self
    }

    pub fn expected_clients(mut self, expected_clients: usize) -> Self {
        self.config.network.expected_clients = expected_clients;
        self
    }

    pub fn consensus_timeout_ms(mut self, timeout_ms: u64) -> Self {
        self.config.network.consensus_timeout_ms = timeout_ms;
        self
    }

    pub fn consensus_timeout(mut self, timeout: Duration) -> Self {
        self.config.network.consensus_timeout_ms = duration_to_millis(timeout);
        self
    }

    pub fn peer(mut self, party_id: usize, address: impl Into<String>) -> Self {
        self.config.network.peers.insert(party_id, address.into());
        self
    }

    pub fn peers<I, S>(mut self, peers: I) -> Self
    where
        I: IntoIterator<Item = (usize, S)>,
        S: Into<String>,
    {
        self.config.network.peers = peers
            .into_iter()
            .map(|(party_id, address)| (party_id, address.into()))
            .collect();
        self
    }

    pub fn with_peers(self, peers: &[(usize, &str)]) -> Self {
        self.peers(peers.iter().copied())
    }

    pub fn threshold(mut self, threshold: usize) -> Self {
        self.config.mpc.threshold = threshold;
        self
    }

    pub fn protocol(mut self, protocol: impl Into<String>) -> Self {
        self.config.mpc.protocol = protocol.into();
        self
    }

    pub fn backend(mut self, backend: MpcBackend) -> Self {
        self.config.mpc.protocol = backend.to_string();
        self
    }

    pub fn manifest<M: GeneratedProgramManifest>(self) -> Self {
        self.backend(M::BACKEND)
    }

    pub fn honeybadger(mut self) -> Self {
        self.config.mpc.protocol = MpcBackend::HoneyBadger.to_string();
        self
    }

    pub fn avss(mut self, curve: Curve) -> Self {
        self.config.mpc.protocol = MpcBackend::Avss { curve }.to_string();
        self
    }

    pub fn preprocessing(mut self, triples: usize, random_shares: usize) -> Self {
        self.config.preprocessing.triples = triples;
        self.config.preprocessing.random_shares = random_shares;
        self
    }

    pub fn build(self) -> Result<NetworkConfig> {
        self.config.validate()?;
        Ok(self.config)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkSection {
    pub party_id: usize,
    pub bind_address: String,
    pub expected_parties: usize,
    pub expected_clients: usize,
    pub consensus_timeout_ms: u64,
    #[serde(default)]
    #[serde(with = "peer_map")]
    pub peers: BTreeMap<usize, String>,
}

impl Default for NetworkSection {
    fn default() -> Self {
        Self {
            party_id: 0,
            bind_address: "127.0.0.1:19200".to_owned(),
            expected_parties: 5,
            expected_clients: 0,
            consensus_timeout_ms: 60_000,
            peers: BTreeMap::new(),
        }
    }
}

mod peer_map {
    use std::collections::BTreeMap;

    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S>(
        peers: &BTreeMap<usize, String>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let as_strings = peers
            .iter()
            .map(|(party_id, address)| (party_id.to_string(), address.clone()))
            .collect::<BTreeMap<_, _>>();
        as_strings.serialize(serializer)
    }

    pub fn deserialize<'de, D>(
        deserializer: D,
    ) -> std::result::Result<BTreeMap<usize, String>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = BTreeMap::<String, String>::deserialize(deserializer)?;
        raw.into_iter()
            .map(|(party_id, address)| {
                let party_id = party_id
                    .parse::<usize>()
                    .map_err(serde::de::Error::custom)?;
                Ok((party_id, address))
            })
            .collect()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MpcSection {
    pub threshold: usize,
    pub protocol: String,
}

impl Default for MpcSection {
    fn default() -> Self {
        Self {
            threshold: 1,
            protocol: "honeybadger".to_owned(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreprocessingConfig {
    pub triples: usize,
    pub random_shares: usize,
}

impl Default for PreprocessingConfig {
    fn default() -> Self {
        Self {
            triples: 1000,
            random_shares: 500,
        }
    }
}

impl PreprocessingConfig {
    pub fn validate(&self) -> Result<()> {
        if self.triples == 0 {
            return Err(Error::Configuration(
                "preprocessing.triples must be greater than 0".to_owned(),
            ));
        }
        if self.random_shares == 0 {
            return Err(Error::Configuration(
                "preprocessing.random_shares must be greater than 0".to_owned(),
            ));
        }
        Ok(())
    }
}

fn normalize_identifier(value: &str) -> String {
    value
        .trim()
        .chars()
        .filter(|character| !matches!(character, '-' | '_'))
        .flat_map(char::to_lowercase)
        .collect()
}

fn byzantine_minimum_parties(threshold: usize) -> Result<usize> {
    checked_threshold_expression(threshold, 4, 1, "Byzantine party threshold")
}

pub(crate) fn validate_socket_address(label: &str, address: &str) -> Result<()> {
    let trimmed = address.trim();
    if trimmed.is_empty() {
        return Err(Error::Configuration(format!("{label} must not be empty")));
    }
    if trimmed
        .to_socket_addrs()
        .map_err(|error| Error::Configuration(format!("{label} '{address}' is invalid: {error}")))?
        .next()
        .is_none()
    {
        return Err(Error::Configuration(format!(
            "{label} '{address}' did not resolve to a socket address"
        )));
    }
    Ok(())
}

fn checked_threshold_expression(
    threshold: usize,
    multiplier: usize,
    addend: usize,
    label: &str,
) -> Result<usize> {
    threshold
        .checked_mul(multiplier)
        .and_then(|value| value.checked_add(addend))
        .ok_or_else(|| {
            Error::Configuration(format!("{label} overflows usize for threshold {threshold}"))
        })
}

fn duration_to_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}
