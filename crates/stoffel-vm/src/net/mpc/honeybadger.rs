use crate::net::curve::SupportedMpcField;
use crate::net::mpc::honeybadger_node_opts;
use crate::net::mpc_engine::{DurableIdentityDigest, MpcPartyId, MpcSessionTopology};
use crate::net::reservation::ReservationRegistry;
use crate::storage::preproc::PreprocStore;
use ark_ec::{CurveGroup, PrimeGroup};
use std::marker::PhantomData;
use std::sync::atomic::AtomicBool;
use std::sync::{Arc, RwLock as StdRwLock};
use stoffelmpc_mpc::common::MPCProtocol;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::HoneyBadgerMPCNode;
use stoffelnet::network_utils::ClientId;
use stoffelnet::transports::quic::QuicNetworkManager;
use tokio::sync::{Mutex, RwLock};

mod capabilities;
mod client_io;
mod config;
mod consensus;
mod engine;
mod operations;
mod preprocessing;
mod reservation;
#[cfg(test)]
mod tests;
pub use config::{HoneyBadgerEngineConfig, HoneyBadgerPreprocessingConfig};

// RBC/SSS type aliases used by HB implementation
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::honeybadger::SessionId as HbSessionId;
type RBCImpl = Avid<HbSessionId>;

use crate::net::engine_config::MpcSessionConfig;

/// HoneyBadger-backed MPC engine that integrates with the VM.
/// This wraps a real HoneyBadgerMPCNode and provides MPC operations
/// (input sharing, multiplication, output reconstruction) to the VM.
pub struct HoneyBadgerMpcEngine<F = ark_bls12_381::Fr, G = ark_bls12_381::G1Projective>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    topology: MpcSessionTopology,
    local_identity: DurableIdentityDigest,
    net: Arc<QuicNetworkManager>,
    node: Arc<Mutex<HoneyBadgerMPCNode<F, RBCImpl>>>,
    ready: AtomicBool,
    group_marker: PhantomData<G>,
    /// Persistent preprocessing store.
    preproc_store: tokio::sync::RwLock<Option<Arc<dyn PreprocStore>>>,
    /// Program hash for keying stored material.
    program_hash: tokio::sync::RwLock<Option<[u8; 32]>>,
    /// Durable node identity used for persistent store keys.
    persistent_identity: StdRwLock<DurableIdentityDigest>,
    /// Reservation registry for masked-input protocol.
    reservation: tokio::sync::RwLock<Option<ReservationRegistry>>,
    /// Optional in-process capture used by coordinator-backed output delivery.
    client_output_capture: Mutex<Option<Vec<HoneyBadgerClientOutputRecord<F>>>>,
    /// Maps VM/client protocol indices to transport-derived client IDs.
    client_output_id_map: RwLock<Vec<ClientId>>,
    /// Session-local router for open-share/open-exp payloads.
    open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
    /// Per-instance open share accumulation registry.
    open_registry: Arc<crate::net::open_registry::InstanceRegistry>,
}

#[derive(Clone)]
pub struct HoneyBadgerClientOutputRecord<F>
where
    F: SupportedMpcField,
{
    pub client_id: ClientId,
    pub shares: Vec<RobustShare<F>>,
}

pub type Bls12381HoneyBadgerMpcEngine =
    HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>;
pub type Bn254HoneyBadgerMpcEngine = HoneyBadgerMpcEngine<ark_bn254::Fr, ark_bn254::G1Projective>;
pub type Curve25519HoneyBadgerMpcEngine =
    HoneyBadgerMpcEngine<ark_curve25519::Fr, ark_curve25519::EdwardsProjective>;
pub type Ed25519HoneyBadgerMpcEngine =
    HoneyBadgerMpcEngine<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>;
pub type Secp256k1HoneyBadgerMpcEngine =
    HoneyBadgerMpcEngine<ark_secp256k1::Fr, ark_secp256k1::Projective>;
pub type P256HoneyBadgerMpcEngine =
    HoneyBadgerMpcEngine<ark_secp256r1::Fr, ark_secp256r1::Projective>;

impl<F, G> HoneyBadgerMpcEngine<F, G>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    pub fn open_message_router(&self) -> Arc<crate::net::open_registry::OpenMessageRouter> {
        self.open_message_router.clone()
    }

    pub fn net(&self) -> Arc<QuicNetworkManager> {
        self.net.clone()
    }

    pub fn topology(&self) -> MpcSessionTopology {
        self.topology
    }

    pub(super) async fn clone_node(&self) -> HoneyBadgerMPCNode<F, RBCImpl> {
        self.node.lock().await.clone()
    }

    pub fn party(&self) -> MpcPartyId {
        self.topology.party()
    }

    pub(crate) fn persistent_identity(&self) -> DurableIdentityDigest {
        *self
            .persistent_identity
            .read()
            .expect("persistent identity lock poisoned")
    }

    pub fn set_preproc_store_identity(&self, identity: DurableIdentityDigest) {
        *self
            .persistent_identity
            .write()
            .expect("persistent identity lock poisoned") = identity;
    }

    pub fn from_config(config: HoneyBadgerEngineConfig) -> Result<Arc<Self>, String> {
        let HoneyBadgerEngineConfig {
            session,
            preprocessing,
        } = config;
        let (topology, local_identity, network, input_ids, open_message_router) =
            session.into_parts();
        let instance_id = topology.instance_id();
        let party_id = topology.party_id();
        let n_parties = topology.n_parties();
        let threshold = topology.threshold();

        // Create the MPC node options
        let mpc_opts = honeybadger_node_opts(
            n_parties,
            threshold,
            preprocessing.triples,
            preprocessing.random_shares,
            instance_id,
        )?;

        // Create the MPC node
        let node = <HoneyBadgerMPCNode<F, RBCImpl> as MPCProtocol<
            F,
            RobustShare<F>,
            QuicNetworkManager,
        >>::setup(party_id, mpc_opts, input_ids)
        .map_err(|e| format!("Failed to create MPC node: {:?}", e))?;

        Ok(Arc::new(Self {
            topology,
            local_identity,
            net: network,
            node: Arc::new(Mutex::new(node)),
            ready: AtomicBool::new(false),
            group_marker: PhantomData,
            preproc_store: tokio::sync::RwLock::new(None),
            program_hash: tokio::sync::RwLock::new(None),
            persistent_identity: StdRwLock::new(local_identity),
            reservation: tokio::sync::RwLock::new(None),
            client_output_capture: Mutex::new(None),
            client_output_id_map: RwLock::new(Vec::new()),
            open_registry: open_message_router.register_instance(instance_id),
            open_message_router,
        }))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        n_triples: usize,
        n_random: usize,
        net: Arc<QuicNetworkManager>,
        input_ids: Vec<ClientId>,
    ) -> Result<Arc<Self>, String> {
        let session = MpcSessionConfig::try_new(instance_id, party_id, n, t, net)
            .map_err(|error| error.to_string())?
            .with_input_ids(input_ids);
        let preprocessing = HoneyBadgerPreprocessingConfig::new(n_triples, n_random);
        Self::from_config(HoneyBadgerEngineConfig::new(session, preprocessing))
    }

    #[allow(clippy::too_many_arguments)]
    pub fn new_with_router(
        open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        n_triples: usize,
        n_random: usize,
        net: Arc<QuicNetworkManager>,
        input_ids: Vec<ClientId>,
    ) -> Result<Arc<Self>, String> {
        let session = MpcSessionConfig::try_new(instance_id, party_id, n, t, net)
            .map_err(|error| error.to_string())?
            .with_input_ids(input_ids)
            .with_open_message_router(open_message_router);
        let preprocessing = HoneyBadgerPreprocessingConfig::new(n_triples, n_random);
        Self::from_config(HoneyBadgerEngineConfig::new(session, preprocessing))
    }

    /// Construct an engine from an existing, network-driven HoneyBadgerMPCNode.
    /// This avoids creating a separate node that isn't wired into the message loop.
    pub fn try_from_existing_node(
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<F, RBCImpl>,
    ) -> Result<Arc<Self>, crate::net::mpc_engine::MpcSessionTopologyError> {
        Self::try_from_existing_node_with_router(
            Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
            instance_id,
            party_id,
            n,
            t,
            net,
            node,
        )
    }

    pub fn try_from_existing_node_with_router(
        open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
        instance_id: u64,
        party_id: usize,
        n: usize,
        t: usize,
        net: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<F, RBCImpl>,
    ) -> Result<Arc<Self>, crate::net::mpc_engine::MpcSessionTopologyError> {
        let topology = MpcSessionTopology::try_new(instance_id, party_id, n, t)?;
        Ok(Self::from_existing_node_with_router_and_topology(
            open_message_router,
            topology,
            DurableIdentityDigest::from_legacy_party_id(party_id),
            net,
            node,
        ))
    }

    pub fn from_existing_node_with_topology(
        topology: MpcSessionTopology,
        net: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<F, RBCImpl>,
    ) -> Arc<Self> {
        Self::from_existing_node_with_router_and_topology(
            Arc::new(crate::net::open_registry::OpenMessageRouter::new()),
            topology,
            DurableIdentityDigest::from_legacy_party_id(topology.party_id()),
            net,
            node,
        )
    }

    pub fn from_existing_node_with_router_and_topology(
        open_message_router: Arc<crate::net::open_registry::OpenMessageRouter>,
        topology: MpcSessionTopology,
        local_identity: DurableIdentityDigest,
        net: Arc<QuicNetworkManager>,
        node: HoneyBadgerMPCNode<F, RBCImpl>,
    ) -> Arc<Self> {
        let instance_id = topology.instance_id();
        let node = Arc::new(Mutex::new(node));
        Arc::new(Self {
            topology,
            local_identity,
            net,
            node,
            ready: AtomicBool::new(true),
            group_marker: PhantomData,
            preproc_store: tokio::sync::RwLock::new(None),
            program_hash: tokio::sync::RwLock::new(None),
            persistent_identity: StdRwLock::new(local_identity),
            reservation: tokio::sync::RwLock::new(None),
            client_output_capture: Mutex::new(None),
            client_output_id_map: RwLock::new(Vec::new()),
            open_registry: open_message_router.register_instance(instance_id),
            open_message_router,
        })
    }

    pub async fn set_client_output_id_map(&self, client_ids: Vec<ClientId>) {
        *self.client_output_id_map.write().await = client_ids;
    }

    pub(crate) async fn client_output_transport_id(&self, client_id: ClientId) -> ClientId {
        self.client_output_id_map
            .read()
            .await
            .get(client_id)
            .copied()
            .unwrap_or(client_id)
    }

    pub(crate) fn client_identity(&self, client_id: ClientId) -> DurableIdentityDigest {
        self.net
            .get_sorted_client_keys()
            .get(client_id)
            .map(|key| DurableIdentityDigest::from_public_key_bytes(&key.0))
            .unwrap_or_else(|| DurableIdentityDigest::from_legacy_party_id(client_id))
    }

    pub async fn enable_client_output_capture(&self) {
        *self.client_output_capture.lock().await = Some(Vec::new());
    }

    pub async fn drain_client_output_records(&self) -> Vec<HoneyBadgerClientOutputRecord<F>> {
        self.client_output_capture
            .lock()
            .await
            .as_mut()
            .map(std::mem::take)
            .unwrap_or_default()
    }

    /// Returns a handle to the inner MPC node for direct access (e.g., InputServer init).
    pub fn node_handle(&self) -> &Arc<Mutex<HoneyBadgerMPCNode<F, RBCImpl>>> {
        &self.node
    }
}
