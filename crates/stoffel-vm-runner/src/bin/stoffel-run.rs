use ark_ec::{CurveGroup, PrimeGroup};
use ark_ff::{BigInteger, PrimeField};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::env;
use std::fs;
use std::fs::File;
use std::io::BufReader;
use std::net::SocketAddr;
use std::process::exit;
use std::str::FromStr;
use std::sync::Arc;
use std::time::Duration;
use stoffel_mpc_coordinator_off_chain::node_rpc::{
    NodeRPCClient as OffChainNodeRPCClient, NodeRPCServer as OffChainNodeRPCServer,
};
use stoffel_mpc_coordinator_off_chain::OffChainCoordinatorClient;
use stoffel_mpc_coordinator_shared::{Coordinator, NodeRPCError, Round};
use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::net::curve::{field_from_i64, field_to_i64, SupportedMpcField};
use stoffel_vm::net::hb_engine::HoneyBadgerMpcEngine;
use stoffel_vm::net::mpc_engine::{DurableIdentityDigest, MpcEngine, MpcSessionTopology};
use stoffel_vm::net::{
    avss_protocol_instance_id, honeybadger_node_opts_with_truncation,
    honeybadger_protocol_instance_id, honeybadger_protocol_timeout, spawn_receive_loops_split,
};
use stoffel_vm::net::{
    program_id_from_bytes, register_and_wait_for_session, run_bootnode_with_config,
    SessionRegistrationConfig,
};
use stoffel_vm::net::{MpcBackendKind, MpcCurveConfig};
use stoffel_vm::runtime_hooks::{HookContext, HookEvent};
use stoffel_vm::storage::preproc::LmdbPreprocStore;
use stoffel_vm::storage::RedbLocalStorage;
use stoffel_vm_types::compiled_binary::{
    BinaryError, ClientIoManifest, CompiledBinary, MpcCurve, MPC_BACKEND_MANIFEST_FORMAT_VERSION,
    MPC_CURVE_MANIFEST_FORMAT_VERSION,
};
use stoffel_vm_types::core_types::{ShareType, TableRef, Value};
use stoffelmpc_mpc::avss_mpc::{AvssMPCClient, AvssSessionId};
use stoffelmpc_mpc::common::rbc::rbc::Avid;
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use stoffelmpc_mpc::common::MPCProtocol;
use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare;
use stoffelmpc_mpc::honeybadger::benchmark::NodeBenchmarkCounters;
use stoffelmpc_mpc::honeybadger::SessionId as HbSessionId;
use stoffelmpc_mpc::honeybadger::{HoneyBadgerMPCClient, HoneyBadgerMPCNode};
use stoffelnet::network_utils::ClientId;
use stoffelnet::network_utils::Network;
use stoffelnet::transports::quic::{NetworkManager, QuicNetworkManager};
use tokio::sync::mpsc;
use x509_parser::prelude::*;
type HbCoordinatorShare<F> = RobustShare<F>;

fn manifest_client_input_types(
    manifest: &ClientIoManifest,
) -> std::collections::BTreeMap<usize, Vec<ShareType>> {
    manifest
        .clients
        .iter()
        .filter_map(|schema| {
            usize::try_from(schema.client_slot)
                .ok()
                .map(|slot| (slot, schema.inputs.clone()))
        })
        .collect()
}

/// Planned preprocessing material counts for one program run.
struct PlannedPreprocessing {
    n_triples: usize,
    n_random: usize,
    n_prandbit: usize,
    n_prandint: usize,
}

fn read_trimmed_u64(path: &str) -> Option<u64> {
    fs::read_to_string(path)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
}

fn current_process_rss_bytes() -> Option<u64> {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|status| {
            status.lines().find_map(|line| {
                let value = line.strip_prefix("VmRSS:")?;
                let kb = value.split_whitespace().next()?.parse::<u64>().ok()?;
                Some(kb.saturating_mul(1024))
            })
        })
}

fn current_cgroup_memory_bytes() -> Option<u64> {
    read_trimmed_u64("/sys/fs/cgroup/memory.current")
        .or_else(|| read_trimmed_u64("/sys/fs/cgroup/memory/memory.usage_in_bytes"))
}

/// Round a demand up to a coarse band for privacy: the observable preprocessing
/// volume reveals only which band the program's demand falls in, not its exact
/// operation count. We band to **eighths of an octave** (the next multiple of
/// 1/8 of the demand's power-of-two floor) rather than to the next full power of
/// two. Full-octave banding can nearly *double* the demand, which both wastes
/// preprocessing and — critically — can push a program that comfortably fits the
/// MPC backend's per-session generation capacity over that ceiling (e.g. a
/// 166k-triple program banded to 262k exceeds HoneyBadger's ~196k triple limit,
/// failing with a spurious `LimitError`). Eighth-octave banding over-provisions
/// by at most ~12.5% while still hiding the exact count to within a size band.
fn band_pow2(n: u64) -> u64 {
    if n == 0 {
        return 0;
    }
    // Largest power of two <= n (the octave floor).
    let floor_pow2 = if n.is_power_of_two() {
        n
    } else {
        n.next_power_of_two() >> 1
    };
    // Round up to the next multiple of an eighth of that octave.
    let granularity = (floor_pow2 >> 3).max(1);
    n.div_ceil(granularity).saturating_mul(granularity)
}

/// Turn the compiler's static preprocessing-demand estimate into concrete
/// material counts to generate up front. Each count is rounded up to a power of
/// two for privacy (see `band_pow2`); `dynamic` programs (data-dependent loops,
/// recursion, runtime-sized batches) get an extra octave of headroom because the
/// static estimate may undercount them. The triple count absorbs the dependency
/// that prandbit generation itself consumes a triple per bit. The random count
/// only covers program-visible random material; HoneyBadger generates the
/// random shares needed to build triples inside `run_preprocessing`.
/// `STOFFEL_PREPROCESSING_TRIPLES` / `STOFFEL_PREPROCESSING_PRANDBITS` override
/// the estimate for unusually loop-heavy programs.
fn plan_preprocessing(
    demand: &stoffel_vm_types::compiled_binary::PreprocessingDemand,
    threshold: usize,
    n_client_random: usize,
) -> PlannedPreprocessing {
    let env_u64 = |name: &str| {
        std::env::var(name)
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
            .filter(|v| *v > 0)
    };

    // Dynamic programs may undercount, so give them an extra octave before banding.
    let with_headroom = |n: u64| -> u64 {
        if demand.dynamic {
            n.saturating_mul(2)
        } else {
            n
        }
    };

    let prandbits = env_u64("STOFFEL_PREPROCESSING_PRANDBITS")
        .map(band_pow2)
        .unwrap_or_else(|| band_pow2(with_headroom(demand.prandbits)));
    let prandints = band_pow2(with_headroom(demand.prandints));
    let direct_randoms = band_pow2(with_headroom(demand.randoms));

    let direct_triples = env_u64("STOFFEL_PREPROCESSING_TRIPLES")
        .map(band_pow2)
        .unwrap_or_else(|| band_pow2(with_headroom(demand.triples)));

    // prandbit generation consumes one triple + one random per bit.
    let mut triple_target = direct_triples.saturating_add(prandbits);
    if triple_target > 0 {
        // Floor to the protocol's minimum triple batch so tiny programs still run.
        triple_target = triple_target.max(2 * threshold as u64 + 1);
    }
    let n_triples = band_pow2(triple_target);
    // HoneyBadger adds and consumes two random shares per triple internally.
    // `n_random` is the pool left for direct program use and prandbit generation
    // after triples have been built; adding `2 * n_triples` here makes the
    // backend generate an extra full random pool.
    let n_random = band_pow2(
        2u64.saturating_add(direct_randoms)
            .saturating_add(prandbits)
            .saturating_add(n_client_random as u64),
    );

    PlannedPreprocessing {
        n_triples: n_triples as usize,
        n_random: n_random as usize,
        n_prandbit: prandbits as usize,
        n_prandint: prandints as usize,
    }
}

type HbOffChainCoordinator<F> = OffChainCoordinatorClient<F, HbCoordinatorShare<F>>;
type HbOffChainNodeRpcClient<F> = OffChainNodeRPCClient<F, HbCoordinatorShare<F>>;
type HbOffChainNodeRpcServer<F> = OffChainNodeRPCServer<F, HbCoordinatorShare<F>>;
type AvssCoordinatorShare<F, G> = FeldmanShamirShare<F, G>;
type AvssOffChainCoordinator<F, G> = OffChainCoordinatorClient<F, AvssCoordinatorShare<F, G>>;
type AvssOffChainNodeRpcClient<F, G> = OffChainNodeRPCClient<F, AvssCoordinatorShare<F, G>>;
type AvssOffChainNodeRpcServer<F, G> = OffChainNodeRPCServer<F, AvssCoordinatorShare<F, G>>;

const HB_PREPROCESSING_READY_PREFIX: &[u8] = b"STOFFEL_HB_PREPROCESSING_READY_V1";

fn session_registration_timeout() -> Duration {
    let seconds = env::var("STOFFEL_SESSION_REGISTRATION_TIMEOUT_SECONDS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(120);
    Duration::from_secs(seconds)
}

fn extract_pubkey_from_cert(cert_der: &[u8]) -> Vec<u8> {
    let (_, parsed) = X509Certificate::from_der(cert_der).expect("parse X.509 cert");
    parsed
        .public_key()
        .subject_public_key
        .data
        .as_ref()
        .to_vec()
}

fn durable_identity_from_cert(cert_der: &[u8]) -> DurableIdentityDigest {
    DurableIdentityDigest::from_cert_der(cert_der).unwrap_or_else(|error| {
        eprintln!("Error: failed to derive durable identity from certificate: {error}");
        exit(2);
    })
}

fn required_storage_identity(
    cert_der: &Option<Vec<u8>>,
    key_der: &Option<Vec<u8>>,
    storage_enabled: bool,
) -> Option<DurableIdentityDigest> {
    if !storage_enabled {
        return None;
    }
    let cert = cert_der.as_ref().unwrap_or_else(|| {
        eprintln!("Error: --cert is required when persistent VM/preprocessing storage is enabled");
        exit(2);
    });
    let _key = key_der.as_ref().unwrap_or_else(|| {
        eprintln!("Error: --key is required when persistent VM/preprocessing storage is enabled");
        exit(2);
    });
    Some(durable_identity_from_cert(cert))
}
#[derive(Debug, Clone, Copy)]
enum CoordinatorOutputFormat {
    FieldInteger,
    FixedPoint { fractional_bits: usize },
}
fn render_fixed_point_i64(scaled: i64, fractional_bits: usize) -> Option<String> {
    let scale = 1_i128.checked_shl(u32::try_from(fractional_bits).ok()?)?;
    if scale == 0 {
        return None;
    }

    let scaled = i128::from(scaled);
    let negative = scaled < 0;
    let magnitude = scaled.abs();
    let whole = magnitude / scale;
    let mut remainder = magnitude % scale;

    if remainder == 0 {
        return Some(if negative {
            format!("-{whole}")
        } else {
            whole.to_string()
        });
    }

    let mut fractional = String::new();
    while remainder != 0 {
        remainder *= 10;
        let digit = remainder / scale;
        fractional.push(char::from(b'0' + u8::try_from(digit).ok()?));
        remainder %= scale;
    }

    Some(if negative {
        format!("-{whole}.{fractional}")
    } else {
        format!("{whole}.{fractional}")
    })
}
fn format_coordinator_outputs<F>(outputs: &[F], output_format: CoordinatorOutputFormat) -> String
where
    F: PrimeField + Copy + PartialEq + std::fmt::Debug,
{
    let rendered = outputs
        .iter()
        .copied()
        .map(|output| match (field_to_i64(output), output_format) {
            (Ok(signed), CoordinatorOutputFormat::FieldInteger)
                if field_from_i64::<F>(signed) == output =>
            {
                signed.to_string()
            }
            (Ok(signed), CoordinatorOutputFormat::FixedPoint { fractional_bits })
                if field_from_i64::<F>(signed) == output =>
            {
                render_fixed_point_i64(signed, fractional_bits)
                    .unwrap_or_else(|| format!("{output:?}"))
            }
            _ => format!("{output:?}"),
        })
        .collect::<Vec<_>>()
        .join(", ");

    format!("[{}]", rendered)
}
trait ReservedMaskIndices {
    fn into_reserved_indices(self) -> Vec<u64>;
}
impl ReservedMaskIndices for u64 {
    fn into_reserved_indices(self) -> Vec<u64> {
        vec![self]
    }
}
impl ReservedMaskIndices for Vec<u64> {
    fn into_reserved_indices(self) -> Vec<u64> {
        self
    }
}
fn normalize_client_to_indices<I, V>(
    client_to_indices: std::collections::HashMap<I, V>,
) -> std::collections::HashMap<I, Vec<u64>>
where
    I: Eq + std::hash::Hash,
    V: ReservedMaskIndices,
{
    client_to_indices
        .into_iter()
        .map(|(client_id, indices)| (client_id, indices.into_reserved_indices()))
        .collect()
}

fn curve_config_from_manifest(curve: MpcCurve) -> MpcCurveConfig {
    match curve {
        MpcCurve::Bls12_381 => MpcCurveConfig::Bls12_381,
        MpcCurve::Bn254 => MpcCurveConfig::Bn254,
        MpcCurve::Curve25519 => MpcCurveConfig::Curve25519,
        MpcCurve::Ed25519 => MpcCurveConfig::Ed25519,
        MpcCurve::Secp256k1 => MpcCurveConfig::Secp256k1,
        MpcCurve::Secp256r1 => MpcCurveConfig::Secp256r1,
    }
}
fn store_reserved_client_inputs<F, I>(
    vm: &mut VirtualMachine,
    client_to_indices: &std::collections::HashMap<I, Vec<u64>>,
    client_inputs: std::collections::HashMap<I, Vec<RobustShare<F>>>,
    client_input_count: usize,
    client_input_slots: &[usize],
    client_input_types: &std::collections::BTreeMap<usize, Vec<ShareType>>,
) where
    F: ark_ff::FftField,
    I: Eq + std::hash::Hash + std::fmt::Debug,
{
    if client_input_count == 0 {
        eprintln!("--client-input-count must be greater than 0");
        exit(13);
    }

    let mut seen_reserved_indices = std::collections::HashSet::new();
    // Group each client's shares independently — clients may provide DIFFERENT
    // numbers of inputs. The runner reserves a contiguous index block per client
    // in slot order, so ordering clients by their lowest reserved index recovers
    // the client-store ordinal (matching `client_input_slots` / the roster).
    let mut per_client: Vec<(u64, Vec<RobustShare<F>>)> = Vec::new();

    for (client_id, shares) in client_inputs {
        if shares.is_empty() {
            eprintln!(
                "Coordinator returned zero input shares for client {:?}",
                client_id
            );
            exit(13);
        }
        let reserved_indices = match client_to_indices.get(&client_id) {
            Some(indices) => indices,
            None => {
                eprintln!(
                    "Coordinator returned input for client {:?} without a reserved index",
                    client_id
                );
                exit(13);
            }
        };
        if reserved_indices.len() != shares.len() {
            eprintln!(
                "Coordinator returned {} input shares for client {:?}, but {} reserved indices were recorded",
                shares.len(),
                client_id,
                reserved_indices.len()
            );
            exit(13);
        }

        let mut indexed_shares: Vec<(u64, RobustShare<F>)> =
            reserved_indices.iter().copied().zip(shares).collect();
        indexed_shares.sort_by_key(|(reserved_index, _)| *reserved_index);

        let min_reserved_index = indexed_shares
            .first()
            .map(|(reserved_index, _)| *reserved_index)
            .unwrap_or(0);
        let mut ordered_shares = Vec::with_capacity(indexed_shares.len());
        for (reserved_index, share) in indexed_shares {
            if reserved_index > usize::MAX as u64 {
                eprintln!(
                    "Coordinator reserved index {} exceeds local usize range",
                    reserved_index
                );
                exit(13);
            }
            if !seen_reserved_indices.insert(reserved_index as usize) {
                eprintln!(
                    "Coordinator assigned duplicate reserved index {} while collecting inputs",
                    reserved_index
                );
                exit(13);
            }
            ordered_shares.push(share);
        }
        per_client.push((min_reserved_index, ordered_shares));
    }

    // Slot order == reservation order == ascending min reserved index.
    per_client.sort_by_key(|(min_reserved_index, _)| *min_reserved_index);

    for (client_store_index, (_min_reserved_index, shares)) in per_client.into_iter().enumerate() {
        let client_slot = client_input_slots
            .get(client_store_index)
            .copied()
            .unwrap_or(client_store_index);
        let result = if let Some(share_types) = client_input_types.get(&client_slot) {
            vm.try_store_client_input_with_types(client_slot, shares, share_types)
        } else {
            vm.try_store_client_input(client_slot, shares)
        };
        if let Err(error) = result {
            eprintln!(
                "Failed to store input shares for client slot {}: {}",
                client_slot, error
            );
            exit(13);
        }
    }
}
fn store_reserved_client_inputs_feldman<F, G, I>(
    vm: &mut VirtualMachine,
    client_to_indices: &std::collections::HashMap<I, Vec<u64>>,
    client_inputs: std::collections::HashMap<I, Vec<FeldmanShamirShare<F, G>>>,
    client_input_count: usize,
    client_input_slots: &[usize],
    client_input_types: &std::collections::BTreeMap<usize, Vec<ShareType>>,
) where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F>,
    I: Eq + std::hash::Hash + std::fmt::Debug,
{
    if client_input_count == 0 {
        eprintln!("--client-input-count must be greater than 0");
        exit(13);
    }

    let mut seen_reserved_indices = std::collections::HashSet::new();
    // Group each client's shares independently — clients may provide DIFFERENT
    // numbers of inputs. The runner reserves a contiguous index block per client
    // in slot order, so ordering clients by their lowest reserved index recovers
    // the client-store ordinal (matching `client_input_slots` / the roster).
    let mut per_client: Vec<(u64, Vec<FeldmanShamirShare<F, G>>)> = Vec::new();

    for (client_id, shares) in client_inputs {
        if shares.is_empty() {
            eprintln!(
                "Coordinator returned zero AVSS input shares for client {:?}",
                client_id
            );
            exit(13);
        }
        let reserved_indices = match client_to_indices.get(&client_id) {
            Some(indices) => indices,
            None => {
                eprintln!(
                    "Coordinator returned input for client {:?} without a reserved index",
                    client_id
                );
                exit(13);
            }
        };
        if reserved_indices.len() != shares.len() {
            eprintln!(
                "Coordinator returned {} AVSS input shares for client {:?}, but {} reserved indices were recorded",
                shares.len(),
                client_id,
                reserved_indices.len()
            );
            exit(13);
        }

        let mut indexed_shares: Vec<(u64, FeldmanShamirShare<F, G>)> =
            reserved_indices.iter().copied().zip(shares).collect();
        indexed_shares.sort_by_key(|(reserved_index, _)| *reserved_index);

        let min_reserved_index = indexed_shares
            .first()
            .map(|(reserved_index, _)| *reserved_index)
            .unwrap_or(0);
        let mut ordered_shares = Vec::with_capacity(indexed_shares.len());
        for (reserved_index, share) in indexed_shares {
            if reserved_index > usize::MAX as u64 {
                eprintln!(
                    "Coordinator reserved index {} exceeds local usize range",
                    reserved_index
                );
                exit(13);
            }
            if !seen_reserved_indices.insert(reserved_index as usize) {
                eprintln!(
                    "Coordinator assigned duplicate reserved index {} while collecting inputs",
                    reserved_index
                );
                exit(13);
            }
            ordered_shares.push(share);
        }
        per_client.push((min_reserved_index, ordered_shares));
    }

    // Slot order == reservation order == ascending min reserved index.
    per_client.sort_by_key(|(min_reserved_index, _)| *min_reserved_index);

    for (client_store_index, (_min_reserved_index, shares)) in per_client.into_iter().enumerate() {
        let client_slot = client_input_slots
            .get(client_store_index)
            .copied()
            .unwrap_or(client_store_index);
        let result = if let Some(share_types) = client_input_types.get(&client_slot) {
            vm.try_store_client_input_feldman_with_types(client_slot, shares, share_types)
        } else {
            vm.try_store_client_input_feldman(client_slot, shares)
        };
        if let Err(error) = result {
            eprintln!(
                "Failed to store AVSS input shares for client slot {}: {}",
                client_slot, error
            );
            exit(13);
        }
    }
}
fn configure_hb_preproc_store<F, G>(
    engine: &Arc<HoneyBadgerMpcEngine<F, G>>,
    program_hash: [u8; 32],
    persistent_identity: DurableIdentityDigest,
    preproc_store_path: Option<&str>,
) -> Result<(), String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let Some(path) = preproc_store_path else {
        return Ok(());
    };

    let store = Arc::new(LmdbPreprocStore::open(path)?);
    engine
        .preproc_persistence_ops()?
        .set_preproc_store(store, program_hash)?;
    engine.set_preproc_store_identity(persistent_identity);
    Ok(())
}
async fn load_reserved_mask_share<F, G>(
    engine: &Arc<HoneyBadgerMpcEngine<F, G>>,
    reserved_index: u64,
) -> Result<RobustShare<F>, String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let reservation = engine.reservation_ops()?;
    let share_bytes = reservation.get_mask_share(reserved_index).await?;
    ark_serialize::CanonicalDeserialize::deserialize_compressed(share_bytes.as_slice())
        .map_err(|e| format!("deserialize reserved mask share {reserved_index}: {:?}", e))
}
async fn load_reserved_mask_shares<F, G>(
    engine: &Arc<HoneyBadgerMpcEngine<F, G>>,
    capacity: usize,
    reserved_indices: impl IntoIterator<Item = u64>,
) -> Result<Vec<RobustShare<F>>, String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    if capacity == 0 {
        return Ok(Vec::new());
    }

    let mut slots: Vec<Option<RobustShare<F>>> = vec![None; capacity];
    let mut reserved_indices: Vec<u64> = reserved_indices.into_iter().collect();
    reserved_indices.sort_unstable();
    for reserved_index in reserved_indices {
        let slot = usize::try_from(reserved_index)
            .map_err(|_| format!("reserved index {reserved_index} exceeds usize range"))?;
        if slot >= capacity {
            return Err(format!(
                "reserved index {reserved_index} exceeds expected input capacity {capacity}"
            ));
        }
        if slots[slot].is_some() {
            return Err(format!(
                "duplicate reserved mask share request for slot {reserved_index}"
            ));
        }
        slots[slot] = Some(load_reserved_mask_share(engine, reserved_index).await?);
    }

    slots
        .into_iter()
        .enumerate()
        .map(|(slot, share)| {
            share.ok_or_else(|| format!("missing reserved mask share for slot {slot}"))
        })
        .collect()
}

/// Network adapter for MPC clients.
///
/// Client receive paths use authenticated sorted-key IDs and normalize them to
/// protocol party IDs before messages enter MPC code. Sends use the explicit
/// server IDs registered from `--servers`, so they are already in protocol
/// party order.
struct ClientNetworkAdapter {
    inner: QuicNetworkManager,
    local_position: usize,
}

fn client_transport_recipient(
    recipient: stoffelnet::network_utils::PartyId,
    local_position: usize,
) -> Option<stoffelnet::network_utils::PartyId> {
    if recipient >= local_position {
        recipient.checked_add(1)
    } else {
        Some(recipient)
    }
}

fn client_transport_targets(
    recipient: stoffelnet::network_utils::PartyId,
    local_position: usize,
) -> Option<[stoffelnet::network_utils::PartyId; 1]> {
    Some([client_transport_recipient(recipient, local_position)?])
}

#[async_trait::async_trait]
impl Network for ClientNetworkAdapter {
    type NodeType = <QuicNetworkManager as Network>::NodeType;
    type NetworkConfig = <QuicNetworkManager as Network>::NetworkConfig;

    async fn send(
        &self,
        recipient: stoffelnet::network_utils::PartyId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        let [mapped] = client_transport_targets(recipient, self.local_position).ok_or(
            stoffelnet::network_utils::NetworkError::PartyNotFound(recipient),
        )?;
        let Some(connection) = self.inner.get_connection_by_party_id(mapped) else {
            return Err(stoffelnet::network_utils::NetworkError::PartyNotFound(
                recipient,
            ));
        };
        let bytes = message.to_vec();
        tokio::spawn(async move {
            if let Err(error) = connection.send(&bytes).await {
                eprintln!("[client] Failed to send MPC message to party {recipient}: {error}");
            }
        });
        Ok(message.len())
    }

    async fn broadcast(
        &self,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        let n = self.party_count();
        let mut total = 0usize;
        let results = futures::future::join_all(
            (0..n).map(|party_id| async move { (party_id, self.send(party_id, message).await) }),
        )
        .await;

        for (party_id, result) in results {
            match result {
                Ok(bytes) => total += bytes,
                Err(e) => {
                    tracing::debug!("client broadcast to party {} failed: {:?}", party_id, e);
                }
            }
        }
        Ok(total)
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.parties()
    }

    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        self.inner.parties_mut()
    }

    fn config(&self) -> &Self::NetworkConfig {
        self.inner.config()
    }

    fn node(&self, id: stoffelnet::network_utils::PartyId) -> Option<&Self::NodeType> {
        self.inner.node(id)
    }

    fn node_mut(&mut self, id: stoffelnet::network_utils::PartyId) -> Option<&mut Self::NodeType> {
        self.inner.node_mut(id)
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        self.inner.send_to_client(client, message).await
    }

    fn clients(&self) -> Vec<ClientId> {
        self.inner.clients()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        self.inner.is_client_connected(client)
    }

    fn local_party_id(&self) -> stoffelnet::network_utils::PartyId {
        self.inner.local_party_id()
    }

    fn party_count(&self) -> usize {
        // Return n (not n+1) — exclude the client from the party count
        self.inner.party_count().saturating_sub(1)
    }

    fn verified_ordering(&self) -> Option<stoffelnet::network_utils::VerifiedOrdering> {
        self.inner.verified_ordering()
    }
}

/// Network adapter for MPC servers that remaps sequential client indices
/// (0, 1, ...) back to transport client IDs for send_to_client().
/// The MPC protocol uses small indices (because session_id only has 8 bits),
/// and the network layer exposes clients in canonical sorted transport order.
struct ServerClientAdapter {
    inner: QuicNetworkManager,
    /// Maps sequential index to transport client ID.
    client_id_map: Vec<ClientId>,
}
#[async_trait::async_trait]
impl Network for ServerClientAdapter {
    type NodeType = <QuicNetworkManager as Network>::NodeType;
    type NetworkConfig = <QuicNetworkManager as Network>::NetworkConfig;

    async fn send(
        &self,
        recipient: stoffelnet::network_utils::PartyId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        self.inner.send(recipient, message).await
    }

    async fn broadcast(
        &self,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        self.inner.broadcast(message).await
    }

    fn parties(&self) -> Vec<&Self::NodeType> {
        self.inner.parties()
    }

    fn parties_mut(&mut self) -> Vec<&mut Self::NodeType> {
        self.inner.parties_mut()
    }

    fn config(&self) -> &Self::NetworkConfig {
        self.inner.config()
    }

    fn node(&self, id: stoffelnet::network_utils::PartyId) -> Option<&Self::NodeType> {
        self.inner.node(id)
    }

    fn node_mut(&mut self, id: stoffelnet::network_utils::PartyId) -> Option<&mut Self::NodeType> {
        self.inner.node_mut(id)
    }

    async fn send_to_client(
        &self,
        client: ClientId,
        message: &[u8],
    ) -> Result<usize, stoffelnet::network_utils::NetworkError> {
        // Remap sequential index to the canonical transport client ID.
        let transport_id = self.client_id_map.get(client).copied().unwrap_or(client);
        self.inner.send_to_client(transport_id, message).await
    }

    fn clients(&self) -> Vec<ClientId> {
        self.inner.clients()
    }

    fn is_client_connected(&self, client: ClientId) -> bool {
        let transport_id = self.client_id_map.get(client).copied().unwrap_or(client);
        self.inner.is_client_connected(transport_id)
    }

    fn local_party_id(&self) -> stoffelnet::network_utils::PartyId {
        self.inner.local_party_id()
    }

    fn party_count(&self) -> usize {
        self.inner.party_count()
    }

    fn verified_ordering(&self) -> Option<stoffelnet::network_utils::VerifiedOrdering> {
        self.inner.verified_ordering()
    }
}

fn is_flag_present(raw_args: &[String], flag: &str) -> bool {
    raw_args
        .iter()
        .any(|arg| arg == flag || arg.starts_with(&format!("{flag}=")))
}

fn fail_removed_flag(raw_args: &[String], old_flag: &str, replacement_hint: &str) {
    if is_flag_present(raw_args, old_flag) {
        eprintln!("Error: `{}` was removed. {}", old_flag, replacement_hint);
        exit(2);
    }
}

fn print_vm_result(vm: &mut VirtualMachine, result: Value) {
    let result = if matches!(result, Value::Share(_, _)) && vm.mpc_runtime_info().is_some() {
        eprintln!("Program returned a secret share, revealing...");
        match vm.open_share_value(&result) {
            Ok(revealed) => revealed,
            Err(e) => {
                eprintln!("Failed to reveal returned share: {}", e);
                result
            }
        }
    } else {
        result
    };

    match &result {
        Value::Array(arr_ref) => {
            if let Some(bytes) = vm
                .read_byte_array(&Value::from(*arr_ref))
                .ok()
                .filter(|bytes| !bytes.is_empty())
            {
                let hex: String = bytes.iter().map(|b| format!("{:02x}", b)).collect();
                println!("Program returned: byte[{}] 0x{}", bytes.len(), hex);
            } else {
                println!("Program returned: {}", format_vm_value(vm, &result, 4));
            }
        }
        _ => println!("Program returned: {}", format_vm_value(vm, &result, 4)),
    }
}

fn format_vm_value(vm: &mut VirtualMachine, value: &Value, max_depth: usize) -> String {
    let mut active_tables = HashSet::new();
    format_vm_value_inner(vm, value, max_depth, &mut active_tables)
}

fn format_vm_value_inner(
    vm: &mut VirtualMachine,
    value: &Value,
    max_depth: usize,
    active_tables: &mut HashSet<TableRef>,
) -> String {
    match value {
        Value::I64(i) => i.to_string(),
        Value::I32(i) => i.to_string(),
        Value::I16(i) => i.to_string(),
        Value::I8(i) => i.to_string(),
        Value::U64(i) => i.to_string(),
        Value::U32(i) => i.to_string(),
        Value::U16(i) => i.to_string(),
        Value::U8(i) => i.to_string(),
        Value::Float(fp) => fp.0.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::String(s) => format!("\"{}\"", s),
        Value::Unit => "()".to_string(),
        Value::Closure(c) => format!("Function({})", c.function_id()),
        Value::Foreign(foreign_ref) => format!("Foreign({})", foreign_ref.id()),
        Value::Share(share_type, _) => format!("Share({:?})", share_type),
        Value::Array(array_ref) => {
            let table_ref = TableRef::from(*array_ref);
            if !active_tables.insert(table_ref) {
                return format!("Array({}) <cycle>", array_ref.id());
            }
            let formatted = format_vm_array(vm, *array_ref, max_depth, active_tables);
            active_tables.remove(&table_ref);
            formatted
        }
        Value::Object(object_ref) => {
            let table_ref = TableRef::from(*object_ref);
            if !active_tables.insert(table_ref) {
                return format!("Object({}) <cycle>", object_ref.id());
            }
            let formatted = format_vm_object(vm, *object_ref, max_depth, active_tables);
            active_tables.remove(&table_ref);
            formatted
        }
    }
}

fn format_vm_array(
    vm: &mut VirtualMachine,
    array_ref: stoffel_vm_types::core_types::ArrayRef,
    max_depth: usize,
    active_tables: &mut HashSet<TableRef>,
) -> String {
    let len = match vm.read_array_len(array_ref) {
        Ok(len) => len,
        Err(error) => return format!("Array({}) <error: {}>", array_ref.id(), error),
    };
    if max_depth == 0 {
        return format!("[...{} elements]", len);
    }

    let display_count = len.min(64);
    let mut parts = Vec::with_capacity(display_count);
    for index in 0..display_count {
        let key = Value::I64(index as i64);
        let value = match vm.read_table_field(TableRef::from(array_ref), &key) {
            Ok(Some(value)) => value,
            Ok(None) => Value::Unit,
            Err(error) => {
                parts.push(format!("<error: {}>", error));
                continue;
            }
        };
        parts.push(format_vm_value_inner(
            vm,
            &value,
            max_depth - 1,
            active_tables,
        ));
    }

    if len > display_count {
        format!("[{}, ...({} more)]", parts.join(", "), len - display_count)
    } else {
        format!("[{}]", parts.join(", "))
    }
}

fn format_vm_object(
    vm: &mut VirtualMachine,
    object_ref: stoffel_vm_types::core_types::ObjectRef,
    max_depth: usize,
    active_tables: &mut HashSet<TableRef>,
) -> String {
    let entries = match vm.read_object_entries(object_ref, 64) {
        Ok(entries) => entries,
        Err(error) => return format!("Object({}) <error: {}>", object_ref.id(), error),
    };
    if max_depth == 0 {
        return format!("{{...{} fields}}", entries.len());
    }

    let mut parts = Vec::with_capacity(entries.len());
    for (key, value) in entries {
        let key = format_vm_value_inner(vm, &key, max_depth - 1, active_tables);
        let value = format_vm_value_inner(vm, &value, max_depth - 1, active_tables);
        parts.push(format!("{}: {}", key, value));
    }
    format!("{{{}}}", parts.join(", "))
}
fn coordinator_output_share_bytes(vm: &mut VirtualMachine, result: &Value) -> Option<Vec<u8>> {
    vm.read_share_object(result)
        .ok()
        .map(|(_ty, share_data)| share_data.as_bytes().to_vec())
}
fn parse_inputs_as_field<F: PrimeField>(inputs_str: &str) -> Vec<F> {
    // An output-only client has no inputs.
    if inputs_str.trim().is_empty() {
        return Vec::new();
    }
    inputs_str
        .split(',')
        .map(|s| {
            let s = s.trim();
            if let Some(hex_value) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
                let mut hex_value = hex_value.to_owned();
                if hex_value.len() % 2 == 1 {
                    hex_value.insert(0, '0');
                }
                let bytes = hex::decode(&hex_value).unwrap_or_else(|error| {
                    eprintln!("Invalid hex input value '{}': {}", s, error);
                    exit(2);
                });
                return F::from_be_bytes_mod_order(&bytes);
            }

            let val: i64 = s.parse().unwrap_or_else(|_| {
                eprintln!("Invalid input value: {}", s);
                exit(2);
            });
            stoffel_vm::net::field_from_i64::<F>(val)
        })
        .collect()
}
fn field_outputs_to_hex<F: PrimeField>(outputs: &[F], curve_config: MpcCurveConfig) -> String {
    let mut bytes = Vec::new();
    for output in outputs {
        if matches!(
            curve_config,
            MpcCurveConfig::Secp256k1 | MpcCurveConfig::Secp256r1
        ) {
            bytes.extend_from_slice(&fixed_width_be_bytes(
                &output.into_bigint().to_bytes_be(),
                32,
            ));
        } else {
            ark_serialize::CanonicalSerialize::serialize_compressed(output, &mut bytes)
                .expect("field serialization to Vec cannot fail");
        }
    }
    hex::encode(bytes)
}
fn fixed_width_be_bytes(bytes: &[u8], width: usize) -> Vec<u8> {
    let significant = bytes
        .iter()
        .position(|byte| *byte != 0)
        .map(|idx| &bytes[idx..])
        .unwrap_or(&[]);
    if significant.len() >= width {
        significant[significant.len() - width..].to_vec()
    } else {
        let mut out = vec![0u8; width - significant.len()];
        out.extend_from_slice(significant);
        out
    }
}

/// Connect to all MPC servers with retry logic, spawning a receive loop per connection.
async fn connect_to_all_servers(
    network: &Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    server_addrs: &[SocketAddr],
    msg_tx: mpsc::Sender<(usize, Vec<u8>)>,
) {
    let max_retries = 10;
    let retry_delay = Duration::from_millis(500);
    let mut connected_servers = Vec::with_capacity(server_addrs.len());

    for (server_idx, &addr) in server_addrs.iter().enumerate() {
        let mut retry_count = 0;

        loop {
            eprintln!(
                "[client] Connecting to server {} at {} (attempt {}/{})",
                server_idx,
                addr,
                retry_count + 1,
                max_retries
            );

            let connection_result = {
                let mut net = network.lock().await;
                net.connect_as_client(addr).await
            };

            match connection_result {
                Ok(connection) => {
                    eprintln!("[client] Connected to server {} at {}", server_idx, addr);
                    connected_servers.push((addr, connection));
                    break;
                }
                Err(e) => {
                    retry_count += 1;
                    if retry_count >= max_retries {
                        eprintln!(
                            "[client] Failed to connect to server {} at {} after {} attempts: {}",
                            server_idx, addr, retry_count, e
                        );
                        exit(21);
                    }
                    eprintln!(
                        "[client] Connection attempt {} failed: {}, retrying...",
                        retry_count, e
                    );
                    tokio::time::sleep(retry_delay).await;
                }
            }
        }
    }

    let (assigned_party_ids, local_party_id) = {
        let net = network.lock().await;
        let assigned = net.assign_party_ids();
        let local = net.compute_local_party_id();
        (assigned, local)
    };
    eprintln!(
        "[client] Assigned authenticated party IDs for {} connections",
        assigned_party_ids
    );

    let mut seen_peers = HashSet::new();
    for (addr, connection) in connected_servers {
        let authenticated_peer = connection.remote_party_id().unwrap_or_else(|| {
            eprintln!(
                "[client] Connected server {} has no authenticated party identity",
                addr
            );
            exit(24);
        });
        let peer = local_party_id.map_or(authenticated_peer, |local_id| {
            if authenticated_peer == local_id {
                eprintln!(
                    "[client] Connected server {} resolved to local authenticated identity {}",
                    addr, authenticated_peer
                );
                exit(24);
            }
            if authenticated_peer > local_id {
                authenticated_peer - 1
            } else {
                authenticated_peer
            }
        });

        if !seen_peers.insert(peer) {
            eprintln!(
                "[client] Duplicate authenticated party identity {} detected for server {}",
                peer, addr
            );
            exit(24);
        }

        let tx = msg_tx.clone();
        tokio::spawn(async move {
            loop {
                match connection.receive().await {
                    Ok(data) => {
                        if let Err(e) = tx.send((peer, data)).await {
                            eprintln!("[client] Failed to forward message: {:?}", e);
                            break;
                        }
                    }
                    Err(e) => {
                        eprintln!("[client] Connection to server {} closed: {}", peer, e);
                        break;
                    }
                }
            }
        });
    }
}
const CLIENT_SET_SYNC_PREFIX: &[u8; 4] = b"CSS1";
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ClientSetSyncMessage {
    sender_party_id: usize,
    client_ids: Vec<ClientId>,
}
fn normalize_client_ids(mut ids: Vec<ClientId>) -> Vec<ClientId> {
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn input_client_ids_from_output_ids(
    output_ids: &[Vec<u8>],
    client_roster: &[usize],
    client_input_slots: &[usize],
    client_input_count: usize,
) -> Vec<Vec<u8>> {
    if client_input_count == 0 {
        return Vec::new();
    }
    if client_input_slots.is_empty() {
        return output_ids.to_vec();
    }

    let input_slots = client_input_slots.iter().copied().collect::<HashSet<_>>();
    output_ids
        .iter()
        .enumerate()
        .filter_map(|(ordinal, client_id)| {
            let slot = client_roster.get(ordinal).copied().unwrap_or(ordinal);
            input_slots.contains(&slot).then(|| client_id.clone())
        })
        .collect()
}

fn encode_client_set_sync(msg: &ClientSetSyncMessage) -> Result<Vec<u8>, String> {
    let payload = bincode::serialize(msg)
        .map_err(|e| format!("Failed to serialize client-set sync payload: {}", e))?;
    let mut out = Vec::with_capacity(CLIENT_SET_SYNC_PREFIX.len() + payload.len());
    out.extend_from_slice(CLIENT_SET_SYNC_PREFIX);
    out.extend_from_slice(&payload);
    Ok(out)
}
fn decode_client_set_sync(bytes: &[u8]) -> Result<ClientSetSyncMessage, String> {
    if bytes.len() < CLIENT_SET_SYNC_PREFIX.len()
        || &bytes[..CLIENT_SET_SYNC_PREFIX.len()] != CLIENT_SET_SYNC_PREFIX
    {
        return Err("Unexpected message prefix while waiting for client-set sync".to_string());
    }

    bincode::deserialize(&bytes[CLIENT_SET_SYNC_PREFIX.len()..])
        .map_err(|e| format!("Failed to deserialize client-set sync payload: {}", e))
}
async fn sync_client_set_across_parties(
    net: Arc<QuicNetworkManager>,
    my_id: usize,
    n_parties: usize,
    local_client_ids: &[ClientId],
) -> Result<(), String> {
    if n_parties <= 1 {
        return Ok(());
    }

    let normalized_local = normalize_client_ids(local_client_ids.to_vec());
    let sync_payload = encode_client_set_sync(&ClientSetSyncMessage {
        sender_party_id: my_id,
        client_ids: normalized_local.clone(),
    })?;

    eprintln!(
        "[party {}] Broadcasting client-set sync payload: {:?}",
        my_id, normalized_local
    );

    for peer_id in 0..n_parties {
        if peer_id == my_id {
            continue;
        }
        net.send(peer_id, &sync_payload)
            .await
            .map_err(|e| format!("Failed to send client-set sync to party {}: {}", peer_id, e))?;
    }

    let mut confirmed_parties: HashSet<usize> = HashSet::new();
    let expected_confirmations = n_parties - 1;
    let receive_deadline = std::time::Instant::now() + Duration::from_secs(20);

    while confirmed_parties.len() < expected_confirmations {
        if std::time::Instant::now() >= receive_deadline {
            return Err(format!(
                "Timed out waiting for client-set sync confirmations ({}/{})",
                confirmed_parties.len(),
                expected_confirmations
            ));
        }

        let mut progressed = false;
        for (derived_id, connection) in net.get_all_server_connections() {
            let sender_id = connection.remote_party_id().unwrap_or(derived_id);
            if sender_id >= n_parties
                || sender_id == my_id
                || confirmed_parties.contains(&sender_id)
            {
                continue;
            }

            let remaining = receive_deadline.saturating_duration_since(std::time::Instant::now());
            let wait_for = remaining.min(Duration::from_millis(500));
            if wait_for.is_zero() {
                continue;
            }

            match tokio::time::timeout(wait_for, connection.receive()).await {
                Ok(Ok(data)) => {
                    let sync = decode_client_set_sync(&data).map_err(|e| {
                        format!(
                            "Failed to decode client-set sync from party {}: {}",
                            sender_id, e
                        )
                    })?;

                    if sync.sender_party_id != sender_id {
                        return Err(format!(
                            "Client-set sync sender mismatch: transport sender={} payload sender={}",
                            sender_id, sync.sender_party_id
                        ));
                    }

                    let normalized_remote = normalize_client_ids(sync.client_ids);
                    if normalized_remote != normalized_local {
                        return Err(format!(
                            "Client-set mismatch with party {}: local={:?}, remote={:?}",
                            sender_id, normalized_local, normalized_remote
                        ));
                    }

                    confirmed_parties.insert(sender_id);
                    progressed = true;
                    eprintln!(
                        "[party {}] Client-set sync confirmed with party {}",
                        my_id, sender_id
                    );
                }
                Ok(Err(e)) => {
                    return Err(format!(
                        "Failed to receive client-set sync from party {}: {}",
                        sender_id, e
                    ));
                }
                Err(_) => {}
            }
        }

        if !progressed {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    eprintln!(
        "[party {}] Client-set sync complete with {} peers",
        my_id, expected_confirmations
    );
    Ok(())
}
struct HbClientProtocolConfig {
    n: usize,
    t: usize,
    /// Number of input values this client contributes (0 for an output-only client).
    input_len: usize,
    /// Number of output values this client receives via `send_to_client` (0 for
    /// an input-only client).
    output_len: usize,
    instance_id: u64,
    client_index: u8,
    local_position: usize,
    curve_config: MpcCurveConfig,
}
struct AvssClientProtocolConfig {
    n: usize,
    t: usize,
    output_len: usize,
    instance_id: u64,
    client_index: u8,
    local_position: usize,
    curve_config: MpcCurveConfig,
}
async fn run_hb_client_protocol_for_curve<F: PrimeField>(
    config: HbClientProtocolConfig,
    inputs_str: &str,
    network_for_process: Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    mut msg_rx: mpsc::Receiver<(usize, Vec<u8>)>,
) -> Result<(), String> {
    let instance_id = honeybadger_protocol_instance_id(config.instance_id);
    // Use the sequential client_index (0, 1, ...) as the MPC identity,
    // not the transport-derived cid, because the session_id only has
    // 8 bits for the client_id field.
    let mpc_cid = config.client_index as usize;
    // A client with no inputs is an output-only client: it does not run the
    // input protocol, it only waits for the servers to deliver its output
    // shares and reconstructs them. The `OutputClient` is sized by the number
    // of outputs the client receives; an input client keeps its prior sizing.
    let is_output_only = config.input_len == 0;
    let output_client_len = if is_output_only {
        config.output_len
    } else {
        config.input_len
    };
    let mut mpc_client = HoneyBadgerMPCClient::<F, Avid<HbSessionId>>::new(
        mpc_cid,
        config.n,
        config.t,
        instance_id,
        parse_inputs_as_field::<F>(inputs_str),
        output_client_len,
    )
    .map_err(|e| format!("Failed to create MPC client: {:?}", e))?;

    let mut messages_processed = 0usize;
    while let Some((sender_id, data)) = msg_rx.recv().await {
        // Skip INST messages from other servers (already consumed the first one)
        if data.len() == 13 && data.starts_with(b"INST") {
            eprintln!(
                "[client {}] Skipping extra INST from sender {}",
                mpc_cid, sender_id
            );
            continue;
        }
        eprintln!(
            "[client {}] Received {} bytes from sender {} (raw)",
            mpc_cid,
            data.len(),
            sender_id
        );

        let adapter = {
            let guard = network_for_process.lock().await;
            ClientNetworkAdapter {
                inner: (*guard).clone(),
                local_position: config.local_position,
            }
        };

        match mpc_client.process(sender_id, data, Arc::new(adapter)).await {
            Ok(()) => {
                messages_processed += 1;
                eprintln!(
                    "[client {}] Successfully processed message #{} from server {}",
                    mpc_cid, messages_processed, sender_id
                );
                // Output-only client: finish as soon as the output shares
                // reconstruct (>= 2t+1 received).
                if is_output_only {
                    if let Some(outputs) = mpc_client.output.get_output() {
                        let output_hex = field_outputs_to_hex(&outputs, config.curve_config);
                        println!("Client output: field[{}] 0x{}", outputs.len(), output_hex);
                        eprintln!(
                            "[client {}] Reconstructed {} output value(s)",
                            mpc_cid,
                            outputs.len()
                        );
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                eprintln!(
                    "[client {}] Failed to process message from {}: {:?}",
                    mpc_cid, sender_id, e
                );
            }
        }

        if !is_output_only && messages_processed >= config.n {
            // Input client: keep the connection alive long enough for servers
            // to drain their preprocessing backlog and process our masked input.
            eprintln!(
                "[client {}] Input protocol complete, holding connection for 300s...",
                mpc_cid
            );
            tokio::time::sleep(Duration::from_secs(300)).await;
            break;
        }
    }

    if is_output_only {
        return Err(format!(
            "HB output client receiver closed before output reconstruction (processed {messages_processed} messages)"
        ));
    }

    eprintln!(
        "[client {}] Message processing done ({} messages)",
        mpc_cid, messages_processed
    );
    Ok(())
}
async fn run_avss_client_protocol_for_curve<F, G>(
    config: AvssClientProtocolConfig,
    inputs_str: &str,
    network_for_process: Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    mut msg_rx: mpsc::Receiver<(usize, Vec<u8>)>,
) -> Result<(), String>
where
    F: PrimeField,
    G: CurveGroup<ScalarField = F>,
{
    let mpc_cid = config.client_index as usize;
    let instance_id = avss_protocol_instance_id(config.instance_id);
    let mut mpc_client = AvssMPCClient::<F, Avid<AvssSessionId>, G>::new(
        mpc_cid,
        config.n,
        config.t,
        instance_id,
        parse_inputs_as_field::<F>(inputs_str),
        config.output_len,
    )
    .map_err(|e| format!("Failed to create AVSS MPC client: {:?}", e))?;

    let mut messages_processed = 0usize;
    while let Some((sender_id, data)) = msg_rx.recv().await {
        eprintln!(
            "[client {}] Received {} AVSS bytes from sender {}",
            mpc_cid,
            data.len(),
            sender_id
        );
        if data.len() == 13 && data.starts_with(b"INST") {
            eprintln!(
                "[client {}] Skipping extra INST from sender {}",
                mpc_cid, sender_id
            );
            continue;
        }

        let adapter = {
            let guard = network_for_process.lock().await;
            ClientNetworkAdapter {
                inner: (*guard).clone(),
                local_position: config.local_position,
            }
        };

        match mpc_client.process(sender_id, data, Arc::new(adapter)).await {
            Ok(()) => {
                messages_processed += 1;
                if let Some(outputs) = mpc_client.output.get_output() {
                    let output_hex = field_outputs_to_hex(&outputs, config.curve_config);
                    println!("Client output: field[{}] 0x{}", outputs.len(), output_hex);
                    return Ok(());
                }
            }
            Err(e) => {
                eprintln!(
                    "[client {}] Failed to process AVSS message from {}: {:?}",
                    mpc_cid, sender_id, e
                );
            }
        }
    }

    Err(format!(
        "AVSS client receiver closed before output reconstruction (processed {} messages)",
        messages_processed
    ))
}
async fn run_avss_client_for_curve(
    curve_config: MpcCurveConfig,
    config: AvssClientProtocolConfig,
    inputs_str: &str,
    network_for_process: Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    msg_rx: mpsc::Receiver<(usize, Vec<u8>)>,
) -> Result<(), String> {
    match curve_config {
        MpcCurveConfig::Bls12_381 => {
            run_avss_client_protocol_for_curve::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>(
                config,
                inputs_str,
                network_for_process,
                msg_rx,
            )
            .await
        }
        MpcCurveConfig::Bn254 => {
            run_avss_client_protocol_for_curve::<ark_bn254::Fr, ark_bn254::G1Projective>(
                config,
                inputs_str,
                network_for_process,
                msg_rx,
            )
            .await
        }
        MpcCurveConfig::Curve25519 => {
            run_avss_client_protocol_for_curve::<
                ark_curve25519::Fr,
                ark_curve25519::EdwardsProjective,
            >(config, inputs_str, network_for_process, msg_rx)
            .await
        }
        MpcCurveConfig::Ed25519 => {
            run_avss_client_protocol_for_curve::<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>(
                config,
                inputs_str,
                network_for_process,
                msg_rx,
            )
            .await
        }
        MpcCurveConfig::Secp256k1 => {
            run_avss_client_protocol_for_curve::<ark_secp256k1::Fr, ark_secp256k1::Projective>(
                config,
                inputs_str,
                network_for_process,
                msg_rx,
            )
            .await
        }
        MpcCurveConfig::Secp256r1 => {
            run_avss_client_protocol_for_curve::<ark_secp256r1::Fr, ark_secp256r1::Projective>(
                config,
                inputs_str,
                network_for_process,
                msg_rx,
            )
            .await
        }
    }
}
async fn run_hb_client_for_curve(
    curve_config: MpcCurveConfig,
    config: HbClientProtocolConfig,
    inputs_str: &str,
    network_for_process: Arc<tokio::sync::Mutex<QuicNetworkManager>>,
    msg_rx: mpsc::Receiver<(usize, Vec<u8>)>,
) -> Result<(), String> {
    match curve_config {
        MpcCurveConfig::Bls12_381 => {
            run_hb_client_protocol_for_curve::<ark_bls12_381::Fr>(
                config,
                inputs_str,
                network_for_process,
                msg_rx,
            )
            .await
        }
        MpcCurveConfig::Bn254 => {
            run_hb_client_protocol_for_curve::<ark_bn254::Fr>(
                config,
                inputs_str,
                network_for_process,
                msg_rx,
            )
            .await
        }
        MpcCurveConfig::Curve25519 => {
            run_hb_client_protocol_for_curve::<ark_curve25519::Fr>(
                config,
                inputs_str,
                network_for_process,
                msg_rx,
            )
            .await
        }
        MpcCurveConfig::Ed25519 => {
            run_hb_client_protocol_for_curve::<ark_ed25519::Fr>(
                config,
                inputs_str,
                network_for_process,
                msg_rx,
            )
            .await
        }
        MpcCurveConfig::Secp256k1 | MpcCurveConfig::Secp256r1 => Err(format!(
            "client mode with honeybadger backend does not support curve {}",
            curve_config.name()
        )),
    }
}
async fn run_as_client(
    n_parties: Option<usize>,
    threshold: Option<usize>,
    mpc_backend: Option<&str>,
    mpc_curve: Option<&str>,
    client_inputs: Option<String>,
    client_outputs: Option<usize>,
    server_addrs: Vec<SocketAddr>,
) {
    let n = n_parties.unwrap_or_else(|| {
        eprintln!("Error: --n-parties is required in client mode");
        exit(2);
    });
    let t = threshold.unwrap_or(1);

    let backend_kind = if let Some(backend_name) = mpc_backend {
        MpcBackendKind::from_str(backend_name).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            exit(2);
        })
    } else {
        MpcBackendKind::default_backend()
    };

    // A client may be an input client (provides `--inputs`), an output-only
    // client (provides `--outputs` and no inputs, e.g. a result recipient), or
    // both. `--inputs` is therefore optional.
    let inputs_str = client_inputs.unwrap_or_default();
    let input_len = if inputs_str.trim().is_empty() {
        0
    } else {
        inputs_str.split(',').count()
    };
    let output_len = client_outputs.unwrap_or(input_len);
    if input_len == 0 && output_len == 0 {
        eprintln!(
            "Error: a client must either provide --inputs (comma-separated values) or receive \
             outputs via --outputs <N> in client mode"
        );
        exit(2);
    }

    if server_addrs.is_empty() {
        eprintln!("Error: --servers is required in client mode (comma-separated addresses)");
        eprintln!("Example: --servers 172.18.0.2:9000,172.18.0.3:9000,172.18.0.4:9000,172.18.0.5:9000,172.18.0.6:9000");
        exit(2);
    }

    if server_addrs.len() != n {
        eprintln!(
            "Warning: number of servers ({}) doesn't match n_parties ({})",
            server_addrs.len(),
            n
        );
    }

    let curve_config = if let Some(name) = mpc_curve {
        MpcCurveConfig::from_str(name).unwrap_or_else(|e| {
            eprintln!("Error: {}", e);
            exit(2);
        })
    } else {
        MpcCurveConfig::default()
    };

    if let Err(e) = curve_config.validate_for_backend(backend_kind) {
        eprintln!("Error: {}", e);
        exit(2);
    }

    eprintln!(
        "[client] Client mode (backend={}, curve={}, n={}, t={}, {} inputs, {} outputs, {} servers)",
        backend_kind.name(),
        curve_config.name(),
        n,
        t,
        input_len,
        output_len,
        server_addrs.len()
    );

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto");

    let network = Arc::new(tokio::sync::Mutex::new(QuicNetworkManager::new()));

    for (party_id, &addr) in server_addrs.iter().enumerate() {
        network.lock().await.add_node_with_party_id(party_id, addr);
        eprintln!("[client] Added server party {} at {}", party_id, addr);
    }

    let (msg_tx, mut msg_rx) = mpsc::channel::<(usize, Vec<u8>)>(1000);

    eprintln!("[client] Connecting to {} servers...", server_addrs.len());
    connect_to_all_servers(&network, &server_addrs, msg_tx.clone()).await;

    let cid = {
        let net = network.lock().await;
        net.local_derived_id()
    };
    eprintln!("[client {}] Derived transport client ID", cid);

    // Read INST message from servers: [b"INST" | instance_id:u64 | client_index:u8]
    let (instance_id, client_index, pending_messages) = {
        let timeout_dur = Duration::from_secs(600);
        let mut result: Option<(u64, u8)> = None;
        let mut pending_messages = Vec::new();
        let deadline = tokio::time::Instant::now() + timeout_dur;
        while result.is_none() {
            match tokio::time::timeout_at(deadline, msg_rx.recv()).await {
                Ok(Some((sender, data))) => {
                    if data.len() == 13 && &data[0..4] == b"INST" {
                        let id_bytes: [u8; 8] = data[4..12].try_into().unwrap();
                        let inst_id = u64::from_le_bytes(id_bytes);
                        let idx = data[12];
                        result = Some((inst_id, idx));
                    } else {
                        pending_messages.push((sender, data));
                    }
                }
                Ok(None) => {
                    eprintln!("[client {}] Channel closed before receiving INST", cid);
                    exit(25);
                }
                Err(_) => {
                    eprintln!("[client {}] Timeout waiting for INST from server", cid);
                    exit(25);
                }
            }
        }
        let (id, idx) = result.unwrap();
        eprintln!(
            "[client {}] Received INST: instance_id={}, client_index={}",
            cid, id, idx
        );
        (id, idx, pending_messages)
    };

    eprintln!(
        "[client {}] Connected to all servers, starting input protocol...",
        cid
    );

    // Get the client's position in the (n+1)-key sorted list so we can
    // remap party IDs when sending (skip our own slot).
    let local_position = {
        let net = network.lock().await;
        net.compute_local_party_id().unwrap_or(0)
    };
    eprintln!(
        "[client {}] Local position in sorted key list: {}",
        cid, local_position
    );

    let msg_rx = if pending_messages.is_empty() {
        msg_rx
    } else {
        eprintln!(
            "[client {}] Replaying {} protocol messages received before INST",
            cid,
            pending_messages.len()
        );
        let (replay_tx, replay_rx) = mpsc::channel::<(usize, Vec<u8>)>(1000);
        tokio::spawn(async move {
            for message in pending_messages {
                if replay_tx.send(message).await.is_err() {
                    return;
                }
            }
            while let Some(message) = msg_rx.recv().await {
                if replay_tx.send(message).await.is_err() {
                    return;
                }
            }
        });
        replay_rx
    };

    let network_for_process = network.clone();
    let inputs_for_task = inputs_str.clone();
    let process_handle = match backend_kind {
        MpcBackendKind::HoneyBadger => {
            let protocol_config = HbClientProtocolConfig {
                n,
                t,
                input_len,
                output_len,
                instance_id,
                client_index,
                local_position,
                curve_config,
            };
            tokio::spawn(async move {
                run_hb_client_for_curve(
                    curve_config,
                    protocol_config,
                    &inputs_for_task,
                    network_for_process,
                    msg_rx,
                )
                .await
            })
        }
        MpcBackendKind::Avss => {
            let protocol_config = AvssClientProtocolConfig {
                n,
                t,
                output_len,
                instance_id,
                client_index,
                local_position,
                curve_config,
            };
            tokio::spawn(async move {
                run_avss_client_for_curve(
                    curve_config,
                    protocol_config,
                    &inputs_for_task,
                    network_for_process,
                    msg_rx,
                )
                .await
            })
        }
    };

    let timeout_duration = Duration::from_secs(600);
    match tokio::time::timeout(timeout_duration, process_handle).await {
        Ok(Ok(Ok(()))) => {
            eprintln!(
                "[client {}] Successfully submitted inputs to MPC network",
                cid
            );
        }
        Ok(Ok(Err(e))) => {
            eprintln!("[client {}] Input protocol failed: {}", cid, e);
            exit(22);
        }
        Ok(Err(e)) => {
            eprintln!("[client {}] Input task error: {:?}", cid, e);
            exit(22);
        }
        Err(_) => {
            eprintln!(
                "[client {}] Timeout waiting for input protocol to complete",
                cid
            );
            exit(23);
        }
    }
}
struct AvssOffchainCoordinatorClientArgs {
    curve_config: MpcCurveConfig,
    client_inputs: Option<String>,
    client_outputs: Option<usize>,
    output_format: CoordinatorOutputFormat,
    server_addrs: Vec<SocketAddr>,
    coord_addr: (String, u16),
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    threshold: Option<usize>,
    coordinator_client_index: Option<u64>,
}
async fn run_avss_offchain_coordinator_client_for_curve<F, G>(
    args: AvssOffchainCoordinatorClientArgs,
) where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + Send + Sync + 'static,
{
    let AvssOffchainCoordinatorClientArgs {
        curve_config,
        client_inputs,
        client_outputs,
        output_format: _output_format,
        server_addrs,
        coord_addr,
        cert_der,
        key_der,
        threshold,
        coordinator_client_index,
    } = args;

    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto");

    let t = threshold.unwrap_or(1);
    let input_str = client_inputs.unwrap_or_else(|| {
        eprintln!("Error: --inputs required in coordinator client mode");
        exit(2);
    });
    let input_values = parse_inputs_as_field::<F>(&input_str);
    if input_values.is_empty() {
        eprintln!("Error: coordinator client mode requires at least one input value");
        exit(2);
    }
    let output_len = client_outputs.unwrap_or(input_values.len());
    let reserved_index = coordinator_client_index.unwrap_or_else(|| {
        eprintln!(
            "Error: coordinator client mode requires --client-index to claim a reserved input slot"
        );
        exit(2);
    });

    let mut coord: AvssOffChainCoordinator<F, G> =
        AvssOffChainCoordinator::<F, G>::start_rpc_client(
            &coord_addr.0,
            coord_addr.1,
            t as u64,
            server_addrs.len() as u64,
            output_len as u64,
            cert_der.clone(),
            key_der.clone(),
        )
        .await
        .unwrap_or_else(|error| {
            eprintln!("Failed to connect to AVSS off-chain coordinator: {error}");
            exit(13);
        });

    coord.wait_for_round(Round::Preprocessing).await.unwrap();
    coord
        .wait_for_round(Round::InputMaskReservation)
        .await
        .unwrap();
    for offset in 0..input_values.len() {
        let index = reserved_index + offset as u64;
        eprintln!("[client slot {index}] reserving input mask");
        coord.reserve_mask_index(index).await.unwrap();
    }

    let rpc_addrs: Vec<(String, u16)> = server_addrs
        .iter()
        .map(|addr| (addr.ip().to_string(), addr.port()))
        .collect();
    let node_rpc_client: AvssOffChainNodeRpcClient<F, G> =
        AvssOffChainNodeRpcClient::<F, G>::start_rpc_client(
            rpc_addrs.len(),
            t,
            rpc_addrs,
            cert_der,
            key_der,
        )
        .await
        .unwrap_or_else(|error| {
            eprintln!("Failed to connect to AVSS node RPC servers: {error}");
            exit(13);
        });
    let mut masks = Vec::with_capacity(input_values.len());
    for offset in 0..input_values.len() {
        let index = reserved_index + offset as u64;
        eprintln!("[client slot {index}] waiting for mask shares");
        masks.push(node_rpc_client.receive_mask().await.unwrap());
    }

    coord.wait_for_round(Round::InputCollection).await.unwrap();
    for (offset, (input_value, mask)) in input_values.iter().zip(masks).enumerate() {
        let index = reserved_index + offset as u64;
        eprintln!("[client slot {index}] submitting masked input");
        coord
            .send_masked_input(mask + *input_value, index)
            .await
            .unwrap();
    }
    if output_len == 0 {
        eprintln!("[client slot {reserved_index}] input submission complete; no outputs requested");
        return;
    }

    coord.wait_for_round(Round::MPCExecution).await.unwrap();
    coord
        .wait_for_round(Round::OutputDistribution)
        .await
        .unwrap();
    let outputs = coord.obtain_outputs().await.unwrap();
    let output_hex = field_outputs_to_hex(&outputs, curve_config);
    println!("Client output: field[{}] 0x{}", outputs.len(), output_hex);
}
async fn run_avss_offchain_coordinator_client(args: AvssOffchainCoordinatorClientArgs) {
    match args.curve_config {
        MpcCurveConfig::Bls12_381 => {
            run_avss_offchain_coordinator_client_for_curve::<
                ark_bls12_381::Fr,
                ark_bls12_381::G1Projective,
            >(args)
            .await
        }
        MpcCurveConfig::Bn254 => run_avss_offchain_coordinator_client_for_curve::<
            ark_bn254::Fr,
            ark_bn254::G1Projective,
        >(args)
        .await,
        MpcCurveConfig::Curve25519 => {
            run_avss_offchain_coordinator_client_for_curve::<
                ark_curve25519::Fr,
                ark_curve25519::EdwardsProjective,
            >(args)
            .await
        }
        MpcCurveConfig::Ed25519 => {
            run_avss_offchain_coordinator_client_for_curve::<
                ark_ed25519::Fr,
                ark_ed25519::EdwardsProjective,
            >(args)
            .await
        }
        MpcCurveConfig::Secp256k1 => {
            run_avss_offchain_coordinator_client_for_curve::<
                ark_secp256k1::Fr,
                ark_secp256k1::Projective,
            >(args)
            .await
        }
        MpcCurveConfig::Secp256r1 => {
            run_avss_offchain_coordinator_client_for_curve::<
                ark_secp256r1::Fr,
                ark_secp256r1::Projective,
            >(args)
            .await
        }
    }
}
#[allow(clippy::too_many_arguments)]
async fn run_hb_coordinator_client_for_field<F>(
    client_inputs: Option<String>,
    client_outputs: Option<usize>,
    output_format: CoordinatorOutputFormat,
    server_addrs: Vec<SocketAddr>,
    coord_addr: Option<(String, u16)>,
    contract_addr: Option<String>,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    threshold: Option<usize>,
    coordinator_client_index: Option<u64>,
    eth_node_addr: Option<String>,
    wallet_sk_str: Option<String>,
) where
    F: SupportedMpcField,
{
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("install rustls crypto");

    let t = threshold.unwrap_or(1);
    let input_str = client_inputs.expect("--inputs required in client mode");
    let input_values = parse_inputs_as_field::<F>(&input_str);
    if input_values.is_empty() {
        eprintln!("Error: coordinator client mode requires at least one input value");
        exit(2);
    }
    let output_len = client_outputs.unwrap_or(input_values.len());
    let reserved_index = coordinator_client_index.unwrap_or_else(|| {
        eprintln!(
            "Error: coordinator client mode requires --client-index to claim a reserved input slot"
        );
        exit(2);
    });

    if contract_addr.is_some() {
        let _ = (eth_node_addr, wallet_sk_str);
        eprintln!(
            "Error: on-chain coordinator mode is temporarily unavailable in the crates.io-ready build"
        );
        exit(2);
    }

    // Off-chain client mode
    let ca = coord_addr.expect("--off-chain-coord required in off-chain client mode");
    let mut coord: HbOffChainCoordinator<F> = HbOffChainCoordinator::<F>::start_rpc_client(
        &ca.0,
        ca.1,
        t as u64,
        server_addrs.len() as u64,
        output_len as u64,
        cert_der.clone(),
        key_der.clone(),
    )
    .await
    .unwrap_or_else(|error| {
        eprintln!("Failed to connect to off-chain coordinator: {error}");
        exit(13);
    });

    coord.wait_for_round(Round::Preprocessing).await.unwrap();
    coord
        .wait_for_round(Round::InputMaskReservation)
        .await
        .unwrap();
    for offset in 0..input_values.len() {
        let index = reserved_index + offset as u64;
        eprintln!("[client slot {index}] reserving input mask");
        coord.reserve_mask_index(index).await.unwrap();
    }

    let rpc_addrs: Vec<(String, u16)> = server_addrs
        .iter()
        .map(|a| (a.ip().to_string(), a.port()))
        .collect();
    let node_rpc_client: HbOffChainNodeRpcClient<F> =
        HbOffChainNodeRpcClient::<F>::start_rpc_client(
            rpc_addrs.len(),
            t,
            rpc_addrs,
            cert_der,
            key_der,
        )
        .await
        .unwrap_or_else(|error| {
            eprintln!("Failed to connect to node RPC servers: {error}");
            exit(13);
        });
    let mut masks = Vec::with_capacity(input_values.len());
    for offset in 0..input_values.len() {
        let index = reserved_index + offset as u64;
        eprintln!("[client slot {index}] waiting for mask shares");
        masks.push(node_rpc_client.receive_mask().await.unwrap());
    }

    coord.wait_for_round(Round::InputCollection).await.unwrap();
    for (offset, (input_value, mask)) in input_values.iter().zip(masks).enumerate() {
        let index = reserved_index + offset as u64;
        eprintln!("[client slot {index}] submitting masked input");
        coord
            .send_masked_input(mask + *input_value, index)
            .await
            .unwrap();
    }
    if output_len == 0 {
        eprintln!("[client slot {reserved_index}] input submission complete; no outputs requested");
        return;
    }

    coord.wait_for_round(Round::MPCExecution).await.unwrap();
    eprintln!("[client slot {reserved_index}] waiting for output distribution");
    coord
        .wait_for_round(Round::OutputDistribution)
        .await
        .unwrap();
    let outputs = coord.obtain_outputs().await.unwrap();
    println!(
        "outputs: {}",
        format_coordinator_outputs(&outputs, output_format)
    );
}
#[allow(clippy::too_many_arguments)]
async fn run_hb_coordinator_client(
    curve_config: MpcCurveConfig,
    client_inputs: Option<String>,
    client_outputs: Option<usize>,
    output_format: CoordinatorOutputFormat,
    server_addrs: Vec<SocketAddr>,
    coord_addr: Option<(String, u16)>,
    contract_addr: Option<String>,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    threshold: Option<usize>,
    coordinator_client_index: Option<u64>,
    eth_node_addr: Option<String>,
    wallet_sk_str: Option<String>,
) {
    match curve_config {
        MpcCurveConfig::Bls12_381 => {
            run_hb_coordinator_client_for_field::<ark_bls12_381::Fr>(
                client_inputs,
                client_outputs,
                output_format,
                server_addrs,
                coord_addr,
                contract_addr,
                cert_der,
                key_der,
                threshold,
                coordinator_client_index,
                eth_node_addr,
                wallet_sk_str,
            )
            .await
        }
        MpcCurveConfig::Bn254 => {
            run_hb_coordinator_client_for_field::<ark_bn254::Fr>(
                client_inputs,
                client_outputs,
                output_format,
                server_addrs,
                coord_addr,
                contract_addr,
                cert_der,
                key_der,
                threshold,
                coordinator_client_index,
                eth_node_addr,
                wallet_sk_str,
            )
            .await
        }
        MpcCurveConfig::Curve25519 => {
            run_hb_coordinator_client_for_field::<ark_curve25519::Fr>(
                client_inputs,
                client_outputs,
                output_format,
                server_addrs,
                coord_addr,
                contract_addr,
                cert_der,
                key_der,
                threshold,
                coordinator_client_index,
                eth_node_addr,
                wallet_sk_str,
            )
            .await
        }
        MpcCurveConfig::Ed25519 => {
            run_hb_coordinator_client_for_field::<ark_ed25519::Fr>(
                client_inputs,
                client_outputs,
                output_format,
                server_addrs,
                coord_addr,
                contract_addr,
                cert_der,
                key_der,
                threshold,
                coordinator_client_index,
                eth_node_addr,
                wallet_sk_str,
            )
            .await
        }
        MpcCurveConfig::Secp256k1 | MpcCurveConfig::Secp256r1 => {
            eprintln!(
                "Error: curve {} is not supported by honeybadger backend",
                curve_config.name()
            );
            exit(2);
        }
    }
}
struct HbPartySetup<'a> {
    net: Arc<QuicNetworkManager>,
    my_id: usize,
    persistent_identity: DurableIdentityDigest,
    n: usize,
    t: usize,
    instance_id: u64,
    expected_client_count: Option<usize>,
    coordinator_client_count_hint: usize,
    client_input_count: usize,
    client_input_types: &'a std::collections::BTreeMap<usize, Vec<ShareType>>,
    preprocessing_demand: stoffel_vm_types::compiled_binary::PreprocessingDemand,
    program_hash: [u8; 32],
    preproc_store_path: Option<&'a str>,
}
async fn setup_hb_party_for_curve<F, G>(
    vm: &mut VirtualMachine,
    setup: HbPartySetup<'_>,
) -> Result<Arc<HoneyBadgerMpcEngine<F, G>>, String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let HbPartySetup {
        net,
        my_id,
        persistent_identity,
        n,
        t,
        instance_id,
        expected_client_count,
        coordinator_client_count_hint,
        client_input_count,
        client_input_types,
        preprocessing_demand,
        program_hash,
        preproc_store_path,
    } = setup;

    // ---- Phase 1: Wait for clients ----
    let mut input_ids: Vec<ClientId> = Vec::new();

    if let Some(expected_count) = expected_client_count {
        if expected_count == 0 {
            return Err("--wait-for-clients count must be greater than 0".to_string());
        }
        if client_input_count == 0 {
            return Err("--client-input-count must be greater than 0".to_string());
        }

        eprintln!(
            "[party {}] Waiting for {} clients...",
            my_id, expected_count
        );

        let mut accept_net = (*net).clone();
        let accept_party_id = my_id;
        tokio::spawn(async move {
            loop {
                match accept_net.accept().await {
                    Ok(_) => {
                        eprintln!("[party {}] Accepted client connection", accept_party_id);
                    }
                    Err(e) => {
                        eprintln!("[party {}] Accept error: {}", accept_party_id, e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        let connect_timeout = Duration::from_secs(600);
        let check_interval = Duration::from_millis(250);
        let start = std::time::Instant::now();

        loop {
            let mut connected_clients = net.clients();
            connected_clients.sort_unstable();
            connected_clients.dedup();

            eprintln!(
                "[party {}] {} of {} expected clients connected: {:?}",
                my_id,
                connected_clients.len(),
                expected_count,
                connected_clients
            );

            if connected_clients.len() > expected_count {
                return Err(format!(
                    "Expected exactly {} clients, but {} are connected: {:?}",
                    expected_count,
                    connected_clients.len(),
                    connected_clients
                ));
            }

            if connected_clients.len() == expected_count {
                input_ids = connected_clients;
                break;
            }

            if start.elapsed() > connect_timeout {
                return Err(format!(
                    "Timeout waiting for {} clients; connected so far: {:?}",
                    expected_count,
                    net.clients()
                ));
            }

            tokio::time::sleep(check_interval).await;
        }

        eprintln!(
            "[party {}] Using canonical client input IDs: {:?}",
            my_id, input_ids
        );

        sync_client_set_across_parties(net.clone(), my_id, n, &input_ids).await?;
    }

    // ---- Phase 2: Setup MPC node and preprocess ----
    //
    // CRITICAL: We use exactly TWO clones of the MPC node to avoid the
    // double-processing bug where init_ransha() is called multiple times:
    //   - Clone 1 (`processing_node`): handles incoming messages via process()
    //   - Clone 2 (inside `engine`): initiates preprocessing via run_preprocessing()
    // Both share the same Arc<Mutex> stores, but only ONE processes each message.
    // Plan the preprocessing material from the compiler's static demand
    // estimate, rounding each count up to a power of 2 so the generated volume
    // reveals only the program's size octave (privacy), not its exact operation
    // counts. The plan folds in the dependency that prandbit generation consumes
    // a triple + random per bit, and a baseline so light programs still run.
    let client_random_count = input_ids.len().max(coordinator_client_count_hint);
    let n_client_random = client_random_count.saturating_mul(client_input_count);
    let plan = plan_preprocessing(&preprocessing_demand, t, n_client_random);
    let n_triples = plan.n_triples;
    let n_random = plan.n_random;
    let n_prandbit = plan.n_prandbit;
    let n_prandint = plan.n_prandint;
    let protocol_timeout = honeybadger_protocol_timeout();
    eprintln!(
        "[party {}] Creating MPC node opts (n_triples={}, n_random={}, n_prandbit={}, n_prandint={}, dynamic={}, timeout={}s)",
        my_id,
        n_triples,
        n_random,
        n_prandbit,
        n_prandint,
        preprocessing_demand.dynamic,
        protocol_timeout.as_secs()
    );
    let mpc_opts = honeybadger_node_opts_with_truncation(
        n,
        t,
        n_triples,
        n_random,
        n_prandbit,
        n_prandint,
        instance_id,
    )
    .unwrap_or_else(|e| {
        eprintln!("Failed to create MPC node options: {}", e);
        std::process::exit(2);
    });

    // Use sequential indices (0..n_clients) as client IDs for the MPC protocol
    // because the session_id only has 8 bits for the client_id field.
    let mpc_input_ids: Vec<ClientId> = (0..input_ids.len()).collect();
    let mpc_node = <HoneyBadgerMPCNode<F, Avid<HbSessionId>> as MPCProtocol<
        F,
        RobustShare<F>,
        QuicNetworkManager,
    >>::setup(my_id, mpc_opts, mpc_input_ids)
    .map_err(|e| format!("Failed to create MPC node: {:?}", e))?;
    eprintln!("[party {}] MPC node setup complete", my_id);

    // Clone 1: the processing node — MOVED into the processing loop task.
    // This is the ONLY clone that calls process() on incoming messages.
    let mut processing_node = mpc_node.clone();

    // Clone 2: the engine node — used for preprocessing initiation only.
    // Created via from_existing_node which wraps it in Arc<Mutex>.
    let open_message_router = Arc::new(stoffel_vm::net::OpenMessageRouter::new());
    let topology = MpcSessionTopology::try_new(instance_id, my_id, n, t)
        .map_err(|error| format!("Invalid HoneyBadger MPC topology: {error}"))?;
    let engine = HoneyBadgerMpcEngine::<F, G>::from_existing_node_with_router_and_topology(
        open_message_router.clone(),
        topology,
        persistent_identity,
        net.clone(),
        mpc_node, // moved, not cloned
    );

    configure_hb_preproc_store(
        &engine,
        program_hash,
        persistent_identity,
        preproc_store_path,
    )?;
    if let Some(path) = preproc_store_path {
        eprintln!("[party {}] Using preprocessing store at {}", my_id, path);
    }
    engine.set_client_output_id_map(input_ids.clone()).await;
    vm.set_mpc_engine(engine.clone());

    eprintln!(
        "[party {}] Spawning receive loops (split channels)...",
        my_id
    );
    let (mut server_rx, mut client_rx) =
        spawn_receive_loops_split(net.clone(), my_id, n, open_message_router).await;

    // Map canonical client transport IDs to MPC protocol indices.
    let client_id_to_index: std::collections::HashMap<ClientId, usize> = input_ids
        .iter()
        .enumerate()
        .map(|(idx, &tid)| (tid, idx))
        .collect();

    // Single processing loop using tokio::select! for both server and client messages.
    // Only this task calls process() — no other task touches the processing_node.
    let processing_net = net.clone();
    let process_party_id = my_id;
    let (preprocessing_ready_tx, mut preprocessing_ready_rx) = mpsc::channel::<usize>(n);
    tokio::spawn(async move {
        let mut msg_count = 0u64;
        let trace_messages = std::env::var("STOFFEL_RUN_TRACE_MESSAGES")
            .is_ok_and(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"));
        loop {
            tokio::select! {
                Some((sender_id, raw_msg)) = server_rx.recv() => {
                    if raw_msg.starts_with(HB_PREPROCESSING_READY_PREFIX) {
                        if let Err(error) = preprocessing_ready_tx.send(sender_id).await {
                            eprintln!(
                                "[party {}] Failed to record preprocessing-ready marker from {}: {}",
                                process_party_id, sender_id, error
                            );
                        }
                        continue;
                    }

                    msg_count += 1;
                    if trace_messages && (msg_count <= 5 || msg_count.is_multiple_of(1000)) {
                        eprintln!(
                            "[party {}] Processing message #{} from sender {} ({} bytes)",
                            process_party_id, msg_count, sender_id, raw_msg.len()
                        );
                    }
                    if let Err(e) = processing_node
                        .process(sender_id, raw_msg, processing_net.clone())
                        .await
                    {
                        eprintln!(
                            "[party {}] Failed to process message from {}: {:?}",
                            process_party_id, sender_id, e
                        );
                    }
                }
                Some((client_id, raw_msg)) = client_rx.recv() => {
                    // Remap transport client ID → sequential index
                    let mpc_sender_id = client_id_to_index
                        .get(&client_id)
                        .copied()
                        .unwrap_or(client_id);
                    if let Err(e) = processing_node
                        .process(mpc_sender_id, raw_msg, processing_net.clone())
                        .await
                    {
                        eprintln!(
                            "[party {}] Failed to process client message from {} (idx {}): {:?}",
                            process_party_id, client_id, mpc_sender_id, e
                        );
                    }
                }
                else => break,
            }
        }
    });

    // Brief delay to let receive loops discover connections
    tokio::time::sleep(Duration::from_secs(2)).await;

    eprintln!("[party {}] Starting MPC preprocessing...", my_id);
    let preprocessing_started_at = std::time::Instant::now();
    engine
        .preprocess()
        .await
        .map_err(|e| format!("MPC preprocessing failed: {}", e))?;
    eprintln!(
        "[party {}] MPC preprocessing complete! elapsed_ms={}",
        my_id,
        preprocessing_started_at.elapsed().as_millis()
    );
    match current_cgroup_memory_bytes() {
        Some(bytes) => eprintln!(
            "[party {}] POST_PREPROCESSING_CGROUP_MEM_BYTES: {}",
            my_id, bytes
        ),
        None => eprintln!(
            "[party {}] POST_PREPROCESSING_CGROUP_MEM_BYTES: unavailable",
            my_id
        ),
    }
    match current_process_rss_bytes() {
        Some(bytes) => eprintln!("[party {}] POST_PREPROCESSING_RSS_BYTES: {}", my_id, bytes),
        None => eprintln!(
            "[party {}] POST_PREPROCESSING_RSS_BYTES: unavailable",
            my_id
        ),
    }

    if n > 1 {
        eprintln!(
            "[party {}] Waiting for all parties to finish MPC preprocessing...",
            my_id
        );
        let mut ready_message =
            Vec::with_capacity(HB_PREPROCESSING_READY_PREFIX.len() + std::mem::size_of::<u64>());
        ready_message.extend_from_slice(HB_PREPROCESSING_READY_PREFIX);
        ready_message.extend_from_slice(&instance_id.to_le_bytes());
        for peer_id in 0..n {
            if peer_id == my_id {
                continue;
            }
            net.send(peer_id, &ready_message).await.map_err(|error| {
                format!(
                    "Failed to send preprocessing-ready marker to party {}: {}",
                    peer_id, error
                )
            })?;
        }

        let mut ready_parties = std::collections::HashSet::with_capacity(n.saturating_sub(1));
        let barrier_timeout = honeybadger_protocol_timeout();
        let barrier_result = tokio::time::timeout(barrier_timeout, async {
            while ready_parties.len() < n.saturating_sub(1) {
                let sender_id = preprocessing_ready_rx.recv().await.ok_or_else(|| {
                    "Preprocessing-ready marker channel closed before all parties were ready"
                        .to_string()
                })?;
                if sender_id != my_id {
                    ready_parties.insert(sender_id);
                }
            }
            Ok::<(), String>(())
        })
        .await
        .map_err(|_| {
            format!(
                "Timed out waiting for preprocessing-ready markers ({}/{})",
                ready_parties.len(),
                n.saturating_sub(1)
            )
        })?;
        barrier_result?;
        eprintln!(
            "[party {}] All parties completed MPC preprocessing; continuing",
            my_id
        );
    }

    if !input_ids.is_empty() {
        let client_index_map: Vec<(usize, ClientId)> = input_ids
            .iter()
            .enumerate()
            .map(|(idx, &tid)| (idx, tid))
            .collect();

        // Create a server-side network adapter that remaps sequential client
        // indices to transport client IDs for send_to_client().
        let server_adapter = Arc::new(ServerClientAdapter {
            inner: (*net).clone(),
            client_id_map: client_index_map.iter().map(|(_, tid)| *tid).collect(),
        });

        // Access the engine's node for InputServer init
        eprintln!(
            "[party {}] Initializing InputServer for {} clients...",
            my_id,
            client_index_map.len()
        );
        {
            let mut node = engine.node_handle().lock().await;
            for &(idx, _tid) in &client_index_map {
                let local_shares = node
                    .preprocessing_material
                    .lock()
                    .await
                    .take_random_shares(client_input_count)
                    .map_err(|e| format!("Not enough random shares for client {}: {:?}", idx, e))?;

                eprintln!(
                    "[party {}] Sending random shares to client index {} (server_id={})",
                    my_id, idx, node.id
                );
                node.preprocess
                    .input
                    .init(
                        idx,
                        local_shares,
                        client_input_count,
                        server_adapter.clone(),
                    )
                    .await
                    .map_err(|e| {
                        format!("Failed to init InputServer for client {}: {:?}", idx, e)
                    })?;
                eprintln!(
                    "[party {}] InputServer initialized for client index {}",
                    my_id, idx
                );
            }
        }

        // Signal readiness to clients
        eprintln!(
            "[party {}] Sending INST to {} clients...",
            my_id,
            client_index_map.len()
        );
        for &(idx, tid) in &client_index_map {
            let mut inst_msg = Vec::with_capacity(13);
            inst_msg.extend_from_slice(b"INST");
            inst_msg.extend_from_slice(&instance_id.to_le_bytes());
            inst_msg.push(idx as u8);
            if let Err(e) = net.send_to_client(tid, &inst_msg).await {
                eprintln!(
                    "[party {}] Failed to send INST to client {}: {:?}",
                    my_id, tid, e
                );
            }
        }

        eprintln!(
            "[party {}] Waiting for all client inputs (timeout=600s)...",
            my_id
        );
        let client_inputs = {
            let mut node = engine.node_handle().lock().await;
            node.preprocess
                .input
                .wait_for_all_inputs(Duration::from_secs(600))
                .await
                .map_err(|e| format!("Failed to receive client inputs: {:?}", e))?
        };

        for (idx, shares) in client_inputs {
            let transport_cid = client_index_map
                .iter()
                .find(|(i, _)| *i == idx)
                .map(|(_, tid)| *tid)
                .unwrap_or(idx);
            if let Some(share_types) = client_input_types.get(&idx) {
                vm.try_store_client_input_with_types(idx, shares, share_types)?;
            } else {
                vm.try_store_client_input(idx, shares)?;
            }
            eprintln!(
                "[party {}] Stored inputs for client index {} (client {})",
                my_id, idx, transport_cid
            );
        }
    }

    Ok(engine)
}
struct AvssPartySetup<'a> {
    my_id: usize,
    local_identity: DurableIdentityDigest,
    n: usize,
    t: usize,
    instance_id: u64,
    expected_client_count: Option<usize>,
    client_input_count: usize,
    client_input_types: &'a std::collections::BTreeMap<usize, Vec<ShareType>>,
}
async fn setup_avss_party_for_curve<F, G>(
    vm: &mut VirtualMachine,
    net: Arc<QuicNetworkManager>,
    setup: AvssPartySetup<'_>,
) -> Result<Arc<stoffel_vm::net::avss_engine::AvssMpcEngine<F, G>>, String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let AvssPartySetup {
        my_id,
        local_identity,
        n,
        t,
        instance_id,
        expected_client_count,
        client_input_count,
        client_input_types,
    } = setup;

    // ---- Phase 1: Wait for clients ----
    let mut input_ids: Vec<ClientId> = Vec::new();

    if let Some(expected_count) = expected_client_count {
        if expected_count == 0 {
            return Err("--wait-for-clients count must be greater than 0".to_string());
        }
        if client_input_count == 0 {
            return Err("--client-input-count must be greater than 0".to_string());
        }

        eprintln!(
            "[party {}] Waiting for {} clients (AVSS)...",
            my_id, expected_count
        );

        let mut accept_net = (*net).clone();
        let accept_party_id = my_id;
        tokio::spawn(async move {
            loop {
                match accept_net.accept().await {
                    Ok(_) => {
                        eprintln!("[party {}] Accepted client connection", accept_party_id);
                    }
                    Err(e) => {
                        eprintln!("[party {}] Accept error: {}", accept_party_id, e);
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        });

        let connect_timeout = Duration::from_secs(600);
        let check_interval = Duration::from_millis(250);
        let start = std::time::Instant::now();

        loop {
            let mut connected_clients = net.clients();
            connected_clients.sort_unstable();
            connected_clients.dedup();

            eprintln!(
                "[party {}] {} of {} expected clients connected: {:?}",
                my_id,
                connected_clients.len(),
                expected_count,
                connected_clients
            );

            if connected_clients.len() > expected_count {
                return Err(format!(
                    "Expected exactly {} clients, but {} are connected: {:?}",
                    expected_count,
                    connected_clients.len(),
                    connected_clients
                ));
            }

            if connected_clients.len() == expected_count {
                input_ids = connected_clients;
                break;
            }

            if start.elapsed() > connect_timeout {
                return Err(format!(
                    "Timeout waiting for {} clients; connected so far: {:?}",
                    expected_count,
                    net.clients()
                ));
            }

            tokio::time::sleep(check_interval).await;
        }

        eprintln!(
            "[party {}] Using canonical client input IDs: {:?}",
            my_id, input_ids
        );

        sync_client_set_across_parties(net.clone(), my_id, n, &input_ids).await?;
    }

    // ---- Phase 2: ECDH key exchange over existing network ----
    let mpc_input_ids: Vec<ClientId> = (0..input_ids.len()).collect();

    // Generate ECDH key pair for AVSS payload confidentiality
    use ark_std::rand::SeedableRng as _;
    let mut rng = ark_std::rand::rngs::StdRng::from_entropy();
    let sk_i = F::rand(&mut rng);
    let pk_i: G = G::generator() * sk_i;

    // Serialize our public key into an envelope: [party_id: u32][pk_bytes]
    let mut pk_bytes = Vec::new();
    pk_i.serialize_compressed(&mut pk_bytes)
        .map_err(|e| format!("Failed to serialize ECDH public key: {:?}", e))?;
    let mut envelope = Vec::with_capacity(4 + pk_bytes.len());
    envelope.extend_from_slice(&(my_id as u32).to_le_bytes());
    envelope.extend_from_slice(&pk_bytes);

    eprintln!(
        "[party {}] Exchanging ECDH public keys over existing network...",
        my_id
    );

    // Broadcast our PK to all peers via existing connections
    let connections = net.get_all_server_connections();
    for (peer_id, conn) in &connections {
        let authenticated_peer_id = conn.remote_party_id().unwrap_or(*peer_id);
        if authenticated_peer_id == my_id {
            continue;
        }
        if let Err(e) = conn.send(&envelope).await {
            eprintln!(
                "[party {}] Failed to send PK to peer {}: {}",
                my_id, authenticated_peer_id, e
            );
        }
    }

    // Collect PKs from all peers
    let mut pk_map: Vec<G> = vec![G::default(); n];
    pk_map[my_id] = pk_i;
    let mut received = 1usize;
    let mut seen = std::collections::HashSet::new();
    seen.insert(my_id);

    let (pk_tx, mut pk_rx) = tokio::sync::mpsc::channel::<(usize, Vec<u8>)>(n);

    for (peer_id, conn) in &connections {
        let authenticated_peer_id = conn.remote_party_id().unwrap_or(*peer_id);
        if authenticated_peer_id == my_id {
            continue;
        }
        let tx = pk_tx.clone();
        let conn = conn.clone();
        tokio::spawn(async move {
            match conn.receive().await {
                Ok(data) => {
                    let _ = tx.send((authenticated_peer_id, data)).await;
                }
                Err(e) => {
                    eprintln!(
                        "[AVSS] Failed to receive PK from peer {}: {}",
                        authenticated_peer_id, e
                    );
                }
            }
        });
    }
    drop(pk_tx);

    let pk_deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    while received < n {
        let remaining = pk_deadline.saturating_duration_since(tokio::time::Instant::now());
        match tokio::time::timeout(remaining, pk_rx.recv()).await {
            Ok(Some((peer_id, data))) => {
                if data.len() < 4 {
                    continue;
                }
                let claimed_id = u32::from_le_bytes(data[..4].try_into().unwrap()) as usize;
                // Verify the payload's claimed sender_id against the transport-authenticated
                // peer_id to prevent a malicious party from registering its key under a
                // different party's identity.
                if claimed_id != peer_id {
                    eprintln!(
                        "[party {}] AVSS PK exchange: transport sender {} claims to be party {} — ignoring",
                        my_id, peer_id, claimed_id
                    );
                    continue;
                }
                let sender_id = claimed_id;
                if sender_id >= n || !seen.insert(sender_id) {
                    continue;
                }
                match G::deserialize_compressed(&data[4..]) {
                    Ok(pk) => {
                        pk_map[sender_id] = pk;
                        received += 1;
                        eprintln!(
                            "[party {}] Received PK from party {} ({}/{})",
                            my_id, sender_id, received, n
                        );
                    }
                    Err(e) => {
                        eprintln!(
                            "[party {}] Failed to deserialize PK from party {}: {:?}",
                            my_id, sender_id, e
                        );
                    }
                }
            }
            Ok(None) => break,
            Err(_) => {
                return Err(format!(
                    "Timeout during PK exchange: received {}/{} keys",
                    received, n
                ));
            }
        }
    }

    if received < n {
        return Err(format!(
            "PK exchange incomplete: received {}/{} keys",
            received, n
        ));
    }
    eprintln!("[party {}] PK exchange complete ({} keys)", my_id, n);

    let pk_map = Arc::new(pk_map);

    // ---- Phase 3: Create engine directly with existing network ----
    use stoffel_vm::net::avss_engine::{AvssEngineConfig, AvssMpcEngine};
    let session = stoffel_vm::net::MpcSessionConfig::try_new(instance_id, my_id, n, t, net.clone())
        .map_err(|error| format!("Invalid AVSS MPC topology: {error}"))?
        .with_local_identity(local_identity)
        .with_input_ids(mpc_input_ids);
    let engine = AvssMpcEngine::<F, G>::from_config(AvssEngineConfig::new(session, sk_i, pk_map))
        .await
        .map_err(|e| format!("Failed to create AVSS engine: {}", e))?;
    engine.set_client_output_id_map(input_ids.clone()).await;

    engine
        .start_async()
        .await
        .map_err(|e| format!("Failed to start AVSS engine: {}", e))?;
    vm.set_mpc_engine(engine.clone());

    // ---- Phase 4: Spawn message loops on existing connections ----
    // Server message loops
    let (msg_tx, _server_rx) = tokio::sync::mpsc::channel::<(usize, Vec<u8>)>(65536);
    let (client_tx, mut client_rx) = tokio::sync::mpsc::channel::<(usize, Vec<u8>)>(4096);

    for (peer_id, conn) in &connections {
        if *peer_id == my_id {
            continue;
        }
        let peer_id = *peer_id;
        let engine = engine.clone();
        let open_message_router = engine.open_message_router();
        let tx = msg_tx.clone();
        let conn = conn.clone();
        let net_clone = net.clone();
        let authenticated_sender_id = conn.remote_party_id().unwrap_or(peer_id);
        tokio::spawn(async move {
            while let Ok(data) = conn.receive().await {
                if let Ok(true) =
                    open_message_router.try_handle_wire_message(authenticated_sender_id, &data)
                {
                    continue;
                }
                if let Ok(true) = open_message_router
                    .try_handle_avss_open_exp_wire_message(authenticated_sender_id, &data)
                {
                    continue;
                }
                if let Ok(true) = open_message_router
                    .try_handle_avss_g2_exp_wire_message(authenticated_sender_id, &data)
                {
                    continue;
                }
                if let Err(e) = engine
                    .process_wrapped_message_with_network(
                        authenticated_sender_id,
                        &data,
                        net_clone.clone(),
                    )
                    .await
                {
                    let _ = tx.send((authenticated_sender_id, data)).await;
                    if !e.contains("deserialize") && !e.contains("process failed") {
                        eprintln!(
                            "[AVSS] Party failed to process message from {}: {}",
                            authenticated_sender_id, e
                        );
                    }
                }
            }
        });
    }

    // Client connection monitor
    let client_net = net.clone();
    tokio::spawn(async move {
        let mut spawned = std::collections::HashSet::new();
        loop {
            for (cid, conn) in client_net.get_all_client_connections() {
                if !spawned.insert(cid) {
                    continue;
                }
                let txx = client_tx.clone();
                tokio::spawn(async move {
                    while let Ok(data) = conn.receive().await {
                        if txx.send((cid, data)).await.is_err() {
                            break;
                        }
                    }
                });
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    });

    // Route client messages through the AVSS node's process()
    if !input_ids.is_empty() {
        let client_id_to_index: std::collections::HashMap<ClientId, usize> = input_ids
            .iter()
            .enumerate()
            .map(|(idx, &tid)| (tid, idx))
            .collect();

        let processing_engine = engine.clone();
        let processing_net = net.clone();
        tokio::spawn(async move {
            while let Some((client_id, raw_msg)) = client_rx.recv().await {
                let mpc_sender_id = client_id_to_index
                    .get(&client_id)
                    .copied()
                    .unwrap_or(client_id);
                if let Err(e) = processing_engine
                    .process_wrapped_message_with_network(
                        mpc_sender_id,
                        &raw_msg,
                        processing_net.clone(),
                    )
                    .await
                {
                    eprintln!(
                        "[party {}] Failed to process client message from {} (idx {}): {:?}",
                        processing_engine.party().id(),
                        client_id,
                        mpc_sender_id,
                        e
                    );
                }
            }
        });
    }

    // ---- Phase 5: Preprocessing ----
    tokio::time::sleep(Duration::from_secs(2)).await;
    eprintln!("[party {}] Starting AVSS preprocessing...", my_id);
    engine.preprocess().await?;
    eprintln!("[party {}] AVSS preprocessing complete!", my_id);

    // ---- Phase 6: Client input initialization ----
    if !input_ids.is_empty() {
        let client_index_map: Vec<(usize, ClientId)> = input_ids
            .iter()
            .enumerate()
            .map(|(idx, &tid)| (idx, tid))
            .collect();

        let server_adapter = Arc::new(ServerClientAdapter {
            inner: (*net).clone(),
            client_id_map: client_index_map.iter().map(|(_, tid)| *tid).collect(),
        });

        eprintln!(
            "[party {}] Initializing AVSS InputServer for {} clients...",
            my_id,
            client_index_map.len()
        );
        {
            let mut node = engine.node_handle().lock().await;
            for &(idx, _tid) in &client_index_map {
                let local_shares = node
                    .preprocessing_material
                    .lock()
                    .await
                    .take_v_random_shares(client_input_count)
                    .map_err(|e| format!("Not enough random shares for client {}: {:?}", idx, e))?;

                node.input_server
                    .init(
                        idx,
                        local_shares,
                        client_input_count,
                        server_adapter.clone(),
                    )
                    .await
                    .map_err(|e| {
                        format!("Failed to init InputServer for client {}: {:?}", idx, e)
                    })?;
                eprintln!(
                    "[party {}] InputServer initialized for client index {}",
                    my_id, idx
                );
            }
        }

        // Signal readiness to clients
        eprintln!(
            "[party {}] Sending INST to {} clients...",
            my_id,
            client_index_map.len()
        );
        for &(idx, tid) in &client_index_map {
            let mut inst_msg = Vec::with_capacity(13);
            inst_msg.extend_from_slice(b"INST");
            inst_msg.extend_from_slice(&instance_id.to_le_bytes());
            inst_msg.push(idx as u8);
            if let Err(e) = net.send_to_client(tid, &inst_msg).await {
                eprintln!(
                    "[party {}] Failed to send INST to client {}: {:?}",
                    my_id, tid, e
                );
            }
        }

        // Wait for all client inputs
        eprintln!(
            "[party {}] Waiting for all client inputs (timeout=600s)...",
            my_id
        );
        let client_inputs = {
            let mut node = engine.node_handle().lock().await;
            node.input_server
                .wait_for_all_inputs(Duration::from_secs(600))
                .await
                .map_err(|e| format!("Failed to receive client inputs: {:?}", e))?
        };

        for (idx, shares) in client_inputs {
            let transport_cid = client_index_map
                .iter()
                .find(|(i, _)| *i == idx)
                .map(|(_, tid)| *tid)
                .unwrap_or(idx);
            if let Some(share_types) = client_input_types.get(&idx) {
                vm.try_store_client_input_feldman_with_types(idx, shares, share_types)?;
            } else {
                vm.try_store_client_input_feldman(idx, shares)?;
            }
            eprintln!(
                "[party {}] Stored inputs for client index {} (client {})",
                my_id, idx, transport_cid
            );
        }
    }

    Ok(engine)
}
#[allow(clippy::too_many_arguments)]
async fn run_avss_coordinated_party_for_curve<F, G>(
    vm: &mut VirtualMachine,
    net: Arc<QuicNetworkManager>,
    my_id: usize,
    n: usize,
    t: usize,
    instance_id: u64,
    coord_addr: (String, u16),
    rpc_addr: (String, u16),
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    expected_clients: &[String],
    as_leader: bool,
    agreed_entry: &str,
) -> Result<(), String>
where
    F: SupportedMpcField,
    G: CurveGroup<ScalarField = F> + PrimeGroup + Send + Sync + 'static,
{
    let input_ids: Vec<Vec<u8>> = expected_clients
        .iter()
        .map(|path| extract_pubkey_from_cert(&fs::read(path).expect("read client cert")))
        .collect();

    let coord: AvssOffChainCoordinator<F, G> = AvssOffChainCoordinator::<F, G>::start_rpc_client(
        &coord_addr.0,
        coord_addr.1,
        t as u64,
        n as u64,
        2,
        cert_der.clone(),
        key_der.clone(),
    )
    .await
    .map_err(|error| format!("Failed to connect to AVSS off-chain coordinator: {error}"))?;

    let mut node_rpc: AvssOffChainNodeRpcServer<F, G> = AvssOffChainNodeRpcServer::<F, G>::start(
        &rpc_addr.0,
        rpc_addr.1,
        cert_der.clone(),
        key_der.clone(),
    )
    .await
    .map_err(|error| format!("Failed to start AVSS node RPC server: {error}"))?;

    if as_leader {
        coord.reset_coord().await.map_err(|e| e.to_string())?;
        coord
            .start_preprocessing()
            .await
            .map_err(|e| e.to_string())?;
    }

    let client_input_types = std::collections::BTreeMap::new();
    let engine = setup_avss_party_for_curve::<F, G>(
        vm,
        net,
        AvssPartySetup {
            my_id,
            local_identity: durable_identity_from_cert(&cert_der),
            n,
            t,
            instance_id,
            expected_client_count: None,
            client_input_count: 1,
            client_input_types: &client_input_types,
        },
    )
    .await?;
    engine.enable_client_output_capture().await;

    if input_ids.is_empty() {
        eprintln!(
            "[party {}] AVSS coordinator mode has no client inputs; preprocessing complete, skipping input collection",
            my_id
        );
    } else {
        let mut mask_shares = Vec::with_capacity(input_ids.len());
        {
            let node = engine.node_handle().lock().await;
            for idx in 0..input_ids.len() {
                let local_shares = node
                    .preprocessing_material
                    .lock()
                    .await
                    .take_v_random_shares(1)
                    .map_err(|e| {
                        format!("Not enough AVSS random shares for client {idx}: {:?}", e)
                    })?;
                let share = local_shares
                    .into_iter()
                    .next()
                    .ok_or_else(|| format!("AVSS random share batch for client {idx} was empty"))?;
                node_rpc
                    .add_mask_share(idx as u64, &share)
                    .await
                    .map_err(|e| format!("add_mask_share: {:?}", e))?;
                mask_shares.push(share);
            }
        }

        if as_leader {
            coord
                .reserve_input_masks()
                .await
                .map_err(|e| e.to_string())?;
        }
        coord
            .wait_for_round(Round::InputMaskReservation)
            .await
            .map_err(|e| e.to_string())?;

        let client_to_indices = normalize_client_to_indices(
            coord
                .wait_for_indices(input_ids.len() as u64)
                .await
                .map_err(|e| e.to_string())?,
        );

        for (cid, indices) in &client_to_indices {
            for idx in indices {
                node_rpc
                    .add_reserved_index(cid.clone(), *idx)
                    .await
                    .or_else(|e| match e {
                        NodeRPCError::JSONError => {
                            eprintln!(
                                "[party {}] add_reserved_index observed a stale client sink for index {}; continuing",
                                my_id, idx
                            );
                            Ok(())
                        }
                        other => Err(format!("add_reserved_index: {:?}", other)),
                    })?;
            }
        }

        if as_leader {
            coord.collect_inputs().await.map_err(|e| e.to_string())?;
        }
        coord
            .wait_for_round(Round::InputCollection)
            .await
            .map_err(|e| e.to_string())?;

        let client_inputs = coord
            .wait_for_inputs(input_ids.len() as u64, mask_shares)
            .await
            .map_err(|e| e.to_string())?;
        let client_input_types = std::collections::BTreeMap::new();
        store_reserved_client_inputs_feldman::<F, G, _>(
            vm,
            &client_to_indices,
            client_inputs,
            1,
            &[],
            &client_input_types,
        );
    }

    if as_leader {
        coord.start_mpc().await.map_err(|e| e.to_string())?;
    }
    coord
        .wait_for_round(Round::MPCExecution)
        .await
        .map_err(|e| e.to_string())?;

    eprintln!("Starting VM execution of '{}'...", agreed_entry);
    let result = vm
        .execute(agreed_entry)
        .map_err(|err| format!("Execution error in '{}': {}", agreed_entry, err))?;

    let captured_outputs = engine.drain_client_output_records().await;
    if !captured_outputs.is_empty() {
        if as_leader {
            coord.send_output().await.map_err(|e| e.to_string())?;
        }
        coord
            .wait_for_round(Round::OutputDistribution)
            .await
            .map_err(|e| e.to_string())?;

        for record in captured_outputs {
            let client_key = input_ids.get(record.client_id).ok_or_else(|| {
                format!(
                    "AVSS output client index {} has no matching coordinator client identity",
                    record.client_id
                )
            })?;
            coord
                .send_output_shares(client_key.clone(), client_key.clone(), record.shares)
                .await
                .map_err(|e| format!("send_output_shares: {e}"))?;
        }

        if as_leader {
            coord.finalize().await.map_err(|e| e.to_string())?;
        }
    }

    print_vm_result(vm, result);
    Ok(())
}
#[allow(clippy::too_many_arguments)]
async fn run_avss_coordinated_party(
    curve_config: MpcCurveConfig,
    vm: &mut VirtualMachine,
    net: Arc<QuicNetworkManager>,
    my_id: usize,
    n: usize,
    t: usize,
    instance_id: u64,
    coord_addr: (String, u16),
    rpc_addr: (String, u16),
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    expected_clients: &[String],
    as_leader: bool,
    agreed_entry: &str,
) -> Result<(), String> {
    match curve_config {
        MpcCurveConfig::Bls12_381 => {
            run_avss_coordinated_party_for_curve::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>(
                vm,
                net,
                my_id,
                n,
                t,
                instance_id,
                coord_addr,
                rpc_addr,
                cert_der,
                key_der,
                expected_clients,
                as_leader,
                agreed_entry,
            )
            .await
        }
        MpcCurveConfig::Bn254 => {
            run_avss_coordinated_party_for_curve::<ark_bn254::Fr, ark_bn254::G1Projective>(
                vm,
                net,
                my_id,
                n,
                t,
                instance_id,
                coord_addr,
                rpc_addr,
                cert_der,
                key_der,
                expected_clients,
                as_leader,
                agreed_entry,
            )
            .await
        }
        MpcCurveConfig::Curve25519 => {
            run_avss_coordinated_party_for_curve::<
                ark_curve25519::Fr,
                ark_curve25519::EdwardsProjective,
            >(
                vm,
                net,
                my_id,
                n,
                t,
                instance_id,
                coord_addr,
                rpc_addr,
                cert_der,
                key_der,
                expected_clients,
                as_leader,
                agreed_entry,
            )
            .await
        }
        MpcCurveConfig::Ed25519 => {
            run_avss_coordinated_party_for_curve::<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>(
                vm,
                net,
                my_id,
                n,
                t,
                instance_id,
                coord_addr,
                rpc_addr,
                cert_der,
                key_der,
                expected_clients,
                as_leader,
                agreed_entry,
            )
            .await
        }
        MpcCurveConfig::Secp256k1 => {
            run_avss_coordinated_party_for_curve::<ark_secp256k1::Fr, ark_secp256k1::Projective>(
                vm,
                net,
                my_id,
                n,
                t,
                instance_id,
                coord_addr,
                rpc_addr,
                cert_der,
                key_der,
                expected_clients,
                as_leader,
                agreed_entry,
            )
            .await
        }
        MpcCurveConfig::Secp256r1 => {
            run_avss_coordinated_party_for_curve::<ark_secp256r1::Fr, ark_secp256r1::Projective>(
                vm,
                net,
                my_id,
                n,
                t,
                instance_id,
                coord_addr,
                rpc_addr,
                cert_der,
                key_der,
                expected_clients,
                as_leader,
                agreed_entry,
            )
            .await
        }
    }
}

// Use a Tokio runtime for async operations
#[tokio::main]
async fn main() {
    // When spawned by the local coordinator runner, tie this process's lifetime
    // to its parent: if the parent (the test/CLI/SDK process) dies — including a
    // SIGKILL, where the parent's `kill_on_drop` cleanup cannot run — this party
    // would otherwise be re-parented to init/launchd and leak as an orphaned MPC
    // process. Poll the parent PID and exit promptly once it changes.
    if std::env::var_os("STOFFEL_DIE_WITH_PARENT").is_some() {
        // SAFETY: `getppid` is always safe to call and takes no arguments.
        let original_parent = unsafe { libc::getppid() };
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_millis(500)).await;
                // SAFETY: see above.
                let current = unsafe { libc::getppid() };
                if current != original_parent || current <= 1 {
                    eprintln!(
                        "[watchdog] parent process exited (ppid {original_parent} -> {current}); shutting down"
                    );
                    std::process::exit(0);
                }
            }
        });
    }

    let raw_args = env::args().skip(1).collect::<Vec<_>>();

    if raw_args.is_empty() {
        // Allow bootnode-only mode without program path
        print_usage_and_exit();
    }

    let mut entry: String = "main".to_string();

    let mut trace_instr = false;
    let mut trace_regs = false;
    let mut trace_stack = false;
    let mut as_bootnode = false;
    let mut as_leader = false;
    let mut as_client = false;
    let mut upload_program_bytes = true;
    let mut bind_addr: Option<SocketAddr> = None;
    let mut party_id: Option<usize> = None;
    let mut bootstrap_addr: Option<SocketAddr> = None;
    let mut n_parties: Option<usize> = None;
    let mut threshold: Option<usize> = None;
    let mut client_inputs: Option<String> = None;
    let mut client_outputs: Option<usize> = None;
    let mut output_fixed_point_fractional_bits: Option<usize> = None;
    let mut expected_client_count: Option<usize> = None;
    let mut client_input_count: usize = 1;
    // Actual TOTAL number of client input values across all clients (sum of each
    // client's count). 0 = unset, in which case we fall back to the uniform
    // `num_clients * client_input_count`. Lets clients provide different counts.
    let mut client_input_total: usize = 0;
    let mut _enable_nat: bool = false;
    let mut _stun_servers: Vec<SocketAddr> = Vec::new();
    let mut server_addrs: Vec<SocketAddr> = Vec::new();
    let mut mpc_backend: Option<String> = None;
    let mut mpc_curve: Option<String> = None;
    let mut rpc_addr: Option<(String, u16)> = None;
    let mut coord_addr: Option<(String, u16)> = None;
    let mut key_der: Option<Vec<u8>> = None;
    let mut cert_der: Option<Vec<u8>> = None;
    let mut expected_clients: Vec<String> = Vec::new();
    let mut client_roster: Vec<usize> = Vec::new();
    let mut client_input_slots: Vec<usize> = Vec::new();
    let mut eth_node_addr: Option<String> = None;
    let mut wallet_sk_str: Option<String> = None;
    let mut contract_addr: Option<String> = None;
    let mut coordinator_client_index: Option<u64> = None;
    let mut preproc_store_path: Option<String> = None;
    let mut local_store_path: Option<String> = None;
    let mut advertise_addr: Option<SocketAddr> = None;

    for arg in &raw_args {
        if arg == "-h" || arg == "--help" {
            print_usage_and_exit();
        } else if arg == "--trace-instr" {
            trace_instr = true;
        } else if arg == "--trace-regs" {
            trace_regs = true;
        } else if arg == "--trace-stack" {
            trace_stack = true;
        } else if arg == "--bootnode" {
            as_bootnode = true;
        } else if arg == "--leader" {
            as_leader = true;
        } else if arg == "--client" {
            as_client = true;
        } else if arg == "--no-program-upload" {
            upload_program_bytes = false;
        } else if arg == "--nat" {
            _enable_nat = true;
        } else if let Some(_rest) = arg.strip_prefix("--bind") {
            // support "--bind" and "--bind=.."
            // actual value parsed later from positional with key
        } else if let Some(_rest) = arg.strip_prefix("--party-id") {
        } else if let Some(_rest) = arg.strip_prefix("--bootstrap") {
        } else if let Some(_rest) = arg.strip_prefix("--n-parties") {
        } else if let Some(_rest) = arg.strip_prefix("--threshold") {
        } else if let Some(_rest) = arg.strip_prefix("--inputs") {
        } else if let Some(_rest) = arg.strip_prefix("--outputs") {
        } else if let Some(_rest) = arg.strip_prefix("--output-fixed-point-fractional-bits") {
        } else if let Some(_rest) = arg.strip_prefix("--wait-for-clients") {
        } else if let Some(_rest) = arg.strip_prefix("--client-input-count") {
        } else if let Some(_rest) = arg.strip_prefix("--client-input-total") {
        } else if let Some(_rest) = arg.strip_prefix("--stun-servers") {
        } else if let Some(_rest) = arg.strip_prefix("--servers") {
        } else if let Some(_rest) = arg.strip_prefix("--mpc-backend") {
        } else if let Some(_rest) = arg.strip_prefix("--mpc-curve") {
        } else if let Some(_rest) = arg.strip_prefix("--rpc-bind") {
        } else if let Some(_rest) = arg.strip_prefix("--off-chain-coord") {
        } else if let Some(_rest) = arg.strip_prefix("--on-chain-coord") {
        } else if let Some(_rest) = arg.strip_prefix("--eth-node") {
        } else if let Some(_rest) = arg.strip_prefix("--wallet-sk") {
        } else if let Some(_rest) = arg.strip_prefix("--key") {
        } else if let Some(_rest) = arg.strip_prefix("--cert") {
        } else if let Some(_rest) = arg.strip_prefix("--expected-clients") {
        } else if let Some(_rest) = arg.strip_prefix("--client-roster") {
        } else if let Some(_rest) = arg.strip_prefix("--client-input-slots") {
        } else if let Some(_rest) = arg.strip_prefix("--client-index") {
        } else if let Some(_rest) = arg.strip_prefix("--preproc-store") {
        } else if let Some(_rest) = arg.strip_prefix("--local-store") {
        } else if let Some(_rest) = arg.strip_prefix("--advertise") {
        } else if let Some(_rest) = arg.strip_prefix("--no-program-upload") {
        }
    }

    fail_removed_flag(
        &raw_args,
        "--client-id",
        "Client IDs are now transport-derived. Remove `--client-id`.",
    );
    fail_removed_flag(
        &raw_args,
        "--expected-client-count",
        "Use `--expected-clients <cert-paths-or-addrs>` instead.",
    );
    fail_removed_flag(
        &raw_args,
        "--node-ids",
        "On-chain coordinator mode is temporarily unavailable in the crates.io-ready build.",
    );
    fail_removed_flag(
        &raw_args,
        "--adkg-curve",
        "Use `--mpc-curve <name>` instead.",
    );

    // collect positional args (non-flags)
    let mut positional = raw_args
        .into_iter()
        .filter(|a| !a.starts_with("--"))
        .collect::<Vec<_>>();

    if positional.is_empty() {
        // Allow bootnode-only mode without program path
        if !as_bootnode {
            print_usage_and_exit();
        }
    }

    // Parse key-value style flags
    let mut args_iter = env::args().skip(1).peekable();
    while let Some(a) = args_iter.next() {
        match a.as_str() {
            "--bind" => {
                if let Some(v) = args_iter.next() {
                    bind_addr = Some(v.parse().expect("Invalid --bind addr"));
                }
            }
            "--party-id" => {
                if let Some(v) = args_iter.next() {
                    party_id = Some(v.parse().expect("Invalid --party-id"));
                }
            }
            "--bootstrap" => {
                if let Some(v) = args_iter.next() {
                    bootstrap_addr = Some(v.parse().expect("Invalid --bootstrap addr"));
                }
            }
            "--n-parties" => {
                if let Some(v) = args_iter.next() {
                    n_parties = Some(v.parse().expect("Invalid --n-parties"));
                }
            }
            "--threshold" => {
                if let Some(v) = args_iter.next() {
                    threshold = Some(v.parse().expect("Invalid --threshold"));
                }
            }
            "--inputs" => {
                if let Some(v) = args_iter.next() {
                    client_inputs = Some(v);
                }
            }
            "--outputs" => {
                if let Some(v) = args_iter.next() {
                    client_outputs = Some(v.parse().expect("Invalid --outputs"));
                }
            }
            "--output-fixed-point-fractional-bits" => {
                if let Some(v) = args_iter.next() {
                    output_fixed_point_fractional_bits = Some(
                        v.parse()
                            .expect("Invalid --output-fixed-point-fractional-bits"),
                    );
                }
            }
            "--wait-for-clients" => {
                if let Some(v) = args_iter.next() {
                    expected_client_count = Some(v.parse().expect("Invalid --wait-for-clients"));
                }
            }
            "--client-input-count" => {
                if let Some(v) = args_iter.next() {
                    client_input_count = v.parse().expect("Invalid --client-input-count");
                }
            }
            "--client-input-total" => {
                if let Some(v) = args_iter.next() {
                    client_input_total = v.parse().expect("Invalid --client-input-total");
                }
            }
            "--stun-servers" => {
                if let Some(v) = args_iter.next() {
                    _stun_servers = v
                        .split(',')
                        .filter_map(|s| {
                            let s = s.trim();
                            s.parse::<SocketAddr>().ok().or_else(|| {
                                eprintln!("Warning: Invalid STUN server address '{}', skipping", s);
                                None
                            })
                        })
                        .collect();
                }
            }
            "--servers" => {
                if let Some(v) = args_iter.next() {
                    server_addrs = v
                        .split(',')
                        .filter_map(|s| {
                            let s = s.trim();
                            s.parse::<SocketAddr>().ok().or_else(|| {
                                eprintln!("Warning: Invalid server address '{}', skipping", s);
                                None
                            })
                        })
                        .collect();
                }
            }
            "--mpc-backend" => {
                if let Some(v) = args_iter.next() {
                    mpc_backend = Some(v);
                }
            }
            "--mpc-curve" => {
                if let Some(v) = args_iter.next() {
                    mpc_curve = Some(v);
                }
            }
            "--rpc-bind" => {
                if let Some(v) = args_iter.next() {
                    let parts: Vec<&str> = v.rsplitn(2, ':').collect();
                    let port: u16 = parts[0].parse().expect("Invalid --rpc-bind port");
                    let host = parts[1].to_string();
                    rpc_addr = Some((host, port));
                }
            }
            "--off-chain-coord" => {
                if let Some(v) = args_iter.next() {
                    let parts: Vec<&str> = v.rsplitn(2, ':').collect();
                    let port: u16 = parts[0].parse().expect("Invalid --off-chain-coord port");
                    let host = parts[1].to_string();
                    coord_addr = Some((host, port));
                }
            }
            "--on-chain-coord" => {
                if let Some(v) = args_iter.next() {
                    contract_addr = Some(v);
                }
            }
            "--eth-node" => {
                if let Some(v) = args_iter.next() {
                    eth_node_addr = Some(v);
                }
            }
            "--wallet-sk" => {
                if let Some(v) = args_iter.next() {
                    wallet_sk_str = Some(v);
                }
            }
            "--key" => {
                if let Some(v) = args_iter.next() {
                    key_der = Some(std::fs::read(&v).expect("Failed to read --key file"));
                }
            }
            "--cert" => {
                if let Some(v) = args_iter.next() {
                    cert_der = Some(std::fs::read(&v).expect("Failed to read --cert file"));
                }
            }
            "--client-index" => {
                if let Some(v) = args_iter.next() {
                    coordinator_client_index = Some(v.parse().expect("Invalid --client-index"));
                }
            }
            "--preproc-store" => {
                if let Some(v) = args_iter.next() {
                    preproc_store_path = Some(v);
                }
            }
            "--local-store" => {
                if let Some(v) = args_iter.next() {
                    local_store_path = Some(v);
                }
            }
            "--expected-clients" => {
                if let Some(v) = args_iter.next() {
                    expected_clients = v.split(',').map(|s| s.trim().to_string()).collect();
                }
            }
            "--client-roster" => {
                if let Some(v) = args_iter.next() {
                    client_roster = v
                        .split(',')
                        .filter(|s| !s.trim().is_empty())
                        .map(|s| s.trim().parse().expect("Invalid --client-roster slot"))
                        .collect();
                }
            }
            "--client-input-slots" => {
                if let Some(v) = args_iter.next() {
                    client_input_slots = v
                        .split(',')
                        .filter(|s| !s.trim().is_empty())
                        .map(|s| s.trim().parse().expect("Invalid --client-input-slots slot"))
                        .collect();
                }
            }
            "--advertise" => {
                if let Some(v) = args_iter.next() {
                    advertise_addr = Some(v.parse().expect("Invalid --advertise addr"));
                }
            }
            "--no-program-upload" => {}
            _ => {}
        }
    }

    let coordinator_output_format = match output_fixed_point_fractional_bits {
        Some(bits) => {
            if bits > 62 {
                eprintln!("Error: --output-fixed-point-fractional-bits must be <= 62");
                exit(2);
            }
            CoordinatorOutputFormat::FixedPoint {
                fractional_bits: bits,
            }
        }
        None => CoordinatorOutputFormat::FieldInteger,
    };
    let storage_identity = required_storage_identity(
        &cert_der,
        &key_der,
        local_store_path.is_some() || preproc_store_path.is_some(),
    );
    if contract_addr.is_some() {
        let _ = (eth_node_addr.as_ref(), wallet_sk_str.as_ref());
        eprintln!(
            "Error: on-chain coordinator mode is temporarily unavailable in the crates.io-ready build"
        );
        exit(2);
    }

    // Bootnode-only mode (no program execution)
    if as_bootnode && !as_leader {
        let bind = bind_addr.unwrap_or_else(|| "127.0.0.1:9000".parse().unwrap());
        eprintln!("Starting bootnode on {}", bind);
        // Install crypto provider for quinn/rustls
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");
        // Pass expected parties if specified, so bootnode waits for all before announcing session
        if let Err(e) = run_bootnode_with_config(bind, n_parties).await {
            eprintln!("Bootnode error: {}", e);
            exit(10);
        }
        return;
    }

    // Client mode: connect to MPC servers and provide inputs
    if as_client {
        if coord_addr.is_some()
            && contract_addr.is_none()
            && mpc_backend.as_deref().is_some_and(|backend| {
                backend.eq_ignore_ascii_case("avss") || backend.eq_ignore_ascii_case("adkg")
            })
        {
            let curve_config = if let Some(ref name) = mpc_curve {
                match MpcCurveConfig::from_str(name) {
                    Ok(c) => c,
                    Err(e) => {
                        eprintln!("Error: {}", e);
                        exit(2);
                    }
                }
            } else {
                MpcCurveConfig::default()
            };
            if let Err(e) = curve_config.validate_for_backend(MpcBackendKind::Avss) {
                eprintln!("Error: {}", e);
                exit(2);
            }
            run_avss_offchain_coordinator_client(AvssOffchainCoordinatorClientArgs {
                curve_config,
                client_inputs,
                client_outputs,
                output_format: coordinator_output_format,
                server_addrs,
                coord_addr: coord_addr.clone().unwrap(),
                cert_der: cert_der.clone().expect("--cert required in client mode"),
                key_der: key_der.clone().expect("--key required in client mode"),
                threshold,
                coordinator_client_index,
            })
            .await;
            return;
        }

        // Coordinator-based client mode
        if contract_addr.is_some() || coord_addr.is_some() {
            {
                let curve_config = if let Some(ref name) = mpc_curve {
                    match MpcCurveConfig::from_str(name) {
                        Ok(c) => c,
                        Err(e) => {
                            eprintln!("Error: {}", e);
                            exit(2);
                        }
                    }
                } else {
                    MpcCurveConfig::default()
                };
                if let Err(e) = curve_config.validate_for_backend(MpcBackendKind::HoneyBadger) {
                    eprintln!("Error: {}", e);
                    exit(2);
                }
                run_hb_coordinator_client(
                    curve_config,
                    client_inputs,
                    client_outputs,
                    coordinator_output_format,
                    server_addrs,
                    coord_addr,
                    None,
                    cert_der.expect("--cert required in client mode"),
                    key_der.expect("--key required in client mode"),
                    threshold,
                    coordinator_client_index,
                    None,
                    None,
                )
                .await;
                return;
            }
        }

        // Direct client mode (no coordinator)
        {
            run_as_client(
                n_parties,
                threshold,
                mpc_backend.as_deref(),
                mpc_curve.as_deref(),
                client_inputs,
                client_outputs,
                server_addrs,
            )
            .await;
            return;
        }
    }

    let path_opt = if !positional.is_empty() {
        Some(positional.remove(0))
    } else {
        None
    };
    entry = if !positional.is_empty() {
        positional.remove(0)
    } else {
        entry
    };

    let manifest_config = path_opt.as_ref().map(|path| {
        let file = File::open(path).unwrap_or_else(|error| {
            eprintln!(
                "Error: failed to open compiled program '{}': {}",
                path, error
            );
            exit(2);
        });
        let (_, bytecode_version, client_io_manifest) =
            CompiledBinary::try_for_each_vm_function_from_reader(&mut BufReader::new(file), |_| {
                Ok(())
            })
            .unwrap_or_else(|error| {
                eprintln!(
                    "Error: failed to deserialize compiled program '{}': {:?}",
                    path, error
                );
                exit(2);
            });
        let backend = (bytecode_version >= MPC_BACKEND_MANIFEST_FORMAT_VERSION)
            .then_some(MpcBackendKind::from(client_io_manifest.mpc_backend));
        let curve = (bytecode_version >= MPC_CURVE_MANIFEST_FORMAT_VERSION)
            .then_some(curve_config_from_manifest(client_io_manifest.mpc_curve));
        (backend, curve)
    });
    let manifest_backend = manifest_config.and_then(|(backend, _)| backend);
    let manifest_curve = manifest_config.and_then(|(_, curve)| curve);

    // Resolve MPC backend kind. v3+ binaries are authoritative; --mpc-backend
    // remains for client mode and legacy v1/v2 binaries without backend metadata.
    let backend_kind = if let Some(ref name) = mpc_backend {
        let cli_backend = match MpcBackendKind::from_str(name) {
            Ok(k) => k,
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(2);
            }
        };
        if let Some(manifest_backend) = manifest_backend {
            if cli_backend != manifest_backend {
                eprintln!(
                    "Error: --mpc-backend '{}' does not match program manifest backend '{}'",
                    cli_backend.name(),
                    manifest_backend.name()
                );
                exit(2);
            }
        }
        cli_backend
    } else if let Some(manifest_backend) = manifest_backend {
        manifest_backend
    } else {
        MpcBackendKind::default_backend()
    };

    let curve_config = if let Some(ref name) = mpc_curve {
        let cli_curve = match MpcCurveConfig::from_str(name) {
            Ok(c) => c,
            Err(e) => {
                eprintln!("Error: {}", e);
                exit(2);
            }
        };
        if let Some(manifest_curve) = manifest_curve {
            if cli_curve != manifest_curve {
                eprintln!(
                    "Error: --mpc-curve '{}' does not match program manifest curve '{}'",
                    cli_curve.name(),
                    manifest_curve.name()
                );
                exit(2);
            }
        }
        cli_curve
    } else {
        manifest_curve.unwrap_or_default()
    };

    if let Err(e) = curve_config.validate_for_backend(backend_kind) {
        eprintln!("Error: {}", e);
        exit(2);
    }

    // Validate incompatible flag combinations
    if !backend_kind.supports_client_input() && as_client {
        eprintln!(
            "Error: {} backend does not support client mode",
            backend_kind.name()
        );
        exit(2);
    }

    if expected_client_count.is_some() && !backend_kind.supports_client_input() {
        eprintln!(
            "Error: {} backend does not support --wait-for-clients",
            backend_kind.name()
        );
        exit(2);
    }

    // Optional: bring up networking in party mode if bootstrap provided or if leader
    let mut net_opt: Option<Arc<QuicNetworkManager>> = None;
    let program_id: [u8; 32];
    let mut agreed_entry = entry.clone();
    let mut session_instance_id: Option<u64> = None;
    let mut session_n_parties: Option<usize> = None;
    let mut session_threshold: Option<usize> = None;

    // Leader mode: this party also runs the bootnode
    if as_leader {
        let bind = bind_addr.unwrap_or_else(|| "127.0.0.1:9000".parse().unwrap());
        let my_id = party_id.unwrap_or(0usize);

        // Install crypto provider for quinn/rustls
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");

        // Must have program path
        if path_opt.is_none() {
            eprintln!("Error: leader mode requires a program path");
            exit(2);
        }
        let program_path = path_opt.as_ref().unwrap();
        let bytes = std::fs::read(program_path).expect("read program");
        program_id = program_id_from_bytes(&bytes);

        // Get MPC parameters (required for session)
        let n = n_parties.unwrap_or_else(|| {
            eprintln!("Error: --n-parties is required for leader mode");
            exit(2);
        });
        let t = threshold.unwrap_or(1);

        eprintln!(
            "[leader/party {}] Starting bootnode on {} and participating in session (n={}, t={})",
            my_id, bind, n, t
        );

        // Spawn bootnode in background
        let bootnode_bind = bind;
        let bootnode_n = n;
        tokio::spawn(async move {
            if let Err(e) = run_bootnode_with_config(bootnode_bind, Some(bootnode_n)).await {
                eprintln!("Bootnode error: {}", e);
            }
        });

        // Give bootnode a moment to start
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Now connect to ourselves as the bootnode
        let mut mgr = QuicNetworkManager::with_node_id(my_id);
        if let (Some(cert), Some(key)) = (cert_der.as_ref(), key_der.as_ref()) {
            if let Err(e) = mgr.set_local_certificate_der(cert.clone(), key.clone()) {
                eprintln!("Failed to configure local node certificate: {}", e);
                exit(11);
            }
        }
        // Listen on a different port for peer connections
        let party_bind: SocketAddr = format!("{}:{}", bind.ip(), bind.port() + 1000)
            .parse()
            .unwrap();
        if let Err(e) = mgr.listen(party_bind).await {
            eprintln!("Failed to listen on {}: {}", party_bind, e);
            exit(11);
        }

        // When the bind address is 0.0.0.0 (e.g. ECS/Fargate), connecting TO 0.0.0.0
        // fails on Linux because it is not a valid destination. Use 127.0.0.1 to reach
        // our own bootnode instead.
        let bootnode_connect: SocketAddr = if bind.ip().is_unspecified() {
            format!("127.0.0.1:{}", bind.port()).parse().unwrap()
        } else {
            bind
        };

        eprintln!(
            "[leader/party {}] Party listening on {}, registering with bootnode {} (connect via {})",
            my_id, party_bind, bind, bootnode_connect
        );

        // Register with our own bootnode and wait for session. By default the
        // leader uploads program bytes so parties without a local copy can fetch
        // them; mounted-program deployments can opt out to avoid a large
        // discovery message.
        let program_bytes = if upload_program_bytes {
            Some(bytes)
        } else {
            None
        };
        let session_info = match register_and_wait_for_session(
            &mut mgr,
            SessionRegistrationConfig {
                bootnode: bootnode_connect,
                my_party_id: my_id,
                my_listen: advertise_addr.unwrap_or(party_bind),
                program_id,
                entry: entry.clone(),
                n_parties: n,
                threshold: t,
                timeout: session_registration_timeout(),
                program_bytes,
            },
        )
        .await
        {
            Ok(info) => info,
            Err(e) => {
                eprintln!("Session registration failed: {}", e);
                exit(12);
            }
        };

        // Use session parameters
        agreed_entry = session_info.entry.clone();
        session_instance_id = Some(session_info.instance_id);
        session_n_parties = Some(session_info.n_parties);
        session_threshold = Some(session_info.threshold);

        eprintln!(
            "[leader/party {}] Session started: instance_id={}, n={}, t={}, entry={}",
            my_id,
            session_info.instance_id,
            session_info.n_parties,
            session_info.threshold,
            agreed_entry
        );

        let net = Arc::new(mgr);
        net_opt = Some(net.clone());
    } else if let Some(bootnode) = bootstrap_addr {
        // Regular party mode: connect to external bootnode
        let bind = bind_addr.unwrap_or_else(|| "127.0.0.1:0".parse().unwrap());
        let my_id = party_id.unwrap_or(0usize);
        rustls::crypto::ring::default_provider()
            .install_default()
            .expect("install rustls crypto");

        // Must have program path in party mode
        if path_opt.is_none() {
            eprintln!("Error: party mode requires a program path");
            exit(2);
        }
        let program_path = path_opt.as_ref().unwrap();
        let bytes = std::fs::read(program_path).expect("read program");
        program_id = program_id_from_bytes(&bytes);

        // Get MPC parameters (required for session)
        let n = n_parties.unwrap_or_else(|| {
            eprintln!("Error: --n-parties is required for party mode");
            exit(2);
        });
        let t = threshold.unwrap_or(1);

        // Prepare QUIC manager
        let mut mgr = QuicNetworkManager::with_node_id(my_id);
        if let (Some(cert), Some(key)) = (cert_der.as_ref(), key_der.as_ref()) {
            if let Err(e) = mgr.set_local_certificate_der(cert.clone(), key.clone()) {
                eprintln!("Failed to configure local node certificate: {}", e);
                exit(11);
            }
        }
        // Listen so peers can connect back directly
        if let Err(e) = mgr.listen(bind).await {
            eprintln!("Failed to listen on {}: {}", bind, e);
            exit(11);
        }

        // Note: if using port 0, the OS assigns a port. For now we use the bind address.
        // In a real deployment, you should use specific ports, not port 0.
        let actual_listen = bind;
        eprintln!(
            "[party {}] Listening on {}, connecting to bootnode {}",
            my_id, actual_listen, bootnode
        );

        // Register with bootnode and wait for session to be announced. This
        // blocks until all n parties have registered. By default parties upload
        // program bytes so the bootnode can distribute to parties that don't
        // have a local copy; mounted-program deployments can opt out.
        let program_bytes = if upload_program_bytes {
            Some(bytes)
        } else {
            None
        };
        let session_info = match register_and_wait_for_session(
            &mut mgr,
            SessionRegistrationConfig {
                bootnode,
                my_party_id: my_id,
                my_listen: advertise_addr.unwrap_or(actual_listen),
                program_id,
                entry: entry.clone(),
                n_parties: n,
                threshold: t,
                timeout: session_registration_timeout(),
                program_bytes,
            },
        )
        .await
        {
            Ok(info) => info,
            Err(e) => {
                eprintln!("Session registration failed: {}", e);
                exit(12);
            }
        };

        // Use session parameters
        agreed_entry = session_info.entry.clone();
        session_instance_id = Some(session_info.instance_id);
        session_n_parties = Some(session_info.n_parties);
        session_threshold = Some(session_info.threshold);

        eprintln!(
            "[party {}] Session started: instance_id={}, n={}, t={}, entry={}",
            my_id,
            session_info.instance_id,
            session_info.n_parties,
            session_info.threshold,
            agreed_entry
        );

        let net = Arc::new(mgr);
        net_opt = Some(net.clone());
    } else {
        // local run: must have path
        if let Some(p) = &path_opt {
            let bytes = std::fs::read(p).expect("read program");
            program_id = program_id_from_bytes(&bytes);
        } else {
            eprintln!("Error: local run requires a program path unless --bootnode or --leader");
            exit(2);
        }
    }

    // Load compiled binary from a file path
    let load_path: String = if let Some(p) = path_opt.clone() {
        p
    } else {
        // Use cached program path if we fetched it from bootnode
        let p = stoffel_vm::net::program_sync::program_path(&program_id);
        p.to_string_lossy().to_string()
    };
    // Initialize VM
    let mut vm_builder = VirtualMachine::builder();
    if let Some(path) = &local_store_path {
        let storage = match RedbLocalStorage::new(path) {
            Ok(storage) => storage,
            Err(err) => {
                eprintln!("Error: failed to open local storage: {}", err);
                exit(3);
            }
        };
        vm_builder = vm_builder.with_local_storage(storage);
    }
    let mut vm = vm_builder.build();

    let (function_count, _bytecode_version, client_io_manifest) = if trace_instr {
        // Instruction tracing hooks need the source Instruction stream for each
        // program counter. Use the source-preserving loader only in traced mode;
        // normal execution keeps the low-peak streaming path below.
        let mut f = File::open(&load_path).expect("open binary file");
        let compiled = match CompiledBinary::deserialize(&mut f) {
            Ok(compiled) => compiled,
            Err(err) => {
                eprintln!("Error: invalid compiled program: {:?}", err);
                exit(3);
            }
        };
        let bytecode_version = compiled.version;
        let client_io_manifest = compiled.client_io_manifest.clone();
        let functions = match compiled.try_to_vm_functions() {
            Ok(functions) => functions,
            Err(err) => {
                eprintln!("Error: invalid compiled program: {:?}", err);
                exit(3);
            }
        };
        let function_count = functions.len();
        for function in functions {
            if let Err(err) = vm.try_register_function(function) {
                eprintln!("Error: invalid VM function: {}", err);
                exit(3);
            }
        }
        (function_count, bytecode_version, client_io_manifest)
    } else {
        // Register all functions as they are read and lowered to avoid retaining
        // the compiled or resolved function table beside the runtime program.
        let f = File::open(&load_path).expect("open binary file");
        match CompiledBinary::try_for_each_resolved_vm_function_from_reader(
            &mut BufReader::new(f),
            |header, stream| {
                let mut stream_error = None;
                let result = vm.try_register_resolved_function_without_source(header, || {
                    match stream.next_instruction() {
                        Ok(instruction) => instruction,
                        Err(err) => {
                            stream_error = Some(err);
                            None
                        }
                    }
                });
                if let Some(err) = stream_error {
                    return Err(err);
                }
                result.map_err(|err| {
                    BinaryError::InvalidData(format!("invalid VM function: {err}"))
                })?;
                Ok(())
            },
        ) {
            Ok(result) => result,
            Err(err) => {
                eprintln!("Error: invalid compiled program: {:?}", err);
                exit(3);
            }
        }
    };
    let client_input_types = manifest_client_input_types(&client_io_manifest);
    let preprocessing_demand = client_io_manifest.preprocessing_demand;
    if function_count == 0 {
        eprintln!("Error: compiled program contains no functions");
        exit(3);
    }

    // Register debugging hooks based on flags
    if trace_instr {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::BeforeInstructionExecute(_) | HookEvent::AfterInstructionExecute(_)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::BeforeInstructionExecute(instr) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let pc = ctx.get_current_instruction();
                    eprintln!(
                        "[instr][depth {}][{}][pc {}] BEFORE {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        pc,
                        instr
                    );
                    Ok(())
                }
                HookEvent::AfterInstructionExecute(instr) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let pc = ctx.get_current_instruction();
                    eprintln!(
                        "[instr][depth {}][{}][pc {}] AFTER  {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        pc,
                        instr
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    if trace_regs {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::RegisterRead(_, _) | HookEvent::RegisterWrite(_, _, _)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::RegisterRead(idx, val) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let bank = if idx.is_secret() { "secret" } else { "clear" };
                    eprintln!(
                        "[regs][depth {}][{}] R{} ({}[{}]) -> {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        idx.index(),
                        bank,
                        idx.bank_index(),
                        val
                    );
                    Ok(())
                }
                HookEvent::RegisterWrite(idx, old, new) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    let bank = if idx.is_secret() { "secret" } else { "clear" };
                    eprintln!(
                        "[regs][depth {}][{}] R{} ({}[{}]): {:?} -> {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        idx.index(),
                        bank,
                        idx.bank_index(),
                        old,
                        new
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    if trace_stack {
        vm.register_hook(
            |event| {
                matches!(
                    event,
                    HookEvent::BeforeFunctionCall(_, _)
                        | HookEvent::AfterFunctionCall(_, _)
                        | HookEvent::StackPush(_)
                        | HookEvent::StackPop(_)
                )
            },
            |event, ctx: &HookContext| match event {
                HookEvent::BeforeFunctionCall(func, args) => {
                    eprintln!(
                        "[stack][depth {}] CALL {} with {:?}",
                        ctx.get_call_depth(),
                        func,
                        args
                    );
                    Ok(())
                }
                HookEvent::AfterFunctionCall(func, ret) => {
                    eprintln!(
                        "[stack][depth {}] RET  {} => {:?}",
                        ctx.get_call_depth(),
                        func,
                        ret
                    );
                    Ok(())
                }
                HookEvent::StackPush(v) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[stack][depth {}][{}] PUSH {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        v
                    );
                    Ok(())
                }
                HookEvent::StackPop(v) => {
                    let fn_name = ctx
                        .get_function_name()
                        .unwrap_or_else(|| "<unknown>".to_string());
                    eprintln!(
                        "[stack][depth {}][{}] POP  {:?}",
                        ctx.get_call_depth(),
                        fn_name,
                        v
                    );
                    Ok(())
                }
                _ => Ok(()),
            },
            0,
        );
    }

    if !trace_instr {
        vm.discard_vm_source_instructions();
    }

    // =====================================================================
    // COORDINATOR (or no coordinator)
    // =====================================================================

    // Coordinator initialization (both leader and party modes)
    let mut coord_opt: Option<HbOffChainCoordinator<ark_bls12_381::Fr>> = None;
    let mut node_rpc_opt: Option<HbOffChainNodeRpcServer<ark_bls12_381::Fr>> = None;
    let mut input_ids: Vec<Vec<u8>> = Vec::new();
    let mut output_ids: Vec<Vec<u8>> = Vec::new();
    let mut hb_bls12381_coord_engine: Option<
        Arc<HoneyBadgerMpcEngine<ark_bls12_381::Fr, ark_bls12_381::G1Projective>>,
    > = None;
    let mut hb_node_counters: Option<Arc<NodeBenchmarkCounters>> = None;

    if matches!(backend_kind, MpcBackendKind::HoneyBadger) {
        if let Some(ref ca) = coord_addr {
            let coord = HbOffChainCoordinator::<ark_bls12_381::Fr>::start_rpc_client(
                &ca.0,
                ca.1,
                session_threshold.unwrap_or(1) as u64,
                session_n_parties.unwrap_or_else(|| n_parties.unwrap_or(5)) as u64,
                1,
                cert_der.clone().expect("--cert required"),
                key_der.clone().expect("--key required"),
            )
            .await
            .unwrap_or_else(|error| {
                eprintln!("Failed to connect to off-chain coordinator: {error}");
                exit(13);
            });
            coord_opt = Some(coord);

            output_ids = expected_clients
                .iter()
                .filter(|path| !path.trim().is_empty())
                .map(|path| extract_pubkey_from_cert(&fs::read(path).expect("read client cert")))
                .collect();
            input_ids = input_client_ids_from_output_ids(
                &output_ids,
                &client_roster,
                &client_input_slots,
                client_input_count,
            );

            if let Some(ref rpc) = rpc_addr {
                let node_rpc = HbOffChainNodeRpcServer::<ark_bls12_381::Fr>::start(
                    &rpc.0,
                    rpc.1,
                    cert_der.clone().unwrap(),
                    key_der.clone().unwrap(),
                )
                .await
                .unwrap_or_else(|error| {
                    eprintln!("Failed to start node RPC server: {error}");
                    exit(13);
                });
                node_rpc_opt = Some(node_rpc);
            }
        }
    }

    // If in party mode, configure MPC engine based on selected backend
    if let Some(net) = net_opt.clone() {
        // Use the network-derived party ID (sorted public key index), not the
        // bootnode-assigned one, because send() routes via sorted public keys.
        let my_id = net.local_party_id();
        // Use session parameters (already agreed upon with bootnode)
        let n = session_n_parties.unwrap_or_else(|| net.parties().len());
        let t = session_threshold.unwrap_or(1);
        // Use the session instance_id (agreed with all parties via bootnode)
        let instance_id =
            session_instance_id.expect("session instance_id should be set in party mode");

        eprintln!(
            "[party {}] Creating MPC engine (backend={}): instance_id={}, n={}, t={}",
            my_id,
            backend_kind.name(),
            instance_id,
            n,
            t
        );

        // Debug: print established connections (server connections are to other MPC parties)
        let connections = net.get_all_server_connections();
        let conn_ids: Vec<_> = connections.iter().map(|(id, _)| *id).collect();
        eprintln!(
            "[party {}] Connections before MPC: {:?} ({} total)",
            my_id,
            conn_ids,
            connections.len()
        );

        match backend_kind {
            MpcBackendKind::HoneyBadger => {
                // Phase 1: Coordinator preprocessing trigger
                if let Some(ref mut coord) = coord_opt {
                    if as_leader {
                        coord.reset_coord().await.unwrap();
                        coord.start_preprocessing().await.unwrap();
                    }
                }
                // Phase 2: Create MPC engine + preprocessing + coordinator input phases
                macro_rules! setup_hb {
                    ($F:ty, $G:ty) => {{
                        match setup_hb_party_for_curve::<$F, $G>(
                            &mut vm,
                            HbPartySetup {
                                net: net.clone(),
                                my_id,
                                persistent_identity: storage_identity.unwrap_or_else(|| {
                                    DurableIdentityDigest::from_legacy_party_id(my_id)
                                }),
                                n,
                                t,
                                instance_id,
                                expected_client_count,
                                coordinator_client_count_hint: 0,
                                client_input_count,
                                client_input_types: &client_input_types,
                                preprocessing_demand,
                                program_hash: program_id,
                                preproc_store_path: preproc_store_path.as_deref(),
                            },
                        )
                        .await
                        {
                            Ok(engine) => {
                                hb_node_counters = engine
                                    .node_handle()
                                    .try_lock()
                                    .ok()
                                    .map(|guard| Arc::clone(&guard.benchmark_counters));
                            }
                            Err(e) => {
                                eprintln!("[party {}] HoneyBadger setup failed: {}", my_id, e);
                                exit(13);
                            }
                        };
                    }};
                }

                // Bls12_381 path with coordinator support
                if coord_opt.is_some() && matches!(curve_config, MpcCurveConfig::Bls12_381) {
                    let engine = match setup_hb_party_for_curve::<
                        ark_bls12_381::Fr,
                        ark_bls12_381::G1Projective,
                    >(
                        &mut vm,
                        HbPartySetup {
                            net: net.clone(),
                            my_id,
                            persistent_identity: storage_identity.unwrap_or_else(|| {
                                DurableIdentityDigest::from_legacy_party_id(my_id)
                            }),
                            n,
                            t,
                            instance_id,
                            expected_client_count: None, // coordinator handles clients
                            coordinator_client_count_hint: output_ids.len(),
                            client_input_count,
                            client_input_types: &client_input_types,
                            preprocessing_demand,
                            program_hash: program_id,
                            preproc_store_path: preproc_store_path.as_deref(),
                        },
                    )
                    .await
                    {
                        Ok(e) => e,
                        Err(e) => {
                            eprintln!("[party {}] HoneyBadger setup failed: {}", my_id, e);
                            exit(13);
                        }
                    };
                    if coord_opt.is_some() {
                        engine.enable_client_output_capture().await;
                        hb_bls12381_coord_engine = Some(engine.clone());
                    }

                    // Coordinator mask distribution + input collection
                    if let Some(ref mut coord) = coord_opt {
                        let node_rpc = node_rpc_opt
                            .as_mut()
                            .expect("--rpc-bind required with coordinator");

                        if !input_ids.is_empty() {
                            // Actual total across clients (supports asymmetric
                            // per-client input counts); fall back to the uniform
                            // estimate only when the total wasn't supplied.
                            let total_input_count = if client_input_total > 0 {
                                client_input_total
                            } else {
                                input_ids.len().saturating_mul(client_input_count)
                            };
                            let precomputed_mask_shares = Some(
                                engine
                                    .node_handle()
                                    .lock()
                                    .await
                                    .preprocessing_material
                                    .lock()
                                    .await
                                    .take_random_shares(total_input_count)
                                    .unwrap_or_else(|e| {
                                        eprintln!("take_random_shares: {}", e);
                                        exit(13);
                                    }),
                            );

                            if let Some(ref mask_shares) = precomputed_mask_shares {
                                for (i, share) in mask_shares.iter().enumerate() {
                                    node_rpc
                                        .add_mask_share(i as u64, share)
                                        .await
                                        .unwrap_or_else(|e| {
                                            eprintln!("add_mask_share: {:?}", e);
                                            exit(13);
                                        });
                                }
                            }

                            if as_leader {
                                eprintln!("[party {my_id}] coordinator -> InputMaskReservation");
                                coord.reserve_input_masks().await.unwrap();
                            }
                            coord
                                .wait_for_round(Round::InputMaskReservation)
                                .await
                                .unwrap();

                            eprintln!("[party {my_id}] waiting for reserved input indices");
                            let client_to_indices = normalize_client_to_indices(
                                coord
                                    .wait_for_indices(total_input_count as u64)
                                    .await
                                    .unwrap(),
                            );
                            eprintln!("[party {my_id}] reserved input indices received");

                            let mask_shares = if let Some(mask_shares) = precomputed_mask_shares {
                                mask_shares
                            } else {
                                let mask_shares = load_reserved_mask_shares(
                                    &engine,
                                    total_input_count,
                                    client_to_indices.values().flatten().copied(),
                                )
                                .await
                                .unwrap_or_else(|e| {
                                    eprintln!("load_reserved_mask_shares: {}", e);
                                    exit(13);
                                });

                                for idx in client_to_indices.values().flatten().copied() {
                                    node_rpc
                                        .add_mask_share(idx, &mask_shares[idx as usize])
                                        .await
                                        .unwrap_or_else(|e| {
                                            eprintln!("add_mask_share: {:?}", e);
                                            exit(13);
                                        });
                                }

                                mask_shares
                            };

                            for (cid, indices) in &client_to_indices {
                                for idx in indices {
                                    node_rpc
                                        .add_reserved_index(cid.clone(), *idx)
                                        .await
                                        .unwrap_or_else(|e| {
                                            eprintln!("add_reserved_index: {:?}", e);
                                            exit(13);
                                        });
                                }
                            }

                            if as_leader {
                                eprintln!("[party {my_id}] coordinator -> InputCollection");
                                coord.collect_inputs().await.unwrap();
                            }
                            coord.wait_for_round(Round::InputCollection).await.unwrap();

                            eprintln!("[party {my_id}] waiting for masked client inputs");
                            let client_inputs = coord
                                .wait_for_inputs(total_input_count as u64, mask_shares)
                                .await
                                .unwrap();
                            eprintln!("[party {my_id}] masked client inputs received");
                            store_reserved_client_inputs(
                                &mut vm,
                                &client_to_indices,
                                client_inputs,
                                client_input_count,
                                &client_input_slots,
                                &client_input_types,
                            );
                        }
                    }
                } else {
                    // No coordinator or non-Bls12_381 curves
                    match curve_config {
                        MpcCurveConfig::Bls12_381 => {
                            setup_hb!(ark_bls12_381::Fr, ark_bls12_381::G1Projective)
                        }
                        MpcCurveConfig::Bn254 => {
                            setup_hb!(ark_bn254::Fr, ark_bn254::G1Projective)
                        }
                        MpcCurveConfig::Curve25519 => {
                            setup_hb!(ark_curve25519::Fr, ark_curve25519::EdwardsProjective)
                        }
                        MpcCurveConfig::Ed25519 => {
                            setup_hb!(ark_ed25519::Fr, ark_ed25519::EdwardsProjective)
                        }
                        MpcCurveConfig::Secp256k1 | MpcCurveConfig::Secp256r1 => {
                            eprintln!(
                                "Error: curve {} is not supported by honeybadger backend",
                                curve_config.name()
                            );
                            exit(2);
                        }
                    }
                }

                eprintln!(
                    "[party {}] HoneyBadger MPC engine set, starting VM execution...",
                    my_id
                );
            }
            MpcBackendKind::Avss => {
                eprintln!(
                    "[party {}] Setting up AVSS backend (curve: {})...",
                    my_id,
                    curve_config.name()
                );

                if let Some(coord) = coord_addr.clone() {
                    let rpc = rpc_addr.clone().unwrap_or_else(|| {
                        eprintln!("Error: --rpc-bind is required with AVSS coordinator mode");
                        exit(2);
                    });
                    let cert = cert_der.clone().unwrap_or_else(|| {
                        eprintln!("Error: --cert is required with AVSS coordinator mode");
                        exit(2);
                    });
                    let key = key_der.clone().unwrap_or_else(|| {
                        eprintln!("Error: --key is required with AVSS coordinator mode");
                        exit(2);
                    });
                    if let Err(e) = run_avss_coordinated_party(
                        curve_config,
                        &mut vm,
                        net.clone(),
                        my_id,
                        n,
                        t,
                        instance_id,
                        coord,
                        rpc,
                        cert,
                        key,
                        &expected_clients,
                        as_leader,
                        &agreed_entry,
                    )
                    .await
                    {
                        eprintln!("[party {}] AVSS coordinator execution failed: {}", my_id, e);
                        exit(13);
                    }
                    return;
                }

                macro_rules! setup_avss {
                    ($F:ty, $G:ty) => {{
                        if let Err(e) = setup_avss_party_for_curve::<$F, $G>(
                            &mut vm,
                            net.clone(),
                            AvssPartySetup {
                                my_id,
                                local_identity: storage_identity.unwrap_or_else(|| {
                                    DurableIdentityDigest::from_legacy_party_id(my_id)
                                }),
                                n,
                                t,
                                instance_id,
                                expected_client_count,
                                client_input_count,
                                client_input_types: &client_input_types,
                            },
                        )
                        .await
                        {
                            eprintln!("[party {}] AVSS setup failed: {}", my_id, e);
                            exit(13);
                        }
                    }};
                }

                match curve_config {
                    MpcCurveConfig::Bls12_381 => {
                        setup_avss!(ark_bls12_381::Fr, ark_bls12_381::G1Projective)
                    }
                    MpcCurveConfig::Bn254 => {
                        setup_avss!(ark_bn254::Fr, ark_bn254::G1Projective)
                    }
                    MpcCurveConfig::Curve25519 => {
                        setup_avss!(ark_curve25519::Fr, ark_curve25519::EdwardsProjective)
                    }
                    MpcCurveConfig::Ed25519 => {
                        setup_avss!(ark_ed25519::Fr, ark_ed25519::EdwardsProjective)
                    }
                    MpcCurveConfig::Secp256k1 => {
                        setup_avss!(ark_secp256k1::Fr, ark_secp256k1::Projective)
                    }
                    MpcCurveConfig::Secp256r1 => {
                        setup_avss!(ark_secp256r1::Fr, ark_secp256r1::Projective)
                    }
                }

                eprintln!(
                    "[party {}] AVSS engine set, starting VM execution...",
                    my_id
                );
            }
        }
    }

    // Coordinator: signal MPC execution phase
    if let Some(ref mut coord) = coord_opt {
        if as_leader {
            eprintln!("[party] coordinator -> MPCExecution");
            coord.start_mpc().await.unwrap();
        }
        coord.wait_for_round(Round::MPCExecution).await.unwrap();
    }

    eprintln!("Starting VM execution of '{}'...", agreed_entry);
    if !client_roster.is_empty() {
        vm.set_client_roster(client_roster.clone());
    }

    // Execute entry function. Prefer the async MPC scheduler when an async-capable
    // engine was installed so secret-share operations yield instead of blocking
    // inside the synchronous VM instruction path.
    //
    // This call is the online phase (preprocessing is already done), so timing it
    // isolates online MPC cost from preprocessing for benchmarking.
    let online_started_at = std::time::Instant::now();
    let execution_result = if let Some(engine) = hb_bls12381_coord_engine.as_ref() {
        vm.execute_async(&agreed_entry, engine.as_ref()).await
    } else {
        vm.execute(&agreed_entry)
    };
    eprintln!(
        "online VM execution complete! elapsed_ms={}",
        online_started_at.elapsed().as_millis()
    );

    match execution_result {
        Ok(result) => {
            {
                let mut handled_by_coordinator = false;

                if let Some(ref mut coord) = coord_opt {
                    handled_by_coordinator = true;
                    // Coordinator output delivery
                    let output_share = if output_ids.is_empty() {
                        None
                    } else {
                        coordinator_output_share_bytes(&mut vm, &result)
                    };
                    let captured_outputs = if let Some(engine) = hb_bls12381_coord_engine.as_ref() {
                        engine.drain_client_output_records().await
                    } else {
                        Vec::new()
                    };

                    if output_share.is_some() || !captured_outputs.is_empty() {
                        let mut output_shares_by_client: Vec<
                            Vec<HbCoordinatorShare<ark_bls12_381::Fr>>,
                        > = vec![Vec::new(); output_ids.len()];

                        if let Some(output_share) = output_share {
                            let share: HbCoordinatorShare<ark_bls12_381::Fr> =
                                ark_serialize::CanonicalDeserialize::deserialize_compressed(
                                    output_share.as_slice(),
                                )
                                .expect("deserialize output share");
                            for shares in output_shares_by_client.iter_mut() {
                                shares.push(share.clone());
                            }
                        }

                        for record in captured_outputs {
                            let Some(shares) = output_shares_by_client.get_mut(record.client_id)
                            else {
                                eprintln!(
                                    "Execution error in '{}': HoneyBadger output client index {} has no matching coordinator client identity",
                                    agreed_entry,
                                    record.client_id
                                );
                                exit(4);
                            };
                            shares.extend(record.shares);
                        }

                        if as_leader {
                            coord.send_output().await.unwrap();
                        }
                        coord
                            .wait_for_round(Round::OutputDistribution)
                            .await
                            .unwrap();

                        for (cid, output_shares) in
                            output_ids.iter().zip(output_shares_by_client.into_iter())
                        {
                            if output_shares.is_empty() {
                                continue;
                            }
                            if let Err(e) = coord
                                .send_output_shares(cid.clone(), cid.clone(), output_shares)
                                .await
                            {
                                eprintln!(
                                    "Warning: failed to submit output shares for client {:?}: {}",
                                    cid, e
                                );
                            }
                        }
                        if as_leader {
                            if let Err(e) = coord.finalize().await {
                                eprintln!(
                                    "Warning: failed to finalize off-chain coordinator round: {}",
                                    e
                                );
                            }
                        }
                    }
                    print_vm_result(&mut vm, result.clone());
                }

                if !handled_by_coordinator {
                    print_vm_result(&mut vm, result);
                }
            }
        }
        Err(err) => {
            eprintln!("Execution error in '{}': {}", agreed_entry, err);
            exit(4);
        }
    }

    #[cfg(feature = "benchmark")]
    if let Some(engine) = hb_bls12381_coord_engine.as_ref() {
        let node = engine.node_handle().lock().await;
        eprintln!("HoneyBadger MPC statistics:\n{}", node.benchmark_snapshot());
    } else if let Some(counters) = hb_node_counters.as_ref() {
        eprintln!("HoneyBadger MPC statistics:\n{}", counters.snapshot());
    }
}

fn print_usage_and_exit() -> ! {
    eprintln!(
        r#"Stoffel VM Runner

Usage:
  stoffel-run <path-to-compiled-binary> [entry_function] [flags]

Flags:
  --trace-instr           Trace instructions before/after execution
  --trace-regs            Trace register reads/writes
  --trace-stack           Trace function calls and stack push/pop
  --bootnode              Run as bootnode only (coordinates party discovery)
  --leader                Run as leader: bootnode + party 0 in one process
  --client                Run as client (provide inputs to MPC network)
  --no-program-upload     Do not upload program bytes during session registration
  --bind <addr:port>      Bind address for bootnode or party listen
  --party-id <usize>      Party id (party mode, 0-indexed)
  --bootstrap <addr:port> Bootnode address (party mode or client mode)
  --n-parties <usize>     Number of parties for MPC (required in party/leader/client mode)
  --threshold <usize>     Threshold t (default: 1)
  --mpc-backend <name>    MPC backend: honeybadger (default) or avss
  --mpc-curve <name>      MPC curve: bls12-381 (default), bn254, curve25519, ed25519;
                          AVSS also supports secp256k1 and p-256
  --inputs <values>       Comma-separated input values (client mode)
  --outputs <n>           Number of output field elements to reconstruct (client mode)
  --output-fixed-point-fractional-bits <n>
                          Decode coordinator client outputs as fixed-point values
                          with n fractional bits instead of raw field integers
  --servers <addrs>       Comma-separated server addresses (client mode)
  --wait-for-clients <n>
                          Number of client inputs to collect before starting computation
                          (HoneyBadger only; ALPN handles routing, this controls coordination)
  --client-input-count <n>
                          Number of input shares each direct host-mode client submits
                          (default: 1; use with --wait-for-clients)
  --off-chain-coord <addr:port>
                          Off-chain coordinator address
  --on-chain-coord <address>
                          Temporarily unavailable in the crates.io-ready build
  --eth-node <url>        Reserved for future on-chain coordinator support
  --wallet-sk <hex>       Reserved for future on-chain coordinator support
  --rpc-bind <addr:port>  Node RPC server bind address (for mask distribution)
  --cert <path>           Path to DER-encoded X.509 certificate
  --key <path>            Path to DER-encoded private key
  --client-index <u64>    Reserved coordinator input index (coordinator client mode)
  --preproc-store <path>  Persistent HoneyBadger preprocessing store directory
  --local-store <path>    Persistent VM local storage database
  --expected-clients <cert-paths>
                          Comma-separated client cert paths for off-chain coordinator mode
  -h, --help              Show this help

Required environment:
  STOFFEL_AUTH_TOKEN      Shared secret required by bootnode and all parties for
                          authenticated discovery registration

Multi-Party Execution:
  In party mode, all parties register with the bootnode and wait until
  all n-parties have joined. The bootnode then broadcasts a session with
  a shared instance_id to all parties, ensuring they all use the same
  MPC configuration.

  Use --leader on one party to have it also run the bootnode. This reduces
  the number of processes needed by one.

Examples:
  # Local execution (no MPC)
  stoffel-run program.stfbin
  stoffel-run program.stfbin main --trace-instr

  # Multi-party execution (5 parties, threshold 1) - Leader mode (recommended)
  # Terminal 1: Leader (bootnode + party 0)
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --leader --bind 127.0.0.1:9000 --n-parties 5 --threshold 1

  # Terminals 2-5: Other parties
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 1 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9002 --n-parties 5 --threshold 1
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 2 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9003 --n-parties 5 --threshold 1
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 3 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9004 --n-parties 5 --threshold 1
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 4 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9005 --n-parties 5 --threshold 1

  # Alternative: Separate bootnode (6 processes total)
  # Terminal 1: Bootnode only
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run --bootnode --bind 127.0.0.1:9000 --n-parties 5

  # Terminals 2-6: All parties
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 0 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9001 --n-parties 5 --threshold 1
  STOFFEL_AUTH_TOKEN=replace-with-random-secret \
  stoffel-run program.stfbin main --party-id 1 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9002 --n-parties 5 --threshold 1
  # ... etc

  # Multi-party execution with client inputs (canonical sorted client IDs)
  # Terminal 1: Leader with expected client count
  stoffel-run program.stfbin main --leader --bind 127.0.0.1:9000 --n-parties 5 --threshold 1 --wait-for-clients 2

  # Terminals 2-5: Other parties (same expected-client-count)
  stoffel-run program.stfbin main --party-id 1 --bootstrap 127.0.0.1:9000 --bind 127.0.0.1:9002 --n-parties 5 --wait-for-clients 2
  # ... etc

  # Client mode: provide inputs to the MPC network
  # Note: clients connect directly to party servers, not the bootnode
  stoffel-run --client --inputs 10,20 --servers 127.0.0.1:10000,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004,127.0.0.1:9005 --n-parties 5
  stoffel-run --client --inputs 30,40 --servers 127.0.0.1:10000,127.0.0.1:9002,127.0.0.1:9003,127.0.0.1:9004,127.0.0.1:9005 --n-parties 5

  # Docker example with client inputs:
  # Start parties with expected-client-count:
  # docker run ... -e STOFFEL_EXPECTED_CLIENT_COUNT=2 stoffelvm:latest
  # Then run clients connecting to the party servers:
  stoffel-run --client --inputs 42 --servers 172.18.0.2:9000,172.18.0.3:9000,172.18.0.4:9000,172.18.0.5:9000,172.18.0.6:9000 --n-parties 5
"#
    );
    exit(1);
}

#[cfg(test)]
mod tests {
    use super::{
        band_pow2, client_transport_recipient, client_transport_targets, field_outputs_to_hex,
        format_coordinator_outputs, input_client_ids_from_output_ids, plan_preprocessing,
        render_fixed_point_i64, CoordinatorOutputFormat,
    };
    use stoffel_vm::net::MpcCurveConfig;
    use stoffel_vm_types::compiled_binary::PreprocessingDemand;

    fn demand(triples: u64, prandbits: u64, prandints: u64, dynamic: bool) -> PreprocessingDemand {
        PreprocessingDemand {
            triples,
            randoms: 0,
            prandbits,
            prandints,
            dynamic,
        }
    }

    #[test]
    fn band_pow2_rounds_up_to_eighth_octave_and_keeps_zero() {
        assert_eq!(band_pow2(0), 0);
        assert_eq!(band_pow2(1), 1);
        // Powers of two and their eighth-octave multiples are exact.
        assert_eq!(band_pow2(16), 16);
        assert_eq!(band_pow2(131072), 131072);
        // 50 → octave floor 32, eighth = 4, round up to 52.
        assert_eq!(band_pow2(50), 52);
        // The banded value never exceeds the demand by more than one eighth of
        // its octave, so a demand that fits the backend capacity stays fitting:
        // 165_696 bands to 180_224 (< the old 262_144 that tripped LimitError).
        assert_eq!(band_pow2(165_696), 180_224);
        for n in [1u64, 7, 9, 100, 1000, 60_000, 134_528, 165_696, 200_000] {
            let b = band_pow2(n);
            assert!(b >= n, "band must not under-provision");
            assert!(
                b <= n + (n / 8) + 8,
                "band over-provisions by at most ~1/8 octave"
            );
        }
    }

    #[test]
    fn client_transport_routing_keeps_lower_recipient_unchanged() {
        assert_eq!(client_transport_recipient(1, 3), Some(1));
    }

    #[test]
    fn client_transport_routing_shifts_past_local_position_without_leaking() {
        assert_eq!(client_transport_recipient(3, 3), Some(4));
        assert_eq!(client_transport_recipient(4, 3), Some(5));
        assert_eq!(client_transport_targets(3, 3), Some([4]));
        assert!(!client_transport_targets(3, 3).unwrap().contains(&3));
    }

    #[test]
    fn client_transport_routing_rejects_shift_overflow() {
        assert_eq!(client_transport_recipient(usize::MAX, 0), None);
    }

    #[test]
    fn plan_for_single_division_folds_prandbit_cost_into_triples_and_randoms() {
        // 16 prandbits + 1 prandint (one secure fix64 / constant). prandbit
        // generation consumes a triple + random per bit, so the planned triple
        // and random pools must cover the banded prandbit count. HoneyBadger
        // generates the random shares needed to build triples internally, so the
        // visible random pool is only the baseline plus prandbits.
        let plan = plan_preprocessing(&demand(0, 16, 1, false), 1, 0);
        assert_eq!(plan.n_prandbit, 16);
        assert_eq!(plan.n_prandint, 1);
        assert_eq!(plan.n_triples, 16);
        assert_eq!(plan.n_random, 18);
    }

    #[test]
    fn plan_for_clear_program_still_provisions_minimal_random_pool() {
        let plan = plan_preprocessing(&demand(0, 0, 0, false), 1, 0);
        assert_eq!(plan.n_prandbit, 0);
        assert_eq!(plan.n_prandint, 0);
        assert_eq!(plan.n_triples, 0);
        assert_eq!(plan.n_random, 2);
    }

    #[test]
    fn plan_for_secret_multiplication_floors_to_protocol_triple_batch() {
        // One triple demanded, but the protocol's minimum batch is 2t+1 = 3.
        // Eighth-octave banding leaves 3 as-is (its octave floor is 2, so the
        // granularity is 1). The requested random pool stays at the baseline
        // because HoneyBadger generates the random shares used to build triples
        // inside preprocessing.
        let plan = plan_preprocessing(&demand(1, 0, 0, false), 1, 0);
        assert_eq!(plan.n_prandbit, 0);
        assert_eq!(plan.n_triples, 3);
        assert_eq!(plan.n_random, 2);
    }

    #[test]
    fn plan_gives_dynamic_programs_an_extra_octave_of_headroom() {
        let stat = plan_preprocessing(&demand(0, 16, 1, false), 1, 0);
        let dyn_ = plan_preprocessing(&demand(0, 16, 1, true), 1, 0);
        // The dynamic flag doubles the estimate before banding, so the prandbit
        // pool is one octave larger than the static plan's.
        assert_eq!(stat.n_prandbit, 16);
        assert_eq!(dyn_.n_prandbit, 32);
        assert!(dyn_.n_triples >= stat.n_triples);
    }

    #[test]
    fn formats_negative_field_outputs_as_signed_i64s() {
        let outputs = vec![-ark_bls12_381::Fr::from(10u64)];
        assert_eq!(
            format_coordinator_outputs(&outputs, CoordinatorOutputFormat::FieldInteger),
            "[-10]"
        );
    }

    #[test]
    fn output_only_clients_do_not_become_input_clients() {
        let output_ids = vec![vec![10], vec![11], vec![12]];

        let input_ids = input_client_ids_from_output_ids(&output_ids, &[0, 1, 2], &[], 0);

        assert!(input_ids.is_empty());
    }

    #[test]
    fn client_input_slots_select_sparse_input_clients_from_output_roster() {
        let output_ids = vec![vec![20], vec![21], vec![22]];

        let input_ids = input_client_ids_from_output_ids(&output_ids, &[0, 2, 5], &[2], 1);

        assert_eq!(input_ids, vec![vec![21]]);
    }

    #[test]
    fn missing_client_input_slots_preserves_legacy_all_clients_are_inputs() {
        let output_ids = vec![vec![30], vec![31]];

        let input_ids = input_client_ids_from_output_ids(&output_ids, &[], &[], 1);

        assert_eq!(input_ids, output_ids);
    }

    #[test]
    fn formats_positive_field_outputs_as_signed_i64s() {
        let outputs = vec![ark_bls12_381::Fr::from(10u64)];
        assert_eq!(
            format_coordinator_outputs(&outputs, CoordinatorOutputFormat::FieldInteger),
            "[10]"
        );
    }

    #[test]
    fn formats_fixed_point_outputs_without_raw_scale() {
        let outputs = vec![
            ark_bls12_381::Fr::from(524_288u64),
            ark_bls12_381::Fr::from(163_840u64),
        ];

        assert_eq!(
            format_coordinator_outputs(
                &outputs,
                CoordinatorOutputFormat::FixedPoint {
                    fractional_bits: 16
                }
            ),
            "[8, 2.5]"
        );
    }

    #[test]
    fn formats_negative_fixed_point_outputs_without_raw_scale() {
        assert_eq!(
            render_fixed_point_i64(-163_840, 16).as_deref(),
            Some("-2.5")
        );
    }

    #[test]
    fn avss_client_output_hex_concatenates_fixed_width_ecdsa_scalars() {
        let outputs = vec![ark_secp256k1::Fr::from(1u64), ark_secp256k1::Fr::from(2u64)];
        let output_hex = field_outputs_to_hex(&outputs, MpcCurveConfig::Secp256k1);

        assert_eq!(output_hex.len(), 128);
        assert_eq!(
            output_hex,
            format!("{}{}", "0".repeat(63) + "1", "0".repeat(63) + "2")
        );
    }
}
