use super::super::{MpcEngineError, MpcEngineResult, MpcExponentGroup};
use super::core::MpcEngine;
use crate::net::client_store::{
    ClientInputHydrationCount, ClientInputStore, ClientOutputShareCount,
};
use crate::net::reservation::ReservationGrant;
use crate::storage::preproc::{PoolAvailability, PreprocStore};
use std::sync::Arc;
use stoffel_vm_types::core_types::{ShareData, ShareType};
use stoffelnet::network_utils::ClientId;

/// Extended MPC engine trait for interactive share multiplication.
///
/// Multiplication consumes preprocessing material and/or network interaction in
/// most MPC protocols, so backends expose it as an explicit capability instead
/// of forcing field-only or input-only engines to carry placeholder methods.
pub trait MpcEngineMultiplication: MpcEngine {
    /// Perform secure multiplication of two shares.
    fn multiply_share(
        &self,
        ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData>;

    /// Perform secure multiplication for a batch of share pairs.
    ///
    /// Backends with a native vectorized protocol should override this method.
    /// The default preserves compatibility by executing scalar multiplications
    /// in order.
    fn batch_multiply_shares(
        &self,
        ty: ShareType,
        pairs: &[(Vec<u8>, Vec<u8>)],
    ) -> MpcEngineResult<Vec<ShareData>> {
        pairs
            .iter()
            .map(|(left, right)| self.multiply_share(ty, left, right))
            .collect()
    }

    /// Divide a secret fixed-point share by a public positive constant.
    ///
    /// `divisor_scaled` is the divisor already scaled into the share's
    /// fixed-point representation (`round(divisor * 2^f)`). Division shares the
    /// multiplication capability because it consumes the same class of
    /// preprocessing (truncation randomness). Backends without fixed-point
    /// division leave the default, which reports the operation unsupported.
    fn divide_fixed_by_constant(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        divisor_scaled: i64,
    ) -> MpcEngineResult<ShareData> {
        let _ = (ty, share_bytes, divisor_scaled);
        Err(MpcEngineError::operation_failed(
            "divide_fixed_by_constant",
            "this MPC backend does not support fixed-point division",
        ))
    }
}

/// Extended MPC engine trait for client input management.
pub trait MpcEngineClientOps: MpcEngine {
    /// Get all client IDs that have submitted inputs.
    fn get_client_ids_sync(&self) -> Vec<ClientId>;

    /// Check if a specific client has submitted inputs.
    fn has_client_input(&self, client_id: ClientId) -> bool {
        self.get_client_ids_sync().contains(&client_id)
    }

    /// Hydrate a `ClientInputStore` with all client inputs from the MPC node.
    ///
    /// Returns the number of clients whose inputs were hydrated.
    fn hydrate_client_inputs_sync(
        &self,
        store: &ClientInputStore,
    ) -> MpcEngineResult<ClientInputHydrationCount>;

    /// Hydrate a `ClientInputStore` with inputs from specific clients.
    fn hydrate_client_inputs_for_sync(
        &self,
        store: &ClientInputStore,
        client_ids: &[ClientId],
    ) -> MpcEngineResult<ClientInputHydrationCount>;
}

/// Extended MPC engine trait for opening shares in an exponent group.
///
/// Backends that implement this capability can expose public group elements
/// derived from secret shares without revealing the scalar itself. Keeping this
/// separate from [`MpcEngine`] lets field-only engines remain small while AVSS
/// or curve-aware backends provide richer threshold-crypto operations.
pub trait MpcEngineOpenInExponent: MpcEngine {
    /// Reveal a share in the exponent: reconstruct `[secret] * generator`.
    fn open_share_in_exp(
        &self,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>>;

    /// Native exponent group handled by [`MpcEngineOpenInExponent::open_share_in_exp`].
    fn native_exponent_group(&self) -> MpcExponentGroup {
        MpcExponentGroup::native_for_curve(self.curve_config())
    }

    /// Whether this engine can open shares into the requested exponent group.
    fn supports_exponent_group(&self, group: MpcExponentGroup) -> bool {
        self.native_exponent_group() == group
    }

    /// Reveal a share in the exponent for a named group.
    ///
    /// Most engines support exactly their native curve/group and can rely on
    /// this default. Engines that support additional groups can override
    /// [`MpcEngineOpenInExponent::supports_exponent_group`] and this method
    /// without requiring VM builtins to downcast to concrete engine types.
    fn open_share_in_exp_group(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        share_bytes: &[u8],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<u8>> {
        if !self.supports_exponent_group(group) {
            return Err(MpcEngineError::operation_failed(
                "open_share_in_exp_group",
                group.unsupported_error(self.protocol_name()),
            ));
        }

        self.open_share_in_exp(ty, share_bytes, generator_bytes)
    }

    /// Reveal several shares in an exponent group. Backends can override this
    /// to exchange all partial points in one transport batch.
    fn batch_open_shares_in_exp_group(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        shares: &[Vec<u8>],
        generator_bytes: &[u8],
    ) -> MpcEngineResult<Vec<Vec<u8>>> {
        shares
            .iter()
            .map(|share| self.open_share_in_exp_group(group, ty, share, generator_bytes))
            .collect()
    }

    /// Reveal several shares against per-item public generators.
    fn batch_open_shares_in_exp_group_custom(
        &self,
        group: MpcExponentGroup,
        ty: ShareType,
        shares: &[Vec<u8>],
        generators: &[Vec<u8>],
    ) -> MpcEngineResult<Vec<Vec<u8>>> {
        if shares.len() != generators.len() {
            return Err(MpcEngineError::operation_failed(
                "batch_open_shares_in_exp_group_custom",
                format!(
                    "share/generator length mismatch: {} != {}",
                    shares.len(),
                    generators.len()
                ),
            ));
        }
        shares
            .iter()
            .zip(generators)
            .map(|(share, generator)| self.open_share_in_exp_group(group, ty, share, generator))
            .collect()
    }
}

/// Extended MPC engine trait for jointly-random share generation.
///
/// This backs VM operations like `Share.random`, where the resulting secret is
/// shared among parties and no individual party knows the clear value.
pub trait MpcEngineRandomness: MpcEngine {
    /// Generate a secret-shared random value of the requested share type.
    fn random_share(&self, ty: ShareType) -> MpcEngineResult<ShareData>;

    /// Generate a secret-shared integer random value suitable for typed integer reveals.
    fn random_integer_share(&self, ty: ShareType) -> MpcEngineResult<ShareData> {
        self.random_share(ty)
    }
}

/// Extended MPC engine trait for opening shares as raw field elements.
///
/// This capability backs `Share.open_field`, which is used by threshold
/// cryptography code that needs the canonical field encoding rather than a VM
/// scalar conversion.
pub trait MpcEngineFieldOpen: MpcEngine {
    /// Reconstruct a secret from shares and return the raw field element bytes.
    fn open_share_as_field(&self, ty: ShareType, share_bytes: &[u8]) -> MpcEngineResult<Vec<u8>>;

    /// Batch-reconstruct secrets as canonical raw field-element bytes.
    fn batch_open_shares_as_fields(
        &self,
        ty: ShareType,
        shares: &[Vec<u8>],
    ) -> MpcEngineResult<Vec<Vec<u8>>> {
        shares
            .iter()
            .map(|share| self.open_share_as_field(ty, share))
            .collect()
    }
}

/// Extended MPC engine trait for persistent preprocessing material.
///
/// Engines that implement this capability can load or save expensive
/// preprocessing artifacts under a program-specific hash before `start()` or
/// `preprocess()` is called. Unsupported engines fail explicitly instead of
/// accepting a store and silently ignoring it.
pub trait MpcEnginePreprocPersistence: MpcEngine {
    /// Attach persistent storage for preprocessing material caching.
    fn set_preproc_store(
        &self,
        store: Arc<dyn PreprocStore>,
        program_hash: [u8; 32],
    ) -> MpcEngineResult<()>;
}

/// Extended MPC engine trait for sending private outputs to clients.
///
/// This is separate from [`MpcEngineClientOps`] because some backends may be
/// able to ingest client input without exposing an output-delivery channel, or
/// vice versa. Keeping it as a capability trait prevents the core VM engine
/// abstraction from accumulating protocol-specific optional methods.
pub trait MpcEngineClientOutput: MpcEngine {
    /// Send output share(s) to a specific client for private reconstruction.
    ///
    /// Unlike `open_share`, which reveals to all parties, this sends this
    /// party's share to a designated client who can collect shares from all
    /// parties and reconstruct the secret privately.
    fn send_output_to_client(
        &self,
        client_id: ClientId,
        shares: &[u8],
        output_share_count: ClientOutputShareCount,
    ) -> MpcEngineResult<()>;
}

/// Extended MPC engine trait for preprocessing reservation.
///
/// Offered by engines whose deployment holds a preprocessing pool across
/// executions — a *standing* pool. The reservation lifecycle:
///
/// 1. `init_reservations` — set up reservation state for this run
/// 2. `reserve_masks` — allocate index ranges to clients and, in the same step,
///    draw the corresponding shares out of the live pool
/// 3. `get_mask_share` — serve a drawn share to the caller
/// 4. `retire_masks` — the reservation is marked consumed and the node's
///    process-local copies of the mask shares are erased
///
/// Step 2 is where a mask leaves the pool, and step 3 serves only what step 2
/// already removed. **An implementor must not serve a mask out of persistent
/// storage.** A stored item a node hands out while leaving it in place is an
/// item a later execution can be handed too, and preprocessing material is
/// correlated: two executions holding the same mask share is the privacy defect
/// this lifecycle exists to prevent. Reserving is therefore a draw, not a
/// bookmark — there is no "reserved at index N" record in the store to come
/// back to, by design.
///
/// A deployment that generates its pool per execution does not offer this
/// capability at all: it takes its masks from the live pool directly, so
/// `MpcEngine::as_reservation` returns `None` and `MpcEngine::reservation_ops`
/// reports the capability as unsupported. Pinned by
/// `a_one_shot_engine_offers_no_reservation_capability`.
///
/// The masked input `x + r` itself is not this trait's business. A client sends
/// it to the coordinator, every node reads the same value from there, and the
/// node subtracts its own mask share in process memory. Nothing on this trait
/// accepts or stores a masked input, which keeps a client's input out of the
/// LMDB environment that holds the mask shares.
#[async_trait::async_trait]
pub trait MpcEngineReservation: MpcEngine {
    /// Initialize or restore reservation state for a program.
    async fn init_reservations(&self, program_hash: [u8; 32], capacity: u64)
        -> MpcEngineResult<()>;

    /// Initialize or restore reservation state for one isolated execution.
    async fn init_reservations_for_run(
        &self,
        program_hash: [u8; 32],
        capacity: u64,
        run_id: u64,
        preproc_offset: PoolAvailability,
    ) -> MpcEngineResult<()>;

    /// Reserve `n` consecutive mask indices for a client.
    async fn reserve_masks(&self, client_id: ClientId, n: u64)
        -> MpcEngineResult<ReservationGrant>;

    /// Get this node's mask share at a given index as serialized bytes.
    async fn get_mask_share(&self, index: u64) -> MpcEngineResult<Vec<u8>>;

    /// Get several mask shares in caller-specified order.
    ///
    /// Required rather than defaulted, because the only amortization available
    /// here is taking the lock over the process-local shares once instead of
    /// per index. There is nothing else to batch: the shares were drawn out of
    /// the pool by `reserve_masks`, so this is a memory read, and an
    /// implementation that batched a *store* read would be serving material the
    /// store still holds — see this trait's documentation.
    async fn get_mask_shares(&self, indices: &[u64]) -> MpcEngineResult<Vec<Vec<u8>>>;

    /// Retire mask material after an external coordinator has completed the
    /// unmasking protocol. This marks the logical reservations consumed and
    /// erases any process-local copies of destructively allocated shares.
    async fn retire_masks(&self, indices: &[u64]) -> MpcEngineResult<()>;

    /// Number of unreserved mask slots.
    async fn available_masks(&self) -> u64;
}
