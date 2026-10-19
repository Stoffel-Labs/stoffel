//! Persistent preprocessing material storage.
//!
//! Stores MPC preprocessing material (Beaver triples, random shares, etc.)
//! keyed by program hash and MPC parameters. Backed by LMDB via the `heed`
//! crate for memory-mapped reads and ACID write transactions.

use crate::net::curve::MpcFieldKind;
use crate::net::mpc_engine::DurableIdentityDigest;
use ark_ff::FftField;
use ark_serialize::{Compress, Validate};
use serde::{Deserialize, Serialize};
use std::future::Future;
use std::path::Path;
use stoffelmpc_mpc::honeybadger::{
    fpmul::f256::Gf256, robust_interpolate::robust_interpolate::RobustShare,
    triple_gen::ShamirBeaverTriple,
};

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum PreprocStoreError {
    #[error("LMDB: {0}")]
    Lmdb(#[from] heed::Error),
    #[error("LMDB actor: {0}")]
    LmdbActor(String),
    #[error("serialization: {0}")]
    Serialization(String),
    #[error("deserialization: {0}")]
    Deserialization(String),
    #[error("I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("not found")]
    NotFound,
    #[error("insufficient material: need {need}, available {available}")]
    Insufficient { need: u32, available: u32 },
    #[error("preprocessing item size mismatch: expected {expected}, actual {actual}")]
    ItemSizeMismatch { expected: u32, actual: u32 },
    #[error(
        "preprocessing volume {path} holds {records} records written before a commit became a \
         division of the generated pool, so its material may already have served an execution; \
         refusing to draw from it. Delete the volume and let this node regenerate — the material \
         is not safe to reuse."
    )]
    UnmarkedVolume { path: String, records: u64 },
    #[error(
        "preprocessing volume {path} holds {records} records under {namespace}, which this \
         binary never writes, so a binary predating the rule that a commit is a division of the \
         generated pool wrote into this volume and material in it may already have served an \
         execution; refusing to draw from it. The format marker cannot catch this on its own \
         because such a binary ignores markers, which is why these prefixes are condemned: a \
         record under one is contamination, whenever it arrived. Delete the volume and let this \
         node regenerate — the material is not safe to reuse."
    )]
    CondemnedRecordsInVolume {
        path: String,
        namespace: CondemnedNamespace,
        records: u64,
    },
    #[error(
        "preprocessing reservoir metadata carries a consumed cursor ({consumed} of {count} \
         items), which no current binary writes: material is physically removed from the store \
         when it is drawn, so a cursor could only have been left by a binary that marked items \
         consumed and kept them — and the items this cursor skips may already have served an \
         execution. Refusing to read it. Delete the volume and let this node regenerate — the \
         material is not safe to reuse."
    )]
    ConsumedCursorInVolume { consumed: u32, count: u32 },
    #[error(
        "preprocessing volume {path} has an unreadable format header ({reason}); refusing to draw \
         from it. Delete the volume and let this node regenerate."
    )]
    UnreadableVolumeHeader { path: String, reason: String },
    #[error(
        "preprocessing volume {path} is owned by {held}, but this process opened it as {opening}; \
         refusing to draw from it. One volume belongs to exactly one standing pool and node \
         identity: two pools holding the same correlated material would each serve it to an \
         execution. Point this pool at its own volume, or delete this one and let the node \
         regenerate."
    )]
    VolumeOwnerMismatch {
        path: String,
        held: String,
        opening: String,
    },
    #[error("partial preprocessing item write: data length {data_len} is not divisible by item size {item_size}")]
    PartialItem { data_len: usize, item_size: u32 },
    #[error("{field} value {value} exceeds u32::MAX")]
    U32Overflow { field: &'static str, value: u64 },
    #[error("task join: {0}")]
    Join(String),
}

impl From<bincode::Error> for PreprocStoreError {
    fn from(e: bincode::Error) -> Self {
        Self::Serialization(e.to_string())
    }
}

impl From<tokio::task::JoinError> for PreprocStoreError {
    fn from(e: tokio::task::JoinError) -> Self {
        Self::Join(e.to_string())
    }
}

// Allows engines that use Result<_, String> to convert seamlessly.
impl From<PreprocStoreError> for String {
    fn from(e: PreprocStoreError) -> Self {
        e.to_string()
    }
}

// ---------------------------------------------------------------------------
// Key types
// ---------------------------------------------------------------------------

/// Kind of preprocessing material.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum MaterialKind {
    BeaverTriple = 0,
    RandomShare = 1,
    PRandBit = 2,
    PRandInt = 3,
}

/// Identifies a stored preprocessing blob.
///
/// Use [`PreprocKeyScope`] when deriving several material keys for the same
/// program/node-identity namespace.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PreprocKey {
    pub program_hash: [u8; 32],
    pub field_kind: MpcFieldKind,
    pub n: usize,
    pub t: usize,
    pub node_identity: DurableIdentityDigest,
    pub kind: MaterialKind,
}

/// The key prefix every preprocessing material record carries.
///
/// Distinct from [`CondemnedNamespace::PreDivisionMaterial`] on purpose, and
/// that is what makes a pre-division write *detectable*. A binary whose commit
/// copied the pool instead of dividing it writes material under the old
/// prefix, so this binary neither reads such a record nor admits a volume that
/// holds one ([`admit_preproc_volume`]). The rename is the mechanism: a volume
/// marker alone cannot help, because a pre-division binary ignores markers by
/// construction, but it cannot write a prefix it does not know.
const PREPROC_MATERIAL_NAMESPACE: &[u8] = b"ppd:";

/// A key prefix this binary never writes, and whose presence in a volume this
/// binary claimed therefore means some *other* binary wrote into it.
///
/// Every variant is a namespace a pre-division binary used — one whose commit
/// copied the generated pool instead of dividing it — so a record under any of
/// them condemns the volume that holds it (`admit_preproc_volume`). Kept as a
/// closed enum rather than bare literals because the set is load-bearing in
/// exactly one place, the refusal, and because what each prefix *means* is the
/// operator-facing half of that refusal.
///
/// A prefix only belongs here once nothing current writes it: condemning a live
/// namespace would make a node refuse its own volume. Both of these are dead by
/// construction — material moved to `PREPROC_MATERIAL_NAMESPACE`, and the
/// reservation registry no longer reaches disk at all
/// ([`crate::net::reservation`]) — which
/// `the_condemned_prefixes_are_ones_this_binary_never_writes` asserts over
/// every key this binary can produce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CondemnedNamespace {
    /// Preprocessing material written by a binary whose commit copied the
    /// generated pool instead of dividing it, so the items may already have
    /// served an execution.
    PreDivisionMaterial,
    /// A reservation index record. Such binaries persisted the mask-index
    /// cursor into the very volume holding the mask shares; that write is gone
    /// and so is the namespace, so a record here dates a volume's writer to
    /// before the division.
    RetiredReservation,
}

impl CondemnedNamespace {
    /// Every variant, in scan order.
    pub(crate) const ALL: &'static [Self] = &[Self::PreDivisionMaterial, Self::RetiredReservation];

    /// The byte prefix a record under this namespace carries.
    ///
    /// `pub(crate)` so the tests that must assert "no key in this volume starts
    /// with a prefix nothing writes any more" can name the prefixes without
    /// re-spelling them. Nothing in production needs it outside this module.
    pub(crate) const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::PreDivisionMaterial => b"pp:",
            Self::RetiredReservation => b"rsv:",
        }
    }
}

impl std::fmt::Display for CondemnedNamespace {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (what, prefix) = match self {
            Self::PreDivisionMaterial => ("the pre-division material prefix", "pp:"),
            Self::RetiredReservation => ("the retired reservation prefix", "rsv:"),
        };
        write!(f, "{what} `{prefix}`")
    }
}

impl PreprocKey {
    pub fn new(
        program_hash: [u8; 32],
        field_kind: MpcFieldKind,
        n: usize,
        t: usize,
        node_identity: DurableIdentityDigest,
        kind: MaterialKind,
    ) -> Self {
        Self {
            program_hash,
            field_kind,
            n,
            t,
            node_identity,
            kind,
        }
    }

    /// Build a key with a different material kind, sharing all other fields.
    pub fn with_kind(&self, kind: MaterialKind) -> Self {
        Self {
            kind,
            ..self.clone()
        }
    }

    /// Encode as a compact byte key for LMDB lookups.
    pub fn encode(&self) -> Result<Vec<u8>, PreprocStoreError> {
        let mut buf = Vec::with_capacity(78);
        buf.extend_from_slice(PREPROC_MATERIAL_NAMESPACE);
        buf.extend_from_slice(&self.program_hash);
        buf.push(field_kind_tag(self.field_kind));
        buf.extend_from_slice(&usize_to_u32(self.n, "preprocessing key n")?.to_le_bytes());
        buf.extend_from_slice(&usize_to_u32(self.t, "preprocessing key threshold")?.to_le_bytes());
        buf.extend_from_slice(&self.node_identity.as_bytes());
        buf.push(material_kind_tag(self.kind));
        Ok(buf)
    }

    /// Encode the metadata key (distinct from the data key).
    fn meta_key(&self) -> Result<Vec<u8>, PreprocStoreError> {
        let mut k = self.encode()?;
        k.push(b'm');
        Ok(k)
    }
}

/// Common namespace for preprocessing material keys belonging to one party.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PreprocKeyScope {
    pub program_hash: [u8; 32],
    pub field_kind: MpcFieldKind,
    pub n: usize,
    pub t: usize,
    pub node_identity: DurableIdentityDigest,
}

impl PreprocKeyScope {
    pub fn new(
        program_hash: [u8; 32],
        field_kind: MpcFieldKind,
        n: usize,
        t: usize,
        node_identity: DurableIdentityDigest,
    ) -> Self {
        Self {
            program_hash,
            field_kind,
            n,
            t,
            node_identity,
        }
    }

    pub fn key(self, kind: MaterialKind) -> PreprocKey {
        PreprocKey {
            program_hash: self.program_hash,
            field_kind: self.field_kind,
            n: self.n,
            t: self.t,
            node_identity: self.node_identity,
            kind,
        }
    }

    pub fn beaver_triple(self) -> PreprocKey {
        self.key(MaterialKind::BeaverTriple)
    }

    pub fn random_share(self) -> PreprocKey {
        self.key(MaterialKind::RandomShare)
    }

    pub fn prand_bit(self) -> PreprocKey {
        self.key(MaterialKind::PRandBit)
    }

    pub fn prand_int(self) -> PreprocKey {
        self.key(MaterialKind::PRandInt)
    }
}

fn field_kind_tag(fk: MpcFieldKind) -> u8 {
    match fk {
        MpcFieldKind::Bls12_381Fr => 0,
        MpcFieldKind::Bn254Fr => 1,
        MpcFieldKind::Curve25519Fr => 2,
        MpcFieldKind::Secp256k1Fr => 3,
        MpcFieldKind::Secp256r1Fr => 4,
    }
}

fn material_kind_tag(kind: MaterialKind) -> u8 {
    match kind {
        MaterialKind::BeaverTriple => 0,
        MaterialKind::RandomShare => 1,
        MaterialKind::PRandBit => 2,
        MaterialKind::PRandInt => 3,
    }
}

fn usize_to_u32(value: usize, field: &'static str) -> Result<u32, PreprocStoreError> {
    u32::try_from(value).map_err(|_| PreprocStoreError::U32Overflow {
        field,
        value: u64::try_from(value).unwrap_or(u64::MAX),
    })
}

/// Metadata stored separately so cursor checks and inventory reads avoid
/// deserializing the potentially large data blob.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreprocMeta {
    pub count: u32,
    pub consumed: u32,
    pub item_size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StandingPreprocAction {
    Reuse,
    TopUp,
    Rebuild,
}

/// Party-exchanged inventory for one correlated preprocessing reservoir.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingPreprocSnapshot {
    pub generation_id: Option<[u8; 32]>,
    pub beaver: PreprocMeta,
    pub random: PreprocMeta,
    pub prand_bit: PreprocMeta,
    pub prand_int: PreprocMeta,
}

impl StandingPreprocSnapshot {
    pub fn availability(self) -> PoolAvailability {
        PoolAvailability {
            beaver: self.beaver.available(),
            random: self.random.available(),
            prand_bit: self.prand_bit.available(),
            prand_int: self.prand_int.available(),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StandingPreprocPlan {
    pub action: StandingPreprocAction,
    pub needed: PoolAvailability,
    pub generation_id: [u8; 32],
}

/// Agree on reuse, top-up, or rebuild from party-indexed inventories.
pub fn agree_standing_preproc_plan(
    targets: PoolAvailability,
    snapshots: &[StandingPreprocSnapshot],
    fresh_generation_id: [u8; 32],
) -> Result<StandingPreprocPlan, String> {
    let (&baseline, rest) = snapshots
        .split_first()
        .ok_or_else(|| "standing preprocessing agreement requires at least one party".to_owned())?;
    if baseline.generation_id.is_none() || rest.iter().any(|snapshot| *snapshot != baseline) {
        return Ok(StandingPreprocPlan {
            action: StandingPreprocAction::Rebuild,
            needed: targets,
            generation_id: fresh_generation_id,
        });
    }
    let available = baseline.availability();
    let needed = PoolAvailability {
        beaver: targets.beaver.saturating_sub(available.beaver),
        random: targets.random.saturating_sub(available.random),
        prand_bit: targets.prand_bit.saturating_sub(available.prand_bit),
        prand_int: targets.prand_int.saturating_sub(available.prand_int),
    };
    let action = if needed == PoolAvailability::default() {
        StandingPreprocAction::Reuse
    } else {
        StandingPreprocAction::TopUp
    };
    Ok(StandingPreprocPlan {
        action,
        needed,
        generation_id: if action == StandingPreprocAction::Reuse {
            baseline.generation_id.expect("generation checked above")
        } else {
            fresh_generation_id
        },
    })
}

impl PreprocMeta {
    pub fn available(&self) -> u32 {
        self.count.saturating_sub(self.consumed)
    }
}

/// Material atomically removed from the front of a preprocessing pool.
///
/// `data` contains exactly `count * item_size` bytes. The backing store no
/// longer contains these bytes when this value is returned, so a crash or a
/// second execution cannot allocate the same correlated material again.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TakenPreproc {
    pub count: u32,
    pub item_size: u32,
    pub data: Vec<u8>,
}

/// The substring a docker suite greps for to see that a party committed
/// material to a preprocessing volume.
///
/// Both engines interpolate it into their commit message rather than spelling
/// it out, and `docker/test-coordinator-preproc-store.sh` and
/// `docker/test-oneshot-preproc-store.sh` read this constant's value out of
/// this file instead of hard-coding a phrase. That is what keeps the standing
/// suite's *absence* assertion honest: rewording the human half of either
/// engine's message cannot make it vacuous, and renaming or deleting this
/// constant makes those scripts exit non-zero instead of asserting nothing.
pub const PREPROC_COMMIT_LOG_MARKER: &str = "preprocessing material to store";

/// The substring a docker suite greps for to see that a party drew material
/// out of a preprocessing volume. The counterpart of
/// [`PREPROC_COMMIT_LOG_MARKER`], read the same way and for the same reason.
pub const PREPROC_LOAD_LOG_MARKER: &str = "preprocessing material from store";

/// The substring a docker suite greps for to see that what a party drew out of
/// a preprocessing volume fell SHORT of the execution's targets, so it had to
/// generate the shortfall.
///
/// This is the one line a one-shot campaign can assert that is more than
/// liveness. Under the copy semantics the fix replaced, a run committed its
/// whole pool and the next run's load covered its targets outright, so this
/// line could not be emitted; it appears only because a commit is now a
/// division. Read and tied exactly like [`PREPROC_COMMIT_LOG_MARKER`].
pub const PREPROC_PARTIAL_LOAD_LOG_MARKER: &str = "does not cover this execution's targets";

/// The reserved record every preprocessing volume carries, written on the
/// volume's first open and never rewritten.
///
/// The key collides with no material or blob namespace: material keys start
/// [`PREPROC_MATERIAL_NAMESPACE`] ([`PreprocKey::encode`]) and every blob key
/// starts with one of [`BlobNamespace`]'s variants. Pinned by
/// [`the_blob_api_cannot_name_the_material_namespace`].
const PREPROC_VOLUME_HEADER_KEY: &[u8] = b"stoffel-preproc-volume-header-v1";

/// The namespace an opaque blob record lives under.
///
/// A closed enum rather than the `&[u8]` this used to be, because the blob API
/// is a *generic* key-value pair on the same LMDB database as the preprocessing
/// material, and the namespace is the only thing separating them. While a
/// caller could name the namespace, `load_blob` was a non-destructive read of a
/// material item — `load_blob(b"pp:", &key.encode()?[3..])` reconstructs the
/// data key exactly, because [`PreprocKey::encode`] is public and its first
/// bytes are the material prefix — and `store_blob` was an unconditional,
/// non-accumulating put of one, which is the capability the division fix
/// deleted `PreprocStore::store` to remove. Neither is expressible now: the
/// material namespace is not a variant, so it cannot be named at all.
///
/// Each variant's bytes end in `:`, none is a prefix of
/// `PREPROC_MATERIAL_NAMESPACE` and none is a [`CondemnedNamespace`], so no
/// caller-supplied key can push a blob into the material namespace, and no
/// write through this API can condemn the volume it lands in. All of that is
/// pinned by `the_blob_api_cannot_name_the_material_namespace`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum BlobNamespace {
    /// The generation marker a standing pool's parties agree their reservoir
    /// under.
    StandingPreprocGeneration,
}

impl BlobNamespace {
    /// Every variant, for the tests that must assert over the whole closed set.
    ///
    /// The honest limit: a variant added to [`BlobNamespace::as_bytes`] and not
    /// to this list is simply untested, rather than rejected. What keeps the
    /// property is the enum, not this array — a new variant still cannot be the
    /// material namespace unless someone writes that prefix into `as_bytes`.
    #[cfg(test)]
    const ALL: &'static [Self] = &[Self::StandingPreprocGeneration];

    /// The byte prefix this namespace contributes to a blob key.
    const fn as_bytes(self) -> &'static [u8] {
        match self {
            Self::StandingPreprocGeneration => b"standing-preproc-generation-v1:",
        }
    }
}

/// The write discipline a preprocessing volume was created under.
///
/// A volume written before [`GeneratedMaterialCommit`] existed holds a
/// `consumed: 0` copy of a pool an execution went on to draw from, so its
/// material may already have served an execution. That is unsafe to reuse and
/// cannot be migrated — the material itself is the problem — so a volume
/// without this marker is refused rather than adopted.
///
/// A variant an older binary does not know fails `bincode` deserialization,
/// which refuses too. That is the intended direction: a volume written by a
/// newer discipline is not one an older binary may draw from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
enum PreprocVolumeFormat {
    /// A commit is a division of the generated pool: an item is written only if
    /// the engine that generated it keeps none of it.
    DividedCommitV1,
}

/// The one standing pool, on the one node, that a volume belongs to.
///
/// Pool ids are globally unique among live deployments and the key namespace is
/// derived from the pool id, so a volume cloned or bind-mounted into a second
/// pool — or shared between two parties — would give both copies of the same
/// correlated material. This record is what makes that a refusal rather than an
/// operator requirement.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PreprocVolumeOwner {
    pool: [u8; 32],
    node: DurableIdentityDigest,
}

impl PreprocVolumeOwner {
    pub const fn new(pool: [u8; 32], node: DurableIdentityDigest) -> Self {
        Self { pool, node }
    }
}

impl std::fmt::Display for PreprocVolumeOwner {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "standing pool ")?;
        for byte in self.pool {
            write!(f, "{byte:02x}")?;
        }
        write!(f, " on node {}", self.node)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
struct PreprocVolumeHeader {
    format: PreprocVolumeFormat,
    owner: Option<PreprocVolumeOwner>,
}

fn describe_volume_owner(owner: Option<PreprocVolumeOwner>) -> String {
    owner.map_or_else(|| "no standing pool".to_owned(), |owner| owner.to_string())
}

/// Serialized preprocessing material with metadata + data.
///
/// Test-only, with `pub(crate)` fields and test-only constructors, because its
/// only reader is [`PreprocStore::load`] — the one non-destructive read, which
/// is itself test-only. `count`, `consumed` and `item_size` must agree with
/// `data.len()`; a value that breaks that agreement is a corrupt source every
/// reader has to defend against, which is why nothing outside this module may
/// build one from loose parts.
#[cfg(test)]
#[derive(Debug, Clone)]
pub struct PreprocBlob {
    pub(crate) meta: PreprocMeta,
    pub(crate) data: Vec<u8>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PoolAvailability {
    pub beaver: u32,
    pub random: u32,
    pub prand_bit: u32,
    pub prand_int: u32,
}

impl PoolAvailability {
    pub fn covers(self, required: Self) -> bool {
        self.beaver >= required.beaver
            && self.random >= required.random
            && self.prand_bit >= required.prand_bit
            && self.prand_int >= required.prand_int
    }

    const fn get(self, kind: MaterialKind) -> u32 {
        match kind {
            MaterialKind::BeaverTriple => self.beaver,
            MaterialKind::RandomShare => self.random,
            MaterialKind::PRandBit => self.prand_bit,
            MaterialKind::PRandInt => self.prand_int,
        }
    }

    fn set(&mut self, kind: MaterialKind, count: u32) {
        match kind {
            MaterialKind::BeaverTriple => self.beaver = count,
            MaterialKind::RandomShare => self.random = count,
            MaterialKind::PRandBit => self.prand_bit = count,
            MaterialKind::PRandInt => self.prand_int = count,
        }
    }
}

/// How a finished generation round divides the material it left in an engine's
/// in-memory pool between that engine and the persistent store.
///
/// The two variants are opposites on purpose, and both are required by the
/// invariant the store rests on: *an item is committed to the store only if the
/// engine that generated it keeps none of it*. Everything the store holds is
/// therefore material no execution has been served, and
/// [`PreprocStore::take_bundle_from_reservoir`] — which physically removes what
/// it hands out — keeps it that way for every later draw.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GeneratedMaterialCommit {
    /// Standing reservoir top-up: commit exactly the agreed chunk and discard
    /// the protocol's over-production.
    ///
    /// The party-agreed inventory is exact, so extras must reach neither the
    /// reservoir — where unequal per-party snapshots force a
    /// [`StandingPreprocAction::Rebuild`] on the next execution — nor the next
    /// chunk. The live pool is left empty, so this engine keeps nothing it
    /// committed.
    AgreedChunk(PoolAvailability),
    /// One-shot execution: keep these targets in the live pool for this
    /// execution and commit everything above them.
    ///
    /// The retained items are the ones this execution goes on to draw, and
    /// they are never written, so no later execution can be handed them.
    SurplusAbove(PoolAvailability),
}

/// The division of one material kind that a [`GeneratedMaterialCommit`]
/// prescribes, given how much of that kind the pool currently holds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MaterialSplit {
    /// Items to take out of the live pool.
    pub drained: u32,
    /// How many of the drained items return to the live pool. The rest are
    /// committed to the store; both engines take that count from the surplus
    /// vector itself, so the count and the bytes it describes come from one
    /// place.
    pub retained: u32,
}

impl GeneratedMaterialCommit {
    /// How much of one material kind to drain from the pool, and how much of
    /// that to put back, given how much the pool holds.
    pub fn split(self, kind: MaterialKind, held: u32) -> MaterialSplit {
        match self {
            // Draining exactly the chunk keeps the existing behaviour that an
            // under-producing round fails here, naming the kind, rather than
            // committing a short reservoir for `apply_standing_preproc_plan`
            // to reject later.
            Self::AgreedChunk(chunk) => MaterialSplit {
                drained: chunk.get(kind),
                retained: 0,
            },
            Self::SurplusAbove(targets) => MaterialSplit {
                drained: held,
                retained: targets.get(kind).min(held),
            },
        }
    }

    /// Whether material the drain left in the pool is discarded afterwards.
    ///
    /// True for [`Self::AgreedChunk`], whose drain takes only the agreed
    /// amount and whose surplus is protocol over-production the agreement does
    /// not account for.
    pub const fn discards_undrained_material(self) -> bool {
        matches!(self, Self::AgreedChunk(_))
    }
}

/// Preprocessing material removed atomically from a stable reservoir.
///
/// This value deliberately is not `Clone`: one successful take creates one
/// owner, and dropping that owner burns the material rather than making it
/// available to another execution.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct OwnedPreprocBundle {
    pub beaver: Option<TakenPreproc>,
    pub random: Option<TakenPreproc>,
    pub prand_bit: Option<TakenPreproc>,
    pub prand_int: Option<TakenPreproc>,
    pub remaining: PoolAvailability,
}

impl OwnedPreprocBundle {
    pub fn availability(&self) -> PoolAvailability {
        PoolAvailability {
            beaver: self.beaver.as_ref().map_or(0, |material| material.count),
            random: self.random.as_ref().map_or(0, |material| material.count),
            prand_bit: self.prand_bit.as_ref().map_or(0, |material| material.count),
            prand_int: self.prand_int.as_ref().map_or(0, |material| material.count),
        }
    }

    fn set(&mut self, kind: MaterialKind, material: TakenPreproc) {
        match kind {
            MaterialKind::BeaverTriple => self.beaver = Some(material),
            MaterialKind::RandomShare => self.random = Some(material),
            MaterialKind::PRandBit => self.prand_bit = Some(material),
            MaterialKind::PRandInt => self.prand_int = Some(material),
        }
    }
}

/// Fixture construction. Production never builds a `PreprocBlob` from loose
/// parts: the one place it exists is [`PreprocStore::load`]'s struct literal,
/// over bytes `append_items` already checked against their metadata. These two
/// constructors take the agreement on trust, which is exactly what makes them
/// unfit for production and useful for a fixture.
#[cfg(test)]
impl PreprocBlob {
    pub(crate) fn new(data: Vec<u8>, item_size: u32, count: u32) -> Self {
        Self {
            meta: PreprocMeta {
                count,
                consumed: 0,
                item_size,
            },
            data,
        }
    }

    pub(crate) fn try_new(
        data: Vec<u8>,
        item_size: u32,
        count: usize,
    ) -> Result<Self, PreprocStoreError> {
        let count = usize_to_u32(count, "preprocessing item count")?;
        Ok(Self::new(data, item_size, count))
    }
}

pub fn u32_index(value: u64, field: &'static str) -> Result<u32, PreprocStoreError> {
    u32::try_from(value).map_err(|_| PreprocStoreError::U32Overflow { field, value })
}

fn u32_to_usize(value: u32, field: &'static str) -> Result<usize, PreprocStoreError> {
    usize::try_from(value).map_err(|_| PreprocStoreError::U32Overflow {
        field,
        value: u64::from(value),
    })
}

fn usize_to_u64(value: usize, field: &'static str) -> Result<u64, PreprocStoreError> {
    u64::try_from(value)
        .map_err(|_| PreprocStoreError::Serialization(format!("{field} {value} exceeds u64::MAX")))
}

fn u64_to_usize(value: u64, field: &'static str) -> Result<usize, PreprocStoreError> {
    usize::try_from(value).map_err(|_| {
        PreprocStoreError::Deserialization(format!("{field} {value} exceeds usize::MAX"))
    })
}

fn byte_offset(
    index: u32,
    item_size: u32,
    field: &'static str,
) -> Result<usize, PreprocStoreError> {
    let index = u32_to_usize(index, field)?;
    let item_size = u32_to_usize(item_size, "preprocessing item size")?;
    index.checked_mul(item_size).ok_or_else(|| {
        PreprocStoreError::Deserialization(format!(
            "{field} overflows usize: index={index}, item_size={item_size}"
        ))
    })
}

fn has_nonzero_item_size(
    data: &[u8],
    item_size: usize,
    field: &'static str,
) -> Result<bool, PreprocStoreError> {
    if item_size != 0 {
        return Ok(true);
    }
    if data.is_empty() {
        return Ok(false);
    }
    Err(PreprocStoreError::Deserialization(format!(
        "{field} item size is zero for non-empty data"
    )))
}

// ---------------------------------------------------------------------------
// Storage trait
// ---------------------------------------------------------------------------

/// Async trait for preprocessing material persistence.
#[async_trait::async_trait]
pub trait PreprocStore: Send + Sync + 'static {
    /// Read a key's raw stored bytes without removing them.
    ///
    /// Test-only, and that is the point. Production reads this store through
    /// [`PreprocStore::meta`], [`PreprocStore::scope_availability`] and
    /// [`PreprocStore::take_bundle_from_reservoir`] — two inventory reads and
    /// one destructive take. No production path can read a stored item and
    /// leave it where a second execution could be handed it. The tests need a
    /// non-destructive read to assert what the store holds.
    ///
    /// Gating this method is not on its own what makes that claim true. The
    /// blob API below shares one LMDB database with the material, so while its
    /// namespace was `&[u8]`, `load_blob(b"pp:", &key.encode()?[3..])` was a
    /// non-destructive read of an item that no `#[cfg(test)]` covered.
    /// [`BlobNamespace`] is the other half, and
    /// [`the_blob_api_cannot_name_the_material_namespace`] pins it.
    #[cfg(test)]
    async fn load(&self, key: &PreprocKey) -> Result<Option<PreprocBlob>, PreprocStoreError>;
    async fn meta(&self, key: &PreprocKey) -> Result<Option<PreprocMeta>, PreprocStoreError>;

    /// Commit freshly generated items to a key, accumulating onto whatever is
    /// already there inside one write transaction.
    ///
    /// This is the only way material enters the store — which holds because
    /// the blob API cannot name the material namespace ([`BlobNamespace`]), so
    /// `store_blob` cannot put an item behind this method's back. It reads the
    /// existing metadata, refuses a different `item_size`, adds to `count` and leaves
    /// `consumed` alone, so a commit can neither overwrite nor un-consume
    /// another writer's material. Material leaves the store only through
    /// [`PreprocStore::take_bundle_from_reservoir`], which physically removes
    /// what it hands out. Together those two make the store's contents, by
    /// construction, material no execution has been served.
    async fn append_items(
        &self,
        key: &PreprocKey,
        item_size: u32,
        added: u32,
        data: &[u8],
    ) -> Result<u32, PreprocStoreError>;

    /// Atomically remove an owned bundle from a stable preprocessing reservoir.
    ///
    /// All four material kinds are validated and physically compacted in one
    /// LMDB transaction. A zero requested count produces `None` for that kind.
    async fn take_bundle_from_reservoir(
        &self,
        source: &PreprocKeyScope,
        requested: PoolAvailability,
    ) -> Result<OwnedPreprocBundle, PreprocStoreError>;
    /// Items available (count - consumed). Returns 0 if not stored.
    ///
    /// Test-only, for the same reason as [`PreprocStore::load`]: production
    /// reads this store's inventory through [`PreprocStore::meta`] and
    /// [`PreprocStore::scope_availability`], and takes material through
    /// [`PreprocStore::take_bundle_from_reservoir`]. This per-key convenience
    /// had no production caller, and the tests need it to assert what a volume
    /// holds.
    #[cfg(test)]
    async fn available(&self, key: &PreprocKey) -> Result<u32, PreprocStoreError>;
    async fn scope_availability(
        &self,
        scope: &PreprocKeyScope,
    ) -> Result<PoolAvailability, PreprocStoreError>;

    async fn delete(&self, key: &PreprocKey) -> Result<(), PreprocStoreError>;

    /// Store an opaque byte blob under a namespaced key (for reservations etc.).
    ///
    /// The namespace is a [`BlobNamespace`], not bytes, so this cannot be aimed
    /// at a material key. That matters: a put here is unconditional and
    /// non-accumulating, which is exactly the write discipline the division fix
    /// removed from the material path.
    async fn store_blob(
        &self,
        ns: BlobNamespace,
        key: &[u8],
        data: &[u8],
    ) -> Result<(), PreprocStoreError>;
    /// Load an opaque byte blob by namespaced key.
    ///
    /// A non-destructive read, which is why its namespace is typed: aimed at a
    /// material key it would hand back an item and leave it in place for a
    /// second execution.
    async fn load_blob(
        &self,
        ns: BlobNamespace,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, PreprocStoreError>;
    /// Delete an opaque namespaced blob.
    async fn delete_blob(&self, ns: BlobNamespace, key: &[u8]) -> Result<(), PreprocStoreError>;
}

/// Decode one material record's metadata, refusing a consumed cursor.
///
/// Every read of material metadata goes through here. `consumed` is zero on
/// every record this binary writes — `append_items` leaves it as it found it
/// and starts it at zero, and `take_bundle_from_reservoir` writes zero back —
/// because material is *removed* when it is drawn rather than marked. So a
/// nonzero cursor did not come from here, and what it would do if honoured is
/// shift which items the next draw serves: `0 < consumed < count` is a record
/// claiming the first `consumed` items are spent while they are still on disk.
/// A rolled-back image or a foreign writer is the only way to produce one, and
/// both are cases where the items it skips may already have served an
/// execution. Refusing is therefore the fail-closed answer, and it is free:
/// nothing legitimate is being rejected.
///
/// The field itself stays. It is what makes this check expressible, it rides
/// the party-exchanged [`StandingPreprocSnapshot`] (where it is *not* refused,
/// because a peer's inventory cannot shift a local draw and a disagreement
/// already forces a rebuild), and removing it would be worse than useless:
/// measured, a 12-byte record written with the field decodes into the
/// two-field struct as `{count, item_size: <old consumed>}` — `bincode` as
/// this crate calls it tolerates trailing bytes — so dropping the field turns
/// an old record into a *silent misread* of its item size rather than a
/// refusal.
fn decode_material_meta(raw: &[u8]) -> Result<PreprocMeta, PreprocStoreError> {
    let meta: PreprocMeta = bincode::deserialize(raw)?;
    if meta.consumed != 0 {
        return Err(PreprocStoreError::ConsumedCursorInVolume {
            consumed: meta.consumed,
            count: meta.count,
        });
    }
    Ok(meta)
}

fn standing_generation_key(scope: PreprocKeyScope) -> Result<Vec<u8>, PreprocStoreError> {
    scope.beaver_triple().encode()
}

pub async fn standing_preproc_snapshot(
    store: &dyn PreprocStore,
    scope: PreprocKeyScope,
) -> Result<StandingPreprocSnapshot, PreprocStoreError> {
    let generation_id = store
        .load_blob(
            BlobNamespace::StandingPreprocGeneration,
            &standing_generation_key(scope)?,
        )
        .await?
        .map(|bytes| {
            bytes.try_into().map_err(|bytes: Vec<u8>| {
                PreprocStoreError::Deserialization(format!(
                    "standing preprocessing generation has {} bytes, expected 32",
                    bytes.len()
                ))
            })
        })
        .transpose()?;
    Ok(StandingPreprocSnapshot {
        generation_id,
        beaver: store
            .meta(&scope.beaver_triple())
            .await?
            .unwrap_or_default(),
        random: store.meta(&scope.random_share()).await?.unwrap_or_default(),
        prand_bit: store.meta(&scope.prand_bit()).await?.unwrap_or_default(),
        prand_int: store.meta(&scope.prand_int()).await?.unwrap_or_default(),
    })
}

pub async fn store_standing_preproc_generation(
    store: &dyn PreprocStore,
    scope: PreprocKeyScope,
    generation_id: [u8; 32],
) -> Result<(), PreprocStoreError> {
    store
        .store_blob(
            BlobNamespace::StandingPreprocGeneration,
            &standing_generation_key(scope)?,
            &generation_id,
        )
        .await
}

/// Verify that every party agreed over one stable, party-indexed inventory,
/// then derive the shared reservoir action.
pub async fn agree_standing_preproc_plan_for_party(
    store: &dyn PreprocStore,
    scope: PreprocKeyScope,
    targets: PoolAvailability,
    snapshots: &[StandingPreprocSnapshot],
    party_id: usize,
    parties: usize,
    fresh_generation_id: [u8; 32],
) -> Result<StandingPreprocPlan, String> {
    if snapshots.len() != parties {
        return Err(format!(
            "standing preprocessing agreement received {} inventories, expected {parties}",
            snapshots.len()
        ));
    }
    let local = standing_preproc_snapshot(store, scope).await?;
    if snapshots.get(party_id) != Some(&local) {
        return Err(format!(
            "standing preprocessing local inventory changed during agreement: local={local:?}, exchanged={:?}",
            snapshots.get(party_id)
        ));
    }
    agree_standing_preproc_plan(targets, snapshots, fresh_generation_id)
}

/// Apply one party-agreed reservoir plan and return the resulting inventory.
/// Backend code supplies only its material generator; clearing, generation
/// ownership, and the final store read stay identical across MPC backends.
pub async fn apply_standing_preproc_plan<F, Fut>(
    store: &dyn PreprocStore,
    scope: PreprocKeyScope,
    targets: PoolAvailability,
    plan: StandingPreprocPlan,
    top_up: F,
) -> Result<StandingPreprocSnapshot, String>
where
    F: FnOnce(PoolAvailability) -> Fut,
    Fut: Future<Output = Result<(), String>>,
{
    match plan.action {
        StandingPreprocAction::Reuse => {}
        StandingPreprocAction::TopUp => top_up(plan.needed).await?,
        StandingPreprocAction::Rebuild => {
            clear_standing_preproc_scope(store, scope).await?;
            top_up(plan.needed).await?;
        }
    }
    if plan.action != StandingPreprocAction::Reuse {
        store_standing_preproc_generation(store, scope, plan.generation_id).await?;
    }
    let final_snapshot = standing_preproc_snapshot(store, scope)
        .await
        .map_err(String::from)?;
    if final_snapshot.generation_id != Some(plan.generation_id)
        || !final_snapshot.availability().covers(targets)
    {
        return Err(format!(
            "standing preprocessing did not reach agreed plan: plan={plan:?}, final={final_snapshot:?}"
        ));
    }
    Ok(final_snapshot)
}

pub async fn clear_standing_preproc_scope(
    store: &dyn PreprocStore,
    scope: PreprocKeyScope,
) -> Result<(), PreprocStoreError> {
    for kind in MATERIAL_KINDS {
        store.delete(&scope.key(kind)).await?;
    }
    store
        .delete_blob(
            BlobNamespace::StandingPreprocGeneration,
            &standing_generation_key(scope)?,
        )
        .await
}

// ---------------------------------------------------------------------------
// LMDB actor backend
// ---------------------------------------------------------------------------

type LmdbDatabase = heed::Database<heed::types::Bytes, heed::types::Bytes>;
type DbJob = Box<dyn FnOnce(&heed::Env, &LmdbDatabase) + Send + 'static>;

const MATERIAL_KINDS: [MaterialKind; 4] = [
    MaterialKind::BeaverTriple,
    MaterialKind::RandomShare,
    MaterialKind::PRandBit,
    MaterialKind::PRandInt,
];
struct ReservoirMaterialKeys {
    kind: MaterialKind,
    meta_key: Vec<u8>,
    data_key: Vec<u8>,
}

fn reservoir_material_keys(
    source: &PreprocKeyScope,
) -> Result<Vec<ReservoirMaterialKeys>, PreprocStoreError> {
    MATERIAL_KINDS
        .into_iter()
        .map(|kind| {
            let key = source.key(kind);
            Ok(ReservoirMaterialKeys {
                kind,
                meta_key: key.meta_key()?,
                data_key: key.encode()?,
            })
        })
        .collect()
}

const DEFAULT_LMDB_MAP_SIZE: usize = 1024 * 1024 * 1024;

fn lmdb_initial_map_size(path: &Path, requested: usize) -> Result<usize, PreprocStoreError> {
    if requested == 0 {
        return Err(PreprocStoreError::LmdbActor(
            "initial map size must be nonzero".into(),
        ));
    }
    let existing_len = match std::fs::metadata(path.join("data.mdb")) {
        Ok(metadata) => usize::try_from(metadata.len()).map_err(|_| {
            PreprocStoreError::LmdbActor(format!(
                "existing LMDB data file is too large for this platform: {} bytes",
                metadata.len()
            ))
        })?,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => 0,
        Err(error) => return Err(error.into()),
    };

    let mut map_size = requested;
    while map_size <= existing_len {
        map_size = map_size.checked_mul(2).ok_or_else(|| {
            PreprocStoreError::LmdbActor(format!(
                "cannot size LMDB map above existing {existing_len}-byte data file"
            ))
        })?;
    }
    Ok(map_size)
}

fn is_lmdb_map_full(error: &PreprocStoreError) -> bool {
    matches!(
        error,
        PreprocStoreError::Lmdb(heed::Error::Mdb(heed::MdbError::MapFull))
    )
}

/// Retry one actor-owned write transaction after growing LMDB's virtual map.
///
/// Every transaction for this environment is created and completed on the
/// actor thread, so when `operation` returns there are no live transactions
/// owned by this store. That is the condition LMDB requires for a safe resize.
fn with_lmdb_map_growth<T>(
    env: &heed::Env,
    mut operation: impl FnMut() -> Result<T, PreprocStoreError>,
) -> Result<T, PreprocStoreError> {
    loop {
        match operation() {
            Err(error) if is_lmdb_map_full(&error) => {
                let current = env.info().map_size;
                let grown = current.checked_mul(2).ok_or_else(|| {
                    PreprocStoreError::LmdbActor(format!(
                        "cannot grow full LMDB map beyond {current} bytes"
                    ))
                })?;
                // SAFETY: LmdbPreprocStore serializes every transaction on this
                // actor thread, and the failed transaction was dropped before
                // `operation` returned.
                unsafe { env.resize(grown) }?;
                tracing::warn!(
                    old_map_size = current,
                    new_map_size = grown,
                    "grew preprocessing LMDB map after MDB_MAP_FULL"
                );
            }
            result => return result,
        }
    }
}

/// LMDB-backed preprocessing store using the actor pattern.
///
/// A dedicated `std::thread` owns the `heed::Env` and processes all
/// database operations sequentially.  Callers communicate via an `mpsc`
/// channel and await `oneshot` replies, guaranteeing that LMDB never
/// touches a tokio worker thread.
///
/// Metadata and data are stored under separate keys so inventory reads never
/// touch the potentially large data blob.
pub struct LmdbPreprocStore {
    tx: std::sync::mpsc::Sender<DbJob>,
    _thread: std::thread::JoinHandle<()>,
}

/// Admit or refuse a volume, inside the write transaction that opened its
/// database and before any caller can read or write material.
///
/// Every constructor funnels through here and there is exactly one
/// `impl PreprocStore` in the tree, so this is the single door. Refusing higher
/// up — in `preproc_home`, or in the runner — would leave the others open.
///
/// | header | database | action |
/// |---|---|---|
/// | present | holds a record under a [`CondemnedNamespace`] | refuse ([`PreprocStoreError::CondemnedRecordsInVolume`]) |
/// | present, owner matches the opener | — | proceed |
/// | present, owner differs | — | refuse ([`PreprocStoreError::VolumeOwnerMismatch`]) |
/// | present, undeserializable or an unknown format | — | refuse |
/// | absent | empty | claim it: write the header |
/// | absent | non-empty | refuse ([`PreprocStoreError::UnmarkedVolume`]) |
///
/// "Non-empty" rather than "holds material keys" on purpose. Anything predating
/// the marker was written by a binary whose commit copied the pool instead of
/// dividing it, `rsv:` reservation blobs included, and one rule to reason about
/// is worth more here than a narrower one. An empty directory — the normal
/// case, and every `tempfile::tempdir()` in the suite — is claimed and
/// proceeds.
///
/// The marker alone would certify only how a volume was *created*. A volume
/// this binary claimed, then written into by a pre-division binary, then
/// reopened here carries a valid header and foreign material, and was admitted
/// until [`find_condemned_records`] ran on every open. What closes it is
/// the prefix rename, not the marker: see
/// [`PREPROC_MATERIAL_NAMESPACE`]. The honest residual is narrower and stated
/// in [`a_volume_contaminated_after_it_was_claimed_is_refused`]: a writer that
/// knows the current prefix is indistinguishable from this binary, so this
/// catches the binaries that predate the division, not an arbitrary forger.
/// Find records a pre-division binary left in this volume, by prefix.
///
/// The one check that notices records which appeared in a volume *without this
/// binary writing them*. A volume marker cannot do that on its own: it records
/// the discipline a volume was created under, not what has been written into it
/// since, and a binary predating the marker ignores it by construction. What
/// such a binary cannot do is write a prefix it does not know — so what it
/// leaves behind carries a [`CondemnedNamespace`] and is visible here.
///
/// Returns the first condemned namespace found and how many records sit under
/// it; the refusal needs one namespace to name, and a volume holding records
/// under two is no more or less unusable than one holding records under either.
///
/// Iterating the whole database is cheap: one volume holds one record per
/// material kind plus its metadata, a header and a handful of blobs, because
/// each kind's items live in a single concatenated value.
fn find_condemned_records(
    database: &LmdbDatabase,
    transaction: &heed::RoTxn<'_>,
) -> Result<Option<(CondemnedNamespace, u64)>, PreprocStoreError> {
    let mut counts = [0_u64; CondemnedNamespace::ALL.len()];
    for record in database.iter(transaction)? {
        let (key, _) = record?;
        for (slot, namespace) in counts.iter_mut().zip(CondemnedNamespace::ALL) {
            if key.starts_with(namespace.as_bytes()) {
                *slot += 1;
            }
        }
    }
    Ok(CondemnedNamespace::ALL
        .iter()
        .zip(counts)
        .find_map(|(namespace, records)| (records != 0).then_some((*namespace, records))))
}

fn admit_preproc_volume(
    path: &Path,
    database: &LmdbDatabase,
    transaction: &mut heed::RwTxn<'_>,
    owner: Option<PreprocVolumeOwner>,
) -> Result<(), PreprocStoreError> {
    if let Some(raw) = database.get(transaction, PREPROC_VOLUME_HEADER_KEY)? {
        let header: PreprocVolumeHeader = bincode::deserialize(raw).map_err(|error| {
            PreprocStoreError::UnreadableVolumeHeader {
                path: path.display().to_string(),
                reason: error.to_string(),
            }
        })?;
        // Read so a future reader sees that the variant is load-bearing: an
        // unknown one never reaches here, because bincode refuses it above.
        let PreprocVolumeFormat::DividedCommitV1 = header.format;
        // Before the owner, because contamination makes a volume unusable by
        // *everyone*, where a mismatched owner only makes it unusable here. A
        // header says who created the volume, not who has written into it
        // since: a pre-division binary rolled onto a volume this binary
        // claimed would leave material under the legacy prefix and the header
        // untouched. Checked on every open, not only the first, since that
        // write can land between two opens.
        if let Some((namespace, records)) = find_condemned_records(database, transaction)? {
            return Err(PreprocStoreError::CondemnedRecordsInVolume {
                path: path.display().to_string(),
                namespace,
                records,
            });
        }
        if header.owner != owner {
            return Err(PreprocStoreError::VolumeOwnerMismatch {
                path: path.display().to_string(),
                held: describe_volume_owner(header.owner),
                opening: describe_volume_owner(owner),
            });
        }
        return Ok(());
    }
    let records = database.len(transaction)?;
    if records != 0 {
        return Err(PreprocStoreError::UnmarkedVolume {
            path: path.display().to_string(),
            records,
        });
    }
    let header = PreprocVolumeHeader {
        format: PreprocVolumeFormat::DividedCommitV1,
        owner,
    };
    database.put(
        transaction,
        PREPROC_VOLUME_HEADER_KEY,
        &bincode::serialize(&header)?,
    )?;
    Ok(())
}

impl LmdbPreprocStore {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, PreprocStoreError> {
        Self::open_with_map_size(path, DEFAULT_LMDB_MAP_SIZE)
    }

    /// Open a preprocessing store with an explicit initial LMDB map size.
    /// The actor automatically doubles this virtual limit when a write reaches
    /// it; this parameter controls only the initial reservation.
    pub fn open_with_map_size(
        path: impl AsRef<Path>,
        initial_map_size: usize,
    ) -> Result<Self, PreprocStoreError> {
        Self::open_inner(path.as_ref(), initial_map_size, None)
    }

    /// Open the volume that belongs to one standing pool on one node, claiming
    /// it on first open and refusing it ever after to any other pool, node or
    /// one-shot run.
    ///
    /// A typed constructor rather than a `claim()` call after the fact, so the
    /// standing path cannot forget to claim.
    ///
    /// The honest limit, stated as the boundary it is: two deployments that
    /// share a pool id *and* a node identity are byte-identical to this check,
    /// so it does not separate them. That is not a hole in the owner record —
    /// the material key namespace is derived from the pool id and the node
    /// identity too ([`PreprocKey::encode`]), so in the protocol's own terms
    /// such deployments *are* one node in one pool, and what has gone wrong is
    /// a pool-id collision rather than a volume being shared. Nothing in the
    /// volume could tell them apart either: a per-deployment nonce written at
    /// claim time would refuse the same deployment's restart, which is the
    /// entire purpose of a standing volume, unless it were persisted somewhere
    /// outside the volume — a second store to keep in step, with its own
    /// half-restored failure mode.
    ///
    /// What defends the collision instead is upstream of here: `--pool-id` is
    /// required, its all-zero value is refused, it is an operator requirement
    /// that it be globally unique among live deployments, and party
    /// certificates differ per node so two parties cannot present one node
    /// identity.
    pub fn open_for_standing_pool(
        path: impl AsRef<Path>,
        pool: [u8; 32],
        node: DurableIdentityDigest,
    ) -> Result<Self, PreprocStoreError> {
        Self::open_inner(
            path.as_ref(),
            DEFAULT_LMDB_MAP_SIZE,
            Some(PreprocVolumeOwner::new(pool, node)),
        )
    }

    fn open_inner(
        path: &Path,
        initial_map_size: usize,
        owner: Option<PreprocVolumeOwner>,
    ) -> Result<Self, PreprocStoreError> {
        std::fs::create_dir_all(path)?;
        let initial_map_size = lmdb_initial_map_size(path, initial_map_size)?;
        let env = unsafe {
            heed::EnvOpenOptions::new()
                .map_size(initial_map_size)
                .max_dbs(1)
                .open(path)
        }?;
        // The header write is a write like any other, so it gets the same map
        // growth every other write gets: a 64 KiB initial map does not
        // necessarily hold a named database plus one record on a 16 KiB-page
        // host. Each attempt creates and drops its own transaction, which is
        // the condition `with_lmdb_map_growth` needs in order to resize, and a
        // refused volume returns on the first attempt because only `MapFull`
        // is retried.
        let database = with_lmdb_map_growth(&env, || {
            let mut transaction = env.write_txn()?;
            let database = env.create_database(&mut transaction, Some("store"))?;
            admit_preproc_volume(path, &database, &mut transaction, owner)?;
            transaction.commit()?;
            Ok(database)
        })?;

        let (tx, rx) = std::sync::mpsc::channel::<DbJob>();
        let thread = std::thread::Builder::new()
            .name("lmdb-actor".into())
            .spawn(move || {
                while let Ok(job) = rx.recv() {
                    job(&env, &database);
                }
            })?;

        Ok(Self {
            tx,
            _thread: thread,
        })
    }

    async fn run<T, F>(&self, operation: F) -> Result<T, PreprocStoreError>
    where
        T: Send + 'static,
        F: FnOnce(&heed::Env, &LmdbDatabase) -> Result<T, PreprocStoreError> + Send + 'static,
    {
        let (reply_tx, reply_rx) = tokio::sync::oneshot::channel();
        self.tx
            .send(Box::new(move |env, database| {
                let _ = reply_tx.send(operation(env, database));
            }))
            .map_err(|_| PreprocStoreError::LmdbActor("thread gone".into()))?;
        reply_rx
            .await
            .map_err(|_| PreprocStoreError::LmdbActor("reply dropped".into()))?
    }
}
/// Fixture seeding. Production code reaches the store only through
/// [`PreprocStore`], whose single write primitive is `append_items`.
#[cfg(test)]
impl LmdbPreprocStore {
    /// Every key the volume holds, for the tests whose subject is what is *on
    /// disk* rather than what an API returns.
    ///
    /// The typed API cannot answer "does this volume hold a record under a
    /// prefix nothing writes any more": [`BlobNamespace`] has no variant for a
    /// condemned prefix, which is the property such a test is asserting. So the
    /// assertion has to read the keys.
    pub(crate) async fn volume_keys(&self) -> Result<Vec<Vec<u8>>, PreprocStoreError> {
        self.run(move |env, database| {
            let transaction = env.read_txn()?;
            let mut keys = Vec::new();
            for record in database.iter(&transaction)? {
                let (key, _) = record?;
                keys.push(key.to_vec());
            }
            Ok(keys)
        })
        .await
    }

    /// Seed a key from a complete blob the way a generator commits one: one
    /// accumulating, validating `append_items`.
    ///
    /// Sugar for the fixtures, not a second write path — it rejects exactly
    /// what `append_items` rejects and accumulates exactly as it does.
    pub(crate) async fn seed_items(
        &self,
        key: &PreprocKey,
        blob: &PreprocBlob,
    ) -> Result<(), PreprocStoreError> {
        self.append_items(key, blob.meta.item_size, blob.meta.count, &blob.data)
            .await
            .map(|_| ())
    }

    /// Write meta and data verbatim, with no validation and no accumulation.
    ///
    /// Exists for the fixtures that must construct a stored state production
    /// can no longer produce, and so cannot be reached through `append_items`:
    ///
    /// * a physically inconsistent source — data shorter than
    ///   `count * item_size` — for
    ///   [`reservoir_bundle_rejects_corrupt_sources_before_mutation`] to
    ///   reject; `append_items` refuses it with `PartialItem`.
    /// * a nonzero `consumed` cursor, for
    ///   [`material_metadata_carrying_a_consumed_cursor_is_refused_on_every_read`].
    ///   `append_items` always leaves `consumed` as it found it and
    ///   `take_bundle_from_reservoir` always writes zero, so no production
    ///   write creates one; it can only arrive on a volume an older binary
    ///   wrote, and `decode_material_meta` now refuses it on every read.
    pub(crate) async fn put_blob_unchecked(
        &self,
        key: &PreprocKey,
        blob: &PreprocBlob,
    ) -> Result<(), PreprocStoreError> {
        let meta_key = key.meta_key()?;
        let data_key = key.encode()?;
        let meta = bincode::serialize(&blob.meta)?;
        let data = blob.data.clone();
        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                database.put(&mut transaction, &meta_key, &meta)?;
                database.put(&mut transaction, &data_key, &data)?;
                transaction.commit()?;
                Ok(())
            })
        })
        .await
    }
}

#[async_trait::async_trait]
impl PreprocStore for LmdbPreprocStore {
    #[cfg(test)]
    async fn load(&self, key: &PreprocKey) -> Result<Option<PreprocBlob>, PreprocStoreError> {
        let meta_key = key.meta_key()?;
        let data_key = key.encode()?;
        self.run(move |env, database| {
            let transaction = env.read_txn()?;
            let Some(raw_meta) = database.get(&transaction, &meta_key)? else {
                return Ok(None);
            };
            let meta = decode_material_meta(raw_meta)?;
            let data = database
                .get(&transaction, &data_key)?
                .ok_or(PreprocStoreError::NotFound)?
                .to_vec();
            Ok(Some(PreprocBlob { meta, data }))
        })
        .await
    }

    async fn meta(&self, key: &PreprocKey) -> Result<Option<PreprocMeta>, PreprocStoreError> {
        let key = key.meta_key()?;
        self.run(move |env, database| {
            let transaction = env.read_txn()?;
            database
                .get(&transaction, &key)?
                .map(decode_material_meta)
                .transpose()
        })
        .await
    }

    async fn append_items(
        &self,
        key: &PreprocKey,
        item_size: u32,
        added: u32,
        data: &[u8],
    ) -> Result<u32, PreprocStoreError> {
        let item_size_usize = u32_to_usize(item_size, "append preprocessing item size")?;
        let expected_len = u32_to_usize(added, "append preprocessing count")?
            .checked_mul(item_size_usize)
            .ok_or_else(|| {
                PreprocStoreError::Serialization(format!(
                    "append data length overflows usize: added={added}, item_size={item_size}"
                ))
            })?;
        if data.len() != expected_len || (item_size == 0 && added != 0) {
            return Err(PreprocStoreError::PartialItem {
                data_len: data.len(),
                item_size,
            });
        }

        let meta_key = key.meta_key()?;
        let data_key = key.encode()?;
        let data = data.to_vec();
        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                let mut meta = match database.get(&transaction, &meta_key)? {
                    Some(raw) => {
                        let meta = decode_material_meta(raw)?;
                        if meta.item_size != item_size {
                            return Err(PreprocStoreError::ItemSizeMismatch {
                                expected: meta.item_size,
                                actual: item_size,
                            });
                        }
                        meta
                    }
                    None => PreprocMeta {
                        count: 0,
                        consumed: 0,
                        item_size,
                    },
                };
                let mut stored = database
                    .get(&transaction, &data_key)?
                    .map_or_else(Vec::new, ToOwned::to_owned);
                stored.extend_from_slice(&data);
                meta.count =
                    meta.count
                        .checked_add(added)
                        .ok_or(PreprocStoreError::U32Overflow {
                            field: "preprocessing item count",
                            value: u64::from(meta.count) + u64::from(added),
                        })?;
                database.put(&mut transaction, &data_key, &stored)?;
                database.put(&mut transaction, &meta_key, &bincode::serialize(&meta)?)?;
                transaction.commit()?;
                Ok(meta.count)
            })
        })
        .await
    }

    async fn take_bundle_from_reservoir(
        &self,
        source: &PreprocKeyScope,
        requested: PoolAvailability,
    ) -> Result<OwnedPreprocBundle, PreprocStoreError> {
        let materials = reservoir_material_keys(source)?;

        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                let mut bundle = OwnedPreprocBundle::default();
                for material in &materials {
                    let count = requested.get(material.kind);
                    let Some(raw_meta) = database.get(&transaction, &material.meta_key)? else {
                        if database.get(&transaction, &material.data_key)?.is_some() {
                            return Err(PreprocStoreError::Deserialization(format!(
                                "preprocessing reservoir {:?} has data without metadata",
                                material.kind
                            )));
                        }
                        if count > 0 {
                            return Err(PreprocStoreError::NotFound);
                        }
                        continue;
                    };
                    let meta = decode_material_meta(raw_meta)?;
                    // `decode_material_meta` has already refused a consumed
                    // cursor, so the only metadata left to disbelieve is a
                    // nonempty pool whose items have no size.
                    if meta.count > 0 && meta.item_size == 0 {
                        return Err(PreprocStoreError::Deserialization(format!(
                            "invalid preprocessing reservoir metadata for {:?}",
                            material.kind
                        )));
                    }
                    if count > meta.available() {
                        return Err(PreprocStoreError::Insufficient {
                            need: count,
                            available: meta.available(),
                        });
                    }
                    let source_data = database
                        .get(&transaction, &material.data_key)?
                        .ok_or(PreprocStoreError::NotFound)?;
                    let expected_len = byte_offset(
                        meta.count,
                        meta.item_size,
                        "preprocessing reservoir source size",
                    )?;
                    if source_data.len() != expected_len {
                        return Err(PreprocStoreError::Deserialization(format!(
                        "preprocessing reservoir {:?} contains {} bytes, expected {expected_len}",
                        material.kind,
                        source_data.len()
                    )));
                    }

                    // A bundle always comes off the front: `consumed` is zero
                    // on every record this store will read, so there is no
                    // prefix to skip and the end index is the requested count.
                    let end =
                        byte_offset(count, meta.item_size, "preprocessing reservoir bundle end")?;
                    let remaining = meta.count - count;
                    bundle.remaining.set(material.kind, remaining);

                    // Retain only the slices that outlive this transaction. This
                    // avoids cloning the complete reservoir blob before extracting
                    // one execution's bundle.
                    let taken_data = (count > 0).then(|| source_data[..end].to_vec());
                    let compacted_remaining =
                        (remaining > 0 && count > 0).then(|| source_data[end..].to_vec());

                    if let Some(data) = taken_data {
                        bundle.set(
                            material.kind,
                            TakenPreproc {
                                count,
                                item_size: meta.item_size,
                                data,
                            },
                        );
                    }

                    if remaining == 0 {
                        database.delete(&mut transaction, &material.meta_key)?;
                        database.delete(&mut transaction, &material.data_key)?;
                    } else if count == 0 {
                        // The bytes are already compact and this kind was not
                        // requested; validating it is sufficient.
                    } else {
                        database.put(
                            &mut transaction,
                            &material.meta_key,
                            &bincode::serialize(&PreprocMeta {
                                count: remaining,
                                consumed: 0,
                                item_size: meta.item_size,
                            })?,
                        )?;
                        database.put(
                            &mut transaction,
                            &material.data_key,
                            compacted_remaining
                                .as_deref()
                                .expect("non-compact reservoir has remaining bytes"),
                        )?;
                    }
                }
                transaction.commit()?;
                Ok(bundle)
            })
        })
        .await
    }

    #[cfg(test)]
    async fn available(&self, key: &PreprocKey) -> Result<u32, PreprocStoreError> {
        Ok(self.meta(key).await?.map_or(0, |meta| meta.available()))
    }

    async fn scope_availability(
        &self,
        scope: &PreprocKeyScope,
    ) -> Result<PoolAvailability, PreprocStoreError> {
        let keys = MATERIAL_KINDS
            .into_iter()
            .map(|kind| Ok((kind, scope.key(kind).meta_key()?)))
            .collect::<Result<Vec<_>, PreprocStoreError>>()?;
        self.run(move |env, database| {
            let transaction = env.read_txn()?;
            let mut availability = PoolAvailability::default();
            for (kind, key) in keys {
                let count = database
                    .get(&transaction, &key)?
                    .map(decode_material_meta)
                    .transpose()?
                    .map_or(0, |meta| meta.available());
                availability.set(kind, count);
            }
            Ok(availability)
        })
        .await
    }

    async fn delete(&self, key: &PreprocKey) -> Result<(), PreprocStoreError> {
        let meta_key = key.meta_key()?;
        let data_key = key.encode()?;
        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                database.delete(&mut transaction, &meta_key)?;
                database.delete(&mut transaction, &data_key)?;
                transaction.commit()?;
                Ok(())
            })
        })
        .await
    }

    async fn store_blob(
        &self,
        namespace: BlobNamespace,
        key: &[u8],
        data: &[u8],
    ) -> Result<(), PreprocStoreError> {
        let key = [namespace.as_bytes(), key].concat();
        let data = data.to_vec();
        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                database.put(&mut transaction, &key, &data)?;
                transaction.commit()?;
                Ok(())
            })
        })
        .await
    }

    async fn load_blob(
        &self,
        namespace: BlobNamespace,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>, PreprocStoreError> {
        let key = [namespace.as_bytes(), key].concat();
        self.run(move |env, database| {
            let transaction = env.read_txn()?;
            Ok(database.get(&transaction, &key)?.map(ToOwned::to_owned))
        })
        .await
    }

    async fn delete_blob(
        &self,
        namespace: BlobNamespace,
        key: &[u8],
    ) -> Result<(), PreprocStoreError> {
        let key = [namespace.as_bytes(), key].concat();
        self.run(move |env, database| {
            with_lmdb_map_growth(env, || {
                let mut transaction = env.write_txn()?;
                database.delete(&mut transaction, &key)?;
                transaction.commit()?;
                Ok(())
            })
        })
        .await
    }
}
fn write_robust_share<F: FftField>(
    share: &RobustShare<F>,
    buf: &mut Vec<u8>,
) -> Result<(), PreprocStoreError> {
    share.share[0]
        .serialize_with_mode(&mut *buf, Compress::Yes)
        .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
    buf.extend_from_slice(&usize_to_u64(share.id, "robust share id")?.to_le_bytes());
    buf.extend_from_slice(&usize_to_u64(share.degree, "robust share degree")?.to_le_bytes());
    Ok(())
}

pub fn robust_share_size<F: FftField>() -> usize {
    F::default().serialized_size(Compress::Yes) + 16
}

pub fn robust_share_item_size<F: FftField>() -> Result<u32, PreprocStoreError> {
    usize_to_u32(robust_share_size::<F>(), "robust share item size")
}

pub fn beaver_triple_size<F: FftField>() -> Result<u32, PreprocStoreError> {
    let share_size = robust_share_size::<F>();
    let triple_size = share_size.checked_mul(3).ok_or_else(|| {
        PreprocStoreError::Serialization(format!(
            "beaver triple item size overflows usize: share_size={share_size}"
        ))
    })?;
    usize_to_u32(triple_size, "beaver triple item size")
}

pub fn prandbit_share_size<F: FftField>() -> Result<u32, PreprocStoreError> {
    let item_size = robust_share_size::<F>()
        .checked_add(1)
        .ok_or_else(|| PreprocStoreError::Serialization("prandbit item size overflow".into()))?;
    usize_to_u32(item_size, "prandbit item size")
}

fn read_robust_share<F: FftField>(
    data: &[u8],
    item_size: usize,
) -> Result<RobustShare<F>, PreprocStoreError> {
    if item_size < 16 {
        return Err(PreprocStoreError::Deserialization(format!(
            "robust share item size {item_size} is too small"
        )));
    }
    let field_size = item_size - 16;
    // Data originates from our own serialization so subgroup checks are not required.
    let elem = F::deserialize_with_mode(&data[..field_size], Compress::Yes, Validate::No)
        .map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
    let id = u64::from_le_bytes(
        data[field_size..field_size + 8]
            .try_into()
            .map_err(|_| PreprocStoreError::Deserialization("bad id bytes".into()))?,
    );
    let id = u64_to_usize(id, "robust share id")?;
    let degree = u64::from_le_bytes(
        data[field_size + 8..field_size + 16]
            .try_into()
            .map_err(|_| PreprocStoreError::Deserialization("bad degree bytes".into()))?,
    );
    let degree = u64_to_usize(degree, "robust share degree")?;
    Ok(RobustShare::new(elem, id, degree))
}

pub fn serialize_robust_shares<F: FftField>(
    shares: &[RobustShare<F>],
) -> Result<(Vec<u8>, u32), PreprocStoreError> {
    let is = robust_share_size::<F>();
    let mut buf = Vec::with_capacity(shares.len() * is);
    for s in shares {
        write_robust_share(s, &mut buf)?;
    }
    Ok((buf, usize_to_u32(is, "robust share item size")?))
}

pub fn deserialize_robust_shares<F: FftField>(
    data: &[u8],
    item_size: u32,
    offset: u32,
) -> Result<Vec<RobustShare<F>>, PreprocStoreError> {
    let is = u32_to_usize(item_size, "robust share item size")?;
    if !has_nonzero_item_size(data, is, "robust share")? {
        return Ok(Vec::new());
    }
    let start = byte_offset(offset, item_size, "robust share offset")?;
    let mut shares = Vec::new();
    let mut pos = start;
    while let Some(end) = pos.checked_add(is).filter(|end| *end <= data.len()) {
        shares.push(read_robust_share::<F>(&data[pos..], is)?);
        pos = end;
    }
    Ok(shares)
}

pub fn serialize_beaver_triples<F: FftField>(
    triples: &[ShamirBeaverTriple<F>],
) -> Result<(Vec<u8>, u32), PreprocStoreError> {
    let triple_size = u32_to_usize(beaver_triple_size::<F>()?, "beaver triple item size")?;
    let mut buf = Vec::with_capacity(triples.len() * triple_size);
    for t in triples {
        write_robust_share(&t.a, &mut buf)?;
        write_robust_share(&t.b, &mut buf)?;
        write_robust_share(&t.mult, &mut buf)?;
    }
    Ok((buf, usize_to_u32(triple_size, "beaver triple item size")?))
}

pub fn deserialize_beaver_triples<F: FftField>(
    data: &[u8],
    item_size: u32,
    offset: u32,
) -> Result<Vec<ShamirBeaverTriple<F>>, PreprocStoreError> {
    let is = u32_to_usize(item_size, "beaver triple item size")?;
    if !has_nonzero_item_size(data, is, "beaver triple")? {
        return Ok(Vec::new());
    }
    let share_size = robust_share_size::<F>();
    let start = byte_offset(offset, item_size, "beaver triple offset")?;
    let mut triples = Vec::new();
    let mut pos = start;
    while let Some(end) = pos.checked_add(is).filter(|end| *end <= data.len()) {
        let a = read_robust_share::<F>(&data[pos..], share_size)?;
        let b = read_robust_share::<F>(&data[pos + share_size..], share_size)?;
        let mult = read_robust_share::<F>(&data[pos + 2 * share_size..], share_size)?;
        triples.push(ShamirBeaverTriple::new(a, b, mult));
        pos = end;
    }
    Ok(triples)
}

pub fn serialize_prandbit_shares<F: FftField>(
    shares: &[(RobustShare<F>, Gf256)],
) -> Result<(Vec<u8>, u32), PreprocStoreError> {
    let item_size = u32_to_usize(prandbit_share_size::<F>()?, "prandbit item size")?;
    let mut buf = Vec::with_capacity(shares.len() * item_size);
    for (s, f) in shares {
        write_robust_share(s, &mut buf)?;
        buf.push(f.0);
    }
    Ok((buf, usize_to_u32(item_size, "prandbit item size")?))
}

pub fn deserialize_prandbit_shares<F: FftField>(
    data: &[u8],
    item_size: u32,
    offset: u32,
) -> Result<Vec<(RobustShare<F>, Gf256)>, PreprocStoreError> {
    let is = u32_to_usize(item_size, "prandbit item size")?;
    if !has_nonzero_item_size(data, is, "prandbit")? {
        return Ok(Vec::new());
    }
    let share_size = robust_share_size::<F>();
    let start = byte_offset(offset, item_size, "prandbit offset")?;
    let mut result = Vec::new();
    let mut pos = start;
    while let Some(end) = pos.checked_add(is).filter(|end| *end <= data.len()) {
        let share = read_robust_share::<F>(&data[pos..], share_size)?;
        let f2_8 = Gf256(data[pos + share_size]);
        result.push((share, f2_8));
        pos = end;
    }
    Ok(result)
}

// ---------------------------------------------------------------------------
// Serialization helpers (AVSS)
// ---------------------------------------------------------------------------

pub fn serialize_feldman_shares<F, G>(
    shares: &[stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare<F, G>],
) -> Result<(Vec<u8>, u32), PreprocStoreError>
where
    F: FftField,
    G: ark_ec::CurveGroup<ScalarField = F>,
{
    use ark_serialize::CanonicalSerialize;
    if shares.is_empty() {
        return Ok((vec![], 0));
    }
    let item_size = shares[0].serialized_size(Compress::Yes);
    let mut buf = Vec::with_capacity(shares.len() * item_size);
    for s in shares {
        s.serialize_with_mode(&mut buf, Compress::Yes)
            .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
    }
    Ok((buf, usize_to_u32(item_size, "feldman share item size")?))
}

pub fn deserialize_feldman_shares<F, G>(
    data: &[u8],
    item_size: u32,
    offset: u32,
) -> Result<Vec<stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare<F, G>>, PreprocStoreError>
where
    F: FftField,
    G: ark_ec::CurveGroup<ScalarField = F>,
{
    use ark_serialize::CanonicalDeserialize;
    let is = u32_to_usize(item_size, "feldman share item size")?;
    if !has_nonzero_item_size(data, is, "feldman share")? {
        return Ok(Vec::new());
    }
    let start = byte_offset(offset, item_size, "feldman share offset")?;
    let mut shares = Vec::new();
    let mut pos = start;
    while let Some(end) = pos.checked_add(is).filter(|end| *end <= data.len()) {
        // Data originates from our own serialization so subgroup checks are not required.
        let share = stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare::<F, G>::deserialize_with_mode(
            &data[pos..end], Compress::Yes, Validate::No,
        ).map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
        shares.push(share);
        pos = end;
    }
    Ok(shares)
}

pub fn serialize_avss_triples<F, G>(
    triples: &[stoffelmpc_mpc::avss_mpc::triple_gen::BeaverTriple<F, G>],
) -> Result<(Vec<u8>, u32), PreprocStoreError>
where
    F: FftField,
    G: ark_ec::CurveGroup<ScalarField = F>,
{
    use ark_serialize::CanonicalSerialize;
    if triples.is_empty() {
        return Ok((vec![], 0));
    }
    let share_size = triples[0].a.serialized_size(Compress::Yes);
    let triple_size = share_size.checked_mul(3).ok_or_else(|| {
        PreprocStoreError::Serialization(format!(
            "AVSS triple item size overflows usize: share_size={share_size}"
        ))
    })?;
    let mut buf = Vec::with_capacity(triples.len() * triple_size);
    for t in triples {
        t.a.serialize_with_mode(&mut buf, Compress::Yes)
            .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
        t.b.serialize_with_mode(&mut buf, Compress::Yes)
            .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
        t.c.serialize_with_mode(&mut buf, Compress::Yes)
            .map_err(|e| PreprocStoreError::Serialization(e.to_string()))?;
    }
    Ok((buf, usize_to_u32(triple_size, "AVSS triple item size")?))
}

pub fn deserialize_avss_triples<F, G>(
    data: &[u8],
    item_size: u32,
    offset: u32,
) -> Result<Vec<stoffelmpc_mpc::avss_mpc::triple_gen::BeaverTriple<F, G>>, PreprocStoreError>
where
    F: FftField,
    G: ark_ec::CurveGroup<ScalarField = F>,
{
    use ark_serialize::CanonicalDeserialize;
    let is = u32_to_usize(item_size, "AVSS triple item size")?;
    if !has_nonzero_item_size(data, is, "AVSS triple")? {
        return Ok(Vec::new());
    }
    let share_size = is / 3;
    let start = byte_offset(offset, item_size, "AVSS triple offset")?;
    let mut triples = Vec::new();
    let mut pos = start;
    while let Some(end) = pos.checked_add(is).filter(|end| *end <= data.len()) {
        // Data originates from our own serialization so subgroup checks are not required.
        let a = stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare::<F, G>::deserialize_with_mode(
            &data[pos..pos + share_size], Compress::Yes, Validate::No,
        ).map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
        let b = stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare::<F, G>::deserialize_with_mode(
            &data[pos + share_size..pos + 2 * share_size], Compress::Yes, Validate::No,
        ).map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
        let c = stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare::<F, G>::deserialize_with_mode(
            &data[pos + 2 * share_size..pos + 3 * share_size], Compress::Yes, Validate::No,
        ).map_err(|e| PreprocStoreError::Deserialization(e.to_string()))?;
        triples.push(stoffelmpc_mpc::avss_mpc::triple_gen::BeaverTriple { a, b, c });
        pos = end;
    }
    Ok(triples)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_identity(party_id: usize) -> DurableIdentityDigest {
        DurableIdentityDigest::from_legacy_party_id(party_id)
    }
    use ark_bn254::Fr;
    use ark_ff::UniformRand;
    use ark_std::rand::SeedableRng;

    fn random_share(rng: &mut impl ark_std::rand::Rng) -> RobustShare<Fr> {
        RobustShare::new(Fr::rand(rng), 1, 2)
    }

    fn random_triple(rng: &mut impl ark_std::rand::Rng) -> ShamirBeaverTriple<Fr> {
        ShamirBeaverTriple::new(random_share(rng), random_share(rng), random_share(rng))
    }

    /// The docker suites read [`PREPROC_COMMIT_LOG_MARKER`],
    /// [`PREPROC_LOAD_LOG_MARKER`] and [`PREPROC_PARTIAL_LOAD_LOG_MARKER`] out
    /// of this file and grep container logs
    /// for the value, so an engine that spelled the phrase out instead of
    /// interpolating the constant would leave them asserting on a string
    /// nothing ties to the source again. That is how
    /// `assert_no_party_committed_from_a_live_execution` could have been
    /// reworded into permanent vacuity, and this is the half of the tie a
    /// shell script cannot carry: the scripts fail closed if the constant goes
    /// away, and this fails if an engine stops using it.
    #[test]
    fn both_engines_interpolate_the_preprocessing_store_log_markers() {
        const ENGINES: [(&str, &str); 2] = [
            (
                "honeybadger",
                include_str!("../net/mpc/honeybadger/preprocessing.rs"),
            ),
            ("avss", include_str!("../net/mpc/avss/preprocessing.rs")),
        ];
        for (engine, source) in ENGINES {
            for name in [
                "preproc::PREPROC_COMMIT_LOG_MARKER",
                "preproc::PREPROC_LOAD_LOG_MARKER",
                "preproc::PREPROC_PARTIAL_LOAD_LOG_MARKER",
            ] {
                assert!(
                    source.contains(name),
                    "the {engine} engine no longer interpolates {name}, so the docker \
                     suites would grep for a phrase nothing in the source ties them to"
                );
            }
            for marker in [
                PREPROC_COMMIT_LOG_MARKER,
                PREPROC_LOAD_LOG_MARKER,
                PREPROC_PARTIAL_LOAD_LOG_MARKER,
            ] {
                assert!(
                    !source.contains(marker),
                    "the {engine} engine spells {marker:?} out literally; interpolate \
                     the constant instead, so rewording a message cannot silently \
                     decouple it from the suites that grep for it"
                );
            }
        }
    }

    #[test]
    fn robust_share_roundtrip() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
        let shares: Vec<_> = (0..5).map(|_| random_share(&mut rng)).collect();
        let (data, item_size) = serialize_robust_shares::<Fr>(&shares).unwrap();
        let decoded = deserialize_robust_shares::<Fr>(&data, item_size, 0).unwrap();
        assert_eq!(shares.len(), decoded.len());
        for (a, b) in shares.iter().zip(decoded.iter()) {
            assert_eq!(a.share[0], b.share[0]);
            assert_eq!(a.id, b.id);
            assert_eq!(a.degree, b.degree);
        }
    }

    #[test]
    fn robust_share_skip_consumed() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
        let shares: Vec<_> = (0..10).map(|_| random_share(&mut rng)).collect();
        let (data, item_size) = serialize_robust_shares::<Fr>(&shares).unwrap();
        let decoded = deserialize_robust_shares::<Fr>(&data, item_size, 3).unwrap();
        assert_eq!(decoded.len(), 7);
        assert_eq!(decoded[0].share[0], shares[3].share[0]);
    }

    #[test]
    fn beaver_triple_roundtrip() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
        let triples: Vec<_> = (0..4).map(|_| random_triple(&mut rng)).collect();
        let (data, item_size) = serialize_beaver_triples::<Fr>(&triples).unwrap();
        let decoded = deserialize_beaver_triples::<Fr>(&data, item_size, 0).unwrap();
        assert_eq!(triples.len(), decoded.len());
        for (a, b) in triples.iter().zip(decoded.iter()) {
            assert_eq!(a.a.share[0], b.a.share[0]);
            assert_eq!(a.b.share[0], b.b.share[0]);
            assert_eq!(a.mult.share[0], b.mult.share[0]);
        }
    }

    #[test]
    fn prandbit_roundtrip() {
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(42);
        let shares: Vec<_> = (0..6)
            .map(|i| (random_share(&mut rng), Gf256(i as u8)))
            .collect();
        let (data, item_size) = serialize_prandbit_shares::<Fr>(&shares).unwrap();
        let decoded = deserialize_prandbit_shares::<Fr>(&data, item_size, 0).unwrap();
        assert_eq!(shares.len(), decoded.len());
        for (a, b) in shares.iter().zip(decoded.iter()) {
            assert_eq!(a.0.share[0], b.0.share[0]);
            assert_eq!(a.1, b.1);
        }
    }

    #[test]
    fn preproc_key_with_kind() {
        let base = PreprocKey::new(
            [0xAB; 32],
            MpcFieldKind::Bn254Fr,
            5,
            2,
            legacy_identity(1),
            MaterialKind::BeaverTriple,
        );
        let rs = base.with_kind(MaterialKind::RandomShare);
        assert_eq!(rs.program_hash, base.program_hash);
        assert_eq!(rs.kind, MaterialKind::RandomShare);
        assert_ne!(base.encode().unwrap(), rs.encode().unwrap());
    }

    #[test]
    fn preproc_key_scope_preserves_shared_key_namespace() {
        let node_identity = legacy_identity(3);
        let scope =
            PreprocKeyScope::new([0xCD; 32], MpcFieldKind::Bls12_381Fr, 7, 2, node_identity);

        let base = scope.beaver_triple();
        let random = scope.random_share();
        let prand_bit = scope.prand_bit();
        let prand_int = scope.prand_int();

        assert_eq!(base.program_hash, [0xCD; 32]);
        assert_eq!(base.n, 7);
        assert_eq!(base.t, 2);
        assert_eq!(base.node_identity, node_identity);
        assert_eq!(base.kind, MaterialKind::BeaverTriple);
        assert_eq!(random, base.with_kind(MaterialKind::RandomShare));
        assert_eq!(prand_bit, base.with_kind(MaterialKind::PRandBit));
        assert_eq!(prand_int, base.with_kind(MaterialKind::PRandInt));
    }

    #[test]
    fn preproc_key_encode_rejects_values_outside_binary_key_domain() {
        if usize::BITS <= u32::BITS {
            return;
        }
        let oversized = usize::try_from(u64::from(u32::MAX) + 1).unwrap();
        let key = PreprocKey::new(
            [0xAB; 32],
            MpcFieldKind::Bn254Fr,
            oversized,
            2,
            legacy_identity(1),
            MaterialKind::BeaverTriple,
        );
        let err = key
            .encode()
            .expect_err("oversized party count should be rejected");
        assert!(matches!(
            err,
            PreprocStoreError::U32Overflow {
                field: "preprocessing key n",
                ..
            }
        ));
    }

    #[test]
    fn preproc_blob_try_new_rejects_counts_outside_metadata_domain() {
        if usize::BITS <= u32::BITS {
            return;
        }
        let oversized = usize::try_from(u64::from(u32::MAX) + 1).unwrap();
        let err = PreprocBlob::try_new(Vec::new(), 0, oversized)
            .expect_err("oversized item counts should be rejected");
        assert!(matches!(
            err,
            PreprocStoreError::U32Overflow {
                field: "preprocessing item count",
                ..
            }
        ));
    }

    #[test]
    fn deserialize_feldman_shares_rejects_zero_item_size_with_data() {
        let err = deserialize_feldman_shares::<Fr, ark_bn254::G1Projective>(&[1, 2, 3], 0, 0)
            .expect_err("zero item size with data should be rejected");
        assert!(
            matches!(err, PreprocStoreError::Deserialization(_)),
            "expected deserialization error, got: {err}"
        );
    }

    // -----------------------------------------------------------------------
    // Volume admission: the format marker (A3) and the owner record (A5)
    // -----------------------------------------------------------------------

    /// Write records into a volume the way a binary without the format marker
    /// did: straight into the same named database, with no header.
    ///
    /// This is what a directory persisted by a pre-fix binary looks like — it
    /// holds a `consumed: 0` copy of a pool an execution went on to draw from.
    /// Going through `LmdbPreprocStore` could not produce it, because every
    /// constructor now claims or refuses the volume first.
    fn write_unmarked_volume(path: &Path, records: &[(&[u8], &[u8])]) {
        std::fs::create_dir_all(path).unwrap();
        let env = unsafe {
            heed::EnvOpenOptions::new()
                .map_size(DEFAULT_LMDB_MAP_SIZE)
                .max_dbs(1)
                .open(path)
        }
        .unwrap();
        let mut transaction = env.write_txn().unwrap();
        let database: LmdbDatabase = env
            .create_database(&mut transaction, Some("store"))
            .unwrap();
        for (key, value) in records {
            database.put(&mut transaction, key, value).unwrap();
        }
        transaction.commit().unwrap();
        drop(env);
    }

    /// The data key a binary predating the division would have written for
    /// `key`: the same body under the old material prefix.
    ///
    /// Derived from `encode()` rather than spelled out, so it stays the same
    /// key this binary would look up if the prefix had not changed.
    fn legacy_material_key(key: &PreprocKey) -> Vec<u8> {
        let encoded = key.encode().unwrap();
        let body = &encoded[PREPROC_MATERIAL_NAMESPACE.len()..];
        [CondemnedNamespace::PreDivisionMaterial.as_bytes(), body].concat()
    }

    fn volume_test_scope() -> PreprocKeyScope {
        PreprocKeyScope::new([0x7a; 32], MpcFieldKind::Bn254Fr, 5, 1, legacy_identity(0))
    }

    fn volume_test_key() -> PreprocKey {
        volume_test_scope().key(MaterialKind::RandomShare)
    }

    /// A volume written before a commit became a division of the pool is
    /// refused, not adopted.
    ///
    /// There is no schema marker on such a volume and no migration that could
    /// make its material safe: it may already have served an execution, which
    /// is the defect the division fixed. Refusing to draw from it is the only
    /// correct answer, and it must be refused at open, before any caller can
    /// reach a single item.
    #[tokio::test]
    async fn an_unmarked_preprocessing_volume_is_refused_rather_than_adopted() {
        let dir = tempfile::tempdir().unwrap();
        let key = volume_test_key();
        write_unmarked_volume(
            dir.path(),
            &[
                (&key.meta_key().unwrap(), b"stale metadata"),
                (&key.encode().unwrap(), b"stale material"),
            ],
        );

        let error = LmdbPreprocStore::open(dir.path())
            .err()
            .expect("a volume with no format marker must be refused");
        assert!(
            matches!(error, PreprocStoreError::UnmarkedVolume { records: 2, .. }),
            "expected UnmarkedVolume over both records, got: {error}"
        );
        let rendered = error.to_string();
        assert!(
            rendered.contains("may already have served an execution")
                && rendered.contains("Delete the volume"),
            "the refusal must say why the material cannot be reused and what to do: {rendered}"
        );
    }

    /// Refusal is volume-scoped, not `pp:`-scoped.
    ///
    /// A pre-fix volume may hold only reservation blobs (`rsv:` is never
    /// deleted) or only a standing generation marker. Those were written by the
    /// same binary under the same discipline, so one rule covers them: content
    /// without a marker is content this binary may not touch.
    #[tokio::test]
    async fn an_unmarked_volume_holding_only_reservation_blobs_is_refused_too() {
        let dir = tempfile::tempdir().unwrap();
        write_unmarked_volume(dir.path(), &[(b"rsv:some-run", b"a persisted registry")]);

        let error = LmdbPreprocStore::open(dir.path())
            .err()
            .expect("an unmarked volume is refused whatever namespace it holds");
        assert!(
            matches!(error, PreprocStoreError::UnmarkedVolume { records: 1, .. }),
            "expected UnmarkedVolume, got: {error}"
        );
    }

    /// A header this binary cannot decode is refused, not ignored.
    ///
    /// `PreprocVolumeFormat` is a closed enum over `bincode`, so a volume
    /// written under a discipline this binary does not know fails to
    /// deserialize. Failing closed in that direction is deliberate: a newer
    /// write discipline is not one an older binary may draw under.
    #[tokio::test]
    async fn a_volume_header_this_binary_cannot_decode_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        // Variant index 7 of a one-variant enum: what a future format reads
        // like to this binary.
        write_unmarked_volume(dir.path(), &[(PREPROC_VOLUME_HEADER_KEY, &[7, 0, 0, 0, 0])]);

        let error = LmdbPreprocStore::open(dir.path())
            .err()
            .expect("an undecodable header must be refused");
        assert!(
            matches!(error, PreprocStoreError::UnreadableVolumeHeader { .. }),
            "expected UnreadableVolumeHeader, got: {error}"
        );
    }

    /// The normal case: a fresh directory is claimed on first open and reopens.
    ///
    /// Every `tempfile::tempdir()` in this suite and every fresh docker volume
    /// takes this path, so the refusal above must not cost it anything.
    #[tokio::test]
    async fn a_fresh_volume_is_marked_on_first_open_and_reopens_with_its_material() {
        let dir = tempfile::tempdir().unwrap();
        let key = volume_test_key();
        {
            let store = LmdbPreprocStore::open(dir.path()).unwrap();
            store.append_items(&key, 2, 2, &[1, 2, 3, 4]).await.unwrap();
        }
        let reopened = LmdbPreprocStore::open(dir.path())
            .expect("a volume this binary marked is one it may reopen");
        assert_eq!(reopened.available(&key).await.unwrap(), 2);
    }

    /// A volume this binary claimed, and a pre-division binary then wrote into,
    /// is refused rather than served.
    ///
    /// The format marker certifies how a volume was *created*; it cannot
    /// certify what has been written into it since, and a binary predating the
    /// marker ignores it by construction. So an image rollback onto a retained
    /// `--preproc-store` volume followed by a roll forward produced a volume
    /// carrying a valid header beside material this binary never wrote — and it
    /// was admitted, and drawn from.
    ///
    /// What closes it is the material prefix rename, not the marker: a
    /// pre-division binary writes [`CondemnedNamespace::PreDivisionMaterial`],
    /// which this binary never reads and now refuses to open over. The residual,
    /// stated rather than papered over: a writer that knows the *current*
    /// prefix is indistinguishable from this binary, so this catches the
    /// binaries that predate the division — the stated threat — and not an
    /// arbitrary forger.
    #[tokio::test]
    async fn a_volume_contaminated_after_it_was_claimed_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let key = volume_test_key();
        // Exactly the on-disk state of "claimed here, then written by a
        // pre-division binary": this binary's own header, beside material under
        // the old prefix.
        let header = bincode::serialize(&PreprocVolumeHeader {
            format: PreprocVolumeFormat::DividedCommitV1,
            owner: None,
        })
        .unwrap();
        let legacy_meta = bincode::serialize(&PreprocMeta {
            count: 3,
            consumed: 0,
            item_size: 2,
        })
        .unwrap();
        let legacy_data_key = legacy_material_key(&key);
        let mut legacy_meta_key = legacy_data_key.clone();
        legacy_meta_key.push(b'm');
        write_unmarked_volume(
            dir.path(),
            &[
                (PREPROC_VOLUME_HEADER_KEY, &header),
                (&legacy_meta_key, &legacy_meta),
                (&legacy_data_key, &[1, 1, 2, 2, 3, 3]),
            ],
        );

        let error = LmdbPreprocStore::open(dir.path())
            .err()
            .expect("a claimed volume holding pre-division material must be refused");
        assert!(
            matches!(
                error,
                PreprocStoreError::CondemnedRecordsInVolume {
                    namespace: CondemnedNamespace::PreDivisionMaterial,
                    records: 2,
                    ..
                }
            ),
            "expected CondemnedRecordsInVolume over both material records, got: {error}"
        );
        let rendered = error.to_string();
        assert!(
            rendered.contains("may already have served an execution")
                && rendered.contains("Delete the volume"),
            "the refusal must say why the material cannot be reused and what to do: {rendered}"
        );
    }

    /// A claimed volume holding only a retired reservation record is refused.
    ///
    /// The second half of the same contamination story as
    /// [`a_volume_contaminated_after_it_was_claimed_is_refused`], and the half
    /// that was admitted until the reservation namespace joined the condemned
    /// set. A pre-division binary that reserved mask indices and committed no
    /// material left exactly this volume: this binary's header, and an `rsv:`
    /// record. Nothing read it and nothing refused it, so a volume that had
    /// been open to a binary with the copy discipline was served.
    ///
    /// Safe to condemn only because nothing current writes that prefix — the
    /// reservation registry no longer reaches disk at all. That is the
    /// precondition, and
    /// [`the_condemned_prefixes_are_ones_this_binary_never_writes`] is what
    /// keeps it true.
    #[tokio::test]
    async fn a_claimed_volume_holding_a_retired_reservation_record_is_refused() {
        let dir = tempfile::tempdir().unwrap();
        let header = bincode::serialize(&PreprocVolumeHeader {
            format: PreprocVolumeFormat::DividedCommitV1,
            owner: None,
        })
        .unwrap();
        let reservation_key = [
            CondemnedNamespace::RetiredReservation.as_bytes(),
            b"program-node-run",
        ]
        .concat();
        write_unmarked_volume(
            dir.path(),
            &[
                (PREPROC_VOLUME_HEADER_KEY, &header),
                (&reservation_key, b"a persisted registry"),
            ],
        );

        let error = LmdbPreprocStore::open(dir.path())
            .err()
            .expect("a claimed volume holding a retired reservation record must be refused");
        assert!(
            matches!(
                error,
                PreprocStoreError::CondemnedRecordsInVolume {
                    namespace: CondemnedNamespace::RetiredReservation,
                    records: 1,
                    ..
                }
            ),
            "expected CondemnedRecordsInVolume over the reservation record, got: {error}"
        );
        let rendered = error.to_string();
        assert!(
            rendered.contains("the retired reservation prefix `rsv:`")
                && rendered.contains("Delete the volume"),
            "the refusal must name the prefix it found and what to do: {rendered}"
        );
    }

    /// No key this binary writes starts with a condemned prefix.
    ///
    /// The precondition for condemning a prefix at all: a live namespace in
    /// that set would make a node refuse the volume it had just written. So
    /// this asserts over every key the binary can produce — the volume header,
    /// a material data key and its metadata key, and every [`BlobNamespace`] —
    /// and then over the volume a real write leaves behind, which also catches
    /// a key written by some path this list forgot.
    #[tokio::test]
    async fn the_condemned_prefixes_are_ones_this_binary_never_writes() {
        let key = volume_test_key();
        let mut produced: Vec<Vec<u8>> = vec![
            PREPROC_VOLUME_HEADER_KEY.to_vec(),
            key.encode().unwrap(),
            key.meta_key().unwrap(),
            standing_generation_key(volume_test_scope()).unwrap(),
        ];
        for namespace in BlobNamespace::ALL {
            produced.push([namespace.as_bytes(), b"any-caller-key"].concat());
        }
        for condemned in CondemnedNamespace::ALL {
            for produced_key in &produced {
                assert!(
                    !produced_key.starts_with(condemned.as_bytes()),
                    "this binary writes {produced_key:?}, which is under {condemned}, so a \
                     volume it wrote would be refused on reopen"
                );
            }
        }

        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        store.append_items(&key, 2, 2, &[1, 2, 3, 4]).await.unwrap();
        store
            .store_blob(
                BlobNamespace::StandingPreprocGeneration,
                &standing_generation_key(volume_test_scope()).unwrap(),
                &[9; 32],
            )
            .await
            .unwrap();
        let keys = store.volume_keys().await.unwrap();
        assert!(
            keys.len() >= 4,
            "the volume under test must hold the header, the material pair and the \
             generation blob: {keys:?}"
        );
        for condemned in CondemnedNamespace::ALL {
            assert!(
                keys.iter()
                    .all(|key| !key.starts_with(condemned.as_bytes())),
                "a volume this binary wrote holds a record under {condemned}"
            );
        }
        drop(store);
        LmdbPreprocStore::open(dir.path())
            .expect("a volume this binary wrote must reopen, not be condemned");
    }

    /// The two material prefixes cannot shadow each other.
    ///
    /// This is the second barrier, and the reason the refusal above cannot
    /// false-positive on this binary's own material: no key this binary derives
    /// carries the legacy prefix, so a pre-division record is not merely
    /// refused at open — it is not a key any read of this store would look up.
    #[test]
    fn the_material_prefix_cannot_be_confused_with_the_pre_division_one() {
        let legacy = CondemnedNamespace::PreDivisionMaterial.as_bytes();
        assert!(
            !PREPROC_MATERIAL_NAMESPACE.starts_with(legacy),
            "this binary's material keys would be counted as pre-division records"
        );
        assert!(
            !legacy.starts_with(PREPROC_MATERIAL_NAMESPACE),
            "a pre-division record would be read as one of this binary's items"
        );
        let encoded = volume_test_key().encode().unwrap();
        assert!(encoded.starts_with(PREPROC_MATERIAL_NAMESPACE));
        assert!(!encoded.starts_with(legacy));
    }

    /// The blob API cannot be aimed at a preprocessing item.
    ///
    /// `store_blob` / `load_blob` / `delete_blob` share one LMDB database with
    /// the preprocessing material, and the namespace is the only thing
    /// separating them. While that namespace was `&[u8]`,
    /// `load_blob(b"pp:", &key.encode()?[3..])` was a production-visible
    /// *non-destructive read* of a material item — [`PreprocKey::encode`] is
    /// public and its leading bytes are the material prefix — and `store_blob`
    /// was the unconditional, non-accumulating put of one that the division fix
    /// deleted `PreprocStore::store` to remove.
    ///
    /// [`BlobNamespace`] makes the material namespace unnameable. Asserted here
    /// over the whole closed set: the prefix arithmetic, and the behaviour
    /// under the sub-key that reconstructs the original exploit — the material
    /// key with as many leading bytes stripped as the namespace re-contributes,
    /// so that `namespace + sub-key` lands on the material key whenever the
    /// namespace's own prefix is the material one. Passing the *whole* encoded
    /// key instead proves nothing: the namespace is prepended, so the result is
    /// `ns + "ppd:" + body`, which cannot collide with anything.
    #[tokio::test]
    async fn the_blob_api_cannot_name_the_material_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let key = volume_test_key();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        store.append_items(&key, 2, 2, &[7, 7, 8, 8]).await.unwrap();
        let encoded = key.encode().unwrap();

        for namespace in BlobNamespace::ALL {
            let prefix = namespace.as_bytes();
            for condemned in CondemnedNamespace::ALL {
                assert_ne!(
                    prefix,
                    condemned.as_bytes(),
                    "{namespace:?} writes under {condemned}, so a blob write would \
                     condemn the volume it lands in"
                );
                assert!(
                    !prefix.starts_with(condemned.as_bytes())
                        && !condemned.as_bytes().starts_with(prefix),
                    "{namespace:?} and {condemned} can shadow each other"
                );
            }
            assert!(
                !prefix.starts_with(PREPROC_MATERIAL_NAMESPACE),
                "{namespace:?} places its blobs inside the material namespace"
            );
            assert!(
                !PREPROC_MATERIAL_NAMESPACE.starts_with(prefix),
                "{namespace:?} is short enough that a caller's key could complete a \
                 material prefix"
            );
            assert!(
                !PREPROC_VOLUME_HEADER_KEY.starts_with(prefix),
                "{namespace:?} could overwrite the volume header"
            );

            let colliding = &encoded[prefix.len().min(encoded.len())..];
            store
                .store_blob(*namespace, colliding, b"overwritten")
                .await
                .unwrap();
            assert_eq!(
                store.load_blob(*namespace, colliding).await.unwrap(),
                Some(b"overwritten".to_vec()),
                "{namespace:?} did not store where it said it would"
            );
        }

        assert_eq!(
            store.load(&key).await.unwrap().map(|blob| blob.data),
            Some(vec![7, 7, 8, 8]),
            "a blob write reached the material item"
        );
        assert_eq!(
            store.available(&key).await.unwrap(),
            2,
            "a blob write disturbed the material inventory"
        );
    }

    /// One preprocessing volume belongs to one standing pool, and the code
    /// enforces that rather than documenting it.
    ///
    /// A volume cloned or bind-mounted into a second pool would give both pools
    /// copies of the same correlated material, and each would serve it to an
    /// execution — the same break as a copying commit, by a different route.
    /// Asserted here: the owning pool reopens its own volume and still finds
    /// its material; a second pool is refused; and a one-shot run, which claims
    /// no pool, is refused too.
    #[tokio::test]
    async fn a_standing_preprocessing_volume_is_refused_to_every_other_opener() {
        let dir = tempfile::tempdir().unwrap();
        let key = volume_test_key();
        let pool = [0x11; 32];
        let other_pool = [0x22; 32];
        let node = legacy_identity(3);
        let other_node = legacy_identity(4);

        {
            let store = LmdbPreprocStore::open_for_standing_pool(dir.path(), pool, node).unwrap();
            store.append_items(&key, 2, 2, &[9, 8, 7, 6]).await.unwrap();
        }

        let second_pool = LmdbPreprocStore::open_for_standing_pool(dir.path(), other_pool, node)
            .err()
            .expect("a second standing pool must be refused this volume");
        assert!(
            matches!(second_pool, PreprocStoreError::VolumeOwnerMismatch { .. }),
            "expected VolumeOwnerMismatch for a second pool, got: {second_pool}"
        );

        // The likelier operator mistake: two parties sharing one bind mount.
        // Keys are namespaced by node identity, so today it silently half-works.
        let second_node = LmdbPreprocStore::open_for_standing_pool(dir.path(), pool, other_node)
            .err()
            .expect("a second node must be refused this volume");
        assert!(
            matches!(second_node, PreprocStoreError::VolumeOwnerMismatch { .. }),
            "expected VolumeOwnerMismatch for a second node, got: {second_node}"
        );

        let unowned = LmdbPreprocStore::open(dir.path())
            .err()
            .expect("a one-shot run must be refused a standing pool's volume");
        assert!(
            matches!(unowned, PreprocStoreError::VolumeOwnerMismatch { .. }),
            "expected VolumeOwnerMismatch for an unowned opener, got: {unowned}"
        );
        assert!(
            unowned.to_string().contains("no standing pool"),
            "the refusal must name what opened it: {unowned}"
        );

        // The owner reopens across a restart — this is the "retained
        // preprocessing volumes" arm of the standing campaign, and `--pool-id`
        // is stable across restarts by deployment.
        let owner = LmdbPreprocStore::open_for_standing_pool(dir.path(), pool, node)
            .expect("the owning pool reopens its own volume");
        assert_eq!(owner.available(&key).await.unwrap(), 2);
    }

    /// A standing pool may claim a fresh volume, and only a fresh one.
    ///
    /// The claim is taken on first open and never changed, so a volume a
    /// one-shot run already marked is not one a standing pool may adopt.
    #[tokio::test]
    async fn a_standing_pool_cannot_adopt_a_volume_another_opener_marked() {
        let dir = tempfile::tempdir().unwrap();
        drop(LmdbPreprocStore::open(dir.path()).unwrap());

        let error =
            LmdbPreprocStore::open_for_standing_pool(dir.path(), [0x33; 32], legacy_identity(1))
                .err()
                .expect("a standing pool must not adopt an unowned volume");
        assert!(
            matches!(error, PreprocStoreError::VolumeOwnerMismatch { .. }),
            "expected VolumeOwnerMismatch, got: {error}"
        );
    }

    #[tokio::test]
    async fn lmdb_store_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();

        let key = PreprocKey::new(
            [0x01; 32],
            MpcFieldKind::Bn254Fr,
            5,
            2,
            legacy_identity(0),
            MaterialKind::RandomShare,
        );
        let blob = PreprocBlob::new(vec![0xAA; 480], 48, 10);

        store.seed_items(&key, &blob).await.unwrap();
        let loaded = store.load(&key).await.unwrap().unwrap();
        assert_eq!(loaded.meta.count, 10);
        assert_eq!(loaded.meta.consumed, 0);
        assert_eq!(loaded.meta.available(), 10);
        assert_eq!(loaded.data, blob.data);
    }
    /// A `Reuse` plan touches nothing.
    ///
    /// When every party reports the same inventory and it already covers the
    /// targets, `apply_standing_preproc_plan` must neither generate nor
    /// rewrite: the reservoir's bytes, counts and generation marker all stay
    /// as they were, and the next execution draws out of exactly the material
    /// that was already there. This arm is safe today because it is a total
    /// no-op, and nothing asserted that; a change to it would otherwise be
    /// caught only if it happened to break one of the shared draw tests.
    #[tokio::test]
    async fn a_reuse_plan_neither_generates_nor_rewrites_the_reservoir() {
        let dir = tempfile::tempdir().expect("temp store dir");
        let store = LmdbPreprocStore::open(dir.path()).expect("open store");
        let scope =
            PreprocKeyScope::new([0x4e; 32], MpcFieldKind::Bn254Fr, 5, 1, legacy_identity(7));
        let generation_id = [0x5f; 32];
        let targets = PoolAvailability {
            beaver: 2,
            random: 3,
            prand_bit: 0,
            prand_int: 0,
        };

        let triples: Vec<_> = (0..2).map(labelled_triple).collect();
        let (triple_data, triple_item_size) = serialize_beaver_triples::<Fr>(&triples).unwrap();
        store
            .seed_items(
                &scope.beaver_triple(),
                &PreprocBlob::try_new(triple_data, triple_item_size, triples.len()).unwrap(),
            )
            .await
            .expect("seed triples");
        let shares: Vec<_> = (0..3).map(labelled_robust_share).collect();
        let (share_data, share_item_size) = serialize_robust_shares::<Fr>(&shares).unwrap();
        store
            .seed_items(
                &scope.random_share(),
                &PreprocBlob::try_new(share_data, share_item_size, shares.len()).unwrap(),
            )
            .await
            .expect("seed random shares");
        store_standing_preproc_generation(&store, scope, generation_id)
            .await
            .expect("mark the generation");

        // Every party reports this inventory, and it covers the targets, so the
        // agreed action is Reuse.
        let snapshot = standing_preproc_snapshot(&store, scope)
            .await
            .expect("read the inventory");
        let plan =
            agree_standing_preproc_plan(targets, &[snapshot; 3], [0xaa; 32]).expect("agree a plan");
        assert_eq!(plan.action, StandingPreprocAction::Reuse);
        assert_eq!(plan.generation_id, generation_id, "Reuse keeps the marker");

        // `PreprocBlob` is not `PartialEq`; compare the metadata and the raw
        // bytes, which is what "touches nothing" has to mean.
        async fn snapshot_bytes(
            store: &LmdbPreprocStore,
            scope: PreprocKeyScope,
        ) -> Vec<Option<(PreprocMeta, Vec<u8>)>> {
            let mut rows = Vec::new();
            for kind in MATERIAL_KINDS {
                // `None` for the kinds this reservoir does not hold, so a plan
                // that invented one would be caught too.
                rows.push(
                    store
                        .load(&scope.key(kind))
                        .await
                        .unwrap()
                        .map(|blob| (blob.meta, blob.data)),
                );
            }
            rows
        }

        let before = snapshot_bytes(&store, scope).await;

        let generated = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let final_snapshot = apply_standing_preproc_plan(&store, scope, targets, plan, |needed| {
            let generated = std::sync::Arc::clone(&generated);
            async move {
                generated.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                panic!("a Reuse plan must not generate, yet it asked for {needed:?}");
            }
        })
        .await
        .expect("apply the Reuse plan");

        assert_eq!(
            generated.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "a Reuse plan must not run an interactive preprocessing round"
        );
        assert_eq!(
            snapshot_bytes(&store, scope).await,
            before,
            "a Reuse plan must leave every byte and every cursor as it found them"
        );
        assert_eq!(
            final_snapshot.generation_id,
            Some(generation_id),
            "a Reuse plan must not re-mark the generation"
        );
        assert_eq!(final_snapshot.availability(), targets);
    }

    /// Build a Beaver triple whose three field elements name its index, so an
    /// item can be identified by its CONTENT rather than by where it sat.
    fn labelled_triple(index: u64) -> ShamirBeaverTriple<Fr> {
        ShamirBeaverTriple::new(
            RobustShare::new(Fr::from(3 * index + 1), 1, 2),
            RobustShare::new(Fr::from(3 * index + 2), 1, 2),
            RobustShare::new(Fr::from(3 * index + 3), 1, 2),
        )
    }

    fn labelled_robust_share(index: u64) -> RobustShare<Fr> {
        RobustShare::new(Fr::from(1_000 + index), 1, 2)
    }

    /// One share's secret plus the identity the protocol interpolates it at.
    type ShareContent = (Fr, usize, usize);
    type TripleContent = (ShareContent, ShareContent, ShareContent);

    /// The full content of a triple: the three secrets plus the share identity
    /// the protocol interpolates them at. Two triples with equal content are
    /// the same correlated material, wherever they were stored.
    fn triple_content(triple: &ShamirBeaverTriple<Fr>) -> TripleContent {
        (
            share_content(&triple.a),
            share_content(&triple.b),
            share_content(&triple.mult),
        )
    }

    fn share_content(share: &RobustShare<Fr>) -> ShareContent {
        (share.share[0], share.id, share.degree)
    }

    /// The item-CONTENT form of the reservoir draw property, on the one draw
    /// path production uses: `take_bundle_from_reservoir`.
    ///
    /// Every production draw from the store, standing or one-shot, goes through
    /// `take_bundle_from_reservoir` (`net/mpc/honeybadger/preprocessing.rs`
    /// `try_load_preproc`, `net/mpc/avss/preprocessing.rs` `try_load_preproc`,
    /// and `reserve_reservoir_bundle` in the runner). The other
    /// `reservoir_bundle_*` tests cover it with byte literals; this one covers
    /// it with real correlated material, decoded, so the claim is about the
    /// secrets and not about slice arithmetic. Each stored item names its own
    /// index in its field elements, so a collision is reported as the
    /// colliding values.
    ///
    /// Asserted: the two executions' bundles have no item in common, in either
    /// material kind; every item they receive is one that was stored; and once
    /// the reservoir is spent a third execution gets nothing rather than a
    /// repeat.
    #[tokio::test]
    async fn two_executions_never_receive_the_same_reservoir_item_content() {
        const STORED: u32 = 6;
        const PER_EXECUTION: u32 = 3;

        let dir = tempfile::tempdir().expect("temp store dir");
        let store = LmdbPreprocStore::open(dir.path()).expect("open store");
        let scope =
            PreprocKeyScope::new([0x3d; 32], MpcFieldKind::Bn254Fr, 5, 1, legacy_identity(2));

        let triples: Vec<_> = (0..u64::from(STORED)).map(labelled_triple).collect();
        let (triple_data, triple_item_size) = serialize_beaver_triples::<Fr>(&triples).unwrap();
        store
            .seed_items(
                &scope.beaver_triple(),
                &PreprocBlob::try_new(triple_data, triple_item_size, triples.len()).unwrap(),
            )
            .await
            .expect("seed triples");

        let shares: Vec<_> = (0..u64::from(STORED)).map(labelled_robust_share).collect();
        let (share_data, share_item_size) = serialize_robust_shares::<Fr>(&shares).unwrap();
        store
            .seed_items(
                &scope.random_share(),
                &PreprocBlob::try_new(share_data, share_item_size, shares.len()).unwrap(),
            )
            .await
            .expect("seed random shares");

        let request = PoolAvailability {
            beaver: PER_EXECUTION,
            random: PER_EXECUTION,
            prand_bit: 0,
            prand_int: 0,
        };

        let first = store
            .take_bundle_from_reservoir(&scope, request)
            .await
            .expect("the first execution allocates its bundle");
        let second = store
            .take_bundle_from_reservoir(&scope, request)
            .await
            .expect("the second execution allocates its bundle");

        fn bundle_triples(material: &Option<TakenPreproc>) -> Vec<ShamirBeaverTriple<Fr>> {
            let material = material.as_ref().expect("bundle carries triples");
            deserialize_beaver_triples::<Fr>(&material.data, material.item_size, 0).unwrap()
        }
        fn bundle_shares(material: &Option<TakenPreproc>) -> Vec<RobustShare<Fr>> {
            let material = material.as_ref().expect("bundle carries random shares");
            deserialize_robust_shares::<Fr>(&material.data, material.item_size, 0).unwrap()
        }

        let first_triples = bundle_triples(&first.beaver);
        let second_triples = bundle_triples(&second.beaver);
        let first_shares = bundle_shares(&first.random);
        let second_shares = bundle_shares(&second.random);

        // Non-vacuity: each execution decoded the full width it asked for, and
        // decoded real stored material rather than padding.
        for (label, got) in [
            ("first triples", first_triples.len()),
            ("second triples", second_triples.len()),
            ("first shares", first_shares.len()),
            ("second shares", second_shares.len()),
        ] {
            assert_eq!(
                got as u32, PER_EXECUTION,
                "{label}: decoded {got} items, expected {PER_EXECUTION}"
            );
        }
        let stored_triples: Vec<_> = triples.iter().map(triple_content).collect();
        for item in first_triples.iter().chain(second_triples.iter()) {
            assert!(
                stored_triples.contains(&triple_content(item)),
                "a bundled triple is not one of the stored triples: {:?}",
                triple_content(item)
            );
        }
        let stored_shares: Vec<_> = shares.iter().map(share_content).collect();
        for item in first_shares.iter().chain(second_shares.iter()) {
            assert!(
                stored_shares.contains(&share_content(item)),
                "a bundled random share is not one of the stored shares: {:?}",
                share_content(item)
            );
        }

        for (i, mine) in first_triples.iter().enumerate() {
            for (j, theirs) in second_triples.iter().enumerate() {
                assert_ne!(
                    triple_content(mine),
                    triple_content(theirs),
                    "execution 1's triple {i} and execution 2's triple {j} are the SAME \
                     correlated material: {:?}",
                    triple_content(mine)
                );
            }
        }
        for (i, mine) in first_shares.iter().enumerate() {
            for (j, theirs) in second_shares.iter().enumerate() {
                assert_ne!(
                    share_content(mine),
                    share_content(theirs),
                    "execution 1's random share {i} and execution 2's share {j} are the \
                     SAME mask: {:?}",
                    share_content(mine)
                );
            }
        }

        // The reservoir held exactly two executions' worth. A third must get
        // nothing rather than a repeat of what the first two already hold.
        let third = store.take_bundle_from_reservoir(&scope, request).await;
        assert!(
            matches!(
                third,
                Err(PreprocStoreError::NotFound) | Err(PreprocStoreError::Insufficient { .. })
            ),
            "a spent reservoir must refuse a third execution, got {third:?}"
        );
        assert_eq!(
            store.scope_availability(&scope).await.unwrap(),
            PoolAvailability::default(),
            "every stored item was served exactly once, so nothing should remain"
        );
    }

    #[tokio::test]
    async fn lmdb_append_accumulates_and_reports_scope_availability() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let scope =
            PreprocKeyScope::new([0x05; 32], MpcFieldKind::Bn254Fr, 4, 1, legacy_identity(0));
        let key = scope.random_share();
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(7);
        let shares_a: Vec<_> = (0..3).map(|_| random_share(&mut rng)).collect();
        let shares_b: Vec<_> = (0..2).map(|_| random_share(&mut rng)).collect();
        let (data_a, item_size) = serialize_robust_shares::<Fr>(&shares_a).unwrap();
        let (data_b, item_size_b) = serialize_robust_shares::<Fr>(&shares_b).unwrap();
        assert_eq!(item_size, item_size_b);

        assert_eq!(
            store
                .append_items(&key, item_size, shares_a.len() as u32, &data_a)
                .await
                .unwrap(),
            3
        );
        assert_eq!(
            store
                .append_items(&key, item_size, shares_b.len() as u32, &data_b)
                .await
                .unwrap(),
            5
        );
        assert_eq!(
            store.load(&key).await.unwrap().unwrap().data,
            [data_a, data_b].concat(),
            "a second append must land behind the first, not replace it"
        );

        let meta = store.meta(&key).await.unwrap().unwrap();
        assert_eq!(meta.count, 5);
        assert_eq!(meta.consumed, 0);
        assert_eq!(meta.available(), 5);
        let availability = store.scope_availability(&scope).await.unwrap();
        assert_eq!(availability.random, 5);
        assert_eq!(availability.beaver, 0);
        assert_eq!(availability.prand_bit, 0);
        assert_eq!(availability.prand_int, 0);
    }

    #[tokio::test]
    async fn lmdb_append_rejects_partial_and_item_size_mismatch() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let key = PreprocKey::new(
            [0x06; 32],
            MpcFieldKind::Bn254Fr,
            4,
            1,
            legacy_identity(0),
            MaterialKind::RandomShare,
        );
        let mut rng = ark_std::rand::rngs::StdRng::seed_from_u64(8);
        let shares: Vec<_> = (0..2).map(|_| random_share(&mut rng)).collect();
        let (data, item_size) = serialize_robust_shares::<Fr>(&shares).unwrap();

        let err = store
            .append_items(&key, item_size, 1, &data[..data.len() - 1])
            .await
            .unwrap_err();
        assert!(matches!(err, PreprocStoreError::PartialItem { .. }));

        store.append_items(&key, item_size, 2, &data).await.unwrap();
        let wrong_size_data = vec![0u8; usize::try_from((item_size + 1) * 2).unwrap()];
        let err = store
            .append_items(&key, item_size + 1, 2, &wrong_size_data)
            .await
            .unwrap_err();
        assert!(matches!(err, PreprocStoreError::ItemSizeMismatch { .. }));
    }

    #[tokio::test]
    async fn reservoir_bundle_takes_multiple_kinds_and_physically_compacts_sources() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let identity = legacy_identity(3);
        let source = PreprocKeyScope::new([0x31; 32], MpcFieldKind::Bn254Fr, 5, 1, identity);

        store
            .seed_items(
                &source.beaver_triple(),
                &PreprocBlob::new(vec![40, 41, 42, 43], 1, 4),
            )
            .await
            .unwrap();
        store
            .seed_items(
                &source.random_share(),
                &PreprocBlob::new(vec![10, 11, 20, 21, 30, 31], 2, 3),
            )
            .await
            .unwrap();

        let bundle = store
            .take_bundle_from_reservoir(
                &source,
                PoolAvailability {
                    beaver: 4,
                    random: 1,
                    prand_bit: 0,
                    prand_int: 0,
                },
            )
            .await
            .unwrap();
        assert_eq!(bundle.random.unwrap().data, vec![10, 11]);
        assert_eq!(bundle.beaver.unwrap().data, vec![40, 41, 42, 43]);
        assert!(bundle.prand_bit.is_none());
        assert!(bundle.prand_int.is_none());
        assert_eq!(bundle.remaining.random, 2);
        assert_eq!(bundle.remaining.beaver, 0);

        // The bytes served are gone from the source, not merely skipped: what
        // is left starts at the next item and the count matches it.
        let source_random = store.load(&source.random_share()).await.unwrap().unwrap();
        assert_eq!(source_random.meta.count, 2);
        assert_eq!(source_random.meta.consumed, 0);
        assert_eq!(source_random.data, vec![20, 21, 30, 31]);
        assert!(store.load(&source.beaver_triple()).await.unwrap().is_none());
        assert_eq!(
            store.scope_availability(&source).await.unwrap(),
            bundle.remaining
        );
    }

    #[tokio::test]
    async fn reservoir_bundle_is_all_or_nothing_when_any_kind_is_insufficient() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let identity = legacy_identity(4);
        let source = PreprocKeyScope::new([0x32; 32], MpcFieldKind::Bn254Fr, 5, 1, identity);
        store
            .seed_items(
                &source.random_share(),
                &PreprocBlob::new(vec![1, 2, 3], 1, 3),
            )
            .await
            .unwrap();
        store
            .seed_items(&source.beaver_triple(), &PreprocBlob::new(vec![9], 1, 1))
            .await
            .unwrap();

        let error = store
            .take_bundle_from_reservoir(
                &source,
                PoolAvailability {
                    beaver: 2,
                    random: 2,
                    prand_bit: 0,
                    prand_int: 0,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(
            error,
            PreprocStoreError::Insufficient {
                need: 2,
                available: 1
            }
        ));
        assert_eq!(
            store
                .load(&source.random_share())
                .await
                .unwrap()
                .unwrap()
                .data,
            vec![1, 2, 3]
        );
        assert_eq!(
            store
                .load(&source.beaver_triple())
                .await
                .unwrap()
                .unwrap()
                .data,
            vec![9]
        );
    }

    /// A kind nobody asked for is validated and left exactly as it was.
    ///
    /// Two subjects: a zero request yields `None` rather than an empty
    /// `TakenPreproc`, and the no-op-write guard in the write-back. That guard
    /// is load-bearing rather than an optimization — without it the `else` arm
    /// runs for an unrequested kind, and its `compacted_remaining` is `None`
    /// precisely because nothing was taken, so the write panics on its own
    /// `expect`.
    #[tokio::test]
    async fn reservoir_bundle_zero_counts_return_none_and_leave_sources_untouched() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let identity = legacy_identity(5);
        let source = PreprocKeyScope::new([0x33; 32], MpcFieldKind::Bn254Fr, 5, 1, identity);
        store
            .seed_items(
                &source.random_share(),
                &PreprocBlob::new(vec![1, 2, 3], 1, 3),
            )
            .await
            .unwrap();

        let bundle = store
            .take_bundle_from_reservoir(&source, PoolAvailability::default())
            .await
            .unwrap();
        assert!(bundle.random.is_none());
        assert!(bundle.beaver.is_none());
        assert!(bundle.prand_bit.is_none());
        assert!(bundle.prand_int.is_none());
        assert_eq!(bundle.remaining.random, 3);

        let remaining = store.load(&source.random_share()).await.unwrap().unwrap();
        assert_eq!(remaining.meta.count, 3);
        assert_eq!(remaining.meta.consumed, 0);
        assert_eq!(
            remaining.data,
            vec![1, 2, 3],
            "an unrequested kind must be left byte-identical, not rewritten"
        );
    }

    /// A record claiming its first items are spent is refused on every read.
    ///
    /// `consumed` is zero on everything this binary writes, because material is
    /// physically removed when it is drawn rather than marked. A nonzero cursor
    /// can therefore only arrive from a rolled-back image or a foreign writer —
    /// and if it were honoured it would shift *which* items the next draw
    /// serves, past items that are still on disk and may already have served an
    /// execution. The attack it closes is the narrow one that survived the
    /// volume header: `0 < consumed < count` was accepted and obeyed, where
    /// `consumed > count` was already rejected as incoherent.
    ///
    /// Asserted over every read, not only the draw, because the refusal is
    /// worth having on the next *append* too: a commit that accumulated onto
    /// such a record would hand its own fresh material a cursor it never wrote.
    #[tokio::test]
    async fn material_metadata_carrying_a_consumed_cursor_is_refused_on_every_read() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let scope = volume_test_scope();
        let key = scope.random_share();
        store
            .put_blob_unchecked(
                &key,
                &PreprocBlob {
                    meta: PreprocMeta {
                        count: 3,
                        consumed: 1,
                        item_size: 2,
                    },
                    data: vec![10, 11, 20, 21, 30, 31],
                },
            )
            .await
            .unwrap();

        let refused = |error: PreprocStoreError, path: &str| {
            assert!(
                matches!(
                    error,
                    PreprocStoreError::ConsumedCursorInVolume {
                        consumed: 1,
                        count: 3
                    }
                ),
                "{path} honoured a consumed cursor instead of refusing it: {error}"
            );
            let rendered = error.to_string();
            assert!(
                rendered.contains("may already have served an execution")
                    && rendered.contains("Delete the volume"),
                "the refusal must say why and what to do: {rendered}"
            );
        };

        refused(store.meta(&key).await.unwrap_err(), "meta");
        refused(store.available(&key).await.unwrap_err(), "available");
        refused(
            store.scope_availability(&scope).await.unwrap_err(),
            "scope_availability",
        );
        refused(store.load(&key).await.unwrap_err(), "load");
        refused(
            store.append_items(&key, 2, 1, &[40, 41]).await.unwrap_err(),
            "append_items",
        );
        refused(
            store
                .take_bundle_from_reservoir(
                    &scope,
                    PoolAvailability {
                        random: 1,
                        ..Default::default()
                    },
                )
                .await
                .unwrap_err(),
            "take_bundle_from_reservoir",
        );

        // A refused read is also a read that changed nothing: the record is
        // still there to be deleted by the operator the message addresses.
        let keys = store.volume_keys().await.unwrap();
        assert!(
            keys.iter().any(|stored| *stored == key.encode().unwrap())
                && keys.iter().any(|stored| *stored == key.meta_key().unwrap()),
            "refusing must not have removed the record it refused: {keys:?}"
        );
    }

    #[tokio::test]
    async fn reservoir_bundle_rejects_corrupt_sources_before_mutation() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();
        let identity = legacy_identity(6);
        let source = PreprocKeyScope::new([0x34; 32], MpcFieldKind::Bn254Fr, 5, 1, identity);
        store
            .seed_items(&source.random_share(), &PreprocBlob::new(vec![1, 2], 1, 2))
            .await
            .unwrap();

        // Bundle taking is the security boundary that validates exact physical
        // sizing before moving anything, so this source has to arrive already
        // corrupt: one byte declared as a single two-byte item. No production
        // write can produce it — `append_items` refuses it with `PartialItem`
        // — hence the test-only raw put.
        store
            .put_blob_unchecked(&source.beaver_triple(), &PreprocBlob::new(vec![9], 2, 1))
            .await
            .unwrap();
        let corrupt = store
            .take_bundle_from_reservoir(
                &source,
                PoolAvailability {
                    beaver: 1,
                    random: 1,
                    prand_bit: 0,
                    prand_int: 0,
                },
            )
            .await
            .unwrap_err();
        assert!(matches!(corrupt, PreprocStoreError::Deserialization(_)));
        assert_eq!(store.available(&source.random_share()).await.unwrap(), 2);
    }
    #[tokio::test]
    async fn lmdb_blob_namespace() {
        let dir = tempfile::tempdir().unwrap();
        let store = LmdbPreprocStore::open(dir.path()).unwrap();

        store
            .store_blob(BlobNamespace::StandingPreprocGeneration, b"key1", b"data1")
            .await
            .unwrap();
        let loaded = store
            .load_blob(BlobNamespace::StandingPreprocGeneration, b"key1")
            .await
            .unwrap();
        assert_eq!(loaded, Some(b"data1".to_vec()));

        assert_eq!(
            store
                .load_blob(BlobNamespace::StandingPreprocGeneration, b"missing")
                .await
                .unwrap(),
            None
        );
    }

    #[tokio::test]
    async fn lmdb_append_grows_map_and_retries_full_write() {
        let dir = tempfile::tempdir().unwrap();
        // 64 KiB is deliberately too small for the value below, but remains a
        // multiple of both common 4 KiB and 16 KiB host page sizes.
        let store = LmdbPreprocStore::open_with_map_size(dir.path(), 64 * 1024).unwrap();
        let key = PreprocKey::new(
            [0xA5; 32],
            MpcFieldKind::Bn254Fr,
            5,
            1,
            legacy_identity(0),
            MaterialKind::BeaverTriple,
        );
        let data = vec![0xA5; 512 * 1024];

        assert_eq!(
            store
                .append_items(&key, 1, data.len() as u32, &data)
                .await
                .unwrap(),
            data.len() as u32
        );

        let loaded = store.load(&key).await.unwrap().unwrap();
        assert_eq!(loaded.meta.count, data.len() as u32);
        assert_eq!(loaded.data, data);
    }

    #[test]
    fn lmdb_reopen_map_size_covers_existing_data_file() {
        let dir = tempfile::tempdir().unwrap();
        let file = std::fs::File::create(dir.path().join("data.mdb")).unwrap();
        file.set_len(512 * 1024).unwrap();

        assert_eq!(
            lmdb_initial_map_size(dir.path(), 64 * 1024).unwrap(),
            1024 * 1024
        );
    }
}
