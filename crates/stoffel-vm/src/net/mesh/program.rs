//! Content-addressed program transfer between peers.
//!
//! Stage 5 of `docs/design/bootnode-elimination.md` (§2, row "Program byte
//! custody"). The bootnode's custody path is deleted rather than moved: it is
//! dead code today, because it validates an upload with bare `blake3::hash`
//! against a *domain-separated* id, so every honest upload is silently dropped
//! (`discovery/bootnode.rs::program_id_matches_bytes` versus
//! `program_sync::program_id_from_bytes`). This module is the replacement for
//! the capability, not for the implementation, and it differs in three ways
//! that matter.
//!
//! **It is content-addressed, and the check is the real one.** Every assembled
//! program goes through `crate::net::program_sync::verify_program_id`, the
//! same domain-separated construction the runner uses to name the program in
//! the first place. A peer — honest, buggy or hostile — cannot substitute a
//! program, so nothing here has to trust the peer it pulled from. That is why
//! the design doc's trust boundary (§3) does not list program bytes among the
//! things a coordinator is trusted for.
//!
//! **It is chunked.** The bootnode moved a program as one `Vec<u8>` inside a
//! single control frame, which is why `--no-program-upload` exists: a large
//! program made the discovery message large. [`PROGRAM_CHUNK_BYTES`] keeps each
//! frame comfortably inside [`crate::net::mesh::MAX_MESH_MESSAGE_LEN`], so the
//! transfer is bounded per frame rather than per program.
//!
//! **It is optional.** Party mode hard-exits without a local program today
//! (`stoffel-run.rs`), and every shipped stack mounts the program into the
//! image, so nothing in production pulls. The pull exists so that a node which
//! has a *content address* but not the bytes has a way to get them that does
//! not involve a trusted party — the case the bootnode's path was supposed to
//! serve and never did.
//!
//! # Ordering
//!
//! [`pull_program`] asks for one chunk and reads one chunk, in lock-step, on a
//! connection it is the sole reader of. That is the same discipline
//! [`crate::net::mesh::join_mesh`] runs its handshake under and for the same
//! reason: a timed-out `receive()` leaves a framed stream positioned mid-frame,
//! so the only safe timeout is one that ends the whole exchange. A pull that
//! times out is therefore fatal to the pull, and the caller reopens or gives up
//! rather than reading the stream again.

use std::time::Duration;

use stoffelnet::transports::quic::PeerConnection;

use crate::net::mesh::wire::{self, MeshMessage};
use crate::net::mesh::{MeshError, MeshResult};
use crate::net::program_sync::verify_program_id;

/// Payload bytes carried by one [`MeshMessage::ProgramChunk`].
///
/// 256 KiB leaves three quarters of [`MAX_MESH_MESSAGE_LEN`](crate::net::mesh::MAX_MESH_MESSAGE_LEN) for the bincode
/// envelope and for any future field, so a chunk can never be the thing that
/// makes a frame unencodable.
pub const PROGRAM_CHUNK_BYTES: usize = 256 * 1024;

/// Largest program this transfer will assemble.
///
/// Bounds what a peer can make this node allocate: without it, a hostile
/// `chunk_count` would size a `Vec` from a number the peer chose. 256 MiB is
/// three orders of magnitude above the largest program in the tree.
pub const MAX_PROGRAM_BYTES: usize = 256 * 1024 * 1024;

/// How long one request/response exchange may take.
pub const DEFAULT_CHUNK_TIMEOUT: Duration = Duration::from_secs(30);

/// Number of chunks a program of `len` bytes is split into.
///
/// A zero-length program is one empty chunk rather than none, so that "the
/// transfer is complete" is always a statement about a chunk having arrived.
pub fn chunk_count(len: usize) -> u64 {
    if len == 0 {
        return 1;
    }
    len.div_ceil(PROGRAM_CHUNK_BYTES) as u64
}

/// A program this node holds and can serve to peers.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramSource {
    program_id: [u8; 32],
    bytes: Vec<u8>,
}

impl ProgramSource {
    /// Take custody of `bytes` under the content address they actually hash to.
    ///
    /// Takes the id as a parameter and checks it rather than deriving it, so a
    /// caller that holds a program under a *stated* id — the runner, which is
    /// given `--program` and an id from the session — finds out here if the two
    /// disagree, instead of serving a program nobody asked for.
    pub fn new(program_id: [u8; 32], bytes: Vec<u8>) -> MeshResult<Self> {
        verify_program_id(&program_id, &bytes).map_err(|error| MeshError::ProgramMismatch {
            reason: error.to_string(),
        })?;
        Ok(Self { program_id, bytes })
    }

    pub fn program_id(&self) -> [u8; 32] {
        self.program_id
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn chunk_count(&self) -> u64 {
        chunk_count(self.bytes.len())
    }

    /// The frame answering one [`MeshMessage::ProgramRequest`].
    ///
    /// `None` when the request names another program or a chunk past the end:
    /// both are questions this source cannot answer, and neither is worth an
    /// error frame that a peer could use to make this node talk.
    pub fn chunk(&self, program_id: &[u8; 32], chunk_index: u64) -> Option<MeshMessage> {
        if *program_id != self.program_id || chunk_index >= self.chunk_count() {
            return None;
        }
        let start = (chunk_index as usize) * PROGRAM_CHUNK_BYTES;
        let end = (start + PROGRAM_CHUNK_BYTES).min(self.bytes.len());
        Some(MeshMessage::ProgramChunk {
            program_id: self.program_id,
            chunk_index,
            chunk_count: self.chunk_count(),
            bytes: self.bytes[start..end].to_vec(),
        })
    }
}

/// Accumulates chunks of one program and verifies the result.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProgramAssembler {
    program_id: [u8; 32],
    chunk_count: Option<u64>,
    next_index: u64,
    bytes: Vec<u8>,
}

impl ProgramAssembler {
    pub fn new(program_id: [u8; 32]) -> Self {
        Self {
            program_id,
            chunk_count: None,
            next_index: 0,
            bytes: Vec::new(),
        }
    }

    /// The chunk this assembler wants next.
    pub fn next_index(&self) -> u64 {
        self.next_index
    }

    /// Whether every chunk has arrived.
    pub fn is_complete(&self) -> bool {
        self.chunk_count == Some(self.next_index)
    }

    /// Fold one [`MeshMessage::ProgramChunk`] in.
    ///
    /// Strictly in order, and strictly for this program. Out-of-order or
    /// foreign chunks are refused rather than buffered: the pull is lock-step,
    /// so a chunk arriving out of order means the stream is not carrying what
    /// this reader thinks it is.
    pub fn absorb(&mut self, message: MeshMessage) -> MeshResult<()> {
        let MeshMessage::ProgramChunk {
            program_id,
            chunk_index,
            chunk_count,
            bytes,
        } = message
        else {
            return Err(MeshError::ProgramTransferFailed {
                reason: "expected a program chunk".to_string(),
            });
        };

        if program_id != self.program_id {
            return Err(MeshError::ProgramTransferFailed {
                reason: format!(
                    "chunk names program {} but this transfer is for {}",
                    hex::encode(&program_id[..8]),
                    hex::encode(&self.program_id[..8])
                ),
            });
        }
        if chunk_index != self.next_index {
            return Err(MeshError::ProgramTransferFailed {
                reason: format!(
                    "chunk {chunk_index} arrived where chunk {} was expected",
                    self.next_index
                ),
            });
        }
        match self.chunk_count {
            None => {
                if chunk_count == 0 {
                    return Err(MeshError::ProgramTransferFailed {
                        reason: "a program is at least one chunk".to_string(),
                    });
                }
                // The peer chooses `chunk_count`, so the allocation it implies
                // is bounded before a single byte is reserved.
                let announced = (chunk_count as usize).saturating_mul(PROGRAM_CHUNK_BYTES);
                if announced > MAX_PROGRAM_BYTES {
                    return Err(MeshError::ProgramTransferFailed {
                        reason: format!(
                            "peer announced {chunk_count} chunks ({announced} bytes), over the \
                             {MAX_PROGRAM_BYTES}-byte cap"
                        ),
                    });
                }
                self.chunk_count = Some(chunk_count);
            }
            Some(known) if known != chunk_count => {
                return Err(MeshError::ProgramTransferFailed {
                    reason: format!("peer changed the chunk count from {known} to {chunk_count}"),
                });
            }
            Some(_) => {}
        }
        if bytes.len() > PROGRAM_CHUNK_BYTES {
            return Err(MeshError::ProgramTransferFailed {
                reason: format!(
                    "chunk {chunk_index} is {} bytes, over the {PROGRAM_CHUNK_BYTES}-byte chunk \
                     size",
                    bytes.len()
                ),
            });
        }
        if self.bytes.len().saturating_add(bytes.len()) > MAX_PROGRAM_BYTES {
            return Err(MeshError::ProgramTransferFailed {
                reason: format!("transfer exceeded the {MAX_PROGRAM_BYTES}-byte cap"),
            });
        }

        self.bytes.extend_from_slice(&bytes);
        self.next_index += 1;
        Ok(())
    }

    /// The assembled program, once every chunk has arrived and the bytes hash
    /// to the address they were requested under.
    ///
    /// This is the only thing that makes the transfer trustworthy, so it is not
    /// optional and not a separate step a caller can forget: there is no other
    /// way to get the bytes out.
    pub fn finish(self) -> MeshResult<Vec<u8>> {
        if !self.is_complete() {
            return Err(MeshError::ProgramTransferFailed {
                reason: format!(
                    "transfer ended after {} of {} chunks",
                    self.next_index,
                    self.chunk_count
                        .map(|count| count.to_string())
                        .unwrap_or_else(|| "an unknown number of".to_string())
                ),
            });
        }
        verify_program_id(&self.program_id, &self.bytes).map_err(|error| {
            MeshError::ProgramMismatch {
                reason: error.to_string(),
            }
        })?;
        Ok(self.bytes)
    }
}

/// Pull a whole program from one peer, chunk by chunk.
///
/// The caller must be the sole reader of `conn` for the duration: each read is
/// bounded by `chunk_timeout`, and a timeout ends the transfer rather than
/// retrying, because a cancelled `receive()` can leave the framed stream
/// positioned mid-frame.
pub async fn pull_program(
    conn: &dyn PeerConnection,
    program_id: [u8; 32],
    chunk_timeout: Duration,
) -> MeshResult<Vec<u8>> {
    let mut assembler = ProgramAssembler::new(program_id);

    loop {
        let request = wire::encode(&MeshMessage::ProgramRequest {
            program_id,
            chunk_index: assembler.next_index(),
        })?;
        conn.send(&request)
            .await
            .map_err(|reason| MeshError::ProgramTransferFailed {
                reason: format!("requesting chunk {}: {reason}", assembler.next_index()),
            })?;

        let payload = tokio::time::timeout(chunk_timeout, conn.receive())
            .await
            .map_err(|_| MeshError::ProgramTransferFailed {
                reason: format!(
                    "timed out after {chunk_timeout:?} waiting for chunk {}",
                    assembler.next_index()
                ),
            })?
            .map_err(|reason| MeshError::ProgramTransferFailed {
                reason: format!("reading chunk {}: {reason}", assembler.next_index()),
            })?;

        let message =
            wire::try_decode(&payload)?.ok_or_else(|| MeshError::ProgramTransferFailed {
                reason: "peer answered a program request with a frame that is not mesh control \
                         traffic"
                    .to_string(),
            })?;
        assembler.absorb(message)?;

        if assembler.is_complete() {
            return assembler.finish();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mesh::wire::MAX_MESH_MESSAGE_LEN;
    use crate::net::program_sync::program_id_from_bytes;

    fn program(len: usize) -> Vec<u8> {
        (0..len).map(|index| (index % 251) as u8).collect()
    }

    fn source(bytes: Vec<u8>) -> ProgramSource {
        ProgramSource::new(program_id_from_bytes(&bytes), bytes).expect("build a program source")
    }

    /// The transfer must survive being reassembled by a peer that only ever
    /// sees chunks, which is the point of chunking at all.
    #[test]
    fn a_multi_chunk_program_round_trips_through_the_assembler() {
        let bytes = program(PROGRAM_CHUNK_BYTES * 2 + 17);
        let source = source(bytes.clone());
        assert_eq!(source.chunk_count(), 3);

        let mut assembler = ProgramAssembler::new(source.program_id());
        while !assembler.is_complete() {
            let chunk = source
                .chunk(&source.program_id(), assembler.next_index())
                .expect("the source holds the requested chunk");
            assembler.absorb(chunk).expect("absorb chunk");
        }

        assert_eq!(assembler.finish().expect("verified program"), bytes);
    }

    #[test]
    fn an_empty_program_is_one_empty_chunk() {
        let source = source(Vec::new());
        assert_eq!(source.chunk_count(), 1);

        let mut assembler = ProgramAssembler::new(source.program_id());
        let chunk = source
            .chunk(&source.program_id(), 0)
            .expect("the empty chunk");
        assembler.absorb(chunk).expect("absorb");
        assert!(assembler.is_complete());
        assert!(assembler.finish().expect("verified").is_empty());
    }

    /// The reason a peer does not have to be trusted: a substituted program
    /// fails its content address, and there is no way to get the bytes out
    /// without that check running.
    #[test]
    fn a_substituted_program_fails_its_content_address() {
        let honest = program(64);
        let program_id = program_id_from_bytes(&honest);
        let attacker = source(program(64).into_iter().map(|byte| byte ^ 0xff).collect());

        let mut assembler = ProgramAssembler::new(program_id);
        // The attacker answers with its own bytes but the requested id.
        let MeshMessage::ProgramChunk {
            chunk_index,
            chunk_count,
            bytes,
            ..
        } = attacker
            .chunk(&attacker.program_id(), 0)
            .expect("attacker chunk")
        else {
            panic!("a program source produces program chunks");
        };
        assembler
            .absorb(MeshMessage::ProgramChunk {
                program_id,
                chunk_index,
                chunk_count,
                bytes,
            })
            .expect("the substitution is only detectable at the end");

        assert!(assembler.is_complete());
        assert!(matches!(
            assembler.finish(),
            Err(MeshError::ProgramMismatch { .. })
        ));
    }

    /// A stated id that does not match the bytes is caught at custody, not when
    /// a peer asks.
    #[test]
    fn a_source_refuses_bytes_that_do_not_hash_to_the_stated_id() {
        assert!(matches!(
            ProgramSource::new([0u8; 32], program(32)),
            Err(MeshError::ProgramMismatch { .. })
        ));
    }

    #[test]
    fn a_source_answers_nothing_for_another_program_or_a_chunk_past_the_end() {
        let source = source(program(16));
        assert!(source.chunk(&[1u8; 32], 0).is_none());
        assert!(source.chunk(&source.program_id(), 1).is_none());
    }

    #[test]
    fn chunks_must_arrive_in_order_and_name_this_program() {
        let bytes = program(PROGRAM_CHUNK_BYTES + 1);
        let source = source(bytes);
        let mut assembler = ProgramAssembler::new(source.program_id());

        let second = source
            .chunk(&source.program_id(), 1)
            .expect("the second chunk");
        assert!(matches!(
            assembler.absorb(second),
            Err(MeshError::ProgramTransferFailed { .. })
        ));

        let foreign = MeshMessage::ProgramChunk {
            program_id: [3u8; 32],
            chunk_index: 0,
            chunk_count: 1,
            bytes: vec![1, 2, 3],
        };
        assert!(matches!(
            assembler.absorb(foreign),
            Err(MeshError::ProgramTransferFailed { .. })
        ));
    }

    /// `chunk_count` is chosen by the peer, so it must not be able to size an
    /// allocation on this node.
    #[test]
    fn an_announced_chunk_count_over_the_cap_is_refused_before_anything_is_reserved() {
        let mut assembler = ProgramAssembler::new([4u8; 32]);
        let error = assembler
            .absorb(MeshMessage::ProgramChunk {
                program_id: [4u8; 32],
                chunk_index: 0,
                chunk_count: u64::MAX,
                bytes: vec![0u8; 8],
            })
            .expect_err("an unbounded chunk count");
        assert!(matches!(error, MeshError::ProgramTransferFailed { .. }));
    }

    #[test]
    fn an_incomplete_transfer_cannot_produce_a_program() {
        let bytes = program(PROGRAM_CHUNK_BYTES + 1);
        let source = source(bytes);
        let mut assembler = ProgramAssembler::new(source.program_id());
        assembler
            .absorb(
                source
                    .chunk(&source.program_id(), 0)
                    .expect("the first chunk"),
            )
            .expect("absorb");

        assert!(!assembler.is_complete());
        assert!(matches!(
            assembler.finish(),
            Err(MeshError::ProgramTransferFailed { .. })
        ));
    }

    /// A chunk has to fit in a mesh control frame, or the transfer could not be
    /// sent at all.
    #[test]
    fn a_full_chunk_encodes_inside_the_control_frame_bound() {
        let source = source(program(PROGRAM_CHUNK_BYTES));
        let chunk = source
            .chunk(&source.program_id(), 0)
            .expect("the only chunk");
        let framed = wire::encode(&chunk).expect("a full chunk must be encodable");
        assert!(framed.len() < MAX_MESH_MESSAGE_LEN);
    }
}
