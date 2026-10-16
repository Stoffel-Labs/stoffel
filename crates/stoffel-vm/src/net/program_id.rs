//! The program content address.
//!
//! A node reaches its program through its own filesystem: a path on the command
//! line in one-shot mode, or the program catalog a standing node is given.
//! Nothing transfers program bytes over the network, so this module is the
//! whole of what used to be `net/program_sync.rs`: the content address itself,
//! which the mesh commits to ([`crate::net::mesh::SessionCommitment`]) so that
//! `n` parties which loaded different bytes for one execution are named and
//! refused.
//!
//! `docs/design/bootnode-elimination.md` §2 and §8 record the message enum, the
//! chunked transfer and the `~/.stoffel/programs` cache this replaced, and why
//! none of it ever moved a byte.

use blake3::Hasher;

/// BLAKE3 domain separator for [`program_id_from_bytes`].
///
/// Distinct from the roster digest (`stoffel-coordinator-node-roster-v1`), the
/// mesh commitment (`stoffel-mesh-commit-v1`) and the per-execution instance id
/// (`stoffel-execution-instance-v1`).
pub const PROGRAM_ID_CONTEXT: &[u8] = b"stoffel-program-v1";

/// The content address of a compiled program.
pub fn program_id_from_bytes(bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Hasher::new();
    hasher.update(PROGRAM_ID_CONTEXT);
    hasher.update(bytes);
    *hasher.finalize().as_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_program_id_is_stable_and_content_addressed() {
        assert_eq!(
            program_id_from_bytes(b"compiled program"),
            program_id_from_bytes(b"compiled program")
        );
        assert_ne!(
            program_id_from_bytes(b"compiled program"),
            program_id_from_bytes(b"another program")
        );
    }

    /// The content address the coordinator computes for the same bytes.
    ///
    /// The two implementations are one line each and in different repositories,
    /// so nothing but a shared vector keeps them equal: a node whose program id
    /// disagrees with the coordinator's `program_hash` refuses every execution
    /// of a program it does in fact hold. The coordinator asserts the same
    /// value over the same input in `program_hash_of_matches_the_shared_golden_vector`
    /// (`coord-shared/src/admission.rs`), §9.C.1 of
    /// `docs/design/bootnode-elimination.md`.
    #[test]
    fn the_program_id_matches_the_shared_golden_vector() {
        assert_eq!(
            hex::encode(program_id_from_bytes(b"stoffel golden program")),
            "fe9f7bf29eff22b4631f8468a32aff7761e78aba67a0ba19724779f0768179ee"
        );
    }

    /// The id is not the hash of the bytes. Anything that validates a program
    /// by hashing it directly computes a different value and rejects every
    /// honest artifact, which is what the separator is here to make loud.
    #[test]
    fn a_program_id_is_domain_separated_from_a_bare_hash() {
        assert_ne!(
            program_id_from_bytes(b"compiled program"),
            *blake3::hash(b"compiled program").as_bytes()
        );
    }
}
