pub mod avss_certificate_programs;
#[cfg(feature = "avss_itest")]
pub mod avss_e2e_integration;
pub mod avss_integration;
pub mod avss_keygen_program;
#[cfg(feature = "hb_itest")]
pub mod dkg_primitives;
pub mod ed25519_compat;
/// Five-party HoneyBadger mesh end to end.
///
/// Was `leader_bootnode_integration`, whose header claimed a bootnode handshake
/// its body never performed (design doc §5). Stage 8 renamed it to what it is.
#[cfg(feature = "hb_itest")]
pub mod mesh_hb_integration;
/// Characterization harness for the roster-pinned mesh join.
///
/// Gated behind `hb_itest` (an existing integration-test feature) so it is off
/// by default, and run explicitly by the `mesh-join-harness` CI job.
#[cfg(feature = "hb_itest")]
pub mod mesh_join_harness;
#[cfg(feature = "hb_itest")]
pub mod mpc_multiplication_integration;
pub mod p2p_integration;
pub mod test_utils;
#[cfg(feature = "avss_itest")]
pub mod threshold_signatures;
#[cfg(feature = "hb_itest")]
pub mod vm_mesh_integration;
#[cfg(feature = "hb_itest")]
pub mod vm_mpc_integration;
#[cfg(all(feature = "hb_itest", feature = "avss_itest"))]
pub mod vm_turmoil_e2e;
