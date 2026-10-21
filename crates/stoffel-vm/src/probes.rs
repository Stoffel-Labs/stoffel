//! Stable, unmangled symbols for external tracers (bpftrace uprobes).
//!
//! They live here rather than beside their callers so that the crates calling
//! them (the SDK's `stoffel run-node` driver) can keep `#![forbid(unsafe_code)]`:
//! `#[no_mangle]` is an unsafe attribute.

/// No-op uprobe target used by the eBPF input-path profilers
/// (`scripts/stoffel-input-path.bt`, `scripts/stoffel-coordinator-input.bt`).
///
/// Exporting one stable C symbol avoids relying on unstable Rust async symbol
/// names. With no tracer attached, this is only one non-inlined function call
/// at each coarse phase boundary and does not perform timing or logging.
#[no_mangle]
#[inline(never)]
pub extern "C" fn stoffel_input_path_probe(phase: u64, clients: u64, inputs: u64) {
    std::hint::black_box((phase, clients, inputs));
}
