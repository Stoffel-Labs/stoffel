use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::net::mpc_engine::{
    MpcCapabilities, MpcEngine, MpcEngineMultiplication, MpcEngineResult, MpcSessionTopology,
    ShareAlgebraResult,
};
use stoffel_vm_types::core_types::{
    ClearShareInput, ClearShareValue, ShareData, ShareType, TableRef, Value,
};

#[derive(Default)]
struct CountingEngine {
    scalar_mul_calls: AtomicUsize,
    batch_mul_calls: AtomicUsize,
    batch_mul_items: AtomicUsize,
}

impl CountingEngine {
    fn counts(&self) -> (usize, usize, usize) {
        (
            self.scalar_mul_calls.load(Ordering::SeqCst),
            self.batch_mul_calls.load(Ordering::SeqCst),
            self.batch_mul_items.load(Ordering::SeqCst),
        )
    }

    fn bool_byte(bytes: &[u8]) -> u8 {
        bytes.first().copied().unwrap_or_default() & 1
    }

    fn share_from_clear(clear: ClearShareInput) -> ShareData {
        let byte = match clear.value() {
            ClearShareValue::Integer(value) => (value & 1) as u8,
            ClearShareValue::UnsignedInteger(value) => (value & 1) as u8,
            ClearShareValue::FixedPoint(value) => ((value.0 as i64) & 1) as u8,
            ClearShareValue::Boolean(value) => u8::from(value),
        };
        ShareData::Opaque(vec![byte].into())
    }

    fn open_bool(share_bytes: &[u8]) -> ClearShareValue {
        ClearShareValue::Boolean(Self::bool_byte(share_bytes) != 0)
    }
}

impl MpcEngine for CountingEngine {
    fn protocol_name(&self) -> &'static str {
        "counting"
    }

    fn topology(&self) -> MpcSessionTopology {
        MpcSessionTopology::try_new(1, 0, 1, 0).expect("valid counting topology")
    }

    fn is_ready(&self) -> bool {
        true
    }

    fn start(&self) -> MpcEngineResult<()> {
        Ok(())
    }

    fn input_share(&self, clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Ok(Self::share_from_clear(clear))
    }

    fn open_share(&self, _ty: ShareType, share_bytes: &[u8]) -> MpcEngineResult<ClearShareValue> {
        Ok(Self::open_bool(share_bytes))
    }

    fn capabilities(&self) -> MpcCapabilities {
        MpcCapabilities::MULTIPLICATION
    }

    fn as_multiplication(&self) -> Option<&dyn MpcEngineMultiplication> {
        Some(self)
    }

    fn add_share_local(
        &self,
        _ty: ShareType,
        lhs_bytes: &[u8],
        rhs_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        Ok(vec![
            Self::bool_byte(lhs_bytes) ^ Self::bool_byte(rhs_bytes),
        ])
    }

    fn sub_share_local(
        &self,
        _ty: ShareType,
        lhs_bytes: &[u8],
        rhs_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        Ok(vec![
            Self::bool_byte(lhs_bytes) ^ Self::bool_byte(rhs_bytes),
        ])
    }

    fn mul_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        Ok(vec![Self::bool_byte(share_bytes) & ((scalar & 1) as u8)])
    }

    fn add_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        Ok(vec![Self::bool_byte(share_bytes) ^ ((scalar & 1) as u8)])
    }

    fn sub_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        Ok(vec![Self::bool_byte(share_bytes) ^ ((scalar & 1) as u8)])
    }

    fn scalar_sub_share_local(
        &self,
        _ty: ShareType,
        scalar: i64,
        share_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        Ok(vec![((scalar & 1) as u8) ^ Self::bool_byte(share_bytes)])
    }

    fn div_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        assert_ne!(scalar & 1, 0, "division by zero in GF(2)");
        Ok(vec![Self::bool_byte(share_bytes)])
    }
}

impl MpcEngineMultiplication for CountingEngine {
    fn multiply_share(
        &self,
        _ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        self.scalar_mul_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ShareData::Opaque(
            vec![CountingEngine::bool_byte(left) & CountingEngine::bool_byte(right)].into(),
        ))
    }
}

#[async_trait::async_trait]
impl stoffel_vm::net::mpc_engine::AsyncMpcEngine for CountingEngine {
    async fn input_share_async(&self, clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Ok(Self::share_from_clear(clear))
    }

    async fn multiply_share_async(
        &self,
        _ty: ShareType,
        left: &[u8],
        right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        self.scalar_mul_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ShareData::Opaque(
            vec![CountingEngine::bool_byte(left) & CountingEngine::bool_byte(right)].into(),
        ))
    }

    async fn batch_multiply_share_async(
        &self,
        _ty: ShareType,
        pairs: &[(Vec<u8>, Vec<u8>)],
    ) -> MpcEngineResult<Vec<ShareData>> {
        self.batch_mul_calls.fetch_add(1, Ordering::SeqCst);
        self.batch_mul_items
            .fetch_add(pairs.len(), Ordering::SeqCst);
        Ok(pairs
            .iter()
            .map(|(left, right)| {
                ShareData::Opaque(
                    vec![CountingEngine::bool_byte(left) & CountingEngine::bool_byte(right)].into(),
                )
            })
            .collect())
    }

    async fn open_share_async(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        Ok(Self::open_bool(share_bytes))
    }

    async fn batch_open_shares_async(
        &self,
        _ty: ShareType,
        shares: &[Vec<u8>],
    ) -> MpcEngineResult<Vec<ClearShareValue>> {
        Ok(shares.iter().map(|share| Self::open_bool(share)).collect())
    }

    async fn random_share_async(&self, _ty: ShareType) -> MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(vec![0].into()))
    }

    async fn random_integer_share_async(&self, _ty: ShareType) -> MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(vec![0].into()))
    }
}

/// Compiling and executing the optimized AES circuit recurses deeply (the
/// inlined S-box network and the VM interpreter), which overflows the default
/// ~2 MB cargo/tokio test-thread stack on some platforms. Run the work on a
/// dedicated large-stack thread with its own runtime.
fn run_on_large_stack<F>(future: F)
where
    F: std::future::Future<Output = ()> + Send + 'static,
{
    std::thread::Builder::new()
        .stack_size(256 * 1024 * 1024)
        .spawn(move || {
            tokio::runtime::Builder::new_multi_thread()
                .worker_threads(2)
                .thread_stack_size(256 * 1024 * 1024)
                .enable_all()
                .build()
                .expect("build tokio runtime")
                .block_on(future);
        })
        .expect("spawn large-stack test thread")
        .join()
        .expect("large-stack test thread panicked");
}

/// Regression test for the -O3 function inliner: a `secret`-typed helper that is
/// inlined must keep its arguments secret, so the secret `and`/multiply still runs
/// as an MPC multiplication (counted in `batch`/`scalar`) rather than collapsing
/// to a clear bitwise op. We compile the same secret program at -O0 and -O3 and
/// require (a) the revealed result is identical and (b) -O3 still performs a real
/// secret multiplication (a non-zero multiply count) — i.e. secrecy survived
/// inlining. If inlining dropped the secret flag, the `and` would compile to a
/// clear op and the multiply count would drop to zero.
#[test]
fn inlining_preserves_secret_multiplication() {
    run_on_large_stack(inlining_preserves_secret_multiplication_impl());
}

async fn inlining_preserves_secret_multiplication_impl() {
    // `gate_and` is a secret-bool helper (an MPC multiply in GF(2)); `combine`
    // chains two of them so inlining has something to fold. `x=1, y=1, z=1` so
    // `gate_and(gate_and(x,y), z) = 1`.
    let source = r#"
def gate_and(a: secret bool, b: secret bool) -> secret bool:
  return a and b

def combine(a: secret bool, b: secret bool, c: secret bool) -> secret bool:
  return gate_and(gate_and(a, b), c)

def main() -> int64:
  var x: secret bool = Share.from_clear_int(1, 1)
  var y: secret bool = Share.from_clear_int(1, 1)
  var z: secret bool = Share.from_clear_int(1, 1)
  var w: secret bool = combine(x, y, z)
  var r: bool = w.reveal()
  if r:
    return 1
  return 0
"#;

    let run_at = |level: u8| async move {
        let options = stoffellang::CompilerOptions {
            optimize: true,
            optimization_level: level,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            ..Default::default()
        };
        let compiled = stoffellang::compile(source, "<inline-secrecy>", &options)
            .unwrap_or_else(|e| panic!("compile at -O{level}: {e:?}"));
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("vm functions");
        let engine = Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        for function in functions {
            vm.try_register_function(function)
                .expect("register function");
        }
        let result = vm
            .execute_async("main", engine.as_ref())
            .await
            .unwrap_or_else(|e| panic!("execute at -O{level}: {e:?}"));
        let (scalar, _batch_calls, batch_items) = engine.counts();
        (result, scalar + batch_items)
    };

    let (base_result, base_muls) = run_at(0).await;
    let (opt_result, opt_muls) = run_at(3).await;

    assert_eq!(
        base_result, opt_result,
        "-O3 inlining changed the revealed secret result"
    );
    assert!(
        base_muls > 0,
        "baseline should perform secret multiplications (test would be vacuous otherwise)"
    );
    assert!(
        opt_muls > 0,
        "-O3 inlined `gate_and` lost its secret typing: the secret `and` compiled \
         to a clear op (zero MPC multiplications), which is the secrecy bug"
    );
}

#[test]
#[ignore = "counts optimized AES MPC multiplication demand"]
fn count_optimized_aes_batch_mul_items() {
    run_on_large_stack(count_optimized_aes_batch_mul_items_impl());
}

async fn count_optimized_aes_batch_mul_items_impl() {
    let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let options = stoffellang::CompilerOptions {
        optimize: true,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<aes-count>", &options).expect("compile AES");
    let binary = stoffellang::convert_to_binary(&compiled);
    let functions = binary.try_to_vm_functions().expect("vm functions");

    let engine = Arc::new(CountingEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    for function in functions {
        vm.try_register_function(function)
            .expect("register function");
    }

    let _ = vm
        .execute_async("main", engine.as_ref())
        .await
        .expect("execute AES with counting engine");
    let (scalar, batch_calls, batch_items) = engine.counts();
    // The optimizer must convert EVERY secret multiplication into a batched one
    // (no leftover scalar `multiply_share` calls) and preserve the exact total
    // number of products — these are the real correctness invariants.
    assert_eq!(
        scalar, 0,
        "optimizer should batch every secret multiply; {scalar} ran as scalar"
    );
    assert_eq!(batch_items, 34_080);
    // This test compiles at the default optimization level (no -O3), so the
    // per-byte S-box loops are not unrolled and the round-minimizing scheduler
    // does not run. At this level the optimizer batches independent multiplies
    // only WITHIN each byte's S-box, yielding many smaller batches (~6.3k). At
    // -O3 (see `optimized_aes_at_o3_matches_nist_vector`) length-aware unrolling
    // plus the list scheduler batch across the formerly-separate iterations and
    // cut this to a few thousand rounds. The meaningful guarantee here is just
    // that batching still collapses the ~34k multiplies into far fewer calls.
    assert!(
        batch_calls < batch_items / 4,
        "multiplies should be meaningfully batched, not near one-call-each; \
         got {batch_calls} calls for {batch_items} items"
    );
}

#[test]
fn optimized_aes_matches_nist_vector_with_compiler_spills() {
    run_on_large_stack(optimized_aes_matches_nist_vector_with_compiler_spills_impl());
}

async fn optimized_aes_matches_nist_vector_with_compiler_spills_impl() {
    let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let options = stoffellang::CompilerOptions {
        optimize: true,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<aes-exec>", &options).expect("compile AES");
    let binary = stoffellang::convert_to_binary(&compiled);
    let functions = binary.try_to_vm_functions().expect("vm functions");

    let engine = Arc::new(CountingEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    for function in functions {
        vm.try_register_function(function)
            .expect("register function");
    }

    let result = vm
        .execute_async("main", engine.as_ref())
        .await
        .expect("execute AES with boolean engine");
    let Value::Array(result_ref) = result else {
        panic!("AES main should return an array");
    };

    let mut ciphertext = Vec::new();
    for index in 0..vm.read_array_len(result_ref).expect("ciphertext length") {
        let value = vm
            .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
            .expect("read ciphertext byte")
            .expect("ciphertext byte");
        let Value::I64(byte) = value else {
            panic!("ciphertext byte should be an int64, got {value:?}");
        };
        ciphertext.push(byte);
    }

    assert_eq!(
        ciphertext,
        vec![105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90]
    );
}

/// Regression test for the ABI-result-register spill bug: at -O3, function
/// inlining turns `aes128_encrypt` into a large zero-parameter function full of
/// `CALL; MOV(dest, 0)` result captures. Register 0 (the ABI result register) has
/// no virtual-register def, so before the fix the allocator spilled it and emitted
/// `LDS` loads with no `STS` — reading an uninitialized `Unit` and failing in a
/// clear/secret conversion (`UnsupportedClearShareValue { value: () }`). Pinning
/// VR0 to physical R0 keeps the result register live and unspilled. This runs the
/// full AES circuit at -O3 (heavy inlining + spilling) and requires the NIST
/// SP 800-38A vector, proving the -O3 pipeline is now both crash-free and correct.
#[test]
fn optimized_aes_at_o3_matches_nist_vector() {
    run_on_large_stack(optimized_aes_at_o3_matches_nist_vector_impl());
}

async fn optimized_aes_at_o3_matches_nist_vector_impl() {
    let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
    let options = stoffellang::CompilerOptions {
        optimize: true,
        optimization_level: 3,
        mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
        ..Default::default()
    };
    let compiled = stoffellang::compile(source, "<aes-o3>", &options).expect("compile AES at -O3");
    let binary = stoffellang::convert_to_binary(&compiled);
    let functions = binary.try_to_vm_functions().expect("vm functions");

    let engine = Arc::new(CountingEngine::default());
    let mut vm = VirtualMachine::builder()
        .with_mpc_engine(engine.clone())
        .build();
    for function in functions {
        vm.try_register_function(function)
            .expect("register function");
    }

    let result = vm
        .execute_async("main", engine.as_ref())
        .await
        .expect("execute AES at -O3");
    let Value::Array(result_ref) = result else {
        panic!("AES main should return an array");
    };

    let mut ciphertext = Vec::new();
    for index in 0..vm.read_array_len(result_ref).expect("ciphertext length") {
        let value = vm
            .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
            .expect("read ciphertext byte")
            .expect("ciphertext byte");
        let Value::I64(byte) = value else {
            panic!("ciphertext byte should be an int64, got {value:?}");
        };
        ciphertext.push(byte);
    }

    assert_eq!(
        ciphertext,
        vec![105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90]
    );

    // The -O3 pipeline (length-aware unrolling + the round-minimizing list
    // scheduler) collapses the ~34k secret multiplies into far fewer
    // communication rounds than the unscheduled build (which needed ~25.7k
    // batch calls). Lock in the round reduction without over-fitting the exact
    // number: it must be well under the -O0 baseline (~6.3k) and the total work
    // and scalar-free invariants must hold.
    let (scalar, batch_calls, batch_items) = engine.counts();
    assert_eq!(scalar, 0, "every secret multiply must be batched at -O3");
    assert_eq!(batch_items, 34_080, "total products preserved");
    assert!(
        batch_calls < 5_000,
        "scheduler should cut multiply rounds far below the ~25.7k unscheduled \
         and ~6.3k -O0 baselines; got {batch_calls} rounds"
    );
}

/// Full-optimization path: with the unroll/inline budgets raised so the whole
/// circuit is flattened, the round-minimizing scheduler collapses the ~34k secret
/// multiplies into only a few hundred `batch_mul` communication rounds — a ~60x
/// reduction from the unscheduled ~25.7k. Ignored by default because flattening
/// AES is heavy in a debug build (~60s compile); run explicitly, ideally in
/// release:
///   STOFFEL_UNROLL_BUDGET=100000000 STOFFEL_UNROLL_MAX_EXPANSION=100000000 \
///   STOFFEL_INLINE_BUDGET=100000000 cargo test --release -p stoffel-vm \
///   --test aes_count optimized_aes_full_unroll_minimizes_rounds -- --ignored
#[test]
#[ignore]
fn optimized_aes_full_unroll_minimizes_rounds() {
    std::env::set_var("STOFFEL_UNROLL_BUDGET", "100000000");
    std::env::set_var("STOFFEL_UNROLL_MAX_EXPANSION", "100000000");
    std::env::set_var("STOFFEL_INLINE_BUDGET", "100000000");
    run_on_large_stack(async move {
        let source = include_str!("../../stoffel-lang/examples/mpc_aes128_circuit/main.stfl");
        let options = stoffellang::CompilerOptions {
            optimize: true,
            optimization_level: 3,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            ..Default::default()
        };
        let compiled = stoffellang::compile(source, "<m>", &options).expect("compile");
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("fns");
        let engine = std::sync::Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        for f in functions {
            vm.try_register_function(f).expect("reg");
        }
        let result = vm
            .execute_async("main", engine.as_ref())
            .await
            .expect("exec");
        // Correct ciphertext (NIST AES-128 test vector).
        let Value::Array(result_ref) = result else {
            panic!("AES main should return an array");
        };
        let mut ciphertext = Vec::new();
        for index in 0..vm.read_array_len(result_ref).expect("len") {
            let value = vm
                .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
                .expect("read")
                .expect("byte");
            let Value::I64(byte) = value else {
                panic!("byte")
            };
            ciphertext.push(byte);
        }
        assert_eq!(
            ciphertext,
            vec![105, 196, 224, 216, 106, 123, 4, 48, 216, 205, 183, 128, 112, 180, 197, 90]
        );
        let (scalar, batch_calls, batch_items) = engine.counts();
        assert_eq!(scalar, 0);
        assert_eq!(batch_items, 34_080);
        assert!(
            batch_calls < 1_000,
            "fully-flattened AES should reach a few hundred multiply rounds; got {batch_calls}"
        );
    });
}

/// Regression for a loop-carried-state mis-optimization when a function with a
/// reassigned (loop-carried) local is inlined more than once. CTR's keystream
/// inlines `aes128_encrypt_rk` (loop-carried `state`) twice — once per block —
/// and at -O3 once produced a wrong block-1 result (C1 != NIST). The single-block
/// AES circuit inlines it only once and was unaffected. This calls a small
/// loop-carried folder twice with distinct inputs and requires -O3 to match -O0.
#[test]
fn loop_carried_state_inlined_twice_o3_matches_o0() {
    run_on_large_stack(loop_carried_state_inlined_twice_o3_matches_o0_impl());
}

async fn loop_carried_state_inlined_twice_o3_matches_o0_impl() {
    let source = r#"
def gate_xor(a: secret bool, b: secret bool) -> secret bool:
  return a xor b

# Loop-carried fold: `result` is reassigned each iteration.
def fold(bits: list[secret bool]) -> secret bool:
  var result: secret bool = Share.from_clear_int(0, 1)
  for i in 0..bits.len():
    result = gate_xor(result, bits[i])
  return result

def main() -> list[int64]:
  # Two INDEPENDENT folds with distinct inputs and distinct results, so a
  # cross-inline collision on `result` is detectable. fold([1,0,0,0]) = 1,
  # fold([0,0,0,0]) = 0.
  var r0 = fold([Share.from_clear_int(1, 1), Share.from_clear_int(0, 1), Share.from_clear_int(0, 1), Share.from_clear_int(0, 1)])
  var r1 = fold([Share.from_clear_int(0, 1), Share.from_clear_int(0, 1), Share.from_clear_int(0, 1), Share.from_clear_int(0, 1)])
  var out: list[int64] = []
  var b0: bool = r0.reveal()
  var b1: bool = r1.reveal()
  if b0:
    out.append(1)
  else:
    out.append(0)
  if b1:
    out.append(1)
  else:
    out.append(0)
  return out
"#;

    let run_at = |level: u8| async move {
        let options = stoffellang::CompilerOptions {
            optimize: level > 0,
            optimization_level: level,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            ..Default::default()
        };
        let compiled = stoffellang::compile(source, "<fold>", &options)
            .unwrap_or_else(|e| panic!("compile at -O{level}: {e:?}"));
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("vm functions");
        let engine = Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        for function in functions {
            vm.try_register_function(function)
                .expect("register function");
        }
        let result = vm
            .execute_async("main", engine.as_ref())
            .await
            .unwrap_or_else(|e| panic!("execute at -O{level}: {e:?}"));
        let Value::Array(result_ref) = result else {
            panic!("fold main should return an array");
        };
        let mut bits = Vec::new();
        for index in 0..vm.read_array_len(result_ref).expect("len") {
            let value = vm
                .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
                .expect("read bit")
                .expect("bit");
            let Value::I64(b) = value else {
                panic!("bit should be int64, got {value:?}");
            };
            bits.push(b);
        }
        bits
    };

    let expected = vec![1, 0]; // fold([1,0,0,0])=1, fold([0,0,0,0])=0
    let o0 = run_at(0).await;
    let o3 = run_at(3).await;
    assert_eq!(o0, expected, "-O0 fold must be correct");
    assert_eq!(
        o3, expected,
        "-O3 must match -O0 when a loop-carried-state function is inlined twice"
    );
}

/// Differential test for the CTR -O3 full-unroll correctness bug using the
/// reduced counter-increment reproducer. The original AES CTR failure presented
/// as a wrong C1 block; shrinking showed the counter increment itself diverged
/// under -O3 inlining/unrolling/scheduling.
#[test]
fn ctr_full_unroll_c1_matches_o0() {
    run_on_large_stack(ctr_full_unroll_c1_matches_o0_impl());
}

async fn ctr_full_unroll_c1_matches_o0_impl() {
    let base = r#"
def gate_and(a: secret bool, b: secret bool) -> secret bool:
  return a and b

def gate_xor(a: secret bool, b: secret bool) -> secret bool:
  return a xor b

def reveal_byte(byte: list[secret bool]) -> int64:
  var value: int64 = 0
  var b0: bool = byte[0].reveal()
  if b0:
    value += 1
  var b1: bool = byte[1].reveal()
  if b1:
    value += 2
  var b2: bool = byte[2].reveal()
  if b2:
    value += 4
  var b3: bool = byte[3].reveal()
  if b3:
    value += 8
  var b4: bool = byte[4].reveal()
  if b4:
    value += 16
  var b5: bool = byte[5].reveal()
  if b5:
    value += 32
  var b6: bool = byte[6].reveal()
  if b6:
    value += 64
  var b7: bool = byte[7].reveal()
  if b7:
    value += 128
  return value

def reveal_block(block: list[list[secret bool]]) -> list[int64]:
  return [reveal_byte(block[0]), reveal_byte(block[1]), reveal_byte(block[2]), reveal_byte(block[3]), reveal_byte(block[4]), reveal_byte(block[5]), reveal_byte(block[6]), reveal_byte(block[7]), reveal_byte(block[8]), reveal_byte(block[9]), reveal_byte(block[10]), reveal_byte(block[11]), reveal_byte(block[12]), reveal_byte(block[13]), reveal_byte(block[14]), reveal_byte(block[15])]

def public_byte(value: int64) -> list[secret bool]:
  var bits: list[secret bool] = []
  var v: int64 = value
  for i in 0..8:
    bits.append(Share.from_clear_int(v % 2, 1))
    v = v / 2
  return bits

def public_block(values: list[int64]) -> list[list[secret bool]]:
  var block: list[list[secret bool]] = []
  for i in 0..16:
    block.append(public_byte(values[i]))
  return block

def increment_counter_byte(byte: list[secret bool], carry_in: secret bool) -> list[secret bool]:
  var out: list[secret bool] = []
  var carry = carry_in
  for bit_index in 0..8:
    out.append(gate_xor(byte[bit_index], carry))
    carry = gate_and(byte[bit_index], carry)
  return out

def increment_counter_byte_carry(byte: list[secret bool], carry_in: secret bool) -> secret bool:
  var carry = carry_in
  for bit_index in 0..8:
    carry = gate_and(byte[bit_index], carry)
  return carry

def increment_counter_block(counter: list[list[secret bool]]) -> list[list[secret bool]]:
  var out: list[list[secret bool]] = []
  var carry = Share.from_clear_int(1, 1)
  for offset in 0..16:
    var byte_index = 15 - offset
    out.insert(0, increment_counter_byte(counter[byte_index], carry))
    carry = increment_counter_byte_carry(counter[byte_index], carry)
  return out
"#;
    let main_lit = r#"
def main_lit() -> list[int64]:
  var ctr0 = public_block([240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255])
  var ctr1 = increment_counter_block(ctr0)
  return reveal_block(ctr1)
"#;
    let source = format!("{base}\n{main_lit}");

    let run_at = |level: u8, full_unroll: bool, source: String| async move {
        if full_unroll {
            std::env::set_var("STOFFEL_INLINE_BUDGET", "100000000");
            std::env::set_var("STOFFEL_UNROLL_BUDGET", "100000000");
            std::env::set_var("STOFFEL_UNROLL_MAX_EXPANSION", "100000000");
        }
        let options = stoffellang::CompilerOptions {
            optimize: level > 0,
            optimization_level: level,
            mpc_backend: stoffel_vm_types::compiled_binary::MpcBackend::HoneyBadger,
            ..Default::default()
        };
        let compiled = stoffellang::compile(&source, "<ctr-lit>", &options)
            .unwrap_or_else(|e| panic!("compile at -O{level}: {e:?}"));
        let binary = stoffellang::convert_to_binary(&compiled);
        let functions = binary.try_to_vm_functions().expect("vm functions");
        let engine = Arc::new(CountingEngine::default());
        let mut vm = VirtualMachine::builder()
            .with_mpc_engine(engine.clone())
            .build();
        for function in functions {
            vm.try_register_function(function)
                .expect("register function");
        }
        let result = vm
            .execute_async("main_lit", engine.as_ref())
            .await
            .unwrap_or_else(|e| panic!("execute at -O{level}: {e:?}"));
        let Value::Array(result_ref) = result else {
            panic!("main_lit should return an array");
        };
        let mut out = Vec::new();
        for index in 0..vm.read_array_len(result_ref).expect("len") {
            let value = vm
                .read_table_field(TableRef::from(result_ref), &Value::I64(index as i64))
                .expect("read byte")
                .expect("byte");
            let Value::I64(b) = value else {
                panic!("byte should be int64, got {value:?}");
            };
            out.push(b);
        }
        out
    };

    let o0 = run_at(0, false, source.clone()).await;
    eprintln!("CTR1_O0 = {:?}", o0);
    std::env::set_var("STOFFEL_INLINE_BUDGET", "100000000");
    std::env::set_var("STOFFEL_UNROLL_BUDGET", "100000000");
    std::env::set_var("STOFFEL_UNROLL_MAX_EXPANSION", "100000000");
    let o3 = run_at(3, false, source).await;
    eprintln!("CTR1_O3 = {:?}", o3);
    eprintln!("match: {}", o0 == o3);
    assert_eq!(
        o0, o3,
        "ctr1 (counter increment) must match between -O0 and -O3"
    );
}
