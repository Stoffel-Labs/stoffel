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
        ShareData::Opaque(vec![byte])
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
        Ok(ShareData::Opaque(vec![
            CountingEngine::bool_byte(left) & CountingEngine::bool_byte(right),
        ]))
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
        Ok(ShareData::Opaque(vec![
            CountingEngine::bool_byte(left) & CountingEngine::bool_byte(right),
        ]))
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
                ShareData::Opaque(vec![
                    CountingEngine::bool_byte(left) & CountingEngine::bool_byte(right),
                ])
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
        Ok(ShareData::Opaque(vec![0]))
    }

    async fn random_integer_share_async(&self, _ty: ShareType) -> MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(vec![0]))
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
    assert_eq!(scalar, 0);
    assert_eq!(batch_items, 34_080);
    assert!(
        batch_calls <= 600,
        "optimized AES should stay batched; got {batch_calls} batch calls"
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
