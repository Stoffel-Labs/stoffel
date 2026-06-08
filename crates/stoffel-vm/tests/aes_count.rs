use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use stoffel_vm::core_vm::VirtualMachine;
use stoffel_vm::net::mpc_engine::{
    MpcCapabilities, MpcEngine, MpcEngineMultiplication, MpcEngineResult, MpcSessionTopology,
    ShareAlgebraResult,
};
use stoffel_vm_types::core_types::{ClearShareInput, ClearShareValue, ShareData, ShareType};

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

    fn input_share(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(vec![0]))
    }

    fn open_share(&self, _ty: ShareType, _share_bytes: &[u8]) -> MpcEngineResult<ClearShareValue> {
        Ok(ClearShareValue::Boolean(false))
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
        _rhs_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        Ok(lhs_bytes.to_vec())
    }

    fn sub_share_local(
        &self,
        _ty: ShareType,
        lhs_bytes: &[u8],
        _rhs_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        Ok(lhs_bytes.to_vec())
    }

    fn mul_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        _scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        Ok(share_bytes.to_vec())
    }

    fn add_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        _scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        Ok(share_bytes.to_vec())
    }

    fn sub_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        _scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        Ok(share_bytes.to_vec())
    }

    fn scalar_sub_share_local(
        &self,
        _ty: ShareType,
        _scalar: i64,
        share_bytes: &[u8],
    ) -> ShareAlgebraResult<Vec<u8>> {
        Ok(share_bytes.to_vec())
    }

    fn div_share_scalar_local(
        &self,
        _ty: ShareType,
        share_bytes: &[u8],
        _scalar: i64,
    ) -> ShareAlgebraResult<Vec<u8>> {
        Ok(share_bytes.to_vec())
    }
}

impl MpcEngineMultiplication for CountingEngine {
    fn multiply_share(
        &self,
        _ty: ShareType,
        left: &[u8],
        _right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        self.scalar_mul_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ShareData::Opaque(left.to_vec()))
    }
}

#[async_trait::async_trait]
impl stoffel_vm::net::mpc_engine::AsyncMpcEngine for CountingEngine {
    async fn input_share_async(&self, _clear: ClearShareInput) -> MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(vec![0]))
    }

    async fn multiply_share_async(
        &self,
        _ty: ShareType,
        left: &[u8],
        _right: &[u8],
    ) -> MpcEngineResult<ShareData> {
        self.scalar_mul_calls.fetch_add(1, Ordering::SeqCst);
        Ok(ShareData::Opaque(left.to_vec()))
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
            .map(|(left, _)| ShareData::Opaque(left.clone()))
            .collect())
    }

    async fn open_share_async(
        &self,
        _ty: ShareType,
        _share_bytes: &[u8],
    ) -> MpcEngineResult<ClearShareValue> {
        Ok(ClearShareValue::Boolean(false))
    }

    async fn batch_open_shares_async(
        &self,
        _ty: ShareType,
        shares: &[Vec<u8>],
    ) -> MpcEngineResult<Vec<ClearShareValue>> {
        Ok(shares
            .iter()
            .map(|_| ClearShareValue::Boolean(false))
            .collect())
    }

    async fn random_share_async(&self, _ty: ShareType) -> MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(vec![0]))
    }

    async fn random_integer_share_async(&self, _ty: ShareType) -> MpcEngineResult<ShareData> {
        Ok(ShareData::Opaque(vec![0]))
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "counts optimized AES MPC multiplication demand"]
async fn count_optimized_aes_batch_mul_items() {
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
