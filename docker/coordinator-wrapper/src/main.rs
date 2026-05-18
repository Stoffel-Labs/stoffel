use std::fs;
use std::marker::PhantomData;
use std::sync::Arc;

use ark_ec::CurveGroup;
use ark_ff::FftField;
use async_trait::async_trait;
use clap::Parser;
use jsonrpsee::{core::RpcResult, server::RpcModule};
use stoffel_mpc_coordinator::off_chain::{
    ClientIdentity, CoordinatorRPCBaseServer, CoordinatorRPCServerConnectionBase,
    CoordinatorRPCServerSharedBase, OffChainCoordinatorServer, StoffelCoordinatorRPCServer,
};
use stoffel_mpc_coordinator::rpc::RPCServerConnection;
use stoffel_mpc_coordinator::{Round, ShareBound};
use stoffelmpc_mpc::common::share::feldman::FeldmanShamirShare;
use tokio::sync::Mutex;
use x509_parser::prelude::*;

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    #[arg(long)]
    hash: String,

    #[arg(long, value_delimiter = ',', num_args = 1..)]
    initial_mpc_nodes: Vec<String>,

    #[arg(long)]
    server_cert: String,

    #[arg(long)]
    server_key: String,

    #[arg(long)]
    n: u64,

    #[arg(long)]
    t: u64,

    #[arg(long)]
    n_inputs: u64,

    #[arg(long, value_delimiter = ',', num_args = 1..)]
    output_clients: Vec<String>,

    #[arg(long, default_value = "secp256k1")]
    mpc_curve: String,

    #[arg(long, default_value = "0.0.0.0")]
    bind_addr: String,

    #[arg(long, default_value_t = 31415)]
    port: u16,
}

#[derive(Clone)]
struct AvssCoordinatorConnection<F, S>
where
    F: FftField,
    S: ShareBound<F>,
{
    base: CoordinatorRPCServerConnectionBase<F, S>,
    _phantom: PhantomData<(F, S)>,
}

impl<F, S> RPCServerConnection for AvssCoordinatorConnection<F, S>
where
    F: FftField,
    S: ShareBound<F>,
{
    type Internal = CoordinatorRPCServerSharedBase<S::ValueType>;

    fn new(internal: Arc<Mutex<Self::Internal>>, id: ClientIdentity) -> Self {
        Self {
            base: CoordinatorRPCServerConnectionBase::new(internal, id),
            _phantom: PhantomData,
        }
    }

    fn into_rpc(self) -> RpcModule<Self> {
        let mut rpc = StoffelCoordinatorRPCServer::into_rpc(self.clone());
        let base_rpc = CoordinatorRPCBaseServer::into_rpc(self.base);
        rpc.merge(base_rpc).expect("merge coordinator RPC modules");
        rpc
    }
}

#[async_trait]
impl<F, S> StoffelCoordinatorRPCServer for AvssCoordinatorConnection<F, S>
where
    F: FftField,
    S: ShareBound<F>,
{
    async fn start_preprocessing(&self) -> RpcResult<()> {
        self.base.transition(Round::Preprocessing).await
    }

    async fn reserve_input_masks(&self) -> RpcResult<()> {
        self.base.transition(Round::InputMaskReservation).await
    }

    async fn collect_inputs(&self) -> RpcResult<()> {
        self.base.transition(Round::InputCollection).await
    }

    async fn start_mpc(&self) -> RpcResult<()> {
        self.base.transition(Round::MPCExecution).await
    }

    async fn send_output(&self) -> RpcResult<()> {
        self.base.transition(Round::OutputDistribution).await
    }

    async fn finalize(&self) -> RpcResult<()> {
        self.base.transition(Round::ProgramFinished).await
    }
}

#[tokio::main]
async fn main() {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install default crypto provider");

    let args = Args::parse();
    match args.mpc_curve.as_str() {
        "bls12-381" | "bls12381" => {
            start_for_curve::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>(args).await
        }
        "bn254" => start_for_curve::<ark_bn254::Fr, ark_bn254::G1Projective>(args).await,
        "curve25519" => {
            start_for_curve::<ark_curve25519::Fr, ark_curve25519::EdwardsProjective>(args).await
        }
        "ed25519" => {
            start_for_curve::<ark_ed25519::Fr, ark_ed25519::EdwardsProjective>(args).await
        }
        "secp256k1" => {
            start_for_curve::<ark_secp256k1::Fr, ark_secp256k1::Projective>(args).await
        }
        "p-256" | "p256" | "secp256r1" => {
            start_for_curve::<ark_secp256r1::Fr, ark_secp256r1::Projective>(args).await
        }
        other => {
            eprintln!("unsupported --mpc-curve '{other}'");
            std::process::exit(2);
        }
    }
}

async fn start_for_curve<F, G>(args: Args)
where
    F: FftField,
    G: CurveGroup<ScalarField = F>,
    FeldmanShamirShare<F, G>: ShareBound<F>,
{
    let hash: [u8; 32] = hex::decode(&args.hash)
        .expect("invalid hash")
        .try_into()
        .expect("hash must be 32 bytes");

    let public_keys = parse_public_keys(&args.initial_mpc_nodes);
    let output_client_keys = parse_public_keys(&args.output_clients);
    let server_cert_der = fs::read(&args.server_cert).expect("could not read server cert");
    let server_key_der = fs::read(&args.server_key).expect("could not read server key");

    let server_state = CoordinatorRPCServerSharedBase::new(
        hash,
        args.n,
        args.t,
        public_keys,
        args.n_inputs,
        output_client_keys,
    );

    let coord = OffChainCoordinatorServer::<
        AvssCoordinatorConnection<F, FeldmanShamirShare<F, G>>,
    >::start_coord(
        server_state,
        &args.bind_addr,
        args.port,
        args.t,
        server_cert_der,
        server_key_der,
    )
    .await
    .expect("failed to start coordinator");

    println!("Listening on {}:{}", args.bind_addr, args.port);
    println!("Timestamp: {}", coord.get_timestamp());

    tokio::time::sleep(tokio::time::Duration::MAX).await;
}

fn parse_public_keys(cert_files: &[String]) -> Vec<Vec<u8>> {
    cert_files
        .iter()
        .map(|cert_file| {
            let cert_der = fs::read(cert_file).expect("could not read certificate file");
            let (_, parsed_cert) =
                X509Certificate::from_der(&cert_der).expect("Failed to parse X.509 certificate");
            parsed_cert
                .public_key()
                .subject_public_key
                .data
                .as_ref()
                .to_vec()
        })
        .collect()
}
