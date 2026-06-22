//! AVSS backend identity and API boundary types.
//!
//! The SDK exposes AVSS configuration and delegates live protocol operations to
//! `stoffel-vm` engines when a caller provides one.

use std::fmt;
use std::sync::Arc;

use crate::backend::Backend;
use crate::config::{Curve, MpcBackend};
use crate::error::{Error, Result};
use crate::types::{FieldElement, GroupElement, PublicKey, Share};
use stoffel_vm::net::mpc::avss::{decode_bls12381_avss_field, Bls12381AvssShare};
use stoffel_vm::net::mpc_engine::AsyncMpcEngine;
use stoffel_vm_types::core_types::ShareType;

#[derive(Debug, Clone)]
pub struct AvssBackend {
    curve: Curve,
}

impl AvssBackend {
    pub fn new(curve: Curve) -> Self {
        Self { curve }
    }

    pub fn curve(&self) -> Curve {
        self.curve
    }
}

impl Backend for AvssBackend {
    fn kind(&self) -> MpcBackend {
        MpcBackend::Avss { curve: self.curve }
    }

    fn name(&self) -> &'static str {
        "avss"
    }
}

#[derive(Clone)]
pub struct AvssEngine {
    curve: Curve,
    inner: AvssEngineInner,
}

#[derive(Clone)]
enum AvssEngineInner {
    Unavailable,
    Bls12381(Arc<stoffel_vm::net::avss_engine::Bls12381AvssMpcEngine>),
}

impl fmt::Debug for AvssEngine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AvssEngine")
            .field("curve", &self.curve)
            .field("live", &self.is_live())
            .finish_non_exhaustive()
    }
}

impl AvssEngine {
    pub(crate) fn unavailable(curve: Curve) -> Self {
        Self {
            curve,
            inner: AvssEngineInner::Unavailable,
        }
    }

    /// Wrap a live BLS12-381 AVSS VM engine.
    ///
    /// This is primarily for server/runtime code that already owns a configured
    /// VM engine. The SDK does not create a networked engine on its own.
    pub fn from_bls12381_engine(
        engine: Arc<stoffel_vm::net::avss_engine::Bls12381AvssMpcEngine>,
    ) -> Self {
        Self {
            curve: Curve::Bls12_381,
            inner: AvssEngineInner::Bls12381(engine),
        }
    }

    pub fn curve(&self) -> Curve {
        self.curve
    }

    pub fn is_live(&self) -> bool {
        matches!(self.inner, AvssEngineInner::Bls12381(_))
    }

    #[tracing::instrument(skip_all, fields(curve = ?self.curve, key_name = key_name))]
    pub async fn generate_random_share(&self, key_name: &str) -> Result<()> {
        match &self.inner {
            AvssEngineInner::Bls12381(engine) => engine
                .generate_random_share(key_name)
                .await
                .map(|_| ())
                .map_err(Error::Computation),
            AvssEngineInner::Unavailable => {
                Err(self.unavailable_error(format!("generate_random_share('{key_name}')")))
            }
        }
    }

    #[tracing::instrument(skip_all, fields(curve = ?self.curve, key_name = key_name))]
    pub async fn generate_share_with_secret(
        &self,
        key_name: &str,
        secret: FieldElement,
    ) -> Result<()> {
        match &self.inner {
            AvssEngineInner::Bls12381(engine) => {
                let secret = decode_bls12381_field(secret.as_bytes())?;
                engine
                    .generate_share_with_secret(key_name, secret)
                    .await
                    .map(|_| ())
                    .map_err(Error::Computation)
            }
            AvssEngineInner::Unavailable => {
                Err(self
                    .unavailable_error(format!("generate_share_with_secret('{key_name}', ...)")))
            }
        }
    }

    #[tracing::instrument(skip_all, fields(curve = ?self.curve, key_name = key_name))]
    pub async fn await_received_share(&self, key_name: &str) -> Result<()> {
        match &self.inner {
            AvssEngineInner::Bls12381(engine) => engine
                .await_received_share(key_name)
                .await
                .map(|_| ())
                .map_err(Error::Computation),
            AvssEngineInner::Unavailable => {
                Err(self.unavailable_error(format!("await_received_share('{key_name}')")))
            }
        }
    }

    pub async fn get_share(&self, key_name: &str) -> Result<Share> {
        match &self.inner {
            AvssEngineInner::Bls12381(engine) => {
                let share = engine.get_share(key_name).await.ok_or_else(|| {
                    Error::Computation(format!("AVSS share '{key_name}' not found"))
                })?;
                bls12381_share_to_sdk(key_name, &share)
            }
            AvssEngineInner::Unavailable => {
                Err(self.unavailable_error(format!("get_share('{key_name}')")))
            }
        }
    }

    pub async fn get_public_key(&self, key_name: &str) -> Result<PublicKey> {
        match &self.inner {
            AvssEngineInner::Bls12381(engine) => {
                let bytes = engine
                    .get_public_key_bytes(key_name)
                    .await
                    .map_err(Error::Computation)?;
                Ok(PublicKey::new(key_name, bytes))
            }
            AvssEngineInner::Unavailable => {
                Err(self.unavailable_error(format!("get_public_key('{key_name}')")))
            }
        }
    }

    #[tracing::instrument(skip_all, fields(curve = ?self.curve, key_name = share.key_name))]
    pub async fn open_share_in_exp(
        &self,
        share: &Share,
        generator: &GroupElement,
    ) -> Result<GroupElement> {
        match &self.inner {
            AvssEngineInner::Bls12381(engine) => {
                let Some(share_data) = share.data() else {
                    return Err(Error::InvalidInput(format!(
                        "AVSS share '{}' does not contain encoded share data",
                        share.key_name
                    )));
                };
                let bytes = engine
                    .open_share_in_exp_async(
                        ShareType::default_secret_int(),
                        share_data,
                        generator.as_bytes(),
                    )
                    .await
                    .map_err(|error| Error::Computation(error.to_string()))?;
                Ok(GroupElement::from_bytes(bytes))
            }
            AvssEngineInner::Unavailable => {
                Err(self.unavailable_error(format!("open_share_in_exp('{}', ...)", share.key_name)))
            }
        }
    }

    fn unavailable_error(&self, operation: String) -> Error {
        Error::Unsupported(format!(
            "{operation} requires a real AVSS engine from stoffel-vm/mpc-protocols; the SDK does not implement AVSS protocol logic"
        ))
    }
}

fn bls12381_share_to_sdk(key_name: &str, share: &Bls12381AvssShare) -> Result<Share> {
    let data = stoffel_vm::net::avss_engine::Bls12381AvssMpcEngine::share_to_share_data(share)
        .map_err(Error::Computation)?;
    match data {
        stoffel_vm_types::core_types::ShareData::Feldman { data, commitments } => Ok(
            Share::feldman(key_name, data.to_vec(), commitments.to_vec()),
        ),
        stoffel_vm_types::core_types::ShareData::Opaque(data) => {
            Ok(Share::opaque(key_name, data.to_vec()))
        }
    }
}

fn decode_bls12381_field(bytes: &[u8]) -> Result<stoffel_vm::net::mpc::avss::Bls12381AvssField> {
    if bytes.is_empty() {
        return Err(Error::InvalidInput(
            "BLS12-381 field element bytes cannot be empty".to_owned(),
        ));
    }
    decode_bls12381_avss_field(bytes).map_err(Error::Computation)
}
