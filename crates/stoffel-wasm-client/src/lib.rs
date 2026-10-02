//! Browser-side cryptographic boundary for coordinator-mediated Stoffel client I/O.
//!
//! Network requests remain in JavaScript so browsers can use their native WebSocket
//! implementation. This crate owns every operation involving clear client values:
//! authenticating requests, reconstructing masks, masking inputs, decrypting output
//! shares, and reconstructing the final result.

use ark_bls12_381::Fr;
use ark_ff::{BigInteger, FftField, PrimeField, Zero};
use ark_poly::{EvaluationDomain, Radix2EvaluationDomain};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{DhP256HkdfSha256, Kem},
    single_shot_open, Deserializable, OpModeR,
};
use p256::{
    ecdsa::{signature::Signer, Signature, SigningKey},
    elliptic_curve::sec1::ToEncodedPoint,
    pkcs8::DecodePrivateKey,
    SecretKey,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::marker::PhantomData;
use std::rc::Rc;
use stoffel_vm_types::core_types::{FixedPointPrecision, ShareType};
use stoffel_vm_types::fixed_point_codec::{
    decode_fixed_point_float, encode_fixed_point_float, encode_fixed_point_integer,
};
use wasm_bindgen::prelude::*;

const AUTH_DOMAIN: &[u8] = b"stoffel-browser-rpc-auth";
const OUTPUT_HPKE_DOMAIN: &[u8] = b"StoffelOutputShareEncryption";
const MAX_PARTIES: usize = 32;
const MAX_THRESHOLD: usize = 8;

type KemImpl = DhP256HkdfSha256;
type KdfImpl = HkdfSha256;
type AeadImpl = AesGcm256;

#[wasm_bindgen(typescript_custom_section)]
const TYPESCRIPT_TYPES: &'static str = r#"
export type ClientScalarType =
  | { kind: "boolean" }
  | { kind: "signed_integer"; bit_length: number }
  | { kind: "unsigned_integer"; bit_length: number }
  | { kind: "fixed_point"; total_bits: number; fractional_bits: number };

export type ClientScalarValue =
  | { kind: "boolean"; value: boolean }
  | { kind: "signed_integer"; value: bigint }
  | { kind: "unsigned_integer"; value: bigint }
  | { kind: "fixed_point"; value: number }
  | { kind: "field"; value: Uint8Array };

export interface TypedClientInput {
  share_type: ClientScalarType;
  value: ClientScalarValue;
}

export interface AssignedMaskShare {
  reserved_index: number | bigint;
  share_bytes: Uint8Array;
}

export interface MaskedInput {
  reserved_index: number;
  masked_input: Uint8Array;
}

export interface EncryptedOutputShare {
  encapped_key: Uint8Array;
  ciphertext: Uint8Array;
}

export interface SignedBrowserRequest {
  public_key: Uint8Array;
  created: number;
  nonce: Uint8Array;
  signature: Uint8Array;
  body: Uint8Array;
}
"#;

#[derive(Debug, thiserror::Error)]
pub enum ClientError {
    #[error("invalid P-256 PKCS#8 private key")]
    InvalidPrivateKey,
    #[error("invalid P-256 SEC1 public key")]
    InvalidPublicKey,
    #[error("this client was constructed from a public key only and has no signing key - sign requests externally (e.g. via a non-extractable WebCrypto key) and use allocate_nonce")]
    NoSigningKey,
    #[error("this client was constructed from a public key only and has no decryption key - decrypt output shares externally (e.g. via a non-extractable WebCrypto key) and use reconstruct_outputs")]
    NoSecretKey,
    #[error("execution ID must contain exactly 64 hexadecimal characters")]
    InvalidExecutionId,
    #[error("unsupported topology n={n}, t={t}")]
    InvalidTopology { n: usize, t: usize },
    #[error("failed to deserialize a coordinator share")]
    InvalidShare,
    #[error("share set contains inconsistent metadata")]
    InconsistentShares,
    #[error("not enough valid shares to reconstruct a value")]
    InsufficientShares,
    #[error("failed to decrypt an output share")]
    OutputDecryption,
    #[error("output party returned {actual} values, expected {expected}")]
    OutputArity { expected: usize, actual: usize },
    #[error("field value is outside the signed 64-bit client range")]
    OutputRange,
    #[error("invalid client scalar type: {0}")]
    InvalidScalarType(String),
    #[error("client value is incompatible with its scalar type: {0}")]
    InvalidScalarValue(String),
    #[error("failed to generate a random nonce")]
    RandomGenerationFailed,
    #[error("JavaScript value conversion failed: {0}")]
    Js(String),
}

impl From<ClientError> for JsValue {
    fn from(value: ClientError) -> Self {
        js_sys::Error::new(&value.to_string()).into()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedBrowserRequest {
    pub public_key: Vec<u8>,
    pub created: u64,
    pub nonce: Vec<u8>,
    pub signature: Vec<u8>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AssignedMaskShare {
    pub reserved_index: u64,
    pub share_bytes: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MaskedInput {
    pub reserved_index: u64,
    pub masked_input: Vec<u8>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptedOutputShare {
    pub encapped_key: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

/// Browser-friendly form of the scalar share types in a compiled client I/O
/// manifest. Integer values are transferred as JavaScript `BigInt`s so all 64
/// bits survive the JavaScript/WASM boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ClientScalarType {
    Boolean,
    SignedInteger {
        bit_length: usize,
    },
    UnsignedInteger {
        bit_length: usize,
    },
    FixedPoint {
        total_bits: usize,
        fractional_bits: usize,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "snake_case")]
pub enum ClientScalarValue {
    Boolean(bool),
    SignedInteger(i64),
    UnsignedInteger(u64),
    FixedPoint(f64),
    /// Exactly one canonical, big-endian scalar-field element. This mirrors
    /// the native client's `Value::Bytes` input path.
    Field(Vec<u8>),
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct TypedClientInput {
    pub share_type: ClientScalarType,
    pub value: ClientScalarValue,
}

/// Canonical-serialization-compatible projection of HoneyBadger's
/// `RobustShare<F>`. The marker is zero-sized on the wire.
#[derive(Clone, Debug, PartialEq, CanonicalSerialize, CanonicalDeserialize)]
struct RobustShare<F: FftField> {
    share: [F; 1],
    id: usize,
    degree: usize,
    marker: PhantomData<fn()>,
}

impl<F: FftField> RobustShare<F> {
    #[cfg(test)]
    fn new(value: F, id: usize, degree: usize) -> Self {
        Self {
            share: [value],
            id,
            degree,
            marker: PhantomData,
        }
    }
}

struct ClientCore {
    /// `None` for a client constructed from a public key only (the WebAuthn
    /// session-key path - see `StoffelWasmClient::from_public_key`), where
    /// signing happens externally via a non-extractable WebCrypto key this
    /// module can never access. `sign_request` errors with `NoSigningKey`
    /// on such a client; use `allocate_nonce` instead.
    signing_key: Option<SigningKey>,
    /// `None` for a public-key-only client, for the same reason. HPKE
    /// decryption happens externally in that case; `decrypt_outputs`
    /// errors with `NoSecretKey` and `reconstruct_outputs` should be used
    /// with externally-decrypted plaintext shares instead.
    secret_key: Option<SecretKey>,
    public_key: Vec<u8>,
    parties: usize,
    threshold: usize,
}

/// Long-lived browser identity. It can open any number of simultaneous
/// execution handles while reusing the same key and topology.
#[wasm_bindgen]
pub struct StoffelWasmClient {
    core: Rc<ClientCore>,
}

/// State belonging to one execution. Multiple handles from a client can be
/// active concurrently and independently - there is no shared counter to
/// keep in sync between them (each signed request carries its own random
/// nonce plus a `created` timestamp; see `authentication_message`).
#[wasm_bindgen]
pub struct StoffelWasmExecution {
    core: Rc<ClientCore>,
    execution_id: [u8; 32],
}

#[wasm_bindgen]
impl StoffelWasmClient {
    #[wasm_bindgen(constructor)]
    pub fn new(
        private_key_pkcs8: &[u8],
        parties: usize,
        threshold: usize,
    ) -> Result<Self, JsValue> {
        console_error_panic_hook::set_once();
        Self::from_pkcs8(private_key_pkcs8, parties, threshold).map_err(Into::into)
    }

    /// Construct a client from a public key only, with no signing or
    /// decryption capability - for the WebAuthn session-key path, where a
    /// non-extractable WebCrypto key pair in JS does the signing
    /// (`allocate_nonce` + external signing, see the browser client
    /// library) and HPKE decryption (external decrypt +
    /// `reconstruct_outputs`) that a full `from_pkcs8` client would do
    /// itself. `public_key` is the raw 65-byte SEC1 uncompressed P-256
    /// point - the same format `public_key()` already returns.
    #[wasm_bindgen(js_name = fromPublicKey)]
    pub fn from_public_key_js(
        public_key: &[u8],
        parties: usize,
        threshold: usize,
    ) -> Result<StoffelWasmClient, JsValue> {
        console_error_panic_hook::set_once();
        Self::from_public_key(public_key, parties, threshold).map_err(Into::into)
    }

    /// SEC1 uncompressed P-256 public key. This is the same byte string stored
    /// in the subjectPublicKey field of the existing demo client certificate.
    pub fn public_key(&self) -> Vec<u8> {
        self.core.public_key.clone()
    }

    /// Open an execution handle. Each signed request it produces carries its
    /// own random nonce and `created` timestamp (see `authentication_message`),
    /// so unlike the old counter-based scheme there is nothing to resume after
    /// a reload and no shared state for multiple open handles (e.g. several
    /// tabs) to fall out of sync on - opening the same execution id twice
    /// just yields two independent, equally valid handles.
    pub fn open_execution(&self, execution_id: &str) -> Result<StoffelWasmExecution, JsValue> {
        Ok(self.execution_handle(parse_execution_id(execution_id)?))
    }
}

#[wasm_bindgen]
impl StoffelWasmExecution {
    pub fn execution_id(&self) -> String {
        hex::encode(self.execution_id)
    }

    /// Sign a request with a fresh random nonce and the current timestamp.
    /// Errors with `NoSigningKey` on a public-key-only client (the WebAuthn
    /// session-key path) - build `authenticationMessage` and sign externally
    /// there instead (see the browser client library).
    #[wasm_bindgen(unchecked_return_type = "SignedBrowserRequest")]
    pub fn sign_request(&self, method: &str, body: &[u8]) -> Result<JsValue, JsValue> {
        let signing_key = self.core.signing_key.as_ref().ok_or(ClientError::NoSigningKey)?;
        let created = (js_sys::Date::now() / 1000.0) as u64;
        let nonce = random_nonce()?;
        let message = authentication_message(method, &self.execution_id, created, &nonce, body);
        let signature: Signature = signing_key.sign(&message);
        serde_wasm_bindgen::to_value(&SignedBrowserRequest {
            public_key: self.core.public_key.clone(),
            created,
            nonce: nonce.to_vec(),
            signature: signature.to_bytes().to_vec(),
            body: body.to_vec(),
        })
        .map_err(|error| ClientError::Js(error.to_string()).into())
    }

    /// Reconstruct and apply one mask per typed input.
    #[wasm_bindgen(unchecked_return_type = "MaskedInput[]")]
    pub fn mask_inputs(
        &self,
        first_reserved_index: u64,
        #[wasm_bindgen(unchecked_param_type = "TypedClientInput[]")] clear_inputs: JsValue,
        #[wasm_bindgen(unchecked_param_type = "AssignedMaskShare[][]")] node_responses: JsValue,
    ) -> Result<JsValue, JsValue> {
        let inputs: Vec<TypedClientInput> = serde_wasm_bindgen::from_value(clear_inputs)
            .map_err(|error| ClientError::Js(error.to_string()))?;
        let responses: Vec<Vec<AssignedMaskShare>> = serde_wasm_bindgen::from_value(node_responses)
            .map_err(|error| ClientError::Js(error.to_string()))?;
        let fields = inputs
            .iter()
            .map(typed_input_to_field)
            .collect::<Result<Vec<_>, _>>()?;
        serde_wasm_bindgen::to_value(&mask_fields_core(
            self.core.parties,
            self.core.threshold,
            first_reserved_index,
            &fields,
            &responses,
        )?)
        .map_err(|error| ClientError::Js(error.to_string()).into())
    }

    /// Decrypt and robustly reconstruct outputs using their manifest types.
    /// Errors with `NoSecretKey` on a public-key-only client (the WebAuthn
    /// session-key path) - decrypt each share externally there (e.g. via a
    /// non-extractable WebCrypto ECDH key) and call `reconstruct_outputs`
    /// with the resulting plaintexts instead.
    #[wasm_bindgen(unchecked_return_type = "ClientScalarValue[]")]
    pub fn decrypt_outputs(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ClientScalarType[]")] output_types: JsValue,
        #[wasm_bindgen(unchecked_param_type = "EncryptedOutputShare[]")] encrypted_shares: JsValue,
    ) -> Result<JsValue, JsValue> {
        let output_types: Vec<ClientScalarType> = serde_wasm_bindgen::from_value(output_types)
            .map_err(|error| ClientError::Js(error.to_string()))?;
        let encrypted: Vec<EncryptedOutputShare> = serde_wasm_bindgen::from_value(encrypted_shares)
            .map_err(|error| ClientError::Js(error.to_string()))?;
        let values = decrypt_fields_core(
            &self.core,
            &self.execution_id,
            output_types.len(),
            &encrypted,
        )?
        .into_iter()
        .zip(output_types)
        .map(|(value, share_type)| field_to_typed_value(value, share_type))
        .collect::<Result<Vec<_>, _>>()?;
        to_js_value_with_bigints(&values)
    }

    /// The non-key-dependent half of `decrypt_outputs`: robustly
    /// reconstruct and type-convert outputs from already-decrypted
    /// plaintext shares (one `Vec<u8>` per encrypted share that was
    /// received, each the plaintext bytes an external HPKE-open produced -
    /// see `decryptShare` in the browser client library). This is what
    /// lets the WebAuthn session-key path stay entirely out of the
    /// robust-share-reconstruction/field-arithmetic business: only the
    /// HPKE-open step (which needs the non-extractable ECDH key) moves to
    /// JS, everything else here is identical to what `decrypt_fields_core`
    /// already does today, minus that one step. Works identically on a
    /// public-key-only client or a full `from_pkcs8` client, since it only
    /// ever touches `self.core.parties`/`threshold`.
    #[wasm_bindgen(unchecked_return_type = "ClientScalarValue[]")]
    pub fn reconstruct_outputs(
        &self,
        #[wasm_bindgen(unchecked_param_type = "ClientScalarType[]")] output_types: JsValue,
        #[wasm_bindgen(unchecked_param_type = "Uint8Array[]")] decrypted_shares: JsValue,
    ) -> Result<JsValue, JsValue> {
        let output_types: Vec<ClientScalarType> = serde_wasm_bindgen::from_value(output_types)
            .map_err(|error| ClientError::Js(error.to_string()))?;
        let plaintexts: Vec<Vec<u8>> = serde_wasm_bindgen::from_value(decrypted_shares)
            .map_err(|error| ClientError::Js(error.to_string()))?;
        let values = reconstruct_outputs_core(&self.core, output_types.len(), &plaintexts)?
            .into_iter()
            .zip(output_types)
            .map(|(value, share_type)| field_to_typed_value(value, share_type))
            .collect::<Result<Vec<_>, _>>()?;
        to_js_value_with_bigints(&values)
    }
}

impl StoffelWasmClient {
    fn execution_handle(&self, execution_id: [u8; 32]) -> StoffelWasmExecution {
        StoffelWasmExecution {
            core: self.core.clone(),
            execution_id,
        }
    }

    pub fn from_pkcs8(
        private_key_pkcs8: &[u8],
        parties: usize,
        threshold: usize,
    ) -> Result<Self, ClientError> {
        validate_topology(parties, threshold)?;
        let secret_key = SecretKey::from_pkcs8_der(private_key_pkcs8)
            .map_err(|_| ClientError::InvalidPrivateKey)?;
        Self::from_secret_key(secret_key, parties, threshold)
    }

    fn from_secret_key(
        secret_key: SecretKey,
        parties: usize,
        threshold: usize,
    ) -> Result<Self, ClientError> {
        validate_topology(parties, threshold)?;
        let signing_key = SigningKey::from(secret_key.clone());
        let public_key = secret_key
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        Ok(Self {
            core: Rc::new(ClientCore {
                signing_key: Some(signing_key),
                secret_key: Some(secret_key),
                public_key,
                parties,
                threshold,
            }),
        })
    }

    /// See `from_public_key_js` (`fromPublicKey` in JS) - the WebAuthn
    /// session-key path, with no signing or decryption capability.
    pub fn from_public_key(
        public_key: &[u8],
        parties: usize,
        threshold: usize,
    ) -> Result<Self, ClientError> {
        validate_topology(parties, threshold)?;
        // Validates the point is a well-formed P-256 SEC1 public key
        // up front, rather than deferring the failure to whenever a
        // request happens to be verified against it.
        p256::PublicKey::from_sec1_bytes(public_key).map_err(|_| ClientError::InvalidPublicKey)?;
        Ok(Self {
            core: Rc::new(ClientCore {
                signing_key: None,
                secret_key: None,
                public_key: public_key.to_vec(),
                parties,
                threshold,
            }),
        })
    }
}

fn mask_fields_core(
    parties: usize,
    threshold: usize,
    first_reserved_index: u64,
    clear_inputs: &[Fr],
    node_responses: &[Vec<AssignedMaskShare>],
) -> Result<Vec<MaskedInput>, ClientError> {
    let mut shares_by_index: BTreeMap<u64, Vec<RobustShare<Fr>>> = BTreeMap::new();
    for response in node_responses {
        for assigned in response {
            let share = RobustShare::<Fr>::deserialize_compressed(assigned.share_bytes.as_slice())
                .map_err(|_| ClientError::InvalidShare)?;
            shares_by_index
                .entry(assigned.reserved_index)
                .or_default()
                .push(share);
        }
    }

    clear_inputs
        .iter()
        .enumerate()
        .map(|(offset, clear)| {
            let reserved_index = first_reserved_index
                .checked_add(offset as u64)
                .ok_or(ClientError::OutputRange)?;
            let shares = shares_by_index
                .get(&reserved_index)
                .ok_or(ClientError::InsufficientShares)?;
            let mask = recover_robust_secret(shares, parties, threshold)?;
            let value = *clear + mask;
            let mut masked_input = Vec::new();
            value
                .serialize_compressed(&mut masked_input)
                .map_err(|_| ClientError::InvalidShare)?;
            Ok(MaskedInput {
                reserved_index,
                masked_input,
            })
        })
        .collect()
}

fn decrypt_fields_core(
    core: &ClientCore,
    execution_id: &[u8; 32],
    output_count: usize,
    encrypted_shares: &[EncryptedOutputShare],
) -> Result<Vec<Fr>, ClientError> {
    let secret_key = core.secret_key.as_ref().ok_or(ClientError::NoSecretKey)?;
    let raw_secret = secret_key.to_bytes();
    let hpke_secret = <KemImpl as Kem>::PrivateKey::from_bytes(&raw_secret)
        .map_err(|_| ClientError::InvalidPrivateKey)?;
    let info = output_encryption_info(execution_id);
    let mut plaintexts = Vec::with_capacity(encrypted_shares.len());

    for encrypted in encrypted_shares {
        let encapped = <KemImpl as Kem>::EncappedKey::from_bytes(&encrypted.encapped_key)
            .map_err(|_| ClientError::OutputDecryption)?;
        let plaintext = single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
            &OpModeR::Base,
            &hpke_secret,
            &encapped,
            &info,
            &encrypted.ciphertext,
            b"",
        )
        .map_err(|_| ClientError::OutputDecryption)?;
        plaintexts.push(plaintext);
    }

    reconstruct_outputs_core(core, output_count, &plaintexts)
}

/// The non-key-dependent half of `decrypt_fields_core` - robust
/// reconstruction across already-decrypted plaintext shares. Shared by the
/// full `from_pkcs8` path (via `decrypt_fields_core` above, after its own
/// HPKE-open) and the WebAuthn session-key path (via `reconstruct_outputs`,
/// fed plaintexts an external, JS-side HPKE-open already produced).
fn reconstruct_outputs_core(
    core: &ClientCore,
    output_count: usize,
    plaintexts: &[Vec<u8>],
) -> Result<Vec<Fr>, ClientError> {
    let mut by_output = vec![Vec::<RobustShare<Fr>>::new(); output_count];

    for plaintext in plaintexts {
        let shares = Vec::<RobustShare<Fr>>::deserialize_compressed(plaintext.as_slice())
            .map_err(|_| ClientError::InvalidShare)?;
        if shares.len() != output_count {
            return Err(ClientError::OutputArity {
                expected: output_count,
                actual: shares.len(),
            });
        }
        for (index, share) in shares.into_iter().enumerate() {
            by_output[index].push(share);
        }
    }

    by_output
        .iter()
        .map(|shares| recover_robust_secret(shares, core.parties, core.threshold))
        .collect()
}

fn scalar_share_type(value: ClientScalarType) -> Result<ShareType, ClientError> {
    match value {
        ClientScalarType::Boolean => Ok(ShareType::boolean()),
        ClientScalarType::SignedInteger { bit_length: 1 } => Err(ClientError::InvalidScalarType(
            "use the boolean type for one-bit secrets".to_owned(),
        )),
        ClientScalarType::SignedInteger { bit_length } => ShareType::try_secret_int(bit_length)
            .map_err(|error| ClientError::InvalidScalarType(error.to_string())),
        ClientScalarType::UnsignedInteger { bit_length } => ShareType::try_secret_uint(bit_length)
            .map_err(|error| ClientError::InvalidScalarType(error.to_string())),
        ClientScalarType::FixedPoint {
            total_bits,
            fractional_bits,
        } => ShareType::try_secret_fixed_point_from_bits(total_bits, fractional_bits)
            .map_err(|error| ClientError::InvalidScalarType(error.to_string())),
    }
}

fn typed_input_to_field(input: &TypedClientInput) -> Result<Fr, ClientError> {
    let share_type = scalar_share_type(input.share_type)?;
    match (share_type, &input.value) {
        (ShareType::SecretInt { bit_length: 1 }, ClientScalarValue::Boolean(value)) => {
            Ok(Fr::from(*value as u64))
        }
        (ShareType::SecretInt { bit_length: 1 }, ClientScalarValue::SignedInteger(value)) => {
            Ok(Fr::from((*value != 0) as u64))
        }
        (ShareType::SecretInt { .. }, ClientScalarValue::SignedInteger(value)) => {
            Ok(field_from_i64(*value))
        }
        (ShareType::SecretInt { .. }, ClientScalarValue::UnsignedInteger(value)) => {
            let value = i64::try_from(*value).map_err(|_| {
                ClientError::InvalidScalarValue(
                    "unsigned secret integer input exceeds the signed 64-bit range".to_owned(),
                )
            })?;
            Ok(field_from_i64(value))
        }
        (ShareType::SecretInt { bit_length, .. }, ClientScalarValue::Field(bytes))
            if bit_length > 1 =>
        {
            canonical_field_from_be_bytes(bytes)
        }
        (ShareType::SecretUInt { .. }, ClientScalarValue::Field(bytes)) => {
            canonical_field_from_be_bytes(bytes)
        }
        (ShareType::SecretUInt { bit_length }, ClientScalarValue::UnsignedInteger(value)) => {
            validate_secret_uint_range(*value, bit_length)?;
            Ok(Fr::from(*value))
        }
        (ShareType::SecretUInt { bit_length }, ClientScalarValue::SignedInteger(value)) => {
            let value = u64::try_from(*value).map_err(|_| {
                ClientError::InvalidScalarValue(
                    "signed input for a secret unsigned integer must be non-negative".to_owned(),
                )
            })?;
            validate_secret_uint_range(value, bit_length)?;
            Ok(Fr::from(value))
        }
        (ShareType::SecretFixedPoint { precision }, ClientScalarValue::SignedInteger(value)) => {
            fixed_point_integer_to_field(i128::from(*value), precision)
        }
        (ShareType::SecretFixedPoint { precision }, ClientScalarValue::UnsignedInteger(value)) => {
            fixed_point_integer_to_field(i128::from(*value), precision)
        }
        (ShareType::SecretFixedPoint { precision }, ClientScalarValue::FixedPoint(value)) => {
            encode_fixed_point_float(*value, precision)
                .map(field_from_i64)
                .map_err(|error| ClientError::InvalidScalarValue(error.to_string()))
        }
        (share_type, value) => Err(ClientError::InvalidScalarValue(format!(
            "value {value:?} is not compatible with {share_type:?}"
        ))),
    }
}

fn field_to_typed_value(
    value: Fr,
    share_type: ClientScalarType,
) -> Result<ClientScalarValue, ClientError> {
    match scalar_share_type(share_type)? {
        ShareType::SecretInt { bit_length: 1 } => Ok(ClientScalarValue::Boolean(!value.is_zero())),
        ShareType::SecretInt { .. } => field_to_i64(value).map(ClientScalarValue::SignedInteger),
        ShareType::SecretUInt { bit_length } => {
            field_to_u64(value, bit_length).map(ClientScalarValue::UnsignedInteger)
        }
        ShareType::SecretFixedPoint { precision } => {
            let encoded = field_to_i64(value)?;
            decode_fixed_point_float(encoded, precision)
                .map(ClientScalarValue::FixedPoint)
                .map_err(|error| ClientError::InvalidScalarValue(error.to_string()))
        }
    }
}

fn fixed_point_integer_to_field(
    value: i128,
    precision: FixedPointPrecision,
) -> Result<Fr, ClientError> {
    encode_fixed_point_integer(value, precision)
        .map(field_from_i64)
        .map_err(|error| ClientError::InvalidScalarValue(error.to_string()))
}

fn validate_secret_uint_range(value: u64, bit_length: usize) -> Result<(), ClientError> {
    if bit_length >= 64 || value < (1u64 << bit_length) {
        Ok(())
    } else {
        Err(ClientError::InvalidScalarValue(format!(
            "secret unsigned integer input {value} does not fit in {bit_length} bit(s)"
        )))
    }
}

fn field_to_u64(value: Fr, bit_length: usize) -> Result<u64, ClientError> {
    let bigint = value.into_bigint();
    let limbs = bigint.as_ref();
    if limbs.iter().skip(1).all(|limb| *limb == 0) {
        let value = limbs.first().copied().unwrap_or(0);
        validate_secret_uint_range(value, bit_length)?;
        Ok(value)
    } else {
        Err(ClientError::InvalidScalarValue(
            "field output cannot be represented as an unsigned 64-bit integer".to_owned(),
        ))
    }
}

fn canonical_field_from_be_bytes(bytes: &[u8]) -> Result<Fr, ClientError> {
    let field_bytes = Fr::MODULUS_BIT_SIZE.div_ceil(8) as usize;
    if bytes.len() != field_bytes {
        return Err(ClientError::InvalidScalarValue(format!(
            "BLS12-381 field input must be exactly {field_bytes} canonical big-endian bytes, got {}",
            bytes.len()
        )));
    }
    let value = Fr::from_be_bytes_mod_order(bytes);
    let encoded = value.into_bigint().to_bytes_be();
    let mut canonical = vec![0u8; field_bytes];
    let start = field_bytes.checked_sub(encoded.len()).ok_or_else(|| {
        ClientError::InvalidScalarValue("field input is not canonical".to_owned())
    })?;
    canonical[start..].copy_from_slice(&encoded);
    if canonical == bytes {
        Ok(value)
    } else {
        Err(ClientError::InvalidScalarValue(
            "field input must be less than the scalar-field modulus".to_owned(),
        ))
    }
}

fn to_js_value_with_bigints<T: Serialize>(value: &T) -> Result<JsValue, JsValue> {
    value
        .serialize(
            &serde_wasm_bindgen::Serializer::new().serialize_large_number_types_as_bigints(true),
        )
        .map_err(|error| ClientError::Js(error.to_string()).into())
}

/// JS-callable wrapper around `authentication_message`, for the WebAuthn
/// session-key path: the browser client library calls this to get the
/// exact same signature-base bytes the coordinator verifies against
/// (`crates/stoffel-mpc-coordinator/.../browser_rpc.rs`'s `authenticate()`),
/// rather than reimplementing this byte layout independently in JS where it
/// could drift out of sync. The library then appends the session token as
/// an additional signed field (see the plan) before signing with
/// `subtle.sign` - this function only builds the base, unmodified from what
/// `sign_request` already signs, to keep the two paths byte-compatible.
#[wasm_bindgen(js_name = authenticationMessage)]
pub fn authentication_message_js(
    method: &str,
    execution_id: &str,
    created: u64,
    nonce: &[u8],
    body: &[u8],
) -> Result<Vec<u8>, JsValue> {
    let execution_id = parse_execution_id(execution_id)?;
    Ok(authentication_message(method, &execution_id, created, nonce, body))
}

/// `created` bounds how long a signed request stays valid; `nonce` (16
/// CSPRNG-random bytes, generated fresh per request - see `random_nonce`)
/// is what actually prevents replay within that window. Neither alone is
/// enough: `created` has only second resolution, so distinct legitimate
/// requests routinely share a value, and a bare timestamp check doesn't stop
/// a captured request from being replayed anywhere inside the window.
pub fn authentication_message(
    method: &str,
    execution_id: &[u8; 32],
    created: u64,
    nonce: &[u8],
    body: &[u8],
) -> Vec<u8> {
    let body_hash = Sha256::digest(body);
    let mut message =
        Vec::with_capacity(AUTH_DOMAIN.len() + method.len() + 1 + 32 + 8 + nonce.len() + 32);
    message.extend_from_slice(AUTH_DOMAIN);
    message.push(0);
    message.extend_from_slice(method.as_bytes());
    message.push(0);
    message.extend_from_slice(execution_id);
    message.extend_from_slice(&created.to_le_bytes());
    message.extend_from_slice(nonce);
    message.extend_from_slice(&body_hash);
    message
}

/// 16 CSPRNG-random bytes (128 bits - collisions within any realistic
/// request volume and freshness window are negligible) for a fresh
/// per-request nonce. `getrandom` backs this uniformly on wasm32 (via its
/// "js" feature, browser `crypto.getRandomValues`) and on native targets
/// (an OS random source) - the latter is what makes this callable from
/// `cargo test`, not just from a real browser.
fn random_nonce() -> Result<[u8; 16], ClientError> {
    let mut nonce = [0u8; 16];
    getrandom::getrandom(&mut nonce).map_err(|_| ClientError::RandomGenerationFailed)?;
    Ok(nonce)
}

fn output_encryption_info(execution_id: &[u8; 32]) -> Vec<u8> {
    let mut info = Vec::with_capacity(OUTPUT_HPKE_DOMAIN.len() + execution_id.len());
    info.extend_from_slice(OUTPUT_HPKE_DOMAIN);
    info.extend_from_slice(execution_id);
    info
}

fn validate_topology(n: usize, t: usize) -> Result<(), ClientError> {
    if n == 0 || n > MAX_PARTIES || t == 0 || t > MAX_THRESHOLD || n < 3 * t + 1 {
        return Err(ClientError::InvalidTopology { n, t });
    }
    Ok(())
}

fn parse_execution_id(value: &str) -> Result<[u8; 32], ClientError> {
    if value.len() != 64 {
        return Err(ClientError::InvalidExecutionId);
    }
    hex::decode(value)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(ClientError::InvalidExecutionId)
}

fn field_from_i64(value: i64) -> Fr {
    if value >= 0 {
        Fr::from(value as u64)
    } else {
        -Fr::from(value.unsigned_abs())
    }
}

fn field_to_i64(value: Fr) -> Result<i64, ClientError> {
    let bigint = value.into_bigint();
    let negated = (-value).into_bigint();
    let to_u64 = |number: &<Fr as PrimeField>::BigInt| {
        let limbs = number.as_ref();
        limbs
            .iter()
            .skip(1)
            .all(|limb| *limb == 0)
            .then(|| limbs.first().copied().unwrap_or(0))
    };
    if !value.is_zero() && negated < bigint {
        let magnitude = to_u64(&negated).ok_or(ClientError::OutputRange)?;
        if magnitude == 1u64 << 63 {
            Ok(i64::MIN)
        } else {
            i64::try_from(magnitude)
                .map(|magnitude| -magnitude)
                .map_err(|_| ClientError::OutputRange)
        }
    } else {
        to_u64(&bigint)
            .and_then(|value| i64::try_from(value).ok())
            .ok_or(ClientError::OutputRange)
    }
}

fn recover_robust_secret(
    shares: &[RobustShare<Fr>],
    n: usize,
    t: usize,
) -> Result<Fr, ClientError> {
    if shares.is_empty() {
        return Err(ClientError::InsufficientShares);
    }
    let degree = shares[0].degree;
    if degree > t
        || shares
            .iter()
            .any(|share| share.degree != degree || share.id >= n)
    {
        return Err(ClientError::InconsistentShares);
    }
    let mut ids = HashSet::new();
    if shares.iter().any(|share| !ids.insert(share.id)) {
        return Err(ClientError::InconsistentShares);
    }
    let required = degree + t + 1;
    if shares.len() < required {
        return Err(ClientError::InsufficientShares);
    }
    let domain =
        Radix2EvaluationDomain::<Fr>::new(n).ok_or(ClientError::InvalidTopology { n, t })?;
    let subset_size = degree + 1;
    let mut best: Option<(usize, Fr)> = None;
    for_each_combination(shares.len(), subset_size, |indices| {
        let points = indices
            .iter()
            .map(|index| (domain.element(shares[*index].id), shares[*index].share[0]))
            .collect::<Vec<_>>();
        let secret = lagrange_evaluate(&points, Fr::zero());
        let agreement = shares
            .iter()
            .filter(|share| lagrange_evaluate(&points, domain.element(share.id)) == share.share[0])
            .count();
        if best.is_none_or(|(best_agreement, _)| agreement > best_agreement) {
            best = Some((agreement, secret));
        }
    });
    match best {
        Some((agreement, secret)) if agreement >= required => Ok(secret),
        _ => Err(ClientError::InsufficientShares),
    }
}

fn lagrange_evaluate(points: &[(Fr, Fr)], at: Fr) -> Fr {
    points
        .iter()
        .enumerate()
        .fold(Fr::zero(), |sum, (j, (xj, yj))| {
            let basis = points
                .iter()
                .enumerate()
                .filter(|(m, _)| *m != j)
                .fold(Fr::from(1u64), |product, (_, (xm, _))| {
                    product * (at - xm) / (*xj - *xm)
                });
            sum + (*yj * basis)
        })
}

fn for_each_combination(n: usize, k: usize, mut visit: impl FnMut(&[usize])) {
    if k == 0 || k > n {
        return;
    }
    let mut indices = (0..k).collect::<Vec<_>>();
    loop {
        visit(&indices);
        let mut position = k;
        while position > 0 {
            position -= 1;
            if indices[position] != position + n - k {
                break;
            }
        }
        if position == 0 && indices[0] == n - k {
            break;
        }
        indices[position] += 1;
        for next in position + 1..k {
            indices[next] = indices[next - 1] + 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hpke::{single_shot_seal, OpModeS, Serializable};
    use p256::ecdsa::{signature::Verifier, VerifyingKey};
    use rand::{rngs::StdRng, SeedableRng};
    use stoffelmpc_mpc::honeybadger::robust_interpolate::robust_interpolate::RobustShare as ProtocolRobustShare;

    fn shares(secret: Fr, n: usize, degree: usize) -> Vec<RobustShare<Fr>> {
        let domain = Radix2EvaluationDomain::<Fr>::new(n).unwrap();
        let slope = Fr::from(19u64);
        (0..n)
            .map(|id| {
                let x = domain.element(id);
                RobustShare::new(secret + slope * x, id, degree)
            })
            .collect()
    }

    #[test]
    fn reconstructs_with_one_corrupt_share() {
        let secret = field_from_i64(-41);
        let mut values = shares(secret, 5, 1);
        values[4].share[0] += Fr::from(7u64);
        assert_eq!(recover_robust_secret(&values, 5, 1).unwrap(), secret);
    }

    #[test]
    fn canonical_share_projection_round_trips() {
        let share = shares(Fr::from(9u64), 5, 1).remove(0);
        let mut bytes = Vec::new();
        share.serialize_compressed(&mut bytes).unwrap();
        assert_eq!(
            RobustShare::<Fr>::deserialize_compressed(bytes.as_slice()).unwrap(),
            share
        );
    }

    #[test]
    fn canonical_share_projection_matches_the_protocol_type() {
        let protocol_share = ProtocolRobustShare::new(Fr::from(29u64), 3, 1);
        let mut bytes = Vec::new();
        protocol_share.serialize_compressed(&mut bytes).unwrap();

        let projected = RobustShare::<Fr>::deserialize_compressed(bytes.as_slice()).unwrap();
        assert_eq!(projected.share, protocol_share.share);
        assert_eq!(projected.id, protocol_share.id);
        assert_eq!(projected.degree, protocol_share.degree);

        let mut projected_bytes = Vec::new();
        projected
            .serialize_compressed(&mut projected_bytes)
            .unwrap();
        let decoded =
            ProtocolRobustShare::<Fr>::deserialize_compressed(projected_bytes.as_slice()).unwrap();
        assert_eq!(decoded, protocol_share);
    }

    #[test]
    fn decrypts_protocol_output_batches_with_the_coordinator_domain() {
        let secret_key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let client = StoffelWasmClient::from_secret_key(secret_key, 5, 1).unwrap();
        let execution_id = [0x42; 32];
        let hpke_public = <KemImpl as Kem>::PublicKey::from_bytes(&client.core.public_key).unwrap();
        let domain = Radix2EvaluationDomain::<Fr>::new(5).unwrap();
        let expected = [17i64, -9, 120, 3];
        let mut encrypted = Vec::new();
        let mut rng = StdRng::seed_from_u64(41);

        for party_id in 0..3 {
            let x = domain.element(party_id);
            let shares = expected
                .iter()
                .enumerate()
                .map(|(output, value)| {
                    let evaluation = field_from_i64(*value) + Fr::from((output + 5) as u64) * x;
                    ProtocolRobustShare::new(evaluation, party_id, 1)
                })
                .collect::<Vec<_>>();
            let mut plaintext = Vec::new();
            shares.serialize_compressed(&mut plaintext).unwrap();
            let (encapped_key, ciphertext) = single_shot_seal::<AeadImpl, KdfImpl, KemImpl, _>(
                &OpModeS::Base,
                &hpke_public,
                &output_encryption_info(&execution_id),
                &plaintext,
                b"",
                &mut rng,
            )
            .unwrap();
            encrypted.push(EncryptedOutputShare {
                encapped_key: encapped_key.to_bytes().to_vec(),
                ciphertext,
            });
        }

        assert_eq!(
            decrypt_fields_core(&client.core, &execution_id, expected.len(), &encrypted).unwrap(),
            expected.map(field_from_i64)
        );
    }

    /// A fixed, deterministic HPKE vector shared with the browser client
    /// library's own test suite (`examples/shared/stoffel-browser-client/
    /// hpke.test.mjs` in the stoffel-browser-examples repo), which decrypts
    /// this exact `encapped_key`/`ciphertext` with `hpkeOpenP256` and
    /// asserts the same plaintext comes out. Regenerating the vector here
    /// (a different RNG seed, a dependency bump that changes encoding,
    /// etc.) without updating the JS side would silently break that
    /// cross-language contract - this test exists so that break shows up
    /// here first, not just as a mysterious decryption failure in a real
    /// browser.
    #[test]
    fn cross_language_hpke_vector_matches_the_js_client_library_fixture() {
        let secret_key = SecretKey::from_slice(&[3u8; 32]).unwrap();
        let public_key = secret_key
            .public_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec();
        let hpke_public = <KemImpl as Kem>::PublicKey::from_bytes(&public_key).unwrap();
        let execution_id = [0x11u8; 32];
        let info = output_encryption_info(&execution_id);
        let plaintext = b"cross-language HPKE vector";
        let mut rng = StdRng::seed_from_u64(1234);
        let (encapped_key, ciphertext) = single_shot_seal::<AeadImpl, KdfImpl, KemImpl, _>(
            &OpModeS::Base,
            &hpke_public,
            &info,
            plaintext,
            b"",
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            hex::encode(&public_key),
            "04591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61adf9f4e6abf0d045c0c693a3c68ad7c97ca72be64def4a26fecd263dd98a92780f0"
        );
        assert_eq!(
            hex::encode(encapped_key.to_bytes()),
            "042468a8ca249dad976fb8ae31c4ac1b0f37d3113c42b26fe59c4b97da95980038b28972a9a30ae9191e874bad8081335ffa3b1fea7e2dcc43785b9a4c5372e435"
        );
        assert_eq!(
            hex::encode(&ciphertext),
            "33a142eeecc7b58a3ca69ebd06845b26d340228518b0e8f66f4dc1f8a7f4c27c575c6f0226708248a612"
        );
    }

    /// The split `decrypt_fields_core` = HPKE-open (now done externally, in
    /// JS, for the WebAuthn session-key path) + `reconstruct_outputs_core`
    /// (unchanged math) must produce identical results either way.
    #[test]
    fn reconstruct_outputs_core_matches_decrypt_fields_core_given_the_same_plaintexts() {
        let secret_key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let client = StoffelWasmClient::from_secret_key(secret_key, 5, 1).unwrap();
        let execution_id = [0x42; 32];
        let hpke_public = <KemImpl as Kem>::PublicKey::from_bytes(&client.core.public_key).unwrap();
        let hpke_secret = <KemImpl as Kem>::PrivateKey::from_bytes(
            &client.core.secret_key.as_ref().unwrap().to_bytes(),
        )
        .unwrap();
        let domain = Radix2EvaluationDomain::<Fr>::new(5).unwrap();
        let expected = [17i64, -9, 120, 3];
        let mut encrypted = Vec::new();
        let mut rng = StdRng::seed_from_u64(41);

        for party_id in 0..3 {
            let x = domain.element(party_id);
            let shares = expected
                .iter()
                .enumerate()
                .map(|(output, value)| {
                    let evaluation = field_from_i64(*value) + Fr::from((output + 5) as u64) * x;
                    ProtocolRobustShare::new(evaluation, party_id, 1)
                })
                .collect::<Vec<_>>();
            let mut plaintext = Vec::new();
            shares.serialize_compressed(&mut plaintext).unwrap();
            let (encapped_key, ciphertext) = single_shot_seal::<AeadImpl, KdfImpl, KemImpl, _>(
                &OpModeS::Base,
                &hpke_public,
                &output_encryption_info(&execution_id),
                &plaintext,
                b"",
                &mut rng,
            )
            .unwrap();
            encrypted.push(EncryptedOutputShare {
                encapped_key: encapped_key.to_bytes().to_vec(),
                ciphertext,
            });
        }

        let via_decrypt_fields_core =
            decrypt_fields_core(&client.core, &execution_id, expected.len(), &encrypted).unwrap();

        // Mirror what an external (JS-side) HPKE-open produces: decrypt each
        // share independently into plaintext bytes, exactly as
        // `WebauthnSession.decryptShare` will, then feed those into
        // `reconstruct_outputs_core` instead of `decrypt_fields_core`.
        let plaintexts: Vec<Vec<u8>> = encrypted
            .iter()
            .map(|share| {
                let encapped =
                    <KemImpl as Kem>::EncappedKey::from_bytes(&share.encapped_key).unwrap();
                single_shot_open::<AeadImpl, KdfImpl, KemImpl>(
                    &OpModeR::Base,
                    &hpke_secret,
                    &encapped,
                    &output_encryption_info(&execution_id),
                    &share.ciphertext,
                    b"",
                )
                .unwrap()
            })
            .collect();

        let via_reconstruct_outputs_core =
            reconstruct_outputs_core(&client.core, expected.len(), &plaintexts).unwrap();

        assert_eq!(via_decrypt_fields_core, via_reconstruct_outputs_core);
        assert_eq!(via_reconstruct_outputs_core, expected.map(field_from_i64));
    }

    #[test]
    fn public_key_only_client_has_no_signing_or_secret_key_but_shares_topology() {
        let secret_key = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let full_client = StoffelWasmClient::from_secret_key(secret_key, 5, 1).unwrap();
        let public_key = full_client.core.public_key.clone();

        let client = StoffelWasmClient::from_public_key(&public_key, 5, 1).unwrap();
        assert_eq!(client.core.public_key, public_key);
        assert!(client.core.signing_key.is_none());
        assert!(client.core.secret_key.is_none());
        assert_eq!(client.core.parties, 5);
        assert_eq!(client.core.threshold, 1);
    }

    #[test]
    fn from_public_key_rejects_malformed_points() {
        assert!(StoffelWasmClient::from_public_key(&[0u8; 10], 5, 1).is_err());
    }

    #[test]
    fn decrypt_fields_core_errors_without_a_secret_key_instead_of_panicking() {
        let full_client =
            StoffelWasmClient::from_secret_key(SecretKey::from_slice(&[7u8; 32]).unwrap(), 5, 1)
                .unwrap();
        let public_client =
            StoffelWasmClient::from_public_key(&full_client.core.public_key, 5, 1).unwrap();
        let result = decrypt_fields_core(&public_client.core, &[0u8; 32], 1, &[]);
        assert!(matches!(result, Err(ClientError::NoSecretKey)));
    }

    /// The JS-callable wrapper must produce byte-identical output to the
    /// function `sign_request` itself signs with - this is what lets the
    /// browser client library build a signature base by calling into WASM
    /// instead of reimplementing this byte layout in JS, where it could
    /// silently drift out of sync with what the coordinator verifies.
    #[test]
    fn authentication_message_js_matches_the_internal_byte_layout() {
        let execution_id = [9u8; 32];
        let execution_id_hex = hex::encode(execution_id);
        let nonce = [7u8; 16];
        let expected = authentication_message(
            "browser_submit_masked_inputs",
            &execution_id,
            1_700_000_000,
            &nonce,
            b"payload",
        );
        let via_js = match authentication_message_js(
            "browser_submit_masked_inputs",
            &execution_id_hex,
            1_700_000_000,
            &nonce,
            b"payload",
        ) {
            Ok(bytes) => bytes,
            Err(_) => panic!("authentication_message_js unexpectedly failed"),
        };
        assert_eq!(expected, via_js);
    }

    // Not tested directly: authentication_message_js's error path (a
    // malformed execution id) converts ClientError into a JsValue via
    // js_sys::Error::new, which panics on non-wasm test targets ("cannot
    // call wasm-bindgen imported functions on non-wasm targets") - this is
    // a native-test-harness limitation, not a code path issue. The
    // validation itself (parse_execution_id's length/hex check) is
    // exercised directly by other tests.

    #[test]
    fn authentication_message_is_signed_by_the_client_identity() {
        let secret = SecretKey::from_slice(&[7u8; 32]).unwrap();
        let client = StoffelWasmClient::from_secret_key(secret, 5, 1).unwrap();
        let execution = [3u8; 32];
        let nonce = [4u8; 16];
        let message = authentication_message("browser_round", &execution, 1_700_000_000, &nonce, b"body");
        let signature: Signature = client.core.signing_key.as_ref().unwrap().sign(&message);
        let verifier = VerifyingKey::from_sec1_bytes(&client.core.public_key).unwrap();
        verifier.verify(&message, &signature).unwrap();
    }

    #[test]
    fn random_nonce_is_16_bytes_and_not_trivially_repeated() {
        let a = random_nonce().unwrap();
        let b = random_nonce().unwrap();
        assert_eq!(a.len(), 16);
        assert_ne!(a, b);
    }

    // Not tested directly: `sign_request` itself, on a native test target -
    // it calls `js_sys::Date::now()` for `created`, which (like
    // `js_sys::Error::new` above) panics with "cannot call wasm-bindgen
    // imported functions on non-wasm targets" outside a real wasm+JS
    // environment. Its two real ingredients are covered directly instead:
    // `authentication_message_is_signed_by_the_client_identity` (the
    // signature/byte-layout side) and
    // `random_nonce_is_16_bytes_and_not_trivially_repeated` (the nonce
    // side) - between them, everything `sign_request` assembles is
    // exercised, just not through the wasm-bindgen boundary itself.

    #[test]
    fn signed_field_values_decode_both_directions() {
        for expected in [i64::MIN, -100, -1, 0, 1, 100, i64::MAX] {
            assert_eq!(field_to_i64(field_from_i64(expected)).unwrap(), expected);
        }
    }

    #[test]
    fn typed_inputs_cover_native_scalar_client_values() {
        let cases = [
            (
                TypedClientInput {
                    share_type: ClientScalarType::Boolean,
                    value: ClientScalarValue::Boolean(true),
                },
                Fr::from(1u64),
            ),
            (
                TypedClientInput {
                    share_type: ClientScalarType::Boolean,
                    value: ClientScalarValue::SignedInteger(0),
                },
                Fr::from(0u64),
            ),
            (
                TypedClientInput {
                    share_type: ClientScalarType::SignedInteger { bit_length: 64 },
                    value: ClientScalarValue::SignedInteger(-91),
                },
                field_from_i64(-91),
            ),
            (
                TypedClientInput {
                    share_type: ClientScalarType::UnsignedInteger { bit_length: 16 },
                    value: ClientScalarValue::UnsignedInteger(65_535),
                },
                Fr::from(65_535u64),
            ),
            (
                TypedClientInput {
                    share_type: ClientScalarType::FixedPoint {
                        total_bits: 64,
                        fractional_bits: 16,
                    },
                    value: ClientScalarValue::FixedPoint(1.5),
                },
                field_from_i64(98_304),
            ),
            (
                TypedClientInput {
                    share_type: ClientScalarType::FixedPoint {
                        total_bits: 32,
                        fractional_bits: 8,
                    },
                    value: ClientScalarValue::SignedInteger(-2),
                },
                field_from_i64(-512),
            ),
        ];

        for (input, expected) in cases {
            assert_eq!(typed_input_to_field(&input).unwrap(), expected);
        }
    }

    #[test]
    fn typed_outputs_preserve_semantic_types() {
        assert_eq!(
            field_to_typed_value(Fr::from(2u64), ClientScalarType::Boolean).unwrap(),
            ClientScalarValue::Boolean(true)
        );
        assert_eq!(
            field_to_typed_value(
                field_from_i64(i64::MIN),
                ClientScalarType::SignedInteger { bit_length: 64 }
            )
            .unwrap(),
            ClientScalarValue::SignedInteger(i64::MIN)
        );
        assert_eq!(
            field_to_typed_value(
                Fr::from(u64::MAX),
                ClientScalarType::UnsignedInteger { bit_length: 64 }
            )
            .unwrap(),
            ClientScalarValue::UnsignedInteger(u64::MAX)
        );
        assert_eq!(
            field_to_typed_value(
                field_from_i64(-32_768),
                ClientScalarType::FixedPoint {
                    total_bits: 64,
                    fractional_bits: 16,
                }
            )
            .unwrap(),
            ClientScalarValue::FixedPoint(-0.5)
        );
    }

    #[test]
    fn typed_inputs_reject_range_and_kind_mismatches() {
        let too_wide = TypedClientInput {
            share_type: ClientScalarType::UnsignedInteger { bit_length: 8 },
            value: ClientScalarValue::UnsignedInteger(256),
        };
        assert!(typed_input_to_field(&too_wide).is_err());

        let negative_unsigned = TypedClientInput {
            share_type: ClientScalarType::UnsignedInteger { bit_length: 64 },
            value: ClientScalarValue::SignedInteger(-1),
        };
        assert!(typed_input_to_field(&negative_unsigned).is_err());

        // This intentionally mirrors the native client's compatibility path:
        // unsigned values supplied for a signed share are accepted when they
        // fit in i64, including the one-bit representation used for booleans.
        let bool_as_unsigned = TypedClientInput {
            share_type: ClientScalarType::Boolean,
            value: ClientScalarValue::UnsignedInteger(1),
        };
        assert_eq!(
            typed_input_to_field(&bool_as_unsigned).unwrap(),
            Fr::from(1u64)
        );

        assert!(scalar_share_type(ClientScalarType::SignedInteger { bit_length: 1 }).is_err());
        assert!(scalar_share_type(ClientScalarType::UnsignedInteger { bit_length: 0 }).is_err());
    }

    #[test]
    fn canonical_field_input_accepts_the_full_scalar_range_only() {
        let field_bytes = Fr::MODULUS_BIT_SIZE.div_ceil(8) as usize;
        let value = Fr::from(123u64);
        let encoded = value.into_bigint().to_bytes_be();
        let mut canonical = vec![0u8; field_bytes];
        canonical[field_bytes - encoded.len()..].copy_from_slice(&encoded);
        assert_eq!(canonical_field_from_be_bytes(&canonical).unwrap(), value);

        let modulus = Fr::MODULUS.to_bytes_be();
        let mut non_canonical = vec![0u8; field_bytes];
        non_canonical[field_bytes - modulus.len()..].copy_from_slice(&modulus);
        assert!(canonical_field_from_be_bytes(&non_canonical).is_err());
        assert!(canonical_field_from_be_bytes(&canonical[1..]).is_err());
    }

}
