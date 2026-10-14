//! Party-process HPKE sealing, wire-compatible with Analytics browser-mask-transport.
use super::{rpc_error, BrowserCall};
use hpke::{
    aead::AesGcm256,
    kdf::HkdfSha256,
    kem::{DhP256HkdfSha256, Kem},
    Deserializable, OpModeS, Serializable,
};
use jsonrpsee::core::RpcResult;
use p256::ecdsa::{signature::Signer, Signature, SigningKey};
use rand::TryRngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DOMAIN: &[u8] = b"StoffelAssignedMaskResponse-v1\0";
const LIMIT: usize = 65536;
type K = DhP256HkdfSha256;

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Envelope {
    version: u8,
    encapped_key: Vec<u8>,
    ciphertext: Vec<u8>,
    signature: Vec<u8>,
}
fn failure() -> jsonrpsee::types::ErrorObjectOwned {
    rpc_error(-32052, "mask response sealing failed")
}
fn context(call: &BrowserCall, party: &[u8]) -> RpcResult<Vec<u8>> {
    if call.request.public_key.len() != 65 || party.len() != 65 || call.request.body.len() > LIMIT {
        return Err(failure());
    }
    let range: super::MaskRange = super::parse_body(&call.request.body)?;
    if range.count != 1 {
        return Err(failure());
    }
    let mut binding = DOMAIN.to_vec();
    binding.extend_from_slice(call.execution_id.as_bytes());
    binding.extend_from_slice(&call.request.public_key);
    binding.extend_from_slice(&call.request.nonce.to_be_bytes());
    binding.extend_from_slice(&Sha256::digest(&call.request.body));
    binding.extend_from_slice(party);
    Ok(binding)
}
fn signed_message(binding: &[u8], envelope: &Envelope) -> RpcResult<Vec<u8>> {
    if envelope.version != 1
        || envelope.encapped_key.len() != 65
        || !(16..=LIMIT).contains(&envelope.ciphertext.len())
    {
        return Err(failure());
    }
    let mut message = binding.to_vec();
    message.push(envelope.version);
    message.extend_from_slice(&envelope.encapped_key);
    message.extend_from_slice(&(envelope.ciphertext.len() as u64).to_be_bytes());
    message.extend_from_slice(&envelope.ciphertext);
    Ok(message)
}
/// Call only after authenticate(); recipient and raw signed body come from that call.
pub(super) fn seal(
    party: &SigningKey,
    call: &BrowserCall,
    result: &Option<Vec<crate::AssignedMaskShare>>,
) -> RpcResult<Envelope> {
    let binding = context(
        call,
        party.verifying_key().to_encoded_point(false).as_bytes(),
    )?;
    let range: super::MaskRange = super::parse_body(&call.request.body)?;
    if result
        .as_ref()
        .is_some_and(|shares| shares.len() != 1 || shares[0].reserved_index != range.start)
    {
        return Err(failure());
    }
    let plaintext = serde_json::to_vec(result).map_err(|_| failure())?;
    if plaintext.len() > LIMIT - 16 {
        return Err(failure());
    }
    let public =
        <K as Kem>::PublicKey::from_bytes(&call.request.public_key).map_err(|_| failure())?;
    let (encapped, ciphertext) = hpke::single_shot_seal::<AesGcm256, HkdfSha256, K, _>(
        &OpModeS::Base,
        &public,
        &binding,
        &plaintext,
        &binding,
        &mut rand::rngs::OsRng.unwrap_err(),
    )
    .map_err(|_| failure())?;
    let mut envelope = Envelope {
        version: 1,
        encapped_key: encapped.to_bytes().to_vec(),
        ciphertext,
        signature: Vec::new(),
    };
    let signature: Signature = party.sign(&signed_message(&binding, &envelope)?);
    envelope.signature = signature.to_bytes().to_vec();
    Ok(envelope)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::{
        ecdsa::{signature::Verifier, VerifyingKey},
        SecretKey,
    };
    fn key(n: u8) -> SecretKey {
        SecretKey::from_slice(&[n; 32]).unwrap()
    }
    fn fixture() -> (SecretKey, SigningKey, BrowserCall) {
        let recipient = key(1);
        let party = SigningKey::from(key(2));
        let call = serde_json::from_value(serde_json::json!({"execution_id":vec![3u8;32],"request":{
            "public_key":recipient.public_key().to_sec1_bytes().to_vec(),"nonce":0x0102030405060708u64,
            "signature":[],"body":br#"{"start":0,"count":1}"#.to_vec()}})).unwrap();
        (recipient, party, call)
    }
    fn open(
        recipient: &SecretKey,
        party: &VerifyingKey,
        call: &BrowserCall,
        envelope: &Envelope,
    ) -> Result<Vec<u8>, ()> {
        let binding = context(call, party.to_encoded_point(false).as_bytes()).map_err(|_| ())?;
        party
            .verify(
                &signed_message(&binding, envelope).map_err(|_| ())?,
                &Signature::from_slice(&envelope.signature).map_err(|_| ())?,
            )
            .map_err(|_| ())?;
        let secret = <K as Kem>::PrivateKey::from_bytes(&recipient.to_bytes()).map_err(|_| ())?;
        let encapped =
            <K as Kem>::EncappedKey::from_bytes(&envelope.encapped_key).map_err(|_| ())?;
        hpke::single_shot_open::<AesGcm256, HkdfSha256, K>(
            &hpke::OpModeR::Base,
            &secret,
            &encapped,
            &binding,
            &envelope.ciphertext,
            &binding,
        )
        .map_err(|_| ())
    }
    #[test]
    fn real_recipient_opens_shares_and_null() {
        let (recipient, party, call) = fixture();
        for result in [
            None,
            Some(vec![crate::AssignedMaskShare {
                reserved_index: 0,
                share_bytes: vec![123, 45, 67],
            }]),
        ] {
            let envelope = seal(&party, &call, &result).unwrap();
            assert_eq!(
                open(&recipient, party.verifying_key(), &call, &envelope).unwrap(),
                serde_json::to_vec(&result).unwrap()
            );
            assert!(!serde_json::to_string(&envelope)
                .unwrap()
                .contains("share_bytes"));
        }
    }
    #[test]
    fn rejects_wrong_keys_and_every_binding_tamper() {
        let (recipient, party, call) = fixture();
        let envelope = seal(&party, &call, &None).unwrap();
        assert!(open(&key(4), party.verifying_key(), &call, &envelope).is_err());
        assert!(open(
            &recipient,
            SigningKey::from(key(5)).verifying_key(),
            &call,
            &envelope
        )
        .is_err());
        for field in 0..4 {
            let mut changed = call.clone();
            match field {
                0 => {
                    changed.execution_id =
                        serde_json::from_value(serde_json::json!(vec![4u8; 32])).unwrap()
                }
                1 => changed.request.nonce += 1,
                2 => changed.request.body.push(b' '),
                _ => changed.request.public_key = key(4).public_key().to_sec1_bytes().to_vec(),
            }
            assert!(open(&recipient, party.verifying_key(), &changed, &envelope).is_err());
        }
        for field in 0..4 {
            let mut changed = envelope.clone();
            match field {
                0 => changed.version = 2,
                1 => changed.encapped_key[1] ^= 1,
                2 => changed.ciphertext[0] ^= 1,
                _ => changed.signature[0] ^= 1,
            }
            assert!(open(&recipient, party.verifying_key(), &call, &changed).is_err());
        }
    }
}
