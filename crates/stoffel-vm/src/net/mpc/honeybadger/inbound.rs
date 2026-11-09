//! Keep peers running ahead from consuming every protocol session slot.
use super::{HoneyBadgerMPCNode, RBCImpl, SupportedMpcField};
use bincode::Options;
use std::collections::{HashMap, HashSet, VecDeque};
use stoffelmpc_mpc::common::ProtocolSessionId;
use stoffelmpc_mpc::honeybadger::{ProtocolType, SessionId, WrappedMessage};

// Each parent can create two BatchRecon children. Leave ample room under the
// upstream per-peer child limit (256 / n), including locally initiated work.
const SPECULATIVE_PARENTS: usize = 16;
const MAX_PENDING_MESSAGES: usize = 16_384;
const MAX_PENDING_BYTES: usize = 64 * 1024 * 1024;

struct Pending {
    sender: usize,
    payload: Vec<u8>,
    parent: Option<(ProtocolType, SessionId)>,
}

/// Bounded raw-message backlog. Existing sessions always remain processable;
/// future multiplication sessions wait for the local VM to catch up instead of
/// hitting upstream admission limits and silently losing reliable messages.
#[derive(Default)]
pub struct HoneyBadgerInboundQueue {
    pending: VecDeque<Pending>,
    bytes: usize,
    peers: HashMap<usize, (usize, usize)>,
}

impl HoneyBadgerInboundQueue {
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty()
    }

    pub fn push(&mut self, sender: usize, payload: Vec<u8>) -> Result<(), String> {
        let (peer_messages, peer_bytes) = self.peers.get(&sender).copied().unwrap_or_default();
        if peer_messages >= MAX_PENDING_MESSAGES / 4
            || payload.len() > (MAX_PENDING_BYTES / 4).saturating_sub(peer_bytes)
            || self.pending.len() >= MAX_PENDING_MESSAGES
            || payload.len() > MAX_PENDING_BYTES.saturating_sub(self.bytes)
        {
            return Err("HoneyBadger inbound backlog limit exceeded".into());
        }
        let parent = multiplication_parent(&payload);
        self.bytes += payload.len();
        self.peers
            .insert(sender, (peer_messages + 1, peer_bytes + payload.len()));
        self.pending.push_back(Pending {
            sender,
            payload,
            parent,
        });
        Ok(())
    }

    pub async fn pop_ready<F: SupportedMpcField>(
        &mut self,
        node: &HoneyBadgerMPCNode<F, RBCImpl>,
    ) -> Option<(usize, Vec<u8>)> {
        if self.pending.is_empty() {
            return None;
        }
        let mul = node.operations.mul.mult_storage.lock().await;
        let mut mul_ids: HashSet<_> = mul.iter().map(|(id, _)| *id).collect();
        drop(mul);
        let children = node.operations.mul.batch_recon.store.lock().await;
        mul_ids.extend(children.iter().map(|(id, _)| parent_id(*id)));
        drop(children);
        let fp = node.type_ops.fpmul.mult_node.mult_storage.lock().await;
        let mut fp_ids: HashSet<_> = fp.iter().map(|(id, _)| *id).collect();
        drop(fp);
        let children = node.type_ops.fpmul.mult_node.batch_recon.store.lock().await;
        fp_ids.extend(children.iter().map(|(id, _)| parent_id(*id)));
        drop(children);
        let index = self
            .pending
            .iter()
            .position(|message| match message.parent {
                None => true,
                Some((kind, id)) => {
                    let ids = if kind == ProtocolType::Mul {
                        &mul_ids
                    } else {
                        &fp_ids
                    };
                    ids.len()
                        < SPECULATIVE_PARENTS
                            .min((256 / node.params.n_parties).saturating_sub(2) / 2)
                            .max(1)
                        || ids.contains(&id)
                }
            })?;
        let message = self.pending.remove(index)?;
        self.bytes -= message.payload.len();
        let peer = self
            .peers
            .get_mut(&message.sender)
            .expect("queued peer accounting");
        peer.0 -= 1;
        peer.1 -= message.payload.len();
        if peer.0 == 0 {
            self.peers.remove(&message.sender);
        }
        Some((message.sender, message.payload))
    }
}

fn parent_id(id: SessionId) -> SessionId {
    SessionId::new(
        id.calling_protocol().expect("valid protocol session"),
        SessionId::pack_slot(id.exec_id(), 0, 0),
        id.instance_id(),
    )
}

fn multiplication_parent(payload: &[u8]) -> Option<(ProtocolType, SessionId)> {
    // Match the upstream wire encoding and allocation limit. Malformed frames
    // still go through the protocol's normal validation/error handling.
    let message: WrappedMessage = bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .with_limit(10 * 1024 * 1024)
        .allow_trailing_bytes()
        .deserialize(payload)
        .ok()?;
    let id = match message {
        WrappedMessage::Mult(message) => message.session_id,
        WrappedMessage::BatchRecon(message) => message.session_id,
        WrappedMessage::Rbc(message) => message.session_id,
        _ => return None,
    };
    let kind = id.calling_protocol()?;
    if !matches!(kind, ProtocolType::Mul | ProtocolType::FpMul) {
        return None;
    }
    Some((kind, parent_id(id)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::net::mpc::honeybadger::{
        HoneyBadgerEngineConfig, HoneyBadgerMpcEngine, HoneyBadgerPreprocessingConfig,
    };
    use crate::net::MpcSessionConfig;
    use std::sync::Arc;
    use stoffelmpc_mpc::honeybadger::mul::MultMessage;
    use stoffelnet::transports::quic::QuicNetworkManager;

    #[tokio::test]
    async fn future_messages_do_not_block_current_session_or_other_protocols() {
        let session =
            MpcSessionConfig::try_new(918273, 0, 5, 1, Arc::new(QuicNetworkManager::new()))
                .unwrap();
        let engine =
            HoneyBadgerMpcEngine::<ark_bls12_381::Fr, ark_bls12_381::G1Projective>::from_config(
                HoneyBadgerEngineConfig::new(session, HoneyBadgerPreprocessingConfig::new(2048, 0)),
            )
            .unwrap();
        let node = engine.clone_node().await;
        let id = |counter| {
            SessionId::new(
                ProtocolType::Mul,
                SessionId::pack_slot(counter, 0, 0),
                node.params.instance_id,
            )
        };
        let frame = |counter| {
            bincode::serialize(&WrappedMessage::Mult(MultMessage::new(
                1,
                id(counter),
                vec![],
            )))
            .unwrap()
        };
        for counter in 0..15 {
            assert!(node
                .operations
                .mul
                .get_or_create_mult_storage(id(counter), 1)
                .await
                .is_some());
        }
        node.operations
            .mul
            .batch_recon
            .store
            .lock()
            .await
            .get_or_create_with(
                SessionId::new(
                    ProtocolType::Mul,
                    SessionId::pack_slot(15, 1, 1),
                    node.params.instance_id,
                ),
                || {
                    (
                        1,
                        std::time::Instant::now(),
                        Arc::new(futures::lock::Mutex::new(
                            stoffelmpc_mpc::honeybadger::batch_recon::BatchReconStore::empty(),
                        )),
                    )
                },
            )
            .unwrap();
        let mut queue = HoneyBadgerInboundQueue::default();
        // AES batches use a child BatchRecon ID; it must count against the
        // parent multiplication's window, not open a separate admission path.
        let mut future = bincode::serialize(&WrappedMessage::BatchRecon(
            stoffelmpc_mpc::honeybadger::batch_recon::BatchReconMsg::new(
                1,
                SessionId::new(
                    ProtocolType::Mul,
                    SessionId::pack_slot(16, 1, 1),
                    node.params.instance_id,
                ),
                stoffelmpc_mpc::honeybadger::batch_recon::BatchReconMsgType::EvalBatch,
                vec![],
            ),
        ))
        .unwrap();
        future.extend_from_slice(&[0, 0]); // Upstream accepts trailing wire bytes.
        let current = frame(0);
        queue.push(1, future.clone()).unwrap();
        queue.push(1, current.clone()).unwrap();
        queue.push(2, vec![255]).unwrap(); // Normal decoder still handles invalid frames.
        assert_eq!(queue.pop_ready(&node).await, Some((1, current)));
        assert_eq!(queue.pop_ready(&node).await, Some((2, vec![255])));
        assert!(queue.pop_ready(&node).await.is_none());
        node.operations.mul.mult_storage.lock().await.retire(id(0));
        assert_eq!(queue.pop_ready(&node).await, Some((1, future)));
        assert_eq!(queue.bytes, 0);
        assert!(queue.pop_ready(&node).await.is_none());
    }
}
