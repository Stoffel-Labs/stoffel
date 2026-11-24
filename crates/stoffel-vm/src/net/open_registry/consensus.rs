use super::wire::MAX_WIRE_MESSAGE_LEN;
use super::{InstanceRegistry, RbcCandidateOwner, RbcProgress, RbcRelay, RbcRelayPhase, RbcState};

const MAX_RBC_PAYLOAD_LEN: usize = MAX_WIRE_MESSAGE_LEN / 4;
/// Undelivered broadcasts one party may have pending at a peer at once.
pub(super) const MAX_PENDING_RBC_CANDIDATES_PER_BROADCASTER: usize = 8;
const MAX_PENDING_RBC_PAYLOAD_BYTES_PER_BROADCASTER: usize =
    MAX_PENDING_RBC_CANDIDATES_PER_BROADCASTER * MAX_RBC_PAYLOAD_LEN;
/// Payloads one peer may hold at a recipient on behalf of other broadcasters, before the
/// broadcaster's VAL takes over the charge.
const MAX_PENDING_RBC_CANDIDATES_PER_RELAY: usize = 1;
const MAX_PENDING_RBC_PAYLOAD_BYTES_PER_RELAY: usize = MAX_RBC_PAYLOAD_LEN;
/// Each authenticated party can hold at most one window plus one relay slot, so the
/// aggregate limits below only bind once 9 * n exceeds them (n > 28).
const MAX_PENDING_RBC_CANDIDATES: usize = 256;
const MAX_PENDING_RBC_PAYLOAD_BYTES: usize = 64 * MAX_WIRE_MESSAGE_LEN;
const MAX_ORPHAN_READY_KEYS_PER_SENDER: usize = 16;
pub(super) const MAX_ORPHAN_ECHO_KEYS_PER_SENDER: usize = 16;

/// Prefix of errors returned when a well-formed RBC frame was refused for lack of room.
pub(crate) const RBC_CAPACITY_ERROR_PREFIX: &str = "RBC capacity:";

type CandidateKey = (u64, usize, [u8; 32]);

fn capacity_error(detail: String) -> String {
    format!("{RBC_CAPACITY_ERROR_PREFIX} {detail}")
}

fn is_capacity_error(error: &str) -> bool {
    error.starts_with(RBC_CAPACITY_ERROR_PREFIX)
}

/// The quota that pays for `key` when `sender` supplies its payload.
fn owner_for(key: &CandidateKey, sender: usize) -> RbcCandidateOwner {
    if sender == key.1 {
        RbcCandidateOwner::Broadcaster(sender)
    } else {
        RbcCandidateOwner::Relay(sender)
    }
}

fn owner_limits(owner: RbcCandidateOwner) -> (usize, usize) {
    match owner {
        RbcCandidateOwner::Broadcaster(_) => (
            MAX_PENDING_RBC_CANDIDATES_PER_BROADCASTER,
            MAX_PENDING_RBC_PAYLOAD_BYTES_PER_BROADCASTER,
        ),
        RbcCandidateOwner::Relay(_) => (
            MAX_PENDING_RBC_CANDIDATES_PER_RELAY,
            MAX_PENDING_RBC_PAYLOAD_BYTES_PER_RELAY,
        ),
    }
}

fn owner_label(owner: RbcCandidateOwner) -> String {
    match owner {
        RbcCandidateOwner::Broadcaster(party) => format!("broadcaster {party} pending window"),
        RbcCandidateOwner::Relay(party) => format!("relay {party} candidate quota"),
    }
}

/// Candidate count and retained bytes charged to `owner`, ignoring `except`.
fn owner_usage(
    registry: &RbcState,
    owner: RbcCandidateOwner,
    except: Option<&CandidateKey>,
) -> Result<(usize, usize), String> {
    registry
        .candidate_owners
        .iter()
        .filter(|(key, candidate_owner)| **candidate_owner == owner && Some(*key) != except)
        .try_fold((0usize, 0usize), |(count, bytes), (key, _)| {
            let len = registry.candidates.get(key).map_or(0, Vec::len);
            Some((count + 1, bytes.checked_add(len)?))
        })
        .ok_or_else(|| "RBC retained payload byte count overflowed".to_string())
}

/// A relay candidate that no VAL vouches for: either no VAL arrived for its session, or
/// the VAL named a different digest. Evicting it never loses an honest broadcaster's
/// payload, because that broadcaster's VAL re-supplies it.
fn evictable_relay_candidate(registry: &RbcState, relay: usize) -> Option<CandidateKey> {
    registry
        .candidate_owners
        .iter()
        .filter(|(key, owner)| {
            **owner == RbcCandidateOwner::Relay(relay)
                && registry.messages.get(&(key.0, key.1)) != Some(&key.2)
        })
        .map(|(key, _)| *key)
        .min()
}

fn reclaim_delivered_rbc_state(registry: &mut RbcState) {
    if registry.receivers.is_empty() {
        return;
    }
    let completed = registry
        .candidates
        .keys()
        .filter_map(|(session_id, party, _)| {
            registry
                .receivers
                .iter()
                .all(|receiver| {
                    *receiver == *party
                        || registry
                            .delivered
                            .contains(&(*receiver, *party, *session_id))
                })
                .then_some((*session_id, *party))
        })
        .collect::<std::collections::HashSet<_>>();
    if completed.is_empty() {
        return;
    }
    registry
        .messages
        .retain(|(session_id, party), _| !completed.contains(&(*session_id, *party)));
    registry
        .candidates
        .retain(|(session_id, party, _), _| !completed.contains(&(*session_id, *party)));
    registry
        .candidate_owners
        .retain(|(session_id, party, _), _| !completed.contains(&(*session_id, *party)));
    registry
        .echoes
        .retain(|(session_id, party, _), _| !completed.contains(&(*session_id, *party)));
    registry
        .readies
        .retain(|(session_id, party, _), _| !completed.contains(&(*session_id, *party)));
    registry
        .sent_echoes
        .retain(|(_, party, session_id)| !completed.contains(&(*session_id, *party)));
    registry
        .sent_readies
        .retain(|(_, party, session_id)| !completed.contains(&(*session_id, *party)));
}

/// Checks that a new candidate fits its owner's quota and the aggregate limits.
///
/// A full relay slot is freed by evicting a candidate that no VAL vouches for; the key to
/// evict is returned so the caller can apply it together with the insertion. Errors caused
/// by lack of room start with [`RBC_CAPACITY_ERROR_PREFIX`].
fn admit_rbc_candidate(
    registry: &mut RbcState,
    owner: RbcCandidateOwner,
    message_len: usize,
) -> Result<Option<CandidateKey>, String> {
    reclaim_delivered_rbc_state(registry);
    if message_len > MAX_RBC_PAYLOAD_LEN {
        return Err(format!(
            "RBC payload is {message_len} bytes (max {MAX_RBC_PAYLOAD_LEN})"
        ));
    }
    let (max_count, max_bytes) = owner_limits(owner);
    let evict = match owner {
        RbcCandidateOwner::Relay(relay) if owner_usage(registry, owner, None)?.0 >= max_count => {
            evictable_relay_candidate(registry, relay)
        }
        _ => None,
    };
    let evicted_len = evict
        .as_ref()
        .and_then(|key| registry.candidates.get(key))
        .map_or(0, Vec::len);

    let (count, bytes) = owner_usage(registry, owner, evict.as_ref())?;
    if count >= max_count {
        return Err(capacity_error(format!(
            "{} is full (max {max_count})",
            owner_label(owner)
        )));
    }
    let retained = bytes
        .checked_add(message_len)
        .ok_or_else(|| "RBC retained payload byte count overflowed".to_string())?;
    if retained > max_bytes {
        return Err(capacity_error(format!(
            "{} retained payload budget exceeded: {retained} bytes (max {max_bytes})",
            owner_label(owner)
        )));
    }

    let aggregate_count = registry.candidates.len() - usize::from(evict.is_some());
    if aggregate_count >= MAX_PENDING_RBC_CANDIDATES {
        return Err(capacity_error(format!(
            "RBC aggregate candidate budget is full (max {MAX_PENDING_RBC_CANDIDATES})"
        )));
    }
    let aggregate_retained = registry
        .candidates
        .values()
        .try_fold(0usize, |total, message| total.checked_add(message.len()))
        .map(|total| total - evicted_len)
        .and_then(|total| total.checked_add(message_len))
        .ok_or_else(|| "RBC aggregate retained payload byte count overflowed".to_string())?;
    if aggregate_retained > MAX_PENDING_RBC_PAYLOAD_BYTES {
        return Err(capacity_error(format!(
            "RBC aggregate retained payload budget exceeded: {aggregate_retained} bytes (max {MAX_PENDING_RBC_PAYLOAD_BYTES})"
        )));
    }
    Ok(evict)
}

fn store_rbc_candidate(
    registry: &mut RbcState,
    key: CandidateKey,
    owner: RbcCandidateOwner,
    message: Vec<u8>,
    evict: Option<CandidateKey>,
) {
    if let Some(evicted) = evict {
        // Votes stay recorded; a later ECHO or the VAL can re-supply the payload.
        registry.candidates.remove(&evicted);
        registry.candidate_owners.remove(&evicted);
        tracing::debug!(
            session_id = evicted.0,
            broadcaster = evicted.1,
            ?owner,
            "Evicted RBC relay candidate without a matching VAL"
        );
    }
    registry.candidates.insert(key, message);
    registry.candidate_owners.insert(key, owner);
}

/// Retains a payload supplied by its own broadcaster (a VAL, or the local broadcast).
fn accept_broadcaster_payload(
    registry: &mut RbcState,
    key: CandidateKey,
    message: Vec<u8>,
) -> Result<(), String> {
    let owner = RbcCandidateOwner::Broadcaster(key.1);
    if registry.candidates.contains_key(&key) {
        // A relay supplied this payload first. Move the charge to the broadcaster when its
        // window has room, which frees the relay's slot; otherwise the relay keeps it.
        if registry.candidate_owners.get(&key) != Some(&owner) {
            let (max_count, max_bytes) = owner_limits(owner);
            let (count, bytes) = owner_usage(registry, owner, Some(&key))?;
            if count < max_count && bytes.saturating_add(message.len()) <= max_bytes {
                registry.candidate_owners.insert(key, owner);
            }
        }
        return Ok(());
    }
    let evict = admit_rbc_candidate(registry, owner, message.len())?;
    store_rbc_candidate(registry, key, owner, message, evict);
    Ok(())
}

impl InstanceRegistry {
    pub(crate) fn insert_rbc_broadcast(
        &self,
        session_id: u64,
        party_id: usize,
        message: Vec<u8>,
    ) -> Result<(), String> {
        let mut registry = self.rbc.lock();
        if registry
            .delivered
            .iter()
            .any(|(_, party, session)| *party == party_id && *session == session_id)
        {
            return Ok(());
        }

        let digest = *blake3::hash(&message).as_bytes();
        if let Some(existing) = registry.messages.get(&(session_id, party_id)) {
            if existing == &digest {
                return Ok(());
            }
            return Err(format!(
                "conflicting RBC payload for session {session_id} from party {party_id}"
            ));
        }

        accept_broadcaster_payload(&mut registry, (session_id, party_id, digest), message)?;
        registry.messages.insert((session_id, party_id), digest);
        drop(registry);
        self.rbc_notify.notify_waiters();
        Ok(())
    }

    pub fn rbc_broadcast(&self, party_id: usize, message: &[u8]) -> Result<u64, String> {
        let mut registry = self.rbc.lock();
        registry.receivers.insert(party_id);
        let session_id = *registry.next_sessions.entry(party_id).or_default();
        let next_session = session_id
            .checked_add(1)
            .ok_or_else(|| "RBC session id overflow".to_string())?;

        let message_len = message.len();
        let digest = *blake3::hash(message).as_bytes();
        accept_broadcaster_payload(
            &mut registry,
            (session_id, party_id, digest),
            message.to_vec(),
        )?;
        registry.next_sessions.insert(party_id, next_session);
        registry.messages.insert((session_id, party_id), digest);
        drop(registry);

        self.rbc_notify.notify_waiters();

        tracing::info!(
            instance_id = self.instance_id(),
            session_id = session_id,
            party_id = party_id,
            message_len,
            "RBC broadcast initiated"
        );

        Ok(session_id)
    }

    pub async fn rbc_broadcast_async(
        &self,
        party_id: usize,
        message: &[u8],
    ) -> Result<u64, String> {
        self.rbc_broadcast(party_id, message)
    }

    /// Direct registry delivery is intentionally disabled. Reliable broadcast requires the
    /// engine to exchange authenticated ECHO/READY relays through the network first.
    pub fn rbc_receive(
        &self,
        receiver_party_id: usize,
        from_party: usize,
        _timeout_ms: u64,
    ) -> Result<Vec<u8>, String> {
        let _ = receiver_party_id;
        Err(format!(
            "RBC receive from party {from_party} requires network quorum processing"
        ))
    }

    pub fn rbc_receive_any(
        &self,
        receiver_party_id: usize,
        _timeout_ms: u64,
    ) -> Result<(usize, Vec<u8>), String> {
        let _ = receiver_party_id;
        Err("RBC receive_any requires network quorum processing".to_string())
    }

    pub(crate) fn insert_rbc_relay(
        &self,
        ready: bool,
        session_id: u64,
        broadcaster_party_id: usize,
        sender_party_id: usize,
        digest: [u8; 32],
        message: Option<Vec<u8>>,
    ) -> Result<(), String> {
        let mut registry = self.rbc.lock();
        if registry
            .delivered
            .iter()
            .any(|(_, party, session)| *party == broadcaster_party_id && *session == session_id)
        {
            return Ok(());
        }
        let relay_key = (session_id, broadcaster_party_id, digest);
        let mut payload_refused = None;
        if let Some(message) = message {
            if *blake3::hash(&message).as_bytes() != digest {
                return Err("RBC ECHO payload digest mismatch".to_string());
            }
            if !registry.candidates.contains_key(&relay_key) {
                let owner = owner_for(&relay_key, sender_party_id);
                match admit_rbc_candidate(&mut registry, owner, message.len()) {
                    Ok(evict) => {
                        store_rbc_candidate(&mut registry, relay_key, owner, message, evict)
                    }
                    // Without room for the payload the vote still counts: once the VAL or
                    // another relay supplies the payload, this ECHO contributes to quorum.
                    Err(error) if is_capacity_error(&error) => payload_refused = Some(error),
                    Err(error) => return Err(error),
                }
            }
        }
        let relays = if ready {
            &registry.readies
        } else {
            &registry.echoes
        };
        if !registry.candidates.contains_key(&relay_key) && !relays.contains_key(&relay_key) {
            let (phase, limit) = if ready {
                ("READY", MAX_ORPHAN_READY_KEYS_PER_SENDER)
            } else {
                ("ECHO", MAX_ORPHAN_ECHO_KEYS_PER_SENDER)
            };
            let sender_orphans = relays
                .iter()
                .filter(|(key, senders)| {
                    !registry.candidates.contains_key(key) && senders.contains(&sender_party_id)
                })
                .count();
            if sender_orphans >= limit {
                return Err(format!(
                    "RBC sender {sender_party_id} exceeded orphan {phase} limit of {limit}"
                ));
            }
        }
        let relays = if ready {
            &mut registry.readies
        } else {
            &mut registry.echoes
        };
        relays.entry(relay_key).or_default().insert(sender_party_id);
        drop(registry);
        if let Some(error) = payload_refused {
            return Err(format!("{error}; ECHO vote kept without its payload"));
        }
        self.rbc_notify.notify_waiters();
        Ok(())
    }

    pub(crate) fn rbc_progress(
        &self,
        receiver_party_id: usize,
        from_party: Option<usize>,
        n_parties: usize,
        threshold: usize,
    ) -> Result<RbcProgress, String> {
        let minimum_parties = threshold
            .checked_mul(3)
            .and_then(|value| value.checked_add(1))
            .ok_or_else(|| "RBC topology threshold overflowed".to_string())?;
        if n_parties == 0 || threshold >= n_parties || n_parties < minimum_parties {
            return Err(format!(
                "invalid RBC topology n={n_parties}, t={threshold}; require n >= 3t + 1"
            ));
        }
        if receiver_party_id >= n_parties
            || from_party.is_some_and(|party_id| party_id >= n_parties)
        {
            return Err(format!(
                "RBC party id is outside topology of {n_parties} parties"
            ));
        }
        let mut registry = self.rbc.lock();
        registry.receivers.insert(receiver_party_id);
        let mut candidates = registry
            .candidates
            .iter()
            .filter_map(|((session_id, party, digest), message)| {
                if from_party.is_some_and(|expected| expected != *party)
                    || (from_party.is_none() && *party == receiver_party_id)
                    || *party >= n_parties
                {
                    return None;
                }
                let delivery_key = (receiver_party_id, *party, *session_id);
                if registry.delivered.contains(&delivery_key) {
                    return None;
                }
                Some((*session_id, *party, *digest, message.clone()))
            })
            .collect::<Vec<_>>();
        candidates.sort_by_key(|(session_id, party, digest, _)| (*session_id, *party, *digest));
        if candidates.is_empty() {
            return Ok(RbcProgress {
                relays: Vec::new(),
                delivery: None,
            });
        }

        let mut relays = Vec::new();
        let mut delivery = None;
        let mut offset = 0;
        while offset < candidates.len() {
            let session_id = candidates[offset].0;
            let party = candidates[offset].1;
            let group_end = candidates[offset..]
                .iter()
                .position(|(candidate_session, candidate_party, _, _)| {
                    *candidate_session != session_id || *candidate_party != party
                })
                .map_or(candidates.len(), |relative| offset + relative);
            let sent_key = (receiver_party_id, party, session_id);

            if let Some(digest) = registry.messages.get(&(session_id, party)).copied() {
                let relay_key = (session_id, party, digest);
                registry
                    .echoes
                    .entry(relay_key)
                    .or_default()
                    .insert(receiver_party_id);
                if registry.sent_echoes.insert(sent_key) {
                    relays.push(RbcRelay {
                        phase: RbcRelayPhase::Echo,
                        session_id,
                        broadcaster_party_id: party,
                        digest,
                        message: registry.candidates.get(&relay_key).cloned(),
                    });
                }
            }

            for (_, _, digest, message) in &candidates[offset..group_end] {
                let relay_key = (session_id, party, *digest);
                let echo_count = registry.echoes.get(&relay_key).map_or(0, |senders| {
                    senders.iter().filter(|sender| **sender < n_parties).count()
                });
                let ready_count = registry.readies.get(&relay_key).map_or(0, |senders| {
                    senders.iter().filter(|sender| **sender < n_parties).count()
                });
                if (echo_count >= n_parties - threshold || ready_count > threshold)
                    && registry.sent_readies.insert(sent_key)
                {
                    registry
                        .readies
                        .entry(relay_key)
                        .or_default()
                        .insert(receiver_party_id);
                    relays.push(RbcRelay {
                        phase: RbcRelayPhase::Ready,
                        session_id,
                        broadcaster_party_id: party,
                        digest: *digest,
                        message: None,
                    });
                }

                let ready_count = registry.readies.get(&relay_key).map_or(0, |senders| {
                    senders.iter().filter(|sender| **sender < n_parties).count()
                });
                // Deliver one broadcaster's sessions in order. Only earlier sessions known
                // from the broadcaster's own VAL hold a later one back, so relayed junk
                // cannot stall delivery.
                let earlier_pending = registry.messages.keys().any(|(earlier, sender)| {
                    *sender == party
                        && *earlier < session_id
                        && !registry
                            .delivered
                            .contains(&(receiver_party_id, party, *earlier))
                });
                if ready_count > 2 * threshold && !earlier_pending {
                    registry
                        .delivered
                        .insert((receiver_party_id, party, session_id));
                    tracing::info!(
                        instance_id = self.instance_id(),
                        session_id,
                        from_party = party,
                        message_len = message.len(),
                        "RBC quorum delivered message"
                    );
                    delivery = Some((party, message.clone()));
                    break;
                }
            }
            if delivery.is_some() {
                break;
            }
            offset = group_end;
        }

        Ok(RbcProgress { relays, delivery })
    }
}
