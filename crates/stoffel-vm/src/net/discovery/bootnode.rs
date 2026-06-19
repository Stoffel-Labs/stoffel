use super::{registration_token_is_valid, send_ctrl, send_session_announce, DiscoveryMessage};
use crate::net::{
    program_sync::{send_ctrl as send_prog_ctrl, send_program_bytes, ProgramSyncMessage},
    session::{derive_instance_id, random_instance_id, SessionInfo, SessionMessage},
};
use std::{collections::HashMap, net::SocketAddr, sync::Arc, time::Duration};
use stoffelnet::network_utils::PartyId;
use stoffelnet::transports::quic::PeerConnection;
use tokio::sync::{broadcast, mpsc, watch, Mutex};

#[derive(Debug, Clone)]
struct PendingSession {
    program_id: [u8; 32],
    entry: String,
    n_parties: usize,
    threshold: usize,
    parties: HashMap<PartyId, SocketAddr>,
    tls_ids: HashMap<PartyId, PartyId>,
    nonce: u64,
}

#[derive(Debug, Clone)]
pub(super) struct SessionRegistration {
    pub party_id: PartyId,
    pub listen_addr: SocketAddr,
    pub program_id: [u8; 32],
    pub entry: String,
    pub n_parties: usize,
    pub threshold: usize,
    pub tls_derived_id: Option<PartyId>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SessionRegistrationEvent {
    Created {
        target_parties: usize,
    },
    Joined {
        registered_parties: usize,
        target_parties: usize,
    },
    RejectedDuplicateParty,
    RejectedProgramMismatch,
}

#[derive(Debug, Clone)]
pub(super) struct SessionRegistrationReport {
    pub event: SessionRegistrationEvent,
    pub ready_session: Option<SessionInfo>,
}

#[derive(Clone)]
pub(super) struct BootnodeState {
    parties: Arc<Mutex<HashMap<PartyId, SocketAddr>>>,
    active_session: Arc<Mutex<Option<SessionInfo>>>,
    program_bytes: Arc<Mutex<Option<CachedProgram>>>,
    pending_session: Arc<Mutex<Option<PendingSession>>>,
    expected_parties: Option<usize>,
    session_tx: watch::Sender<Option<SessionInfo>>,
    ice_tx: broadcast::Sender<DiscoveryMessage>,
}

#[derive(Clone)]
struct CachedProgram {
    program_id: [u8; 32],
    bytes: Arc<Vec<u8>>,
}

impl BootnodeState {
    pub fn new(expected_parties: Option<usize>) -> Self {
        let (session_tx, _session_rx) = watch::channel(None);
        let (ice_tx, _ice_rx) = broadcast::channel(256);
        Self {
            parties: Arc::new(Mutex::new(HashMap::new())),
            active_session: Arc::new(Mutex::new(None)),
            program_bytes: Arc::new(Mutex::new(None)),
            pending_session: Arc::new(Mutex::new(None)),
            expected_parties,
            session_tx,
            ice_tx,
        }
    }

    pub fn subscribe_session(&self) -> watch::Receiver<Option<SessionInfo>> {
        self.session_tx.subscribe()
    }

    pub fn subscribe_ice(&self) -> broadcast::Receiver<DiscoveryMessage> {
        self.ice_tx.subscribe()
    }

    pub fn publish_ice(&self, message: DiscoveryMessage) {
        let _ = self.ice_tx.send(message);
    }

    pub async fn register_peer_and_list_others(
        &self,
        party_id: PartyId,
        listen_addr: SocketAddr,
    ) -> PeerRegistration {
        let mut parties = self.parties.lock().await;
        let is_new = !parties.contains_key(&party_id);
        parties.insert(party_id, listen_addr);
        let peers = parties
            .iter()
            .filter(|(pid, _)| **pid != party_id)
            .map(|(pid, addr)| (*pid, *addr))
            .collect();
        PeerRegistration { is_new, peers }
    }

    pub async fn register_peer(&self, party_id: PartyId, listen_addr: SocketAddr) {
        self.parties.lock().await.insert(party_id, listen_addr);
    }

    pub async fn peer_list(&self) -> Vec<(PartyId, SocketAddr)> {
        self.parties
            .lock()
            .await
            .iter()
            .map(|(pid, addr)| (*pid, *addr))
            .collect()
    }

    pub async fn store_program_bytes_if_missing(
        &self,
        program_id: [u8; 32],
        bytes: Vec<u8>,
    ) -> bool {
        let mut program_bytes = self.program_bytes.lock().await;
        if program_bytes.is_some() {
            return false;
        }
        *program_bytes = Some(CachedProgram {
            program_id,
            bytes: Arc::new(bytes),
        });
        true
    }

    pub async fn program_bytes_for(&self, program_id: &[u8; 32]) -> Option<Arc<Vec<u8>>> {
        self.program_bytes
            .lock()
            .await
            .as_ref()
            .filter(|cached| cached.program_id == *program_id)
            .map(|cached| cached.bytes.clone())
    }

    pub async fn register_session(
        &self,
        registration: SessionRegistration,
    ) -> Result<SessionRegistrationReport, String> {
        let mut pending = self.pending_session.lock().await;
        let target_parties = self.expected_parties.unwrap_or(registration.n_parties);

        let event = match pending.as_mut() {
            Some(session) => {
                if session.parties.contains_key(&registration.party_id) {
                    SessionRegistrationEvent::RejectedDuplicateParty
                } else if session.program_id != registration.program_id {
                    SessionRegistrationEvent::RejectedProgramMismatch
                } else {
                    session
                        .parties
                        .insert(registration.party_id, registration.listen_addr);
                    if let Some(tls_derived_id) = registration.tls_derived_id {
                        session
                            .tls_ids
                            .insert(registration.party_id, tls_derived_id);
                    }
                    SessionRegistrationEvent::Joined {
                        registered_parties: session.parties.len(),
                        target_parties: session.n_parties,
                    }
                }
            }
            None => {
                let mut parties = HashMap::new();
                parties.insert(registration.party_id, registration.listen_addr);
                let mut tls_ids = HashMap::new();
                if let Some(tls_derived_id) = registration.tls_derived_id {
                    tls_ids.insert(registration.party_id, tls_derived_id);
                }
                *pending = Some(PendingSession {
                    program_id: registration.program_id,
                    entry: registration.entry,
                    n_parties: target_parties,
                    threshold: registration.threshold,
                    parties,
                    tls_ids,
                    nonce: session_nonce(),
                });
                SessionRegistrationEvent::Created { target_parties }
            }
        };

        if matches!(
            event,
            SessionRegistrationEvent::RejectedDuplicateParty
                | SessionRegistrationEvent::RejectedProgramMismatch
        ) {
            return Ok(SessionRegistrationReport {
                event,
                ready_session: None,
            });
        }

        let ready = pending
            .as_ref()
            .is_some_and(|session| session.parties.len() >= session.n_parties);

        let ready_session = if ready {
            let Some(session) = pending.take() else {
                return Err("pending session disappeared while announcing readiness".to_string());
            };
            let session_info = session.into_session_info();
            *self.active_session.lock().await = Some(session_info.clone());
            let _ = self.session_tx.send(Some(session_info.clone()));
            Some(session_info)
        } else {
            None
        };

        Ok(SessionRegistrationReport {
            event,
            ready_session,
        })
    }
}

pub(super) fn spawn_connection_handler(
    conn: Arc<dyn PeerConnection>,
    state: BootnodeState,
    required_auth_token: Option<String>,
) {
    tokio::spawn(async move {
        BootnodeConnection::new(conn, state, required_auth_token)
            .run()
            .await;
    });
}

#[derive(Debug, Clone)]
pub(super) struct PeerRegistration {
    pub is_new: bool,
    pub peers: Vec<(PartyId, SocketAddr)>,
}

struct BootnodeConnection {
    conn: Arc<dyn PeerConnection>,
    state: BootnodeState,
    session_rx: watch::Receiver<Option<SessionInfo>>,
    ice_rx: broadcast::Receiver<DiscoveryMessage>,
    required_auth_token: Option<String>,
    waiting_for_session: bool,
    my_party_id: Option<PartyId>,
}

impl BootnodeConnection {
    fn new(
        conn: Arc<dyn PeerConnection>,
        state: BootnodeState,
        required_auth_token: Option<String>,
    ) -> Self {
        let session_rx = state.subscribe_session();
        let ice_rx = state.subscribe_ice();
        Self {
            conn,
            state,
            session_rx,
            ice_rx,
            required_auth_token,
            waiting_for_session: false,
            my_party_id: None,
        }
    }

    async fn run(mut self) {
        // Read framed messages in a dedicated task so the periodic session/ICE
        // polling below never cancels an in-progress socket read. The transport's
        // `receive()` reads a length prefix and then the payload into a local
        // buffer, so it is NOT cancellation-safe: wrapping it directly in a short
        // timeout (as this loop used to) drops the future mid-read on a large
        // message — e.g. a multi-MB program upload at session registration —
        // leaving the QUIC stream misaligned so the registration is never decoded
        // and the session never forms. By moving the read into its own task, the
        // 50ms tick below cancels only a cancellation-safe channel receive.
        let (msg_tx, mut msg_rx) = mpsc::channel::<Vec<u8>>(8);
        let reader_conn = Arc::clone(&self.conn);
        let reader = tokio::spawn(async move {
            loop {
                match reader_conn.receive().await {
                    Ok(buf) => {
                        if msg_tx.send(buf).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        loop {
            self.send_ready_session_if_waiting().await;
            self.relay_pending_ice_messages().await;

            match tokio::time::timeout(Duration::from_millis(50), msg_rx.recv()).await {
                Ok(Some(buf)) => self.handle_buffer(buf).await,
                Ok(None) => break,
                Err(_) => continue,
            }
        }

        reader.abort();
    }

    async fn send_ready_session_if_waiting(&mut self) {
        if !self.waiting_for_session {
            return;
        }

        let session_info = self.session_rx.borrow().clone();
        if let Some(info) = session_info {
            if let Err(err) = send_session_announce(&*self.conn, &info).await {
                eprintln!("[bootnode] Failed to send SessionAnnounce: {}", err);
            }
            self.waiting_for_session = false;
        }
    }

    async fn relay_pending_ice_messages(&mut self) {
        let Some(party_id) = self.my_party_id else {
            return;
        };

        while let Ok(ice_msg) = self.ice_rx.try_recv() {
            let should_forward = match &ice_msg {
                DiscoveryMessage::IceCandidates { to_party_id, .. }
                | DiscoveryMessage::IceExchangeRequest { to_party_id, .. } => {
                    *to_party_id == party_id
                }
                _ => false,
            };

            if should_forward {
                let _ = send_ctrl(&*self.conn, &ice_msg).await;
            }
        }
    }

    async fn handle_buffer(&mut self, buf: Vec<u8>) {
        if let Ok(message) = bincode::deserialize::<DiscoveryMessage>(&buf) {
            self.handle_discovery_message(message).await;
        } else if let Ok(message) = bincode::deserialize::<ProgramSyncMessage>(&buf) {
            self.handle_program_sync_message(message).await;
        } else if let Ok(message) = bincode::deserialize::<SessionMessage>(&buf) {
            self.handle_session_message(message);
        }
    }

    async fn handle_discovery_message(&mut self, message: DiscoveryMessage) {
        match message {
            DiscoveryMessage::Register {
                party_id,
                listen_addr,
                auth_token,
            } => {
                self.handle_register(party_id, listen_addr, auth_token)
                    .await;
            }
            DiscoveryMessage::RegisterWithSession {
                party_id,
                listen_addr,
                program_id,
                entry,
                n_parties,
                threshold,
                program_bytes,
                auth_token,
                tls_derived_id,
            } => {
                let registration = SessionRegistration {
                    party_id,
                    listen_addr,
                    program_id,
                    entry,
                    n_parties,
                    threshold,
                    tls_derived_id,
                };
                self.handle_session_registration(registration, program_bytes, auth_token)
                    .await;
            }
            DiscoveryMessage::RequestPeers => {
                if self.authenticated_party_id("RequestPeers").is_none() {
                    return;
                }
                let peers = self.state.peer_list().await;
                let _ = send_ctrl(&*self.conn, &DiscoveryMessage::PeerList { peers }).await;
            }
            DiscoveryMessage::Heartbeat => {}
            DiscoveryMessage::ProgramFetchRequest { program_id } => {
                if self.authenticated_party_id("ProgramFetchRequest").is_none() {
                    return;
                }
                self.handle_program_fetch_request(program_id).await;
            }
            DiscoveryMessage::IceCandidates {
                from_party_id,
                to_party_id,
                ufrag,
                pwd,
                candidates,
            } => {
                if !self.authenticated_sender_matches("IceCandidates", from_party_id) {
                    return;
                }
                eprintln!(
                    "[bootnode] Relaying {} ICE candidates from party {} to party {}",
                    candidates.len(),
                    from_party_id,
                    to_party_id
                );
                self.state.publish_ice(DiscoveryMessage::IceCandidates {
                    from_party_id,
                    to_party_id,
                    ufrag,
                    pwd,
                    candidates,
                });
            }
            DiscoveryMessage::IceExchangeRequest {
                from_party_id,
                to_party_id,
            } => {
                if !self.authenticated_sender_matches("IceExchangeRequest", from_party_id) {
                    return;
                }
                eprintln!(
                    "[bootnode] ICE exchange request from party {} to party {}",
                    from_party_id, to_party_id
                );
                self.state
                    .publish_ice(DiscoveryMessage::IceExchangeRequest {
                        from_party_id,
                        to_party_id,
                    });
            }
            _ => {}
        }
    }

    fn authenticated_party_id(&self, message_kind: &str) -> Option<PartyId> {
        let party_id = self.my_party_id;
        if party_id.is_none() {
            eprintln!(
                "[bootnode] Rejected {} from unauthenticated connection",
                message_kind
            );
        }
        party_id
    }

    fn authenticated_sender_matches(&self, message_kind: &str, from_party_id: PartyId) -> bool {
        match self.authenticated_party_id(message_kind) {
            Some(party_id) if party_id == from_party_id => true,
            Some(party_id) => {
                eprintln!(
                    "[bootnode] Rejected {} from party {} spoofing party {}",
                    message_kind, party_id, from_party_id
                );
                false
            }
            None => false,
        }
    }

    async fn handle_register(
        &mut self,
        party_id: PartyId,
        listen_addr: SocketAddr,
        auth_token: Option<String>,
    ) {
        if !registration_token_is_valid(self.required_auth_token.as_deref(), auth_token.as_deref())
        {
            eprintln!(
                "[bootnode] Rejected Register from party {} (invalid auth token)",
                party_id
            );
            return;
        }

        self.my_party_id = Some(party_id);
        let registration = self
            .state
            .register_peer_and_list_others(party_id, listen_addr)
            .await;
        let peers = registration.peers;
        let _ = send_ctrl(&*self.conn, &DiscoveryMessage::PeerList { peers }).await;

        if registration.is_new {
            let joined = DiscoveryMessage::PeerJoined {
                party_id,
                listen_addr,
            };
            let _ = send_ctrl(&*self.conn, &joined).await;
        }
    }

    async fn handle_session_registration(
        &mut self,
        registration: SessionRegistration,
        program_bytes: Option<Vec<u8>>,
        auth_token: Option<String>,
    ) {
        let party_id = registration.party_id;
        let listen_addr = registration.listen_addr;
        eprintln!(
            "[bootnode] Received RegisterWithSession from party {} (program: {}, n={}, t={}, has_bytes={})",
            party_id,
            hex::encode(&registration.program_id[..8]),
            registration.n_parties,
            registration.threshold,
            program_bytes.is_some()
        );
        if !registration_token_is_valid(self.required_auth_token.as_deref(), auth_token.as_deref())
        {
            eprintln!(
                "[bootnode] Rejected RegisterWithSession from party {} (invalid auth token)",
                party_id
            );
            self.waiting_for_session = false;
            return;
        }

        eprintln!(
            "[bootnode] Party {} registering for session (program: {}, n={}, t={}, has_bytes={})",
            party_id,
            hex::encode(&registration.program_id[..8]),
            registration.n_parties,
            registration.threshold,
            program_bytes.is_some()
        );

        if let Some(bytes) = program_bytes {
            let byte_len = bytes.len();
            if !program_id_matches_bytes(&registration.program_id, &bytes) {
                eprintln!(
                    "[bootnode] Rejected program bytes from party {} for {} (hash mismatch)",
                    party_id,
                    hex::encode(&registration.program_id[..8])
                );
            } else if self
                .state
                .store_program_bytes_if_missing(registration.program_id, bytes)
                .await
            {
                eprintln!(
                    "[bootnode] Storing program bytes from party {} ({} bytes)",
                    party_id, byte_len
                );
            }
        }

        self.waiting_for_session = true;

        let report = match self.state.register_session(registration).await {
            Ok(report) => report,
            Err(err) => {
                eprintln!(
                    "[bootnode] Failed to register party {} for session: {}",
                    party_id, err
                );
                self.waiting_for_session = false;
                return;
            }
        };

        match report.event {
            SessionRegistrationEvent::Created { target_parties } => {
                eprintln!(
                    "[bootnode] Created pending session, waiting for {} parties (have 1)",
                    target_parties
                );
            }
            SessionRegistrationEvent::Joined {
                registered_parties,
                target_parties,
            } => {
                eprintln!(
                    "[bootnode] Party {} joined, have {}/{} parties",
                    party_id, registered_parties, target_parties
                );
            }
            SessionRegistrationEvent::RejectedProgramMismatch => {
                eprintln!(
                    "[bootnode] Warning: party {} has different program_id",
                    party_id
                );
                let _ = send_ctrl(&*self.conn, &DiscoveryMessage::PeerLeft { party_id }).await;
                self.waiting_for_session = false;
                return;
            }
            SessionRegistrationEvent::RejectedDuplicateParty => {
                eprintln!(
                    "[bootnode] Rejected RegisterWithSession from party {} (duplicate party_id)",
                    party_id
                );
                let _ = send_ctrl(&*self.conn, &DiscoveryMessage::PeerLeft { party_id }).await;
                self.waiting_for_session = false;
                return;
            }
        }

        self.my_party_id = Some(party_id);
        self.state.register_peer(party_id, listen_addr).await;

        if let Some(session_info) = report.ready_session {
            eprintln!(
                "[bootnode] Session ready! instance_id={}, n_parties={}",
                session_info.instance_id, session_info.n_parties
            );
            if let Err(err) = send_session_announce(&*self.conn, &session_info).await {
                eprintln!(
                    "[bootnode] Failed to send immediate SessionAnnounce to party {}: {}",
                    party_id, err
                );
            }
            self.waiting_for_session = false;
        }
    }

    async fn handle_program_fetch_request(&self, program_id: [u8; 32]) {
        if let Some(bytes) = self.state.program_bytes_for(&program_id).await {
            eprintln!(
                "[bootnode] Sending program bytes ({} bytes) for {}",
                bytes.len(),
                hex::encode(&program_id[..8])
            );
            let resp = DiscoveryMessage::ProgramFetchResponse {
                program_id,
                bytes: bytes.to_vec(),
            };
            let _ = send_ctrl(&*self.conn, &resp).await;
        } else {
            eprintln!(
                "[bootnode] Program fetch request for {} but no bytes cached",
                hex::encode(&program_id[..8])
            );
        }
    }

    async fn handle_program_sync_message(&self, message: ProgramSyncMessage) {
        match message {
            ProgramSyncMessage::ProgramAnnounce { .. } => {
                let _ = send_prog_ctrl(&*self.conn, &message).await;
            }
            ProgramSyncMessage::ProgramFetchRequest { program_id } => {
                if self
                    .authenticated_party_id("ProgramSync::ProgramFetchRequest")
                    .is_none()
                {
                    return;
                }
                if let Some(bytes) = self.state.program_bytes_for(&program_id).await {
                    let _ = send_program_bytes(&*self.conn, program_id, bytes).await;
                }
            }
            _ => {}
        }
    }

    fn handle_session_message(&self, message: SessionMessage) {
        match message {
            SessionMessage::SessionAnnounce(_) => {}
            SessionMessage::SessionAck {
                party_id,
                instance_id,
                ..
            } => {
                eprintln!(
                    "[bootnode] Received SessionAck from party {} for instance {}",
                    party_id, instance_id
                );
            }
            _ => {}
        }
    }
}

impl PendingSession {
    fn into_session_info(self) -> SessionInfo {
        SessionInfo {
            program_id: self.program_id,
            instance_id: derive_instance_id(&self.program_id, self.nonce),
            entry: self.entry,
            parties: self.parties.into_iter().collect(),
            n_parties: self.n_parties,
            threshold: self.threshold,
            tls_ids: self.tls_ids.into_iter().collect(),
        }
    }
}

fn session_nonce() -> u64 {
    random_instance_id()
}

fn program_id_matches_bytes(program_id: &[u8; 32], bytes: &[u8]) -> bool {
    blake3::hash(bytes).as_bytes() == program_id
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::future::Future;
    use std::net::{Ipv4Addr, SocketAddrV4};
    use std::pin::Pin;
    use std::sync::{Arc, Mutex as StdMutex};
    use stoffelnet::network_utils::ClientType;
    use stoffelnet::transports::quic::{ConnectionState, PeerConnection};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, port))
    }

    fn program_id(bytes: &[u8]) -> [u8; 32] {
        *blake3::hash(bytes).as_bytes()
    }

    fn registration(party_id: PartyId, program_id: [u8; 32]) -> SessionRegistration {
        SessionRegistration {
            party_id,
            listen_addr: addr(10_000 + party_id as u16),
            program_id,
            entry: "main".to_string(),
            n_parties: 2,
            threshold: 1,
            tls_derived_id: Some(100 + party_id),
        }
    }

    #[derive(Default)]
    struct RecordingConnection {
        sent: StdMutex<Vec<Vec<u8>>>,
    }

    impl RecordingConnection {
        fn sent_messages(&self) -> Vec<Vec<u8>> {
            self.sent.lock().expect("sent lock poisoned").clone()
        }

        fn clear_sent(&self) {
            self.sent.lock().expect("sent lock poisoned").clear();
        }
    }

    impl PeerConnection for RecordingConnection {
        fn send<'a>(
            &'a self,
            data: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async move {
                self.sent
                    .lock()
                    .expect("sent lock poisoned")
                    .push(data.to_vec());
                Ok(())
            })
        }

        fn receive<'a>(
            &'a self,
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>, String>> + Send + 'a>> {
            Box::pin(async { Err("no scripted receive".to_string()) })
        }

        fn remote_address(&self) -> SocketAddr {
            addr(20_000)
        }

        fn close<'a>(&'a self) -> Pin<Box<dyn Future<Output = Result<(), String>> + Send + 'a>> {
            Box::pin(async { Ok(()) })
        }

        fn state<'a>(&'a self) -> Pin<Box<dyn Future<Output = ConnectionState> + Send + 'a>> {
            Box::pin(async { ConnectionState::Connected })
        }

        fn is_connected<'a>(&'a self) -> Pin<Box<dyn Future<Output = bool> + Send + 'a>> {
            Box::pin(async { true })
        }

        fn get_connection_role(&self) -> ClientType {
            ClientType::Server
        }

        fn remote_party_id(&self) -> Option<PartyId> {
            None
        }

        fn set_remote_party_id(&self, _party_id: PartyId) {}
    }

    #[tokio::test]
    async fn unauthenticated_program_fetch_does_not_disclose_cached_bytes() {
        let state = BootnodeState::new(None);
        let bytes = b"compiled program".to_vec();
        let program_id = program_id(&bytes);
        assert!(
            state
                .store_program_bytes_if_missing(program_id, bytes)
                .await
        );

        let conn = Arc::new(RecordingConnection::default());
        let mut handler = BootnodeConnection::new(conn.clone(), state, Some("secret".to_string()));

        handler
            .handle_discovery_message(DiscoveryMessage::ProgramFetchRequest { program_id })
            .await;

        assert!(conn.sent_messages().is_empty());
    }

    #[tokio::test]
    async fn program_fetch_requires_matching_cached_program_id() {
        let state = BootnodeState::new(None);
        let bytes = b"compiled program".to_vec();
        let program_id = program_id(&bytes);
        assert!(
            state
                .store_program_bytes_if_missing(program_id, bytes.clone())
                .await
        );

        let conn = Arc::new(RecordingConnection::default());
        let mut handler = BootnodeConnection::new(conn.clone(), state, None);
        handler.handle_register(0, addr(10_000), None).await;
        conn.clear_sent();

        handler
            .handle_discovery_message(DiscoveryMessage::ProgramFetchRequest {
                program_id: [9u8; 32],
            })
            .await;
        assert!(conn.sent_messages().is_empty());

        handler
            .handle_discovery_message(DiscoveryMessage::ProgramFetchRequest { program_id })
            .await;
        let sent = conn.sent_messages();
        assert_eq!(sent.len(), 1);
        let response =
            bincode::deserialize::<DiscoveryMessage>(&sent[0]).expect("response decodes");
        assert!(matches!(
            response,
            DiscoveryMessage::ProgramFetchResponse {
                program_id: id,
                bytes: response_bytes
            } if id == program_id && response_bytes == bytes
        ));
    }

    #[tokio::test]
    async fn ice_relay_rejects_unauthenticated_and_spoofed_senders() {
        let state = BootnodeState::new(None);
        let mut ice_rx = state.subscribe_ice();
        let conn = Arc::new(RecordingConnection::default());
        let mut handler = BootnodeConnection::new(conn, state, None);

        handler
            .handle_discovery_message(DiscoveryMessage::IceExchangeRequest {
                from_party_id: 1,
                to_party_id: 2,
            })
            .await;
        assert!(ice_rx.try_recv().is_err());

        handler.my_party_id = Some(1);
        handler
            .handle_discovery_message(DiscoveryMessage::IceExchangeRequest {
                from_party_id: 2,
                to_party_id: 3,
            })
            .await;
        assert!(ice_rx.try_recv().is_err());

        handler
            .handle_discovery_message(DiscoveryMessage::IceCandidates {
                from_party_id: 2,
                to_party_id: 3,
                ufrag: "ufrag".to_string(),
                pwd: "pwd".to_string(),
                candidates: Vec::new(),
            })
            .await;
        assert!(ice_rx.try_recv().is_err());

        handler
            .handle_discovery_message(DiscoveryMessage::IceExchangeRequest {
                from_party_id: 1,
                to_party_id: 3,
            })
            .await;
        let relayed = ice_rx.try_recv().expect("matching sender relayed");
        assert!(matches!(
            relayed,
            DiscoveryMessage::IceExchangeRequest {
                from_party_id: 1,
                to_party_id: 3
            }
        ));

        handler
            .handle_discovery_message(DiscoveryMessage::IceCandidates {
                from_party_id: 1,
                to_party_id: 3,
                ufrag: "ufrag".to_string(),
                pwd: "pwd".to_string(),
                candidates: Vec::new(),
            })
            .await;
        let relayed = ice_rx.try_recv().expect("matching candidates relayed");
        assert!(matches!(
            relayed,
            DiscoveryMessage::IceCandidates {
                from_party_id: 1,
                to_party_id: 3,
                ..
            }
        ));
    }

    #[tokio::test]
    async fn session_registration_rejects_program_bytes_hash_mismatch() {
        let state = BootnodeState::new(None);
        let conn = Arc::new(RecordingConnection::default());
        let mut handler = BootnodeConnection::new(conn, state.clone(), None);

        handler
            .handle_session_registration(
                registration(0, [4u8; 32]),
                Some(b"wrong bytes".to_vec()),
                None,
            )
            .await;

        assert!(state.program_bytes_for(&[4u8; 32]).await.is_none());
    }

    #[tokio::test]
    async fn duplicate_session_registration_does_not_authenticate_or_replace_peer() {
        let state = BootnodeState::new(Some(2));
        let program_id = [8u8; 32];

        let first_conn = Arc::new(RecordingConnection::default());
        let mut first_handler = BootnodeConnection::new(first_conn, state.clone(), None);
        first_handler
            .handle_session_registration(registration(0, program_id), None, None)
            .await;

        let attacker_addr = addr(12_345);
        let duplicate = SessionRegistration {
            listen_addr: attacker_addr,
            tls_derived_id: Some(777),
            ..registration(0, program_id)
        };
        let duplicate_conn = Arc::new(RecordingConnection::default());
        let mut duplicate_handler =
            BootnodeConnection::new(duplicate_conn.clone(), state.clone(), None);
        duplicate_handler
            .handle_session_registration(duplicate, None, None)
            .await;

        assert_eq!(duplicate_handler.my_party_id, None);
        assert!(state
            .peer_list()
            .await
            .iter()
            .any(|(party_id, listen_addr)| *party_id == 0 && *listen_addr == addr(10_000)));
        assert!(!state
            .peer_list()
            .await
            .iter()
            .any(|(party_id, listen_addr)| *party_id == 0 && *listen_addr == attacker_addr));

        let sent = duplicate_conn.sent_messages();
        assert_eq!(sent.len(), 1);
        let response =
            bincode::deserialize::<DiscoveryMessage>(&sent[0]).expect("response decodes");
        assert!(matches!(
            response,
            DiscoveryMessage::PeerLeft { party_id: 0 }
        ));
    }

    #[tokio::test]
    async fn session_registration_announces_ready_without_manual_unwraps() {
        let state = BootnodeState::new(None);
        let program_id = [7u8; 32];

        let first = state
            .register_session(registration(0, program_id))
            .await
            .expect("first party registers");
        assert_eq!(
            first.event,
            SessionRegistrationEvent::Created { target_parties: 2 }
        );
        assert!(first.ready_session.is_none());

        let second = state
            .register_session(registration(1, program_id))
            .await
            .expect("second party registers");
        assert_eq!(
            second.event,
            SessionRegistrationEvent::Joined {
                registered_parties: 2,
                target_parties: 2
            }
        );
        let session = second.ready_session.expect("session is ready");
        assert_eq!(session.n_parties, 2);
        assert_eq!(session.threshold, 1);
        assert_eq!(session.parties.len(), 2);
        assert_eq!(session.tls_ids.len(), 2);
    }

    #[tokio::test]
    async fn session_registration_rejects_mismatched_program_without_poisoning_pending_session() {
        let state = BootnodeState::new(Some(2));

        state
            .register_session(registration(0, [1u8; 32]))
            .await
            .expect("first party registers");

        let mismatch = state
            .register_session(registration(1, [2u8; 32]))
            .await
            .expect("mismatched party is handled");
        assert_eq!(
            mismatch.event,
            SessionRegistrationEvent::RejectedProgramMismatch
        );
        assert!(mismatch.ready_session.is_none());

        let valid = state
            .register_session(registration(1, [1u8; 32]))
            .await
            .expect("matching party registers after mismatch");
        let session = valid.ready_session.expect("session becomes ready");
        assert!(session
            .parties
            .iter()
            .any(|(party_id, listen_addr)| *party_id == 1 && *listen_addr == addr(10_001)));
    }

    #[tokio::test]
    async fn session_registration_rejects_duplicate_party_without_overwriting_existing_slot() {
        let state = BootnodeState::new(Some(2));
        let program_id = [9u8; 32];

        state
            .register_session(registration(0, program_id))
            .await
            .expect("first party registers");

        let attacker_addr = addr(12_345);
        let attacker_tls_id = 777;
        let duplicate = SessionRegistration {
            listen_addr: attacker_addr,
            tls_derived_id: Some(attacker_tls_id),
            ..registration(0, program_id)
        };
        let duplicate_report = state
            .register_session(duplicate)
            .await
            .expect("duplicate party registration is handled");
        assert_eq!(
            duplicate_report.event,
            SessionRegistrationEvent::RejectedDuplicateParty
        );
        assert!(duplicate_report.ready_session.is_none());

        let final_report = state
            .register_session(registration(1, program_id))
            .await
            .expect("second unique party registers");
        let session = final_report.ready_session.expect("session becomes ready");
        assert!(session
            .parties
            .iter()
            .any(|(party_id, listen_addr)| *party_id == 0 && *listen_addr == addr(10_000)));
        assert!(!session
            .parties
            .iter()
            .any(|(party_id, listen_addr)| *party_id == 0 && *listen_addr == attacker_addr));
        assert!(session
            .tls_ids
            .iter()
            .any(|(party_id, tls_id)| *party_id == 0 && *tls_id == 100));
        assert!(!session
            .tls_ids
            .iter()
            .any(|(party_id, tls_id)| *party_id == 0 && *tls_id == attacker_tls_id));
    }
}
