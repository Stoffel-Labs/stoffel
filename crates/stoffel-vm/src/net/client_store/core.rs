use super::{ClientInputEntry, ClientInputIndex, ClientInputStore, ClientShare, ClientShareIndex};
use std::time::SystemTime;
use stoffelnet::network_utils::ClientId;

impl ClientInputStore {
    /// Create a new empty client input store.
    pub fn new() -> Self {
        Self::default()
    }

    /// Store VM share payloads from a client.
    pub fn store_client_shares(&self, client_id: ClientId, shares: Vec<ClientShare>) {
        let entry = ClientInputEntry {
            client_id,
            shares,
            timestamp: SystemTime::now(),
        };

        let mut entries = self.entries.write();
        entries.insert(client_id, entry);
        drop(entries);
        self.add_known_client(client_id);
    }

    /// Replace every stored client input with VM share payloads.
    ///
    /// The replacement happens while holding one write lock, so consumers never
    /// observe a partially cleared/repopulated store.
    pub fn replace_client_shares<I>(&self, inputs: I) -> usize
    where
        I: IntoIterator<Item = (ClientId, Vec<ClientShare>)>,
    {
        let mut total_shares = 0;
        let timestamp = SystemTime::now();
        let mut input_clients = Vec::new();
        let mut entries = self.entries.write();
        entries.clear();

        for (client_id, shares) in inputs {
            total_shares += shares.len();
            input_clients.push(client_id);
            entries.insert(
                client_id,
                ClientInputEntry {
                    client_id,
                    shares,
                    timestamp,
                },
            );
        }
        drop(entries);
        self.add_known_clients(input_clients);

        total_shares
    }

    /// Snapshot every stored client input as backend-neutral VM share payloads.
    pub fn snapshot_client_shares(&self) -> Vec<(ClientId, Vec<ClientShare>)> {
        let entries = self.entries.read();
        entries
            .iter()
            .map(|(&client_id, entry)| (client_id, entry.shares.clone()))
            .collect()
    }

    /// Snapshot the deterministic VM-facing client roster.
    pub fn snapshot_client_roster(&self) -> Vec<ClientId> {
        self.client_ids()
    }

    /// Store serialized share bytes from a client.
    pub fn store_client_input_bytes(&self, client_id: ClientId, share_bytes: Vec<Vec<u8>>) {
        self.store_client_shares(
            client_id,
            share_bytes
                .into_iter()
                .map(ClientShare::untyped_bytes)
                .collect(),
        );
    }

    /// Retrieve VM share payloads for a specific client.
    pub fn get_client_input_shares(&self, client_id: ClientId) -> Option<Vec<ClientShare>> {
        let entries = self.entries.read();
        entries.get(&client_id).map(|entry| entry.shares.clone())
    }

    /// Retrieve a specific VM share payload for a client by index.
    pub fn get_client_share_data(
        &self,
        client_id: ClientId,
        index: ClientShareIndex,
    ) -> Option<ClientShare> {
        let entries = self.entries.read();
        entries
            .get(&client_id)
            .and_then(|entry| entry.shares.get(index.index()).cloned())
    }

    /// Retrieve serialized shares for a specific client.
    pub fn get_client_input_bytes(&self, client_id: ClientId) -> Option<Vec<Vec<u8>>> {
        let entries = self.entries.read();
        entries.get(&client_id).map(|entry| {
            entry
                .shares
                .iter()
                .map(|share| share.bytes().to_vec())
                .collect()
        })
    }

    /// Retrieve a specific serialized share for a client by index.
    pub fn get_client_share_bytes(
        &self,
        client_id: ClientId,
        index: ClientShareIndex,
    ) -> Option<Vec<u8>> {
        self.get_client_share_data(client_id, index)
            .map(|share| share.bytes().to_vec())
    }

    /// Check if a client has provided inputs.
    pub fn has_client_input(&self, client_id: ClientId) -> bool {
        let entries = self.entries.read();
        entries.contains_key(&client_id)
    }

    /// Get the number of shares a client has provided.
    pub fn get_client_input_count(&self, client_id: ClientId) -> usize {
        let entries = self.entries.read();
        entries
            .get(&client_id)
            .map(|entry| entry.shares.len())
            .unwrap_or(0)
    }

    /// List all client IDs that have provided inputs.
    pub fn list_clients(&self) -> Vec<ClientId> {
        let entries = self.entries.read();
        entries.keys().copied().collect()
    }

    /// Remove shares for a specific client.
    pub fn remove_client_input(&self, client_id: ClientId) -> Option<ClientInputEntry> {
        let mut entries = self.entries.write();
        entries.remove(&client_id)
    }

    /// Clear all client inputs.
    pub fn clear(&self) {
        let mut entries = self.entries.write();
        entries.clear();
        drop(entries);
        self.client_roster.write().clear();
    }

    /// Get the total number of known clients in the store.
    pub fn len(&self) -> usize {
        let roster = self.client_roster.read();
        if roster.is_empty() {
            self.entries.read().len()
        } else {
            roster.len()
        }
    }

    /// Get the number of clients that have provided input material.
    pub fn input_client_count(&self) -> usize {
        self.entries.read().len()
    }

    /// Get the number of output-capable clients known to the VM.
    pub fn output_client_count(&self) -> usize {
        self.len()
    }

    /// Check if the store is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Return the client ID at a given index in sorted order.
    pub fn client_id_at(&self, index: ClientInputIndex) -> Option<ClientId> {
        let roster = self.client_roster.read();
        if roster.is_empty() {
            self.entries.read().keys().nth(index.index()).copied()
        } else {
            roster.get(index.index()).copied()
        }
    }

    /// Return all client IDs in sorted order.
    pub fn client_ids(&self) -> Vec<ClientId> {
        let roster = self.client_roster.read();
        if roster.is_empty() {
            self.entries.read().keys().copied().collect()
        } else {
            roster.clone()
        }
    }

    /// Replace the VM-facing known client roster.
    pub fn set_client_roster<I>(&self, clients: I)
    where
        I: IntoIterator<Item = ClientId>,
    {
        let mut clients = clients.into_iter().collect::<Vec<_>>();
        clients.sort_unstable();
        clients.dedup();
        *self.client_roster.write() = clients;
    }

    /// Add one known client while preserving deterministic client-slot order.
    pub fn add_known_client(&self, client_id: ClientId) {
        let mut roster = self.client_roster.write();
        match roster.binary_search(&client_id) {
            Ok(_) => {}
            Err(index) => roster.insert(index, client_id),
        }
    }

    fn add_known_clients<I>(&self, clients: I)
    where
        I: IntoIterator<Item = ClientId>,
    {
        let mut roster = self.client_roster.read().clone();
        roster.extend(clients);
        self.set_client_roster(roster);
    }
}
