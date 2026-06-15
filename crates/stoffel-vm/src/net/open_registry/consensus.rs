use std::time::{Duration, Instant};

use tokio::sync::Notify;

use super::InstanceRegistry;

fn wait_for_registry_result<T, Check>(
    notify: &Notify,
    timeout_ms: u64,
    timeout_message: impl Fn() -> String,
    mut check: Check,
) -> Result<T, String>
where
    Check: FnMut() -> Option<T>,
{
    if let Ok(handle) = tokio::runtime::Handle::try_current() {
        if handle.runtime_flavor() == tokio::runtime::RuntimeFlavor::MultiThread {
            return tokio::task::block_in_place(|| {
                handle.block_on(async {
                    let deadline = tokio::time::Instant::now()
                        + tokio::time::Duration::from_millis(timeout_ms);
                    loop {
                        let notified = notify.notified();
                        if let Some(result) = check() {
                            return Ok(result);
                        }
                        if tokio::time::Instant::now() >= deadline {
                            return Err(timeout_message());
                        }
                        tokio::select! {
                            _ = notified => {}
                            _ = tokio::time::sleep_until(deadline) => {}
                        }
                    }
                })
            });
        }
    }

    let deadline = Instant::now() + Duration::from_millis(timeout_ms);
    loop {
        if let Some(result) = check() {
            return Ok(result);
        }
        if Instant::now() >= deadline {
            return Err(timeout_message());
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

async fn wait_for_registry_result_async<T, Check>(
    notify: &Notify,
    timeout_ms: u64,
    timeout_message: impl Fn() -> String,
    mut check: Check,
) -> Result<T, String>
where
    Check: FnMut() -> Option<T>,
{
    let deadline = tokio::time::Instant::now() + tokio::time::Duration::from_millis(timeout_ms);

    loop {
        let notified = notify.notified();
        if let Some(result) = check() {
            return Ok(result);
        }
        if tokio::time::Instant::now() >= deadline {
            return Err(timeout_message());
        }
        tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep_until(deadline) => {}
        }
    }
}

impl InstanceRegistry {
    pub(crate) fn insert_rbc_broadcast(&self, party_id: usize, message: Vec<u8>) {
        let mut registry = self.rbc.lock();

        let mut session_id = 0u64;
        while registry.messages.contains_key(&(session_id, party_id)) {
            session_id = match session_id.checked_add(1) {
                Some(next) => next,
                None => return,
            };
        }

        registry.messages.insert((session_id, party_id), message);
        drop(registry);
        self.rbc_notify.notify_waiters();
    }

    pub fn rbc_broadcast(&self, party_id: usize, message: &[u8]) -> Result<u64, String> {
        let mut registry = self.rbc.lock();

        let mut session_id = 0u64;
        while registry.messages.contains_key(&(session_id, party_id)) {
            session_id = session_id
                .checked_add(1)
                .ok_or_else(|| "RBC session id overflow".to_string())?;
        }

        registry
            .messages
            .insert((session_id, party_id), message.to_vec());
        drop(registry);

        self.rbc_notify.notify_waiters();

        tracing::info!(
            instance_id = self.instance_id(),
            session_id = session_id,
            party_id = party_id,
            message_len = message.len(),
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

    pub fn rbc_receive(
        &self,
        receiver_party_id: usize,
        from_party: usize,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, String> {
        let instance_id = self.instance_id();
        wait_for_registry_result(
            &self.rbc_notify,
            timeout_ms,
            || format!("RBC receive timeout waiting for message from party {from_party}"),
            || {
                let mut registry = self.rbc.lock();
                let mut next: Option<(u64, Vec<u8>)> = None;
                for ((session_id, party), message) in registry.messages.iter() {
                    if *party != from_party {
                        continue;
                    }
                    let delivery_key = (receiver_party_id, from_party, *session_id);
                    if registry.delivered.contains(&delivery_key) {
                        continue;
                    }
                    match next {
                        Some((best_session, _)) if *session_id >= best_session => {}
                        _ => next = Some((*session_id, message.clone())),
                    }
                }
                if let Some((session_id, message)) = next {
                    registry
                        .delivered
                        .insert((receiver_party_id, from_party, session_id));
                    tracing::info!(
                        instance_id = instance_id,
                        session_id = session_id,
                        from_party = from_party,
                        message_len = message.len(),
                        "RBC receive delivered message"
                    );
                    return Some(message);
                }
                None
            },
        )
    }

    pub async fn rbc_receive_async(
        &self,
        receiver_party_id: usize,
        from_party: usize,
        timeout_ms: u64,
    ) -> Result<Vec<u8>, String> {
        let instance_id = self.instance_id();
        wait_for_registry_result_async(
            &self.rbc_notify,
            timeout_ms,
            || format!("RBC receive timeout waiting for message from party {from_party}"),
            || self.try_deliver_rbc_from(instance_id, receiver_party_id, from_party),
        )
        .await
    }

    pub fn rbc_receive_any(
        &self,
        receiver_party_id: usize,
        timeout_ms: u64,
    ) -> Result<(usize, Vec<u8>), String> {
        let instance_id = self.instance_id();
        wait_for_registry_result(
            &self.rbc_notify,
            timeout_ms,
            || "RBC receive_any timeout waiting for message from any party".to_string(),
            || {
                let mut registry = self.rbc.lock();
                let mut next: Option<(u64, usize, Vec<u8>)> = None;
                for ((session_id, party), message) in registry.messages.iter() {
                    if *party == receiver_party_id {
                        continue;
                    }
                    let delivery_key = (receiver_party_id, *party, *session_id);
                    if registry.delivered.contains(&delivery_key) {
                        continue;
                    }
                    match next {
                        Some((best_session, best_party, _))
                            if (*session_id, *party) >= (best_session, best_party) => {}
                        _ => next = Some((*session_id, *party, message.clone())),
                    }
                }
                if let Some((session_id, party, message)) = next {
                    registry
                        .delivered
                        .insert((receiver_party_id, party, session_id));
                    tracing::info!(
                        instance_id = instance_id,
                        session_id = session_id,
                        from_party = party,
                        message_len = message.len(),
                        "RBC receive_any delivered message"
                    );
                    return Some((party, message));
                }
                None
            },
        )
    }

    pub async fn rbc_receive_any_async(
        &self,
        receiver_party_id: usize,
        timeout_ms: u64,
    ) -> Result<(usize, Vec<u8>), String> {
        let instance_id = self.instance_id();
        wait_for_registry_result_async(
            &self.rbc_notify,
            timeout_ms,
            || "RBC receive_any timeout waiting for message from any party".to_string(),
            || self.try_deliver_rbc_any(instance_id, receiver_party_id),
        )
        .await
    }

    fn try_deliver_rbc_from(
        &self,
        instance_id: u64,
        receiver_party_id: usize,
        from_party: usize,
    ) -> Option<Vec<u8>> {
        let mut registry = self.rbc.lock();
        let mut next: Option<(u64, Vec<u8>)> = None;
        for ((session_id, party), message) in registry.messages.iter() {
            if *party != from_party {
                continue;
            }
            let delivery_key = (receiver_party_id, from_party, *session_id);
            if registry.delivered.contains(&delivery_key) {
                continue;
            }
            match next {
                Some((best_session, _)) if *session_id >= best_session => {}
                _ => next = Some((*session_id, message.clone())),
            }
        }
        if let Some((session_id, message)) = next {
            registry
                .delivered
                .insert((receiver_party_id, from_party, session_id));
            tracing::info!(
                instance_id = instance_id,
                session_id = session_id,
                from_party = from_party,
                message_len = message.len(),
                "RBC receive delivered message"
            );
            return Some(message);
        }
        None
    }

    fn try_deliver_rbc_any(
        &self,
        instance_id: u64,
        receiver_party_id: usize,
    ) -> Option<(usize, Vec<u8>)> {
        let mut registry = self.rbc.lock();
        let mut next: Option<(u64, usize, Vec<u8>)> = None;
        for ((session_id, party), message) in registry.messages.iter() {
            if *party == receiver_party_id {
                continue;
            }
            let delivery_key = (receiver_party_id, *party, *session_id);
            if registry.delivered.contains(&delivery_key) {
                continue;
            }
            match next {
                Some((best_session, best_party, _))
                    if (*session_id, *party) >= (best_session, best_party) => {}
                _ => next = Some((*session_id, *party, message.clone())),
            }
        }
        if let Some((session_id, party, message)) = next {
            registry
                .delivered
                .insert((receiver_party_id, party, session_id));
            tracing::info!(
                instance_id = instance_id,
                session_id = session_id,
                from_party = party,
                message_len = message.len(),
                "RBC receive_any delivered message"
            );
            return Some((party, message));
        }
        None
    }
}
