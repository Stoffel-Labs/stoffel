use super::ClientShareIndex;
use stoffelnet::network_utils::ClientId;

#[derive(Debug, thiserror::Error)]
pub enum ClientInputStoreError {
    #[error(
        "client {client_id} provided {share_count} shares but {type_count} share types were declared"
    )]
    ShareTypeCountMismatch {
        client_id: ClientId,
        share_count: usize,
        type_count: usize,
    },
    #[error(
        "failed to serialize robust share for client {client_id} at index {share_index}: {reason}"
    )]
    RobustShareSerialization {
        client_id: ClientId,
        share_index: ClientShareIndex,
        reason: String,
    },
    #[error(
        "failed to serialize Feldman share for client {client_id} at index {share_index}: {reason}"
    )]
    FeldmanShareSerialization {
        client_id: ClientId,
        share_index: ClientShareIndex,
        reason: String,
    },
    #[error(
        "failed to serialize Feldman commitments for client {client_id} at index {share_index}: {reason}"
    )]
    FeldmanCommitmentSerialization {
        client_id: ClientId,
        share_index: ClientShareIndex,
        reason: String,
    },
}
