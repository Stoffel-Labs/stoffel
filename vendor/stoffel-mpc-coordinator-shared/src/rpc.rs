use crate::{self_signed_certs, CoordinatorError};
use hyper_util::rt::TokioIo;
use hyper_util::service::TowerToHyperService;
use jsonrpsee::server::{Methods, RpcModule, Server};
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io::Cursor;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::{oneshot, Mutex};
use tokio::task::{JoinHandle, JoinSet};
use tokio_rustls::TlsAcceptor;
use x509_parser::prelude::*;

/// This represents the JSON-RPC server's state for one client connection. Internally, it refers to
/// some cross-client shared state of the server and also stores the client's public key.
/// This allows the JSON-RPC methods that implement a `jsonrpsee` trait created using the `#rpc`
/// attribute to access such client-specific information, in particular the client's identity.
pub trait RPCServerConnection {
    type Internal: 'static + Send;
    fn new(internal: Arc<Mutex<Self::Internal>>, id: Vec<u8>) -> Self;
    fn into_rpc(self) -> RpcModule<Self>
    where
        Self: Sized;
}

/// Owns one listener and all connections accepted by it.
pub struct RPCServerHandle {
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

impl RPCServerHandle {
    pub async fn shutdown(mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        let _ = (&mut self.task).await;
    }
}

impl Drop for RPCServerHandle {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        self.task.abort();
    }
}

/// Starts a JSON-RPC server, which listens for Websocket connections over TLS.
pub async fn start_coord<T: RPCServerConnection>(
    addr: &str,
    port: u16,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    rpc_server_data: Arc<Mutex<T::Internal>>,
) -> Result<RPCServerHandle, CoordinatorError> {
    let full_addr = format!("{}:{}", addr, port);
    let tls_config = self_signed_certs::server_tls_config(cert_der, key_der)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(&full_addr)
        .await
        .map_err(|e| CoordinatorError::BindError(e.to_string()))?;

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                Some(_) = connections.join_next(), if !connections.is_empty() => {},
                accepted = listener.accept() => {
                    let (tcp_stream, _) = match accepted {
                        Ok(value) => value,
                        Err(error) => {
                            tracing::warn!("Accept failed: {error}");
                            continue;
                        }
                    };
                    let tls_acceptor = tls_acceptor.clone();
                    let rpc_server_data = rpc_server_data.clone();
                    connections.spawn(async move {
                        let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                            Ok(stream) => stream,
                            Err(error) => {
                                tracing::warn!("TLS handshake failed: {error}");
                                return;
                            }
                        };

                        let cert_der = match tls_stream
                            .get_ref()
                            .1
                            .peer_certificates()
                            .and_then(|certificates| certificates.first())
                            .map(|certificate| certificate.to_vec())
                        {
                            Some(certificate) => certificate,
                            None => {
                                tracing::warn!("Client connected without a certificate, rejecting");
                                return;
                            }
                        };

                        let public_key = match X509Certificate::from_der(&cert_der) {
                            Ok((_remainder, certificate)) => certificate
                                .public_key()
                                .subject_public_key
                                .data
                                .as_ref()
                                .to_vec(),
                            Err(error) => {
                                tracing::warn!("Failed to parse client certificate: {error}");
                                return;
                            }
                        };

                        let (stop_rx, stop_tx) = jsonrpsee::server::stop_channel();
                        let rpc_service = Server::builder()
                            .to_service_builder()
                            .build(T::new(rpc_server_data, public_key).into_rpc(), stop_rx);
                        let result = hyper::server::conn::http1::Builder::new()
                            .serve_connection(
                                TokioIo::new(tls_stream),
                                TowerToHyperService::new(rpc_service),
                            )
                            .with_upgrades()
                            .await;
                        if let Err(error) = result {
                            tracing::warn!("Connection error: {error}");
                        }
                        // Hyper finishes after upgrading the socket, while jsonrpsee continues
                        // the WebSocket in its own task. Keep the stop sender owned by this task
                        // until that upgraded task ends.
                        stop_tx.stopped().await;
                    });
                }
            }
        }
        connections.shutdown().await;
    });

    Ok(RPCServerHandle {
        shutdown: Some(shutdown_tx),
        task,
    })
}

/// Builds a `rustls::ServerConfig` that authenticates only the server, not the client -- the
/// TLS handshake a browser's `new WebSocket("wss://...")` performs. Unlike
/// `self_signed_certs::server_tls_config` (mTLS, self-signed, client cert required), this reads
/// an ordinary PEM certificate chain and private key -- typically CA-issued (e.g. Let's
/// Encrypt/ACM), since browsers reject a self-signed cert on a raw WebSocket handshake with no
/// prompt to accept it. Client identity for `start_coord_browser_tls`'s connections must instead
/// be established at the application layer, per request; see `stoffel_mpc_coordinator_off_chain::browser_rpc`.
pub fn browser_tls_config(
    cert_chain_pem: &[u8],
    key_pem: &[u8],
) -> Result<rustls::ServerConfig, CoordinatorError> {
    let certs: Vec<CertificateDer<'static>> =
        rustls_pemfile::certs(&mut Cursor::new(cert_chain_pem))
            .collect::<Result<_, _>>()
            .map_err(|e| {
                CoordinatorError::TlsConfigError(format!("invalid certificate chain PEM: {e}"))
            })?;
    if certs.is_empty() {
        return Err(CoordinatorError::TlsConfigError(
            "certificate chain PEM contained no certificates".to_string(),
        ));
    }
    let key: PrivateKeyDer<'static> = rustls_pemfile::private_key(&mut Cursor::new(key_pem))
        .map_err(|e| CoordinatorError::TlsConfigError(format!("invalid private key PEM: {e}")))?
        .ok_or_else(|| {
            CoordinatorError::TlsConfigError("private key PEM contained no key".to_string())
        })?;

    rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| CoordinatorError::TlsConfigError(e.to_string()))
}

/// Starts a JSON-RPC server for browser clients over ordinary server-authenticated TLS, serving
/// the same pre-built `methods` to every connection.
///
/// This deliberately does not derive a per-connection client identity from the TLS handshake
/// the way `start_coord` does: a browser cannot present a TLS client certificate at all (there
/// is no browser API for it), so `methods` is expected to authenticate each individual request
/// itself instead of once per connection -- see `stoffel_mpc_coordinator_off_chain::browser_rpc`,
/// which signs every request with a P-256 keypair the browser fully controls and verifies that
/// signature inside each handler.
pub async fn start_coord_browser_tls(
    addr: &str,
    port: u16,
    cert_chain_pem: Vec<u8>,
    key_pem: Vec<u8>,
    methods: impl Into<Methods>,
) -> Result<RPCServerHandle, CoordinatorError> {
    let methods = methods.into();
    let full_addr = format!("{}:{}", addr, port);
    let tls_config = browser_tls_config(&cert_chain_pem, &key_pem)?;
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    let listener = TcpListener::bind(&full_addr)
        .await
        .map_err(|e| CoordinatorError::BindError(e.to_string()))?;

    let (shutdown_tx, mut shutdown_rx) = oneshot::channel();
    let task = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                _ = &mut shutdown_rx => break,
                Some(_) = connections.join_next(), if !connections.is_empty() => {},
                accepted = listener.accept() => {
                    let (tcp_stream, _) = match accepted {
                        Ok(value) => value,
                        Err(error) => {
                            tracing::warn!("Accept failed: {error}");
                            continue;
                        }
                    };
                    let tls_acceptor = tls_acceptor.clone();
                    let methods = methods.clone();
                    connections.spawn(async move {
                        let tls_stream = match tls_acceptor.accept(tcp_stream).await {
                            Ok(stream) => stream,
                            Err(error) => {
                                tracing::warn!("TLS handshake failed: {error}");
                                return;
                            }
                        };

                        let (stop_rx, stop_tx) = jsonrpsee::server::stop_channel();
                        let rpc_service = Server::builder()
                            .to_service_builder()
                            .build(methods, stop_rx);
                        let result = hyper::server::conn::http1::Builder::new()
                            .serve_connection(
                                TokioIo::new(tls_stream),
                                TowerToHyperService::new(rpc_service),
                            )
                            .with_upgrades()
                            .await;
                        if let Err(error) = result {
                            tracing::warn!("Connection error: {error}");
                        }
                        // Hyper finishes after upgrading the socket, while jsonrpsee continues
                        // the WebSocket in its own task. Keep the stop sender owned by this task
                        // until that upgraded task ends.
                        stop_tx.stopped().await;
                    });
                }
            }
        }
        connections.shutdown().await;
    });

    Ok(RPCServerHandle {
        shutdown: Some(shutdown_tx),
        task,
    })
}
