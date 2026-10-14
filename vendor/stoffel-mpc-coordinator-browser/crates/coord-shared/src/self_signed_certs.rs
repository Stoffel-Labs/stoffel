//! TLS utilities for mutual TLS (mTLS) connections using self-signed certificates.
//!
//! The legacy helpers skip certificate-chain validation. Native open collection
//! uses `setup_client_pinned` instead: it requires an independently trusted P-256
//! identity, certificate validity, and cryptographic handshake signature verification.

use crate::CoordinatorError;
use jsonrpsee::async_client::Client;
use jsonrpsee::client_transport::ws::WsTransportClientBuilder;
use jsonrpsee::core::client::ClientBuilder;
use rustls::client::danger::{ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::CertificateDer;
use rustls::pki_types::PrivateKeyDer;
use rustls::pki_types::PrivatePkcs8KeyDer;
use rustls::pki_types::ServerName;
use rustls::pki_types::UnixTime;
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::ClientConfig;
use rustls::DistinguishedName;
use std::sync::Arc;
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use url::Url;

/// Server-side verifier that accepts any self-signed client certificate.
///
/// Skips chain validation entirely; used when clients authenticate with
/// self-signed certs that have no CA anchor.
#[derive(Debug)]
pub struct SelfSignedClientVerifier;

/// Client-side verifier that accepts any self-signed server certificate.
///
/// Skips chain validation entirely; used when the server presents a self-signed
/// cert that has no CA anchor.
#[derive(Debug)]
pub struct SelfSignedServerVerifier;

impl ClientCertVerifier for SelfSignedClientVerifier {
    /// Returns no CA hint subjects — chain validation is not performed.
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }

    /// Accepts any client certificate unconditionally.
    fn verify_client_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        Ok(ClientCertVerified::assertion())
    }

    /// Verifies the TLS 1.2 handshake signature using the ring crypto provider.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    /// Verifies the TLS 1.3 handshake signature using the ring crypto provider.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    /// Returns the signature schemes supported by the ring crypto provider.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

impl ServerCertVerifier for SelfSignedServerVerifier {
    /// Accepts any server certificate unconditionally.
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    /// Verifies the TLS 1.2 handshake signature using the ring crypto provider.
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    /// Verifies the TLS 1.3 handshake signature using the ring crypto provider.
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }

    /// Returns the signature schemes supported by the ring crypto provider.
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Generates a self-signed certificate for the server, valid for `localhost` and `127.0.0.1`.
pub fn server_cert() -> Arc<rcgen::CertifiedKey<rcgen::KeyPair>> {
    let subject_alt_names = vec!["localhost".to_string(), "127.0.0.1".to_string()];

    Arc::new(
        rcgen::generate_simple_self_signed(subject_alt_names)
            .expect("cert generation with fixed subject alt names never fails"),
    )
}

/// Generates a self-signed certificate for a client.
pub fn client_cert() -> Arc<rcgen::CertifiedKey<rcgen::KeyPair>> {
    let subject_alt_names = vec!["client".to_string()];

    Arc::new(
        rcgen::generate_simple_self_signed(subject_alt_names)
            .expect("cert generation with fixed subject alt names never fails"),
    )
}

/// Builds a `rustls::ServerConfig` for mTLS using `SelfSignedClientVerifier`.
///
/// Clients must present a certificate, but chain validation is skipped.
pub fn server_tls_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<rustls::ServerConfig, CoordinatorError> {
    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    rustls::ServerConfig::builder()
        .with_client_cert_verifier(Arc::new(SelfSignedClientVerifier {}))
        .with_single_cert(certs, key)
        .map_err(|e| CoordinatorError::TlsConfigError(e.to_string()))
}

/// Builds a `rustls::ClientConfig` for mTLS, presenting the given client certificate.
fn client_tls_config(
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<ClientConfig, CoordinatorError> {
    let certs = vec![CertificateDer::from(cert_der)];
    let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_der));

    ClientConfig::builder()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_client_auth_cert(certs, key)
        .map_err(|e| CoordinatorError::TlsConfigError(e.to_string()))
}

/// Connects to a remote WebSocket server over mTLS and returns a `Client`.
///
/// Establishes a TCP connection to `addr:port`, upgrades it to TLS using the
/// provided client certificate, and wraps the TLS stream in a WebSocket transport.
/// Server certificate chain validation is skipped via `SelfSignedServerVerifier`.
pub async fn setup_client(
    addr: &str,
    port: u16,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
) -> Result<Client, CoordinatorError> {
    let full_addr = format!("{}:{}", addr, port);
    let url = format!("wss://{}/", full_addr);
    let mut tls_config = client_tls_config(cert_der, key_der)?;
    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(SelfSignedServerVerifier {}));

    let tls_connector = TlsConnector::from(Arc::new(tls_config));
    let tcp_stream = TcpStream::connect(&full_addr)
        .await
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?;
    let domain = ServerName::try_from(addr)
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?
        .to_owned();
    let tls_stream = tls_connector
        .connect(domain, tcp_stream)
        .await
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?;

    let (sender, receiver) = WsTransportClientBuilder::default()
        .build_with_stream(
            Url::parse(&url).map_err(|e| CoordinatorError::ConnectError(e.to_string()))?,
            tls_stream,
        )
        .await
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?;

    Ok(ClientBuilder::default().build_with_tokio(sender, receiver))
}

/// Strict identity verifier for native open collection. Trust comes only from the
/// independently configured canonical, uncompressed P-256 SEC1 public key, not DNS.
#[derive(Debug)]
struct PinnedServerVerifier {
    expected_spki: Vec<u8>,
}
impl PinnedServerVerifier {
    fn new(pin: &[u8]) -> Result<Self, CoordinatorError> {
        use p256::{elliptic_curve::sec1::ToEncodedPoint, pkcs8::EncodePublicKey};
        let key = p256::PublicKey::from_sec1_bytes(pin).map_err(|_| {
            CoordinatorError::TlsConfigError("invalid coordinator P-256 public key".into())
        })?;
        if key.to_encoded_point(false).as_bytes() != pin {
            return Err(CoordinatorError::TlsConfigError(
                "coordinator key must be canonical uncompressed SEC1".into(),
            ));
        }
        let spki = key
            .to_public_key_der()
            .map_err(|_| CoordinatorError::TlsConfigError("invalid coordinator SPKI".into()))?;
        Ok(Self {
            expected_spki: spki.as_bytes().to_vec(),
        })
    }
}
impl ServerCertVerifier for PinnedServerVerifier {
    fn verify_server_cert(
        &self,
        cert: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let invalid = || {
            rustls::Error::General("coordinator certificate identity or validity mismatch".into())
        };
        let (remaining, parsed) =
            x509_parser::parse_x509_certificate(cert.as_ref()).map_err(|_| invalid())?;
        if !remaining.is_empty() || parsed.public_key().raw != self.expected_spki.as_slice() {
            return Err(invalid());
        }
        let now = i64::try_from(now.as_secs()).map_err(|_| invalid())?;
        if now < parsed.validity().not_before.timestamp()
            || now > parsed.validity().not_after.timestamp()
        {
            return Err(invalid());
        }
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &rustls::crypto::ring::default_provider().signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Connect using a REQUIRED independently trusted coordinator identity. Invalid
/// pins fail before opening TCP; there is no legacy accept-any fallback.
pub async fn setup_client_pinned(
    addr: &str,
    port: u16,
    cert_der: Vec<u8>,
    key_der: Vec<u8>,
    expected_coordinator_public_key: &[u8],
) -> Result<Client, CoordinatorError> {
    let verifier = PinnedServerVerifier::new(expected_coordinator_public_key)?;
    let full_addr = format!("{}:{}", addr, port);
    let url = format!("wss://{}/", full_addr);
    let mut tls_config = client_tls_config(cert_der, key_der)?;
    tls_config
        .dangerous()
        .set_certificate_verifier(Arc::new(verifier));

    let tls_connector = TlsConnector::from(Arc::new(tls_config));
    let tcp_stream = TcpStream::connect(&full_addr)
        .await
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?;
    let domain = ServerName::try_from(addr)
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?
        .to_owned();
    let tls_stream = tls_connector
        .connect(domain, tcp_stream)
        .await
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?;

    let (sender, receiver) = WsTransportClientBuilder::default()
        .build_with_stream(
            Url::parse(&url).map_err(|e| CoordinatorError::ConnectError(e.to_string()))?,
            tls_stream,
        )
        .await
        .map_err(|e| CoordinatorError::ConnectError(e.to_string()))?;

    Ok(ClientBuilder::default().build_with_tokio(sender, receiver))
}

#[cfg(test)]
mod pinned_tests {
    use super::*;
    use tokio::{
        io::AsyncWriteExt,
        net::TcpListener,
        time::{timeout, Duration},
    };
    fn public(cert: &rcgen::CertifiedKey<rcgen::KeyPair>) -> Vec<u8> {
        cert.signing_key.public_key_raw().to_vec()
    }
    async fn peer(
        cert: Arc<rcgen::CertifiedKey<rcgen::KeyPair>>,
    ) -> (u16, tokio::task::JoinHandle<bool>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let config =
            server_tls_config(cert.cert.der().to_vec(), cert.signing_key.serialize_der()).unwrap();
        let task = tokio::spawn(async move {
            let accepted = timeout(Duration::from_millis(800), listener.accept()).await;
            let Ok(Ok((tcp, _))) = accepted else {
                return false;
            };
            let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
            match acceptor.accept(tcp).await {
                Ok(mut tls) => {
                    let _ = tls.write_all(b"x").await;
                    true
                }
                Err(_) => false,
            }
        });
        (port, task)
    }
    #[tokio::test]
    async fn actual_tls_peer_correct_and_wrong_identity() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = server_cert();
        for (pin, expected) in [(public(&server), true), (public(&server_cert()), false)] {
            let (port, task) = peer(server.clone()).await;
            let client = client_cert();
            let mut config = client_tls_config(
                client.cert.der().to_vec(),
                client.signing_key.serialize_der(),
            )
            .unwrap();
            config
                .dangerous()
                .set_certificate_verifier(Arc::new(PinnedServerVerifier::new(&pin).unwrap()));
            let tcp = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
            let result = TlsConnector::from(Arc::new(config))
                .connect(ServerName::try_from("localhost").unwrap(), tcp)
                .await;
            assert_eq!(result.is_ok(), expected);
            drop(result);
            let _ = task.await.unwrap();
        }
    }
    #[tokio::test]
    async fn empty_invalid_and_compressed_pin_fail_before_tcp() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let server = server_cert();
        let valid = public(&server);
        use p256::elliptic_curve::sec1::ToEncodedPoint;
        let compressed = p256::PublicKey::from_sec1_bytes(&valid)
            .unwrap()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        for pin in [vec![], vec![4; 65], compressed] {
            let (port, task) = peer(server.clone()).await;
            let client = client_cert();
            assert!(setup_client_pinned(
                "127.0.0.1",
                port,
                client.cert.der().to_vec(),
                client.signing_key.serialize_der(),
                &pin
            )
            .await
            .is_err());
            assert!(!task.await.unwrap(), "invalid pin must not open TCP");
        }
    }
    #[test]
    fn certificate_validity_and_malformed_der_rejected() {
        let signing_key = rcgen::KeyPair::generate().unwrap();
        let mut params = rcgen::CertificateParams::new(vec!["localhost".into()]).unwrap();
        params.not_before = rcgen::date_time_ymd(2020, 1, 1);
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        let cert = params.self_signed(&signing_key).unwrap();
        let server = rcgen::CertifiedKey { cert, signing_key };
        let verifier = PinnedServerVerifier::new(&public(&server)).unwrap();
        let name = ServerName::try_from("localhost").unwrap();
        for now in [0, 10_000_000_000] {
            assert!(verifier
                .verify_server_cert(
                    server.cert.der(),
                    &[],
                    &name,
                    &[],
                    UnixTime::since_unix_epoch(std::time::Duration::from_secs(now))
                )
                .is_err());
        }
        assert!(verifier
            .verify_server_cert(
                &CertificateDer::from(vec![0; 10]),
                &[],
                &name,
                &[],
                UnixTime::now()
            )
            .is_err());
    }
}
