use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;

use rcgen::{CertificateParams, CustomExtension, KeyPair, SanType};
use ring::digest;
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;

use crate::acme::ChallengeInfo;
use crate::error::{Error, Result};

// OID for id-pe-acmeIdentifier (1.3.6.1.5.5.7.1.31)
const ACME_IDENTIFIER_OID: &[u64] = &[1, 3, 6, 1, 5, 5, 7, 1, 31];

// ALPN protocol for ACME TLS-ALPN-01
const ACME_TLS_ALPN_PROTO: &[u8] = b"acme-tls/1";

/// TLS-ALPN-01 solver with dynamic certificate resolution.
pub struct TlsAlpn01Solver {
    listen: SocketAddr,
    certs: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
    _server_handle: tokio::sync::OnceCell<tokio::task::JoinHandle<()>>,
    server_started: Arc<tokio::sync::Notify>,
}

impl TlsAlpn01Solver {
    pub fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            certs: Arc::new(RwLock::new(HashMap::new())),
            _server_handle: tokio::sync::OnceCell::new(),
            server_started: Arc::new(tokio::sync::Notify::new()),
        }
    }

    async fn ensure_server_running(&self) -> Result<()> {
        let _ = self._server_handle.get_or_try_init(|| async {
            let listener = TcpListener::bind(self.listen).await.map_err(|e| {
                Error::Config(format!("TLS-ALPN-01 solver: failed to bind {}: {e}", self.listen))
            })?;
            tracing::info!(listen = %self.listen, "TLS-ALPN-01 challenge server started");

            let certs = self.certs.clone();
            let started = self.server_started.clone();

            let resolver = Arc::new(AcmeResolver {
                certs: certs.clone(),
            });

            let tls_config = Arc::new(
                rustls::ServerConfig::builder()
                    .with_no_client_auth()
                    .with_cert_resolver(resolver),
            );

            // Set ALPN protocols
            // Note: we accept acme-tls/1 — the resolver handles cert selection
            let mut tls_config_mut = (*tls_config).clone();
            tls_config_mut.alpn_protocols = vec![ACME_TLS_ALPN_PROTO.to_vec()];
            let tls_config = Arc::new(tls_config_mut);

            let acceptor = TlsAcceptor::from(tls_config);

            let handle = tokio::spawn(async move {
                started.notify_waiters();
                loop {
                    let Ok((stream, _addr)) = listener.accept().await else {
                        continue;
                    };
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        // Just accept and immediately close — the TLS handshake IS the validation
                        let _ = acceptor.accept(stream).await;
                    });
                }
            });

            self.server_started.notified().await;

            Ok::<_, Error>(handle)
        }).await;
        Ok(())
    }
}

/// Dynamic certificate resolver for TLS-ALPN-01 challenges.
#[derive(Debug)]
struct AcmeResolver {
    certs: Arc<RwLock<HashMap<String, Arc<CertifiedKey>>>>,
}

impl ResolvesServerCert for AcmeResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        let server_name = client_hello.server_name()?;
        // Try blocking read — this runs in the TLS handshake path
        let certs = self.certs.blocking_read();
        certs.get(server_name).cloned()
    }
}

/// Generate a self-signed certificate for TLS-ALPN-01 validation.
///
/// The certificate contains:
/// - SAN matching the identifier (domain or IP)
/// - Critical acmeIdentifier extension with SHA-256(key_authorization)
fn generate_acme_cert(identifier: &str, key_authorization: &str) -> Result<CertifiedKey> {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .map_err(|e| Error::Certificate(format!("failed to generate ALPN cert key: {e}")))?;

    let mut params = if let Ok(ip) = identifier.parse::<IpAddr>() {
        let mut p = CertificateParams::default();
        p.subject_alt_names = vec![SanType::IpAddress(ip)];
        p
    } else {
        CertificateParams::new(vec![identifier.to_string()])
            .map_err(|e| Error::Certificate(format!("invalid ALPN cert params: {e}")))?
    };

    params.distinguished_name = rcgen::DistinguishedName::new();

    // acmeIdentifier extension: DER-encoded ASN.1 OCTET STRING of SHA-256(key_authorization)
    // RFC 8737 Section 3: The value is the SHA-256 digest, wrapped in an ASN.1 OCTET STRING
    let auth_hash = digest::digest(&digest::SHA256, key_authorization.as_bytes());
    let mut der_value = Vec::new();
    der_value.push(0x04); // OCTET STRING tag
    der_value.push(auth_hash.as_ref().len() as u8);
    der_value.extend_from_slice(auth_hash.as_ref());

    let mut ext = CustomExtension::from_oid_content(ACME_IDENTIFIER_OID, der_value);
    ext.set_criticality(true);
    params.custom_extensions = vec![ext];

    let cert = params.self_signed(&key_pair)
        .map_err(|e| Error::Certificate(format!("failed to generate ALPN cert: {e}")))?;

    let cert_der = rustls_pki_types::CertificateDer::from(cert.der().to_vec());
    let key_der = rustls_pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der());

    let signing_key = rustls::crypto::ring::sign::any_supported_type(&key_der.into())
        .map_err(|e| Error::Certificate(format!("failed to create signing key: {e}")))?;

    Ok(CertifiedKey::new(vec![cert_der], signing_key))
}

#[async_trait::async_trait]
impl super::Solver for TlsAlpn01Solver {
    async fn present(&self, challenge: &ChallengeInfo) -> Result<()> {
        self.ensure_server_running().await?;

        tracing::debug!(
            identifier = %challenge.identifier,
            "presenting TLS-ALPN-01 challenge"
        );

        let certified_key = generate_acme_cert(&challenge.identifier, &challenge.key_authorization)?;

        self.certs
            .write()
            .await
            .insert(challenge.identifier.clone(), Arc::new(certified_key));

        Ok(())
    }

    async fn cleanup(&self, challenge: &ChallengeInfo) -> Result<()> {
        self.certs.write().await.remove(&challenge.identifier);
        tracing::debug!(
            identifier = %challenge.identifier,
            "cleaned up TLS-ALPN-01 challenge"
        );
        Ok(())
    }
}
