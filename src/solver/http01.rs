use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use crate::acme::ChallengeInfo;
use crate::error::{Error, Result};

/// HTTP-01 solver: standalone HTTP server mode.
pub struct Http01StandaloneSolver {
    listen: Vec<SocketAddr>,
    tokens: Arc<RwLock<HashMap<String, String>>>,
    server_started: Arc<tokio::sync::Notify>,
    _server_handle: tokio::sync::OnceCell<tokio::task::JoinHandle<()>>,
}

impl Http01StandaloneSolver {
    pub fn new(listen: Vec<SocketAddr>) -> Self {
        Self {
            listen,
            tokens: Arc::new(RwLock::new(HashMap::new())),
            server_started: Arc::new(tokio::sync::Notify::new()),
            _server_handle: tokio::sync::OnceCell::new(),
        }
    }

    async fn ensure_server_running(&self) -> Result<()> {
        let _ = self._server_handle.get_or_try_init(|| async {
            // Try binding all addresses, succeed if at least one works
            let mut listeners = Vec::new();
            let mut errors = Vec::new();

            for addr in &self.listen {
                match TcpListener::bind(addr).await {
                    Ok(listener) => {
                        tracing::info!(listen = %addr, "HTTP-01 challenge server listening");
                        listeners.push(listener);
                    }
                    Err(e) => {
                        tracing::warn!(listen = %addr, error = %e, "HTTP-01 solver: failed to bind address");
                        errors.push(format!("{addr}: {e}"));
                    }
                }
            }

            if listeners.is_empty() {
                return Err(Error::Config(format!(
                    "HTTP-01 solver: failed to bind any address: {}",
                    errors.join(", ")
                )));
            }

            let tokens = self.tokens.clone();
            let started = self.server_started.clone();

            // Register the listener before spawning so we don't miss the notification
            let notified = self.server_started.notified();

            let handle = tokio::spawn(async move {
                started.notify_waiters();
                // Spawn an accept loop for each bound listener
                let mut handles = Vec::new();
                for listener in listeners {
                    let tokens = tokens.clone();
                    handles.push(tokio::spawn(async move {
                        loop {
                            let Ok((stream, _addr)) = listener.accept().await else {
                                continue;
                            };
                            let tokens = tokens.clone();
                            tokio::spawn(async move {
                                let service = service_fn(move |req: Request<hyper::body::Incoming>| {
                                    let tokens = tokens.clone();
                                    async move {
                                        handle_request(req, &tokens).await
                                    }
                                });
                                let _ = http1::Builder::new()
                                    .serve_connection(hyper_util::rt::TokioIo::new(stream), service)
                                    .await;
                            });
                        }
                    }));
                }
                // Wait for all accept loops (they run forever)
                for h in handles {
                    let _ = h.await;
                }
            });

            notified.await;

            Ok::<_, Error>(handle)
        }).await;
        Ok(())
    }
}

async fn handle_request(
    req: Request<hyper::body::Incoming>,
    tokens: &RwLock<HashMap<String, String>>,
) -> std::result::Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();

    if let Some(token) = path.strip_prefix("/.well-known/acme-challenge/") {
        let tokens = tokens.read().await;
        if let Some(key_auth) = tokens.get(token) {
            tracing::debug!(%token, "serving HTTP-01 challenge response");
            return Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain")
                .body(Full::new(Bytes::from(key_auth.clone())))
                .unwrap());
        }
    }

    Ok(Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from("not found")))
        .unwrap())
}

#[async_trait::async_trait]
impl super::Solver for Http01StandaloneSolver {
    async fn present(&self, challenge: &ChallengeInfo) -> Result<()> {
        self.ensure_server_running().await?;

        tracing::debug!(
            identifier = %challenge.identifier,
            token = %challenge.token,
            "presenting HTTP-01 challenge"
        );

        self.tokens
            .write()
            .await
            .insert(challenge.token.clone(), challenge.key_authorization.clone());

        Ok(())
    }

    async fn cleanup(&self, challenge: &ChallengeInfo) -> Result<()> {
        self.tokens.write().await.remove(&challenge.token);
        tracing::debug!(
            identifier = %challenge.identifier,
            "cleaned up HTTP-01 challenge"
        );
        Ok(())
    }
}

/// HTTP-01 solver: webroot mode.
pub struct Http01WebrootSolver {
    webroot: PathBuf,
}

impl Http01WebrootSolver {
    pub fn new(webroot: PathBuf) -> Self {
        Self { webroot }
    }

    fn challenge_path(&self, token: &str) -> PathBuf {
        self.webroot
            .join(".well-known")
            .join("acme-challenge")
            .join(token)
    }
}

#[async_trait::async_trait]
impl super::Solver for Http01WebrootSolver {
    async fn present(&self, challenge: &ChallengeInfo) -> Result<()> {
        let path = self.challenge_path(&challenge.token);
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&path, &challenge.key_authorization)?;
        tracing::debug!(
            identifier = %challenge.identifier,
            path = %path.display(),
            "wrote HTTP-01 challenge token"
        );
        Ok(())
    }

    async fn cleanup(&self, challenge: &ChallengeInfo) -> Result<()> {
        let path = self.challenge_path(&challenge.token);
        if path.exists() {
            std::fs::remove_file(&path)?;
            tracing::debug!(
                identifier = %challenge.identifier,
                path = %path.display(),
                "removed HTTP-01 challenge token"
            );
        }
        Ok(())
    }
}
