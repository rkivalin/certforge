use std::path::PathBuf;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("ACME error: {0}")]
    Acme(#[from] instant_acme::Error),

    #[error("DNS update failed: {0}")]
    DnsUpdate(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("key error: {0}")]
    Key(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("credential {name} not found at {path}")]
    CredentialNotFound { name: String, path: PathBuf },

    #[error("systemd-creds failed: {0}")]
    SystemdCreds(String),

    #[error("hook {hook} failed: {message}")]
    Hook { hook: String, message: String },

    #[error("state error: {0}")]
    State(String),

    #[error(transparent)]
    Io(#[from] std::io::Error),

    #[error(transparent)]
    Other(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;
