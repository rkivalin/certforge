use std::path::Path;
use tokio::process::Command;

use crate::error::{Error, Result};

/// Load a secret from either a systemd encrypted credential file or a plain file.
///
/// If `credential` is set, decrypts it at runtime via `systemd-creds decrypt`.
/// If only `path` is set, reads the file directly.
pub async fn load_secret(credential: Option<&Path>, path: Option<&Path>) -> Result<Vec<u8>> {
    if let Some(cred_path) = credential {
        decrypt_credential(cred_path).await
    } else if let Some(file_path) = path {
        std::fs::read(file_path).map_err(|_| Error::CredentialNotFound {
            name: file_path.display().to_string(),
            path: file_path.to_path_buf(),
        })
    } else {
        Err(Error::Config(
            "neither credential nor path configured".into(),
        ))
    }
}

/// Decrypt an encrypted credential file using `systemd-creds decrypt`.
async fn decrypt_credential(path: &Path) -> Result<Vec<u8>> {
    let output = Command::new("systemd-creds")
        .arg("decrypt")
        .arg(path)
        .arg("-")
        .output()
        .await
        .map_err(|e| Error::SystemdCreds(format!("failed to run systemd-creds: {e}")))?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::SystemdCreds(format!(
            "systemd-creds decrypt {} failed: {stderr}",
            path.display()
        )));
    }

    Ok(output.stdout)
}

/// Encrypt data and write it to an encrypted credential file.
///
/// Uses `systemd-creds encrypt --name=<name> - <path>`.
pub async fn encrypt_credential(name: &str, data: &[u8], path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let mut child = Command::new("systemd-creds")
        .arg("encrypt")
        .arg(format!("--name={name}"))
        .arg("-")
        .arg(path)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn()
        .map_err(|e| Error::SystemdCreds(format!("failed to run systemd-creds: {e}")))?;

    use tokio::io::AsyncWriteExt;
    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(data).await?;
        // Drop stdin to close it so systemd-creds can proceed
    }

    let output = child.wait_with_output().await?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::SystemdCreds(format!(
            "systemd-creds encrypt to {} failed: {stderr}",
            path.display()
        )));
    }

    Ok(())
}

