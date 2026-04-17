use std::path::Path;

use crate::config::{self, CertificateConfig};
use crate::error::{Error, Result};

/// Apply configured file permissions (mode, owner, group) to a path.
/// Only makes system calls when the current state differs from the desired state.
/// Skips if the file does not exist.
#[cfg(unix)]
pub fn apply(
    path: &Path,
    mode: Option<&str>,
    default_mode: u32,
    owner: Option<&str>,
    group: Option<&str>,
) -> Result<()> {
    if !path.exists() {
        return Ok(());
    }

    let desired_mode = match mode {
        Some(s) => config::parse_mode(s)?,
        None => default_mode,
    };

    // Check and apply mode
    use std::os::unix::fs::PermissionsExt;
    let metadata = std::fs::metadata(path)?;
    let current_mode = metadata.permissions().mode() & 0o7777;
    if current_mode != desired_mode {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(desired_mode))?;
        tracing::info!(path = %path.display(), from = format!("{current_mode:04o}"), to = format!("{desired_mode:04o}"), "updated file mode");
    }

    // Check and apply ownership
    if owner.is_some() || group.is_some() {
        use std::os::unix::fs::MetadataExt;
        let current_uid = metadata.uid();
        let current_gid = metadata.gid();

        let desired_uid = match owner {
            Some(name) => Some(resolve_uid(name)?),
            None => None,
        };
        let desired_gid = match group {
            Some(name) => Some(resolve_gid(name)?),
            None => None,
        };

        let uid_changed = desired_uid.is_some_and(|u| u != current_uid);
        let gid_changed = desired_gid.is_some_and(|g| g != current_gid);

        if uid_changed || gid_changed {
            chown(path, desired_uid, desired_gid)?;
            tracing::info!(
                path = %path.display(),
                uid = ?desired_uid.filter(|_| uid_changed),
                gid = ?desired_gid.filter(|_| gid_changed),
                "updated file ownership"
            );
        }
    }

    Ok(())
}

/// Ensure file permissions for a certificate's key and cert files.
pub fn ensure_permissions(cert_config: &CertificateConfig) -> Result<()> {
    #[cfg(unix)]
    {
        if let Some(key_path) = &cert_config.key_path {
            apply(
                key_path,
                cert_config.key_mode.as_deref(),
                0o600,
                cert_config.key_owner.as_deref(),
                cert_config.key_group.as_deref(),
            )?;
        }
        apply(
            &cert_config.cert_path,
            cert_config.cert_mode.as_deref(),
            0o644,
            cert_config.cert_owner.as_deref(),
            cert_config.cert_group.as_deref(),
        )?;
    }
    Ok(())
}

#[cfg(unix)]
fn resolve_uid(name: &str) -> Result<u32> {
    use std::ffi::CString;
    let c_name = CString::new(name)
        .map_err(|_| Error::Config(format!("invalid user name '{name}'")))?;
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pw.is_null() {
        return Err(Error::Config(format!("user '{name}' not found")));
    }
    Ok(unsafe { (*pw).pw_uid })
}

#[cfg(unix)]
fn resolve_gid(name: &str) -> Result<u32> {
    use std::ffi::CString;
    let c_name = CString::new(name)
        .map_err(|_| Error::Config(format!("invalid group name '{name}'")))?;
    let gr = unsafe { libc::getgrnam(c_name.as_ptr()) };
    if gr.is_null() {
        return Err(Error::Config(format!("group '{name}' not found")));
    }
    Ok(unsafe { (*gr).gr_gid })
}

#[cfg(unix)]
fn chown(path: &Path, uid: Option<u32>, gid: Option<u32>) -> Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let c_path = CString::new(path.as_os_str().as_bytes())
        .map_err(|_| Error::Io(std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid path")))?;

    let uid = uid.map(|u| u as libc::uid_t).unwrap_or(u32::MAX);
    let gid = gid.map(|g| g as libc::gid_t).unwrap_or(u32::MAX);

    let ret = unsafe { libc::chown(c_path.as_ptr(), uid, gid) };
    if ret != 0 {
        return Err(Error::Io(std::io::Error::last_os_error()));
    }
    Ok(())
}
