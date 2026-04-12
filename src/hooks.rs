use crate::config::HookConfig;
use crate::error::{Error, Result};

/// Execute post-renewal hooks.
///
/// Hooks run sequentially. A hook failure is logged but does not prevent
/// subsequent hooks from running.
pub async fn run_hooks(hooks: &[HookConfig], dry_run: bool) -> Vec<Result<()>> {
    let mut results = Vec::new();

    for hook in hooks {
        let result = run_hook(hook, dry_run).await;
        if let Err(ref e) = result {
            tracing::error!(%e, "hook failed");
        }
        results.push(result);
    }

    results
}

async fn run_hook(hook: &HookConfig, dry_run: bool) -> Result<()> {
    match hook {
        HookConfig::SystemdReload { unit } => {
            tracing::info!(%unit, "reloading systemd unit");
            if dry_run {
                tracing::info!(%unit, "dry-run: would reload unit");
                return Ok(());
            }
            systemd_unit_action(unit, "reload").await
        }
        HookConfig::SystemdRestart { unit } => {
            tracing::info!(%unit, "restarting systemd unit");
            if dry_run {
                tracing::info!(%unit, "dry-run: would restart unit");
                return Ok(());
            }
            systemd_unit_action(unit, "restart").await
        }
        HookConfig::Command { command } => {
            let cmd_str = command.join(" ");
            tracing::info!(command = %cmd_str, "running command hook");
            if dry_run {
                tracing::info!(command = %cmd_str, "dry-run: would run command");
                return Ok(());
            }
            run_command(command).await
        }
    }
}

/// Reload or restart a systemd unit via D-Bus.
async fn systemd_unit_action(unit: &str, action: &str) -> Result<()> {
    let connection = zbus::Connection::system()
        .await
        .map_err(|e| Error::Hook {
            hook: format!("systemd-{action}({unit})"),
            message: format!("failed to connect to system bus: {e}"),
        })?;

    let proxy: zbus::Proxy<'_> = zbus::proxy::Builder::new(&connection)
        .interface("org.freedesktop.systemd1.Manager")
        .expect("valid interface")
        .path("/org/freedesktop/systemd1")
        .expect("valid path")
        .destination("org.freedesktop.systemd1")
        .expect("valid destination")
        .build()
        .await
        .map_err(|e| Error::Hook {
            hook: format!("systemd-{action}({unit})"),
            message: format!("failed to create proxy: {e}"),
        })?;

    let method = match action {
        "reload" => "ReloadUnit",
        "restart" => "RestartUnit",
        _ => unreachable!(),
    };

    let _: zbus::zvariant::OwnedObjectPath = proxy
        .call(method, &(unit, "replace"))
        .await
        .map_err(|e| Error::Hook {
            hook: format!("systemd-{action}({unit})"),
            message: format!("{method} failed: {e}"),
        })?;

    tracing::info!(%unit, %action, "systemd unit action completed");
    Ok(())
}

async fn run_command(command: &[String]) -> Result<()> {
    let (program, args) = command.split_first().ok_or_else(|| Error::Hook {
        hook: "command".into(),
        message: "empty command".into(),
    })?;

    let output = tokio::process::Command::new(program)
        .args(args)
        .output()
        .await
        .map_err(|e| Error::Hook {
            hook: format!("command({})", command.join(" ")),
            message: format!("failed to execute: {e}"),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(Error::Hook {
            hook: format!("command({})", command.join(" ")),
            message: format!("exited with {}: {stderr}", output.status),
        });
    }

    Ok(())
}
