// EXPERIMENTAL DIAGNOSTIC - DO NOT MERGE TO MAIN
use std::process::{Command, Stdio};
use std::fs::File;
use std::time::UNIX_EPOCH;
use anyhow::{Result, Context};
use crate::config::config_dir;

pub fn apply_install_diagnostics(cmd: &mut Command) -> Result<()> {
    if std::env::var("STEAMFLOW_DIAGNOSE_INSTALL").unwrap_or_default() != "1" {
        return Ok(());
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let log_dir = config_dir()?.join("logs");
    std::fs::create_dir_all(&log_dir).context("failed to create logs directory")?;

    let log_path = log_dir.join(format!("install_diagnose_{}.log", timestamp));
    println!("EXPERIMENTAL: Steamflow install diagnostic mode active");
    println!("Logging trace to: {}", log_path.display());

    let log_file = File::create(&log_path)
        .context(format!("failed to create log file at {}", log_path.display()))?;

    cmd.env("WINEDEBUG", "err+all,warn+module,warn+loaddll,+setupapi,+file");

    // Redirect both stdout and stderr to the same file
    let log_file_clone = log_file.try_clone()?;
    cmd.stdout(Stdio::from(log_file));
    cmd.stderr(Stdio::from(log_file_clone));

    Ok(())
}
