use std::path::{Path, PathBuf};
use std::process::Command;
use anyhow::{Result, bail};

pub fn build_runner_command(runner_path: &Path) -> Result<Command> {
    // 1. Check if it's a directory containing 'proton'
    if runner_path.join("proton").exists() {
        let mut cmd = Command::new(runner_path.join("proton"));
        cmd.arg("run");
        return Ok(cmd);
    }

    // 2. Check if it's a directory containing 'bin/wine'
    if runner_path.join("bin/wine").exists() {
        return Ok(Command::new(runner_path.join("bin/wine")));
    }

    // 3. Check if the path itself is the binary
    if let Some(file_name) = runner_path.file_name().and_then(|f| f.to_str()) {
        if file_name == "wine" || file_name == "wine64" {
            return Ok(Command::new(runner_path));
        }
        if file_name == "proton" {
            let mut cmd = Command::new(runner_path);
            cmd.arg("run");
            return Ok(cmd);
        }
    }

    // 4. Fallback: check if parent is bin and it's wine
    if runner_path.ends_with("bin/wine") || runner_path.ends_with("bin/wine64") {
         return Ok(Command::new(runner_path));
    }

    bail!("Failed to find a valid runner (proton or bin/wine) in {}", runner_path.display())
}

pub fn copy_dir_all(src: impl AsRef<Path>, dst: impl AsRef<Path>) -> Result<()> {
    std::fs::create_dir_all(&dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_dir_all(entry.path(), dst.as_ref().join(entry.file_name()))?;
        } else {
            std::fs::copy(entry.path(), dst.as_ref().join(entry.file_name()))?;
        }
    }
    Ok(())
}

pub fn setup_fake_steam_trap(config_dir: &Path) -> Result<PathBuf> {
    let trap_dir = config_dir.join("fake_env");
    std::fs::create_dir_all(&trap_dir)?;

    let dummy_script = "#!/bin/sh\nexit 0\n";

    let steam_path = trap_dir.join("steam");
    let steam_sh_path = trap_dir.join("steam.sh");

    if !steam_path.exists() {
        std::fs::write(&steam_path, dummy_script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&steam_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&steam_path, perms)?;
        }
    }

    if !steam_sh_path.exists() {
        std::fs::write(&steam_sh_path, dummy_script)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&steam_sh_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&steam_sh_path, perms)?;
        }
    }

    Ok(trap_dir)
}
