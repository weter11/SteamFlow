use std::path::Path;
use std::process::Command;
use anyhow::{Result, bail};

pub fn build_runner_command(runner_path: &Path) -> Result<Command> {
    if runner_path.join("proton").exists() {
        let mut cmd = Command::new(runner_path.join("proton"));
        cmd.arg("run");
        return Ok(cmd);
    }

    if runner_path.join("bin/wine").exists() {
        return Ok(Command::new(runner_path.join("bin/wine")));
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
