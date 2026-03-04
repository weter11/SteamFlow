use anyhow::Result;
use std::process::{Command, Stdio};
use super::{Runner, LaunchContext, CommandSpec};

/// Implementation of Runner for Wine-tkg (and general Wine/Proton) runners.
#[derive(Debug, Default)]
pub struct WineTkgRunner;

impl WineTkgRunner {
    pub fn new() -> Self {
        Self
    }
}

impl Runner for WineTkgRunner {
    fn prepare_prefix(&self, _ctx: &LaunchContext) -> Result<()> {
        // TODO: Move prefix preparation logic from steam_client.rs here
        Ok(())
    }

    fn build_env(&self, _ctx: &LaunchContext) -> Result<CommandSpec> {
        // TODO: Move environment building logic from steam_client.rs here
        Ok(CommandSpec::default())
    }

    fn build_command(&self, _ctx: &LaunchContext, _spec: &mut CommandSpec) -> Result<()> {
        // TODO: Move command building logic from steam_client.rs here
        Ok(())
    }

    fn launch(&self, spec: CommandSpec) -> Result<std::process::Child> {
        // TODO: Implement actual process spawning using the spec
        let mut cmd = Command::new(spec.program);
        cmd.args(spec.args);
        if let Some(cwd) = spec.cwd {
            cmd.current_dir(cwd);
        }
        for (key, val) in spec.env {
            cmd.env(key, val);
        }

        // Initial scaffolding: just forwarding with defaults for now
        cmd.stdout(Stdio::inherit());
        cmd.stderr(Stdio::inherit());

        Ok(cmd.spawn()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_winetkg_runner_creation() {
        let _runner = WineTkgRunner::new();
    }
}
