use anyhow::Result;
use super::{LaunchContext, CommandSpec};

/// Trait defining the behavior of a game runner.
pub trait Runner {
    /// Prepare the WINEPREFIX or environment for execution.
    fn prepare_prefix(&self, ctx: &LaunchContext) -> Result<()>;

    /// Build the environment variables for execution.
    fn build_env(&self, ctx: &LaunchContext) -> Result<CommandSpec>;

    /// Build the final command for execution.
    fn build_command(&self, ctx: &LaunchContext, spec: &mut CommandSpec) -> Result<()>;

    /// Launch the process based on the built command spec.
    fn launch(&self, spec: CommandSpec) -> Result<std::process::Child>;
}
