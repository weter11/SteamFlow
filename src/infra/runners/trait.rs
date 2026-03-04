use std::collections::HashMap;
use std::path::PathBuf;
use anyhow::Result;

#[derive(Debug, Clone, Default)]
pub struct LaunchContext {
    pub app_id: u32,
    // TODO: Add more fields as needed (e.g., config, paths)
}

#[derive(Debug, Clone, Default)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: HashMap<String, String>,
}

pub trait Runner {
    fn prepare_prefix(&self, ctx: &LaunchContext) -> Result<()>;
    fn build_env(&self, ctx: &LaunchContext) -> Result<HashMap<String, String>>;
    fn build_command(&self, ctx: &LaunchContext) -> Result<CommandSpec>;
    fn launch(&self, spec: &CommandSpec) -> Result<()>;
}
