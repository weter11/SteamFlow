use std::collections::HashMap;
use std::path::PathBuf;
use anyhow::Result;
use crate::models::{LibraryGame, UserAppConfig};
use crate::config::LauncherConfig;
use crate::steam_client::LaunchInfo;

#[derive(Debug, Clone)]
pub struct LaunchContext {
    pub app: LibraryGame,
    pub launch_info: LaunchInfo,
    pub launcher_config: LauncherConfig,
    pub user_config: Option<UserAppConfig>,
    pub proton_path: Option<String>,
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
    fn launch(&self, spec: &CommandSpec) -> Result<std::process::Child>;
}
