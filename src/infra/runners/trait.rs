use std::collections::HashMap;
use std::path::PathBuf;
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

pub trait Runner: Send + Sync {
    fn name(&self) -> &str;
    fn prepare_prefix(&self, ctx: &LaunchContext) -> std::result::Result<(), crate::launch::pipeline::LaunchError>;
    fn build_env(&self, ctx: &LaunchContext) -> std::result::Result<HashMap<String, String>, crate::launch::pipeline::LaunchError>;
    fn build_command(&self, ctx: &LaunchContext) -> std::result::Result<CommandSpec, crate::launch::pipeline::LaunchError>;
    fn launch(&self, spec: &CommandSpec) -> std::result::Result<std::process::Child, crate::launch::pipeline::LaunchError>;
}
