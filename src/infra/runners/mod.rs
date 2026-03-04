pub mod r#trait;
pub mod wine_tkg;

pub use r#trait::Runner;
pub use wine_tkg::WineTkgRunner;

use std::collections::HashMap;
use std::path::PathBuf;

/// Context for launching a game or tool.
/// TODO: Add fields for app_id, install_dir, user_config, etc.
#[derive(Debug, Clone, Default)]
pub struct LaunchContext {
    pub app_id: u32,
    // Add more fields as needed for Day 2+ integration
}

/// Specification for a command to be executed.
#[derive(Debug, Clone, Default)]
pub struct CommandSpec {
    pub program: PathBuf,
    pub args: Vec<String>,
    pub cwd: Option<PathBuf>,
    pub env: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_launch_context_default() {
        let ctx = LaunchContext::default();
        assert_eq!(ctx.app_id, 0);
    }

    #[test]
    fn test_command_spec_default() {
        let spec = CommandSpec::default();
        assert!(spec.program.to_string_lossy().is_empty());
        assert!(spec.args.is_empty());
        assert!(spec.cwd.is_none());
        assert!(spec.env.is_empty());
    }
}
