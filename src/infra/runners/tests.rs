#[cfg(test)]
mod tests {
    use crate::infra::runners::{LaunchContext, CommandSpec, Runner, WineTkgRunner};
    use std::path::PathBuf;

    #[test]
    fn test_launch_context_construction() {
        let ctx = LaunchContext { app_id: 123 };
        assert_eq!(ctx.app_id, 123);
    }

    #[test]
    fn test_command_spec_construction() {
        let mut spec = CommandSpec::default();
        spec.program = PathBuf::from("/usr/bin/wine");
        spec.args.push("game.exe".to_string());
        spec.env.insert("WINEPREFIX".to_string(), "/tmp/prefix".to_string());

        assert_eq!(spec.program, PathBuf::from("/usr/bin/wine"));
        assert_eq!(spec.args[0], "game.exe");
        assert_eq!(spec.env.get("WINEPREFIX").unwrap(), "/tmp/prefix");
    }

    #[test]
    fn test_wine_tkg_runner_instantiation() {
        let runner = WineTkgRunner;
        let ctx = LaunchContext { app_id: 456 };

        assert!(runner.prepare_prefix(&ctx).is_ok());
        assert!(runner.build_env(&ctx).is_ok());
        assert!(runner.build_command(&ctx).is_ok());
    }
}
