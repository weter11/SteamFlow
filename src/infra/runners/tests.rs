#[cfg(test)]
mod tests {
    use crate::infra::runners::{LaunchContext, CommandSpec, Runner, WineTkgRunner};
    use crate::models::LibraryGame;
    use crate::steam_client::{LaunchInfo, LaunchTarget};
    use crate::config::LauncherConfig;
    use std::path::PathBuf;

    fn mock_context() -> LaunchContext {
        LaunchContext {
            app: LibraryGame {
                app_id: 123,
                name: "Test Game".to_string(),
                playtime_forever_minutes: None,
                is_installed: true,
                install_path: Some("/tmp/game".to_string()),
                local_manifest_ids: Default::default(),
                update_available: false,
                update_queued: false,
                active_branch: "public".to_string(),
            },
            launch_info: LaunchInfo {
                app_id: 123,
                id: "0".to_string(),
                description: "Test".to_string(),
                executable: "game.exe".to_string(),
                arguments: "-v".to_string(),
                workingdir: None,
                target: LaunchTarget::WindowsProton,
            },
            launcher_config: LauncherConfig::default(),
            user_config: None,
            proton_path: Some("/tmp/proton".to_string()),
        }
    }

    #[test]
    fn test_launch_context_construction() {
        let ctx = mock_context();
        assert_eq!(ctx.app.app_id, 123);
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
    fn test_wine_tkg_runner_stubs() {
        // We can only test stubs that don't hit the filesystem hard or expect real Proton/Wine
        let runner = WineTkgRunner;
        let ctx = mock_context();

        // build_env should succeed without real filesystem
        let env = runner.build_env(&ctx).unwrap();
        assert_eq!(env.get("SteamAppId").unwrap(), "123");
    }
}
