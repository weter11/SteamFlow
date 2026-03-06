use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext, LaunchError, LaunchErrorKind};
use crate::launch::dll_provider_resolver::DllProviderResolver;
use std::path::PathBuf;

pub struct ResolveDllProvidersStage;

#[async_trait]
impl PipelineStage for ResolveDllProvidersStage {
    fn name(&self) -> &str { "ResolveDllProviders" }

    async fn execute(&self, ctx: &mut PipelineContext) -> std::result::Result<(), LaunchError> {
        let app = ctx.app.as_ref().ok_or_else(|| LaunchError::new(LaunchErrorKind::Validation, "App context missing"))?;
        let install_path = app.install_path.as_ref().ok_or_else(|| LaunchError::new(LaunchErrorKind::GameData, "Install path missing"))?;

        let mut game_exe_dir = PathBuf::from(install_path);
        // If we have launch info, we can be more precise about the exe dir
        if let Some(info) = &ctx.launch_info {
            let exe_rel = info.executable.replace('\\', "/");
            if let Some(parent) = std::path::Path::new(&exe_rel).parent() {
                game_exe_dir = game_exe_dir.join(parent);
            }
        }

        let resolver = DllProviderResolver::new();

        // We need runner components. This implies ResolveComponentsStage must have run.
        // Actually, we can just detect them here or ensure ResolveComponentsStage provides them.
        let proton_path = ctx.proton_path.as_deref().unwrap_or("wine");
        let library_root = ctx.launcher_config.as_ref().map(|c| PathBuf::from(&c.steam_library_path)).unwrap_or_default();
        let resolved_runner = crate::utils::resolve_runner(proton_path, &library_root);

        // Resolve WINEPREFIX for component detection
        let wineprefix = if let (Some(config), Some(app)) = (&ctx.launcher_config, &ctx.app) {
            Some(crate::utils::steam_wineprefix_for_game(
                config,
                app.app_id,
                &ctx.user_config.as_ref().map(|_| {
                    // This is a bit circular, but we just need it for detection
                    let mut store = std::collections::HashMap::new();
                    store.insert(app.app_id, ctx.user_config.clone().unwrap());
                    store
                }).unwrap_or_default().into()
            ))
        } else {
            None
        };

        let components = crate::utils::detect_runner_components(&resolved_runner, wineprefix.as_deref());

        ctx.dll_resolutions = resolver.resolve(&game_exe_dir, &resolved_runner, &components);

        if let Some(logger) = &ctx.logger {
            for res in &ctx.dll_resolutions {
                let mut metadata = std::collections::HashMap::new();
                metadata.insert("dll".into(), res.name.clone());
                metadata.insert("provider".into(), format!("{:?}", res.chosen_provider));
                if let Some(path) = &res.chosen_path {
                    metadata.insert("path".into(), path.to_string_lossy().to_string());
                }
                let _ = logger.info("dll_resolved", format!("Resolved {} to {:?}", res.name, res.chosen_provider), Some("ResolveDllProviders".into()), metadata);
            }
        }

        Ok(())
    }
}
