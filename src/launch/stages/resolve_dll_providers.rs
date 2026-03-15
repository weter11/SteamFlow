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
        let d3d12_policy = ctx.user_config.as_ref().map(|c| c.graphics_layers.d3d12_policy.clone()).unwrap_or_default();

        // Detect architecture before resolution
        let mut exe_path = PathBuf::from(install_path);
        if let Some(info) = &ctx.launch_info {
            exe_path = exe_path.join(info.executable.replace('\\', "/"));
        }
        if exe_path.exists() {
            ctx.target_architecture = crate::utils::detect_exe_architecture(&exe_path);
            // Pre-populate this so downstream stages can use it
            ctx.resolved_executable_path = Some(exe_path.clone());

            if let Some(logger) = &ctx.logger {
                let mut metadata = std::collections::HashMap::new();
                metadata.insert("exe_path".into(), exe_path.to_string_lossy().to_string());
                metadata.insert("detected_arch".into(), format!("{:?}", ctx.target_architecture).to_lowercase());
                metadata.insert("detection_method".into(), "PE header".to_string());
                let _ = logger.info("arch_detected", "Target executable architecture determined".into(), Some("ResolveDllProviders".into()), metadata);
            }
        }

        let (resolutions, scan_report) = resolver.resolve(&game_exe_dir, &resolved_runner, &components, &d3d12_policy, &ctx.target_architecture);
        ctx.dll_resolutions = resolutions;

        // Strict Backend Policy Enforcement
        if let Some(config) = &ctx.user_config {
            let backend_policy = &config.graphics_layers.graphics_backend_policy;

            if *backend_policy == crate::models::GraphicsBackendPolicy::DXVK {
                let dxvk_dlls = ["d3d11", "dxgi", "d3d9", "d3d8", "d3d10core"];
                let mut missing = Vec::new();

                for dll in dxvk_dlls {
                    let resolved = ctx.dll_resolutions.iter().find(|r| r.name == dll);
                    let has_native = resolved.map(|r| {
                        r.chosen_provider == crate::launch::dll_provider_resolver::DllProvider::Runner ||
                        r.chosen_provider == crate::launch::dll_provider_resolver::DllProvider::GameLocal
                    }).unwrap_or(false);

                    if !has_native {
                        missing.push(dll);
                    }
                }

                if !missing.is_empty() {
                    return Err(LaunchError::new(
                        LaunchErrorKind::Environment,
                        format!("Explicit DXVK mode requested but required DLLs are missing: {}. \
                                Ensure DXVK is bundled with your runner or present in the game directory.",
                                missing.join(", "))
                    ).with_context("missing_dlls", missing.join(",")));
                }
            }
        }

        if let Some(session) = &ctx.session {
            let scan_report_path = session.log_dir.join("component_scan.json");
            if let Ok(content) = serde_json::to_string_pretty(&scan_report) {
                let _ = std::fs::write(scan_report_path, content);
            }
        }

        if let Some(logger) = &ctx.logger {
            if scan_report.warnings.is_empty() && scan_report.scan_roots.is_empty() {
                let _ = logger.log(crate::infra::logging::LogLevel::Warn, "zero_runner_roots", "Zero Runner roots derived from runner path".into(), Some("ResolveDllProviders".into()), std::collections::HashMap::new());
            }

            for res in &ctx.dll_resolutions {
                let mut metadata = std::collections::HashMap::new();
                metadata.insert("dll".into(), res.name.clone());
                metadata.insert("provider".into(), format!("{:?}", res.chosen_provider));
                if let Some(path) = &res.chosen_path {
                    metadata.insert("path".into(), path.to_string_lossy().to_string());
                }

                let game_local_count = res.candidates.iter().filter(|c| c.provider == crate::launch::dll_provider_resolver::DllProvider::GameLocal && c.exists).count();
                let runner_count = res.candidates.iter().filter(|c| c.provider == crate::launch::dll_provider_resolver::DllProvider::Runner && c.exists).count();
                let system_count = res.candidates.iter().filter(|c| c.provider == crate::launch::dll_provider_resolver::DllProvider::System && c.exists).count();

                metadata.insert("count_gamelocal".into(), game_local_count.to_string());
                metadata.insert("count_runner".into(), runner_count.to_string());
                metadata.insert("count_system".into(), system_count.to_string());

                let _ = logger.info("dll_resolved", format!("Resolved {} to {:?}", res.name, res.chosen_provider), Some("ResolveDllProviders".into()), metadata);
            }
        }

        Ok(())
    }
}
