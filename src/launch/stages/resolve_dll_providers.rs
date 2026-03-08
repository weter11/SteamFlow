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

        let (resolutions, scan_report) = resolver.resolve(&game_exe_dir, &resolved_runner, &components, &d3d12_policy);
        ctx.dll_resolutions = resolutions.clone();

        // ── Architecture-Aware Binding ───────────────────────────────────────
        // Filter and bind based on target_process_arch
        let target_arch = ctx.target_process_arch;
        tracing::info!("Applying arch-aware DLL binding for target: {}", target_arch);

        for res in resolutions {
            let mut metadata = std::collections::HashMap::new();
            metadata.insert("dll".to_string(), res.name.clone());
            metadata.insert("target_arch".to_string(), target_arch.to_string());

            // Strategy: filter candidates that are definitely incompatible with target arch
            // We only filter 'Runner' candidates for now as they have known paths.
            // GameLocal is assumed compatible if it's in the game dir.
            // System is assumed compatible (Wine will pick right arch from system paths).

            let original_chosen = res.chosen_provider;
            let mut bound_res = res.clone();

            let filtered_candidates: Vec<_> = res.candidates.iter().map(|c| {
                let mut c = c.clone();
                if c.provider == crate::launch::dll_provider_resolver::DllProvider::Runner {
                    let path_s = c.path.to_string_lossy().to_lowercase();
                    let is_x64 = path_s.contains("x86_64-windows") || path_s.contains("lib64");
                    let is_x86 = path_s.contains("i386-windows") || (path_s.contains("lib") && !is_x64);

                    match target_arch {
                        crate::utils::Architecture::X86_64 => {
                            if is_x86 && !is_x64 {
                                c.exists = false;
                                c.rejection_reason = Some("arch_mismatch".to_string());
                            }
                        }
                        crate::utils::Architecture::I386 => {
                            if is_x64 {
                                c.exists = false;
                                c.rejection_reason = Some("arch_mismatch".to_string());
                            }
                        }
                        _ => {} // Unknown -> keep all
                    }
                }
                c
            }).collect();

            bound_res.candidates = filtered_candidates;

            // Re-resolve chosen based on filtered candidates
            let chosen = bound_res.candidates.iter().find(|c| c.exists).cloned();
            bound_res.chosen_provider = chosen.as_ref().map(|c| c.provider).unwrap_or(crate::launch::dll_provider_resolver::DllProvider::None);
            bound_res.chosen_path = chosen.as_ref().map(|c| c.path.clone());

            if bound_res.chosen_provider != original_chosen {
                 tracing::info!("Arch-filter changed {} provider from {:?} to {:?}", res.name, original_chosen, bound_res.chosen_provider);
            }

            ctx.effective_dll_bindings.insert(res.name.clone(), bound_res);
        }

        if let Some(session) = &ctx.session {
            let scan_report_path = session.log_dir.join("component_scan.json");
            if let Ok(content) = serde_json::to_string_pretty(&scan_report) {
                let _ = std::fs::write(scan_report_path, content);
            }

            let bindings_path = session.log_dir.join("effective_dll_bindings.json");
            if let Ok(content) = serde_json::to_string_pretty(&ctx.effective_dll_bindings) {
                 let _ = std::fs::write(bindings_path, content);
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
