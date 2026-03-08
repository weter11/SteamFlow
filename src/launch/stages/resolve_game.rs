use async_trait::async_trait;
use crate::launch::pipeline::{PipelineStage, PipelineContext, LaunchError, LaunchErrorKind};

pub struct ResolveGameStage;

#[async_trait]
impl PipelineStage for ResolveGameStage {
    fn name(&self) -> &str { "ResolveGame" }
    async fn execute(&self, ctx: &mut PipelineContext) -> std::result::Result<(), LaunchError> {
        let app = ctx.app.as_ref().ok_or_else(|| {
            LaunchError::new(LaunchErrorKind::Validation, "App context missing in ResolveGameStage")
                .with_context("app_id", ctx.app_id.to_string())
        })?;

        let launch_info = ctx.launch_info.as_ref().ok_or_else(|| {
             LaunchError::new(LaunchErrorKind::Validation, "Launch info missing in ResolveGameStage")
                .with_context("app_id", ctx.app_id.to_string())
        })?;

        // Authoritative architecture detection
        if let Some(install_path) = &app.install_path {
            let exe_path = std::path::Path::new(install_path).join(&launch_info.executable.replace('\\', "/"));
            if exe_path.exists() {
                match crate::utils::detect_exe_arch(&exe_path) {
                    Ok(arch) => {
                        tracing::info!("Detected target architecture for {}: {}", launch_info.executable, arch);
                        ctx.target_process_arch = arch;
                        ctx.graphics_stack.target_process_arch = arch;
                    }
                    Err(e) => {
                        tracing::warn!("Failed to detect architecture for {}: {}", exe_path.display(), e);
                        ctx.add_warning("arch_detection_failed", format!("Failed to detect architecture for {}: {}", launch_info.executable, e));
                    }
                }
            }
        }

        Ok(())
    }
}
