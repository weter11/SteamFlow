use crate::launch::pipeline::PipelineContext;
use crate::launch::validators::LaunchValidator;

pub struct LaunchInvariantValidator;

impl LaunchValidator for LaunchInvariantValidator {
    fn name(&self) -> &str { "LaunchInvariant" }

    fn validate(&self, ctx: &mut PipelineContext) {
        let mut warnings = Vec::new();

        // 1. Invariant B: baseline/WineD3D must not keep forced native DXVK/VKD3D overrides
        if ctx.graphics_stack.effective_backend == "WineD3D (Baseline)" {
            if let Some(spec) = &ctx.command_spec {
                if let Some(overrides) = spec.env.get("WINEDLLOVERRIDES") {
                    let conflicts = ["d3d8", "d3d9", "d3d10", "d3d10_1", "d3d10core", "d3d11", "dxgi", "d3d12", "d3d12core"];
                    for part in overrides.split(';') {
                        if let Some((dll, mode)) = part.split_once('=') {
                            let dll_trimmed = dll.trim().to_lowercase();
                            if conflicts.contains(&dll_trimmed.as_str()) && mode.contains('n') {
                                warnings.push((
                                    "INVARIANT_B_CONFLICT",
                                    format!("Forced native override '{dll}={mode}' found in baseline mode. Graphics may fail.")
                                ));
                            }
                        }
                    }
                }
            }
        }

        // 2. Invariant C: effective D3D12 provider must match resolved provider paths
        if !ctx.graphics_stack.effective_d3d12_provider.is_empty() {
             let provider = &ctx.graphics_stack.effective_d3d12_provider;
             for res in &ctx.dll_resolutions {
                 if res.name == "d3d12" || res.name == "d3d12core" {
                     if let Some(path) = &res.chosen_path {
                         let path_str = path.to_string_lossy().to_lowercase();
                         if provider == "vkd3d-proton" && !path_str.contains("vkd3d-proton") && path_str.contains("vkd3d") {
                              warnings.push((
                                 "INVARIANT_C_MISMATCH",
                                 format!("Effective provider is vkd3d-proton but resolved path points to plain vkd3d: {}", path.display())
                             ));
                         } else if provider == "vkd3d" && path_str.contains("vkd3d-proton") {
                              warnings.push((
                                 "INVARIANT_C_MISMATCH",
                                 format!("Effective provider is vkd3d but resolved path points to vkd3d-proton: {}", path.display())
                             ));
                         }
                     }
                 }
             }
        }

        // 3. Invariant D: explicit user setting must not be silently overwritten
        if !ctx.graphics_stack.requested_backend.is_empty() && ctx.graphics_stack.requested_backend != "Auto" {
            if ctx.graphics_stack.requested_backend != ctx.graphics_stack.effective_backend {
                let reason = ctx.graphics_stack.fallback_reasons.get("graphics_backend").cloned().unwrap_or_else(|| "unknown".into());
                warnings.push((
                    "INVARIANT_D_BACKEND_MISMATCH",
                    format!("Requested backend '{}' differs from effective '{}'. Reason: {}",
                        ctx.graphics_stack.requested_backend, ctx.graphics_stack.effective_backend, reason)
                ));
            }
        }

        if !ctx.graphics_stack.requested_d3d12_provider.is_empty() && ctx.graphics_stack.requested_d3d12_provider != "Auto" {
            if ctx.graphics_stack.requested_d3d12_provider != ctx.graphics_stack.effective_d3d12_provider {
                 let reason = ctx.graphics_stack.fallback_reasons.get("d3d12_provider").cloned().unwrap_or_else(|| "unknown".into());
                 warnings.push((
                    "INVARIANT_D_D3D12_MISMATCH",
                    format!("Requested D3D12 provider '{}' differs from effective '{}'. Reason: {}",
                        ctx.graphics_stack.requested_d3d12_provider, ctx.graphics_stack.effective_d3d12_provider, reason)
                ));
            }
        }

        if let Some(requested_gpu) = &ctx.graphics_stack.requested_gpu {
            if ctx.graphics_stack.effective_gpu.as_ref() != Some(requested_gpu) {
                let reason = ctx.graphics_stack.fallback_reasons.get("gpu").cloned().unwrap_or_else(|| "unknown".into());
                warnings.push((
                    "INVARIANT_D_GPU_MISMATCH",
                    format!("Requested GPU '{}' differs from effective '{:?}'. Reason: {}",
                        requested_gpu, ctx.graphics_stack.effective_gpu, reason)
                ));
            }
        }

        for (code, msg) in warnings {
            ctx.add_warning(code, msg);
        }
    }
}
