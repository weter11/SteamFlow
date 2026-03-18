pub fn classify_graphics_evidence(log_line: &str) -> Option<String> {
    let line_lower = log_line.to_lowercase();

    // DXVK signatures
    if line_lower.contains("info:  dxvk:") ||
       line_lower.contains("dxvk: v") ||
       line_lower.contains("info:  game:") ||
       line_lower.contains("d3d11internalcreatedevice") ||
       line_lower.contains("presenter: actual swapchain properties") ||
       (line_lower.contains("vulkan:") && line_lower.contains("found vkgetinstanceprocaddr")) {
        return Some(format!("DXVK Detected: {}", log_line.trim()));
    }

    // VKD3D-Proton signatures
    if line_lower.contains("vkd3d-proton: v") {
        return Some(format!("VKD3D-Proton Detected: {}", log_line.trim()));
    }

    // Generic VKD3D
    if line_lower.contains("vkd3d: v") {
        return Some(format!("VKD3D Detected: {}", log_line.trim()));
    }

    // WineD3D fallback hints
    if line_lower.contains("wined3d: v") || line_lower.contains("wined3d-adapter") {
        return Some(format!("WineD3D Fallback Detected: {}", log_line.trim()));
    }

    // DLL Load Failures
    if line_lower.contains("failed to load module") && line_lower.contains("status=") {
        // Filter out winemac.drv which is normal to fail on Linux (standard Wine bootstrap noise)
        if line_lower.contains("winemac.drv") {
            return None;
        }

        // Specific middleware/dependency failure patterns
        if line_lower.contains("physx") {
             return Some(format!("PhysX/Middleware failure: {}", log_line.trim()));
        }

        return Some(format!("DLL Load Failure: {}", log_line.trim()));
    }
    if line_lower.contains("not found") && line_lower.contains("which is needed by") {
        return Some(format!("DLL Dependency Missing: {}", log_line.trim()));
    }

    // Steam/Client patterns
    if line_lower.contains("failed to create steam.exe") ||
       line_lower.contains("cannot find 'steam.exe'") ||
       (line_lower.contains("steam.exe") && (line_lower.contains("not found") || line_lower.contains("failed"))) {
        return Some(format!("Steam Client/Environment Failure: {}", log_line.trim()));
    }

    // Override/Policy regressions
    if line_lower.contains("invalid dll") ||
       (line_lower.contains("failed to load") && (line_lower.contains("d3d11"))) {
         return Some(format!("Override Policy Conflict: {}", log_line.trim()));
    }

    None
}
