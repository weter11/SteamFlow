pub fn classify_graphics_evidence(log_line: &str) -> Option<String> {
    let line_lower = log_line.to_lowercase();

    // DXVK signatures
    if line_lower.contains("dxvk: v") ||
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
        return Some(format!("DLL Load Failure: {}", log_line.trim()));
    }
    if line_lower.contains("not found") && line_lower.contains("which is needed by") {
        return Some(format!("DLL Dependency Missing: {}", log_line.trim()));
    }

    None
}
