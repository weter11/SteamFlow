use steamflow::utils::build_dll_overrides;

#[test]
fn test_build_dll_overrides_baseline() {
    // Default case: no graphics layers, no overlay
    let overrides = build_dll_overrides(false, false, false, false, false, None);

    // Essential Steam integration should be present
    assert!(overrides.contains("vstdlib_s=n"));
    assert!(overrides.contains("steamclient=n"));

    // Unsafe D3D/DXGI defaults should NOT be present
    assert!(!overrides.contains("d3d9=n,b"));
    assert!(!overrides.contains("d3d11=n,b"));
    assert!(!overrides.contains("dxgi=n,b"));
    assert!(!overrides.contains("d3d12=n,b"));

    // Overlay should be enabled (not overridden to 'n')
    assert!(!overrides.contains("GameOverlayRenderer=n"));
}

#[test]
fn test_build_dll_overrides_dxvk_active() {
    let overrides = build_dll_overrides(true, false, false, true, false, None);

    // DXVK keys should be present
    assert!(overrides.contains("d3d9=n,b"));
    assert!(overrides.contains("d3d11=n,b"));
    assert!(overrides.contains("dxgi=n,b"));

    // Overlay should be disabled
    assert!(overrides.contains("GameOverlayRenderer=n"));
}

#[test]
fn test_build_dll_overrides_vkd3d_active() {
    let overrides = build_dll_overrides(false, true, false, true, false, None);

    // VKD3D keys should be present
    assert!(overrides.contains("d3d12=n,b"));

    // DXVK keys should NOT be present
    assert!(!overrides.contains("d3d11=n,b"));
}

#[test]
fn test_build_dll_overrides_local_dll_skip() {
    let tmp = tempfile::tempdir().unwrap();
    let d3d11_path = tmp.path().join("d3d11.dll");
    std::fs::write(&d3d11_path, "fake dll").unwrap();

    let overrides = build_dll_overrides(true, false, false, true, false, Some(tmp.path()));

    // d3d11 should be skipped because it exists locally
    assert!(!overrides.contains("d3d11=n,b"));
    // other dxvk keys should still be present
    assert!(overrides.contains("d3d9=n,b"));
}
