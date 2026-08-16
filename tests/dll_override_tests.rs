use steamflow::utils::build_dll_overrides;

#[test]
fn test_build_dll_overrides_baseline() {
    // Default case: no graphics layers, no overlay
    let overrides = build_dll_overrides(false, false, false, false, false, None, false, None);

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
    let overrides = build_dll_overrides(true, false, false, true, false, None, false, None);

    // DXVK keys should be present
    assert!(overrides.contains("d3d9=n,b"));
    assert!(overrides.contains("d3d11=n,b"));
    assert!(overrides.contains("dxgi=n,b"));

    // Overlay should be disabled
    assert!(overrides.contains("GameOverlayRenderer=n"));
}

#[test]
fn test_build_dll_overrides_vkd3d_active() {
    // dxvk_enabled=false + VKD3D-Proton: D3D12 pairing only. The
    // d3d8/d3d9/d3d10core/d3d11 "=n,b" entries are DXVK pairings — emitting
    // them without DXVK would hand the game the runner's DXVK DLLs and defeat
    // dxvk_enabled=false (with WineD3D active the proton script installs the
    // wined3d dxgi, so native dxgi == wined3d builtin — no null-import crash).
    let overrides = build_dll_overrides(false, true, false, true, false, None, false, None);

    // VKD3D keys should be present
    assert!(overrides.contains("d3d12=n,b"));
    assert!(overrides.contains("d3d12core=n,b"));
    // vkd3d-proton requires native dxgi for its swapchain
    assert!(overrides.contains("dxgi=n,b"));

    // WineD3D D3D9/D3D11 must NOT be forced native when DXVK is off.
    assert!(!overrides.contains("d3d11=n,b"));
    assert!(!overrides.contains("d3d10core=n,b"));
    assert!(!overrides.contains("d3d9=n,b"));
    assert!(!overrides.contains("d3d8=n,b"));
}

#[test]
fn test_build_dll_overrides_vkd3d_active_with_dxvk() {
    // dxvk_enabled=true + VKD3D-Proton: full DXVK pairing applies (native
    // dxgi is DXVK's, so every D3D8-11 DLL must pair native with it).
    let overrides = build_dll_overrides(true, true, false, true, false, None, false, None);
    assert!(overrides.contains("d3d12=n,b"));
    assert!(overrides.contains("dxgi=n,b"));
    assert!(overrides.contains("d3d11=n,b"));
    assert!(overrides.contains("d3d10core=n,b"));
    assert!(overrides.contains("d3d9=n,b"));
    assert!(overrides.contains("d3d8=n,b"));
}

#[test]
fn test_build_dll_overrides_local_dll_skip() {
    let tmp = tempfile::tempdir().unwrap();
    let d3d11_path = tmp.path().join("d3d11.dll");
    std::fs::write(&d3d11_path, "fake dll").unwrap();

    let overrides = build_dll_overrides(true, false, false, true, false, Some(tmp.path()), false, None);

    // d3d11 should be skipped because it exists locally
    assert!(!overrides.contains("d3d11=n,b"));
    // other dxvk keys should still be present
    assert!(overrides.contains("d3d9=n,b"));
}

#[test]
fn test_build_dll_overrides_strict_dxvk() {
    let overrides = build_dll_overrides(true, false, false, true, false, None, true, None);

    // DXVK keys should use 'n' (native only) in strict mode
    assert!(overrides.contains("d3d9=n"));
    assert!(overrides.contains("d3d11=n"));
    assert!(overrides.contains("dxgi=n"));
    assert!(overrides.contains("d3d8=n"));
    assert!(overrides.contains("d3d10core=n"));

    // They should NOT contain 'n,b'
    assert!(!overrides.contains("d3d9=n,b"));
    assert!(!overrides.contains("d3d11=n,b"));
}

#[test]
fn test_build_dll_overrides_strict_dxvk_ignores_local() {
    let tmp = tempfile::tempdir().unwrap();
    let d3d11_path = tmp.path().join("d3d11.dll");
    std::fs::write(&d3d11_path, "fake dll").unwrap();

    let overrides = build_dll_overrides(true, false, false, true, false, Some(tmp.path()), true, None);

    // PR #67 (3529d0a): game-local DLL priority is ABSOLUTE — a game's own
    // d3d11.dll (e.g. RTX Remix fork) must win even in strict DXVK mode, so
    // NO override may be emitted for it. Other DXVK keys stay native-only.
    assert!(!overrides.contains("d3d11=n,b"), "game-local d3d11 must not be overridden: {overrides}");
    assert!(!overrides.contains("d3d11=n"), "game-local d3d11 must not be overridden: {overrides}");
    assert!(overrides.contains("d3d9=n"), "non-local DXVK keys should still be native-only: {overrides}");
}
