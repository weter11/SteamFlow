#[test]
fn test_version_parsing() {
    use steamflow::utils::parse_short_version;

    assert_eq!(parse_short_version("dxvk (v2.7.1-404-g0bf876eb)"), "2.7.1-404");
    assert_eq!(parse_short_version("vkd3d-proton (v2.11-1-g0bf876eb)"), "2.11-1");
    assert_eq!(parse_short_version("v2.3"), "2.3");
    assert_eq!(parse_short_version("2.3.1-dirty"), "2.3.1-dirty");
    assert_eq!(parse_short_version("dxvk (2.10)"), "2.10");
    assert_eq!(parse_short_version(""), "unknown");
}

#[test]
fn test_path_discovery_roots() {
    use std::fs;
    use tempfile::tempdir;
    use steamflow::utils::{detect_runner_components, ComponentSource};

    let tmp = tempdir().unwrap();
    let runner_root = tmp.path().to_path_buf();

    // 1. Proton style layout
    let dxvk_dir = runner_root.join("files/lib/wine/dxvk");
    fs::create_dir_all(&dxvk_dir).unwrap();
    fs::write(dxvk_dir.join("d3d11.dll"), "fake dll").unwrap();

    let share_dxvk = runner_root.join("files/share/dxvk");
    fs::create_dir_all(&share_dxvk).unwrap();
    fs::write(share_dxvk.join("version"), "dxvk (v2.3-g1234567)").unwrap();

    // 2. Critical vkd3d layout (files/lib/wine/vkd3d)
    let vkd3d_dir = runner_root.join("files/lib/wine/vkd3d");
    fs::create_dir_all(&vkd3d_dir).unwrap();
    fs::write(vkd3d_dir.join("libvkd3d-1.dll"), "fake dll").unwrap();

    let share_vkd3d = runner_root.join("files/share/vkd3d");
    fs::create_dir_all(&share_vkd3d).unwrap();
    fs::write(share_vkd3d.join("version"), "vkd3d (v1.10-gabcdef0)").unwrap();

    let components = detect_runner_components(&runner_root, None);

    assert!(components.dxvk.is_some());
    let dxvk = components.dxvk.unwrap();
    assert_eq!(dxvk.version, "2.3");
    assert_eq!(dxvk.source, ComponentSource::BundledWithRunner);

    assert!(components.vkd3d.is_some());
    let vkd3d = components.vkd3d.unwrap();
    assert_eq!(vkd3d.version, "1.10");
    assert_eq!(vkd3d.source, ComponentSource::BundledWithRunner);
}

#[test]
fn test_unified_layout_discovery() {
    use std::fs;
    use tempfile::tempdir;
    use steamflow::utils::{detect_runner_components, ComponentSource};

    let tmp = tempdir().unwrap();
    let runner_root = tmp.path().to_path_buf();

    // Modern Unified layout: files/lib/wine/x86_64-windows/
    let unified_dir = runner_root.join("files/lib/wine/x86_64-windows");
    fs::create_dir_all(&unified_dir).unwrap();

    // Create DXVK DLLs in unified directory
    fs::write(unified_dir.join("d3d11.dll"), "fake dll").unwrap();
    fs::write(unified_dir.join("dxgi.dll"), "fake dll").unwrap();
    fs::write(unified_dir.join("d3d9.dll"), "fake dll").unwrap();
    fs::write(unified_dir.join("d3d8.dll"), "fake dll").unwrap();
    fs::write(unified_dir.join("d3d10core.dll"), "fake dll").unwrap();

    // Create version file in unified directory
    fs::write(unified_dir.join("version"), "dxvk (v2.4.1-g567890a)").unwrap();

    let components = detect_runner_components(&runner_root, None);

    assert!(components.dxvk.is_some());
    let dxvk = components.dxvk.unwrap();
    assert_eq!(dxvk.version, "2.4.1");
    assert_eq!(dxvk.source, ComponentSource::BundledWithRunner);
    assert!(dxvk.path.unwrap().to_string_lossy().contains("files/lib/wine/x86_64-windows"));
}

#[test]
fn test_architecture_aware_discovery() {
    use std::fs;
    use tempfile::tempdir;
    use steamflow::launch::dll_provider_resolver::DllProviderResolver;
    use steamflow::models::ExecutableArchitecture;
    use steamflow::utils::RunnerComponents;
    use std::path::Path;

    let tmp = tempdir().unwrap();
    let runner_root = tmp.path().to_path_buf();

    // Create both 64-bit and 32-bit directories in unified layout
    let x64_dir = runner_root.join("files/lib/wine/x86_64-windows");
    let x86_dir = runner_root.join("files/lib/wine/i386-windows");
    fs::create_dir_all(&x64_dir).unwrap();
    fs::create_dir_all(&x86_dir).unwrap();

    let d3d11_64 = x64_dir.join("d3d11.dll");
    let d3d11_32 = x86_dir.join("d3d11.dll");
    fs::write(&d3d11_64, "64-bit dll").unwrap();
    fs::write(&d3d11_32, "32-bit dll").unwrap();

    let mut components = RunnerComponents::default();
    components.dxvk = Some(steamflow::utils::ComponentInfo {
        version: "2.3".into(),
        source: steamflow::utils::ComponentSource::BundledWithRunner,
        path: None,
    });

    let resolver = DllProviderResolver::new();
    let game_dir = Path::new("/tmp/game");

    // Case 1: 64-bit architecture
    let (res_64, _) = resolver.resolve(game_dir, &runner_root, &components, &steamflow::models::D3D12ProviderPolicy::Auto, &ExecutableArchitecture::X86_64, None, None, None);
    let d3d11_res_64 = res_64.iter().find(|r| r.name == "d3d11").unwrap();
    assert_eq!(d3d11_res_64.chosen_path.as_ref().unwrap(), &d3d11_64);

    // Case 2: 32-bit architecture
    let (res_32, _) = resolver.resolve(game_dir, &runner_root, &components, &steamflow::models::D3D12ProviderPolicy::Auto, &ExecutableArchitecture::X86, None, None, None);
    let d3d11_res_32 = res_32.iter().find(|r| r.name == "d3d11").unwrap();
    assert_eq!(d3d11_res_32.chosen_path.as_ref().unwrap(), &d3d11_32);
}
