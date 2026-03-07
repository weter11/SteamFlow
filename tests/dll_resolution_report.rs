use std::fs;
use tempfile::tempdir;
use steamflow::launch::dll_provider_resolver::{DllProviderResolver, DllProvider};
use steamflow::utils::RunnerComponents;
use steamflow::models::D3D12ProviderPolicy;

#[test]
fn test_dll_resolution_report_includes_multiple_runner_candidates() {
    let tmp = tempdir().unwrap();
    let runner_root = tmp.path().to_path_buf();

    // Create multiple possible roots
    let dxvk_dir1 = runner_root.join("files/lib/wine/dxvk");
    let dxvk_dir2 = runner_root.join("lib/wine/dxvk");
    fs::create_dir_all(&dxvk_dir1).unwrap();
    fs::create_dir_all(&dxvk_dir2).unwrap();

    fs::write(dxvk_dir1.join("d3d11.dll"), "fake").unwrap();
    // dxvk_dir2 stays empty of files but directory exists

    let proton_script = runner_root.join("proton");
    fs::write(&proton_script, "dummy").unwrap();

    let components = RunnerComponents::default();
    let resolver = DllProviderResolver::new();
    let (resolutions, _) = resolver.resolve(
        tmp.path(),
        &proton_script,
        &components,
        &D3D12ProviderPolicy::Auto
    );

    let d3d11 = resolutions.iter().find(|r| r.name == "d3d11").unwrap();

    // Should have multiple runner candidates
    let runner_candidates: Vec<_> = d3d11.candidates.iter().filter(|c| c.provider == DllProvider::Runner).collect();
    assert!(runner_candidates.len() >= 2);

    // At least one exists
    assert!(runner_candidates.iter().any(|c| c.exists));
    // At least one does NOT exist (one of the other 9 roots)
    assert!(runner_candidates.iter().any(|c| !c.exists));
}
