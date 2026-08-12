use std::fs;
use tempfile::tempdir;
use steamflow::utils::{deploy_dll_symlinks, cleanup_dll_symlinks};
use steamflow::launch::dll_provider_resolver::{DllResolution, DllProvider};
use steamflow::models::ExecutableArchitecture;

#[test]
fn test_symlink_deployment_and_cleanup() {
    let tmp = tempdir().unwrap();
    let prefix = tmp.path().join("prefix");
    let system32 = prefix.join("drive_c/windows/system32");
    fs::create_dir_all(&system32).unwrap();

    let src_dir = tmp.path().join("src");
    fs::create_dir_all(&src_dir).unwrap();
    let d3d11_src = src_dir.join("d3d11.dll");
    fs::write(&d3d11_src, "fake dxvk").unwrap();

    let resolutions = vec![
        DllResolution {
            name: "d3d11".into(),
            chosen_provider: DllProvider::Runner,
            chosen_path: Some(d3d11_src.clone()),
            fallback_reason: None,
            candidates: vec![],
        }
    ];

    // Original builtin
    let d3d11_dest = system32.join("d3d11.dll");
    fs::write(&d3d11_dest, "wine builtin").unwrap();

    // Deploy
    let deployed = deploy_dll_symlinks(&prefix, &resolutions, &ExecutableArchitecture::X86_64).unwrap();
    assert_eq!(deployed.len(), 1);
    assert!(d3d11_dest.exists());

    let meta = fs::symlink_metadata(&d3d11_dest).unwrap();
    assert!(meta.file_type().is_symlink());

    let backup = system32.join("d3d11.dll.bak");
    assert!(backup.exists());
    assert_eq!(fs::read_to_string(&backup).unwrap(), "wine builtin");

    // Cleanup
    cleanup_dll_symlinks(&prefix).unwrap();
    assert!(d3d11_dest.exists());
    let meta2 = fs::symlink_metadata(&d3d11_dest).unwrap();
    assert!(!meta2.file_type().is_symlink());
    assert_eq!(fs::read_to_string(&d3d11_dest).unwrap(), "wine builtin");
    assert!(!backup.exists());
}

#[test]
fn test_symlink_deployment_dual_arch() {
    let tmp = tempdir().unwrap();
    let prefix = tmp.path().join("prefix");
    let system32 = prefix.join("drive_c/windows/system32");
    let syswow64 = prefix.join("drive_c/windows/syswow64");
    fs::create_dir_all(&system32).unwrap();
    fs::create_dir_all(&syswow64).unwrap();

    let src_root = tmp.path().join("runner");
    let x64_src_dir = src_root.join("x86_64-windows");
    let x86_src_dir = src_root.join("i386-windows");
    fs::create_dir_all(&x64_src_dir).unwrap();
    fs::create_dir_all(&x86_src_dir).unwrap();

    let d3d11_x64 = x64_src_dir.join("d3d11.dll");
    let d3d11_x86 = x86_src_dir.join("d3d11.dll");
    fs::write(&d3d11_x64, "x64").unwrap();
    fs::write(&d3d11_x86, "x86").unwrap();

    let resolutions = vec![
        DllResolution {
            name: "d3d11".into(),
            chosen_provider: DllProvider::Runner,
            chosen_path: Some(d3d11_x64.clone()),
            fallback_reason: None,
            candidates: vec![],
        }
    ];

    // Deploy starting from x64
    let deployed = deploy_dll_symlinks(&prefix, &resolutions, &ExecutableArchitecture::X86_64).unwrap();
    // Should deploy both x64 to system32 and x86 to syswow64 if sibling found
    assert_eq!(deployed.len(), 2);

    assert!(system32.join("d3d11.dll").exists());
    assert!(syswow64.join("d3d11.dll").exists());

    assert!(fs::symlink_metadata(system32.join("d3d11.dll")).unwrap().file_type().is_symlink());
    assert!(fs::symlink_metadata(syswow64.join("d3d11.dll")).unwrap().file_type().is_symlink());

    // Cleanup
    cleanup_dll_symlinks(&prefix).unwrap();
    assert!(!system32.join("d3d11.dll").exists()); // no backup existed, so it's gone (or should it stay gone? in this case yes because no backup)
    assert!(!syswow64.join("d3d11.dll").exists());
}

#[test]
fn test_repair_dangling_prefix_symlinks() {
    // Regression for exit-53 after a runner dir is removed: a prefix seeded by
    // an old runner keeps absolute symlinks into that runner's lib/wine tree;
    // when the dir vanishes every builtin DLL link dangles and wine dies with
    // `could not load kernel32.dll`. The repair must re-point them at the
    // active runner and drop links the active runner doesn't ship.
    use steamflow::utils::repair_dangling_prefix_symlinks;

    let tmp = tempdir().unwrap();
    let prefix = tmp.path().join("prefix");
    let system32 = prefix.join("drive_c/windows/system32");
    let syswow64 = prefix.join("drive_c/windows/syswow64");
    fs::create_dir_all(&system32).unwrap();
    fs::create_dir_all(&syswow64).unwrap();

    // Old (deleted) runner tree the prefix was seeded from.
    let old_runner = tmp.path().join("old-runner");
    let old_x64 = old_runner.join("files/lib/wine/x86_64-windows");
    let old_x86 = old_runner.join("files/lib/wine/i386-windows");
    fs::create_dir_all(&old_x64).unwrap();
    fs::create_dir_all(&old_x86).unwrap();

    // Dangling links: target the old runner dir, which we then delete.
    let kernel32_link = system32.join("kernel32.dll");
    std::os::unix::fs::symlink(old_x64.join("kernel32.dll"), &kernel32_link).unwrap();
    let acledit_link = syswow64.join("acledit.dll");
    std::os::unix::fs::symlink(old_x86.join("acledit.dll"), &acledit_link).unwrap();

    // A healthy link pointing at the current runner must be left alone.
    let healthy_src = tmp.path().join("healthy-source.dll");
    fs::write(&healthy_src, "x").unwrap();
    let healthy_link = system32.join("healthy.dll");
    std::os::unix::fs::symlink(&healthy_src, &healthy_link).unwrap();

    // Delete the old runner → both seed links now dangle.
    fs::remove_dir_all(&old_runner).unwrap();
    assert!(!kernel32_link.exists()); // dangling
    assert!(!acledit_link.exists()); // dangling

    // New active runner ships kernel32 (x64) + acledit (x86) but NOT winipcfg.dll.
    let new_runner = tmp.path().join("new-runner");
    let new_x64 = new_runner.join("files/lib/wine/x86_64-windows");
    let new_x86 = new_runner.join("files/lib/wine/i386-windows");
    fs::create_dir_all(&new_x64).unwrap();
    fs::create_dir_all(&new_x86).unwrap();
    fs::write(new_x64.join("kernel32.dll"), "k32").unwrap();
    fs::write(new_x86.join("acledit.dll"), "ace").unwrap();

    // A link to a file the new runner doesn't ship → must be dropped.
    let winipcfg_link = system32.join("winipcfg.dll");
    std::os::unix::fs::symlink(old_x64.join("winipcfg.dll"), &winipcfg_link).unwrap();

    let (repointed, removed) = repair_dangling_prefix_symlinks(&prefix, &new_runner).unwrap();
    assert_eq!(repointed, 2);
    assert_eq!(removed, 1);

    // Re-pointed links now resolve to the new runner's files.
    assert!(kernel32_link.exists());
    assert!(acledit_link.exists());
    assert_eq!(fs::read_to_string(&kernel32_link).unwrap(), "k32");
    assert_eq!(fs::read_to_string(&acledit_link).unwrap(), "ace");

    // Dropped link is gone; healthy link untouched.
    assert!(!winipcfg_link.symlink_metadata().is_ok());
    assert!(healthy_link.exists());

    // Second pass is a no-op (idempotent).
    let (r2, m2) = repair_dangling_prefix_symlinks(&prefix, &new_runner).unwrap();
    assert_eq!((r2, m2), (0, 0));
}
