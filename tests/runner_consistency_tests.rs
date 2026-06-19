use steamflow::utils::{check_runner_consistency, resolve_runner};
use tempfile::tempdir;

#[test]
fn test_check_runner_consistency_basic() {
    let tmp = tempdir().unwrap();
    let prefix_root = tmp.path();
    let runner_a = prefix_root.join("runner_a");
    let runner_b = prefix_root.join("runner_b");

    // Create dummy files so canonicalize works if they exist
    std::fs::File::create(&runner_a).unwrap();
    std::fs::File::create(&runner_b).unwrap();

    // First call initializes marker
    check_runner_consistency(prefix_root, &runner_a).expect("first call should succeed");

    // Second call with same runner should succeed
    check_runner_consistency(prefix_root, &runner_a).expect("second call with same runner should succeed");

    // Third call with different runner should fail IF drive_c exists
    let drive_c = prefix_root.join("drive_c");
    std::fs::create_dir(&drive_c).unwrap();

    let res = check_runner_consistency(prefix_root, &runner_b);
    assert!(res.is_err(), "should fail when runner changed and drive_c exists");
    assert!(res.unwrap_err().to_string().contains("initialized with a different runner"));
}

#[test]
fn test_resolve_runner_stability() {
    let tmp = tempdir().unwrap();
    let library_root = tmp.path();
    let common_dir = library_root.join("steamapps/common");
    std::fs::create_dir_all(&common_dir).unwrap();

    let runner_name = "Proton-Test";
    let runner_dir = common_dir.join(runner_name);
    std::fs::create_dir(&runner_dir).unwrap();

    let path1 = resolve_runner(runner_name, library_root);
    let path2 = resolve_runner(runner_name, library_root);

    assert_eq!(path1, path2, "resolve_runner should be stable across calls");
    assert!(path1.exists());
}
