use std::fs;
use steamflow::utils::{is_suspicious_installdir, probe_install_dir_by_appid};

#[test]
fn test_suspicious_detection() {
    assert!(is_suspicious_installdir("App 2410180", 2410180));
    assert!(is_suspicious_installdir("App 123", 123));
    assert!(!is_suspicious_installdir("Portal Prelude RTX", 2410180));
}

#[test]
fn test_probing() {
    let temp = tempfile::tempdir().unwrap();
    let steamapps = temp.path().join("steamapps");
    let common = steamapps.join("common");
    fs::create_dir_all(&common).unwrap();

    let portal_dir = common.join("Portal Prelude RTX");
    fs::create_dir(&portal_dir).unwrap();
    fs::write(portal_dir.join("steam_appid.txt"), "2410180").unwrap();

    let probed = probe_install_dir_by_appid(&steamapps, 2410180).unwrap();
    assert_eq!(probed.file_name().unwrap(), "Portal Prelude RTX");
}

#[test]
fn test_probing_by_name_contains_appid() {
    let temp = tempfile::tempdir().unwrap();
    let steamapps = temp.path().join("steamapps");
    let common = steamapps.join("common");
    fs::create_dir_all(&common).unwrap();

    let game_dir = common.join("Some Game 123");
    fs::create_dir(&game_dir).unwrap();

    let probed = probe_install_dir_by_appid(&steamapps, 123).unwrap();
    assert_eq!(probed.file_name().unwrap(), "Some Game 123");
}
