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

#[tokio::test]
async fn test_orphaned_directory_recovery() {
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    let steamapps = root.join("steamapps");
    let common = steamapps.join("common");
    fs::create_dir_all(&common).unwrap();

    // 1. A normal game with ACF
    let game1_dir = common.join("Game One");
    fs::create_dir(&game1_dir).unwrap();
    let acf1_content = "\"AppState\"\n{\n\t\"appid\"\t\"101\"\n\t\"name\"\t\"Game One\"\n\t\"installdir\"\t\"Game One\"\n}\n";
    fs::write(steamapps.join("appmanifest_101.acf"), acf1_content).unwrap();

    // 2. An orphaned game directory (missing ACF)
    let game2_dir = common.join("Orphaned Game");
    fs::create_dir(&game2_dir).unwrap();
    fs::write(game2_dir.join("steam_appid.txt"), "202").unwrap();

    let installed = steamflow::library::scan_library_info(root).await.unwrap();

    // Verify game 1 (ACF)
    assert!(installed.contains_key(&101));
    assert_eq!(installed.get(&101).unwrap().manifest_missing, false);
    assert_eq!(installed.get(&101).unwrap().install_dir_resolution_method, "manifest_validated");

    // Verify game 2 (Recovered)
    assert!(installed.contains_key(&202));
    assert_eq!(installed.get(&202).unwrap().manifest_missing, true);
    assert_eq!(installed.get(&202).unwrap().install_dir_resolution_method, "recovery_orphaned_manifest");
    assert_eq!(installed.get(&202).unwrap().name.as_deref(), Some("Orphaned Game"));
}

#[test]
fn test_manifest_generation_minimal() {
    let temp = tempfile::tempdir().unwrap();
    let manifest_path = temp.path().join("appmanifest_123.acf");

    steamflow::steam_client::SteamClient::write_appmanifest(
        &manifest_path,
        123,
        "Test Game",
        "TestGameDir",
        Vec::new()
    ).unwrap();

    let content = std::fs::read_to_string(&manifest_path).unwrap();
    assert!(content.contains("\"appid\"\t\"123\""));
    assert!(content.contains("\"name\"\t\"Test Game\""));
    assert!(content.contains("\"installdir\"\t\"TestGameDir\""));
    assert!(content.contains("\"Universe\"\t\"1\""));
    assert!(content.contains("\"StateFlags\"\t\"4\""));
}
