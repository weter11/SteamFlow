use std::fs;

use tempfile::tempdir;

#[tokio::test]
async fn scan_recovers_install_path_from_steam_appid_marker() {
    let tmp = tempdir().unwrap();
    let library_root = tmp.path();
    let steamapps = library_root.join("steamapps");
    let common = steamapps.join("common");
    fs::create_dir_all(&common).unwrap();

    let app_id = 2410180_u32;

    let actual_name = "Portal Prelude RTX";
    let actual_dir = common.join(actual_name);
    fs::create_dir_all(&actual_dir).unwrap();
    fs::write(actual_dir.join("steam_appid.txt"), app_id.to_string()).unwrap();
    fs::write(actual_dir.join("game.exe"), "fake").unwrap();

    let manifest_path = steamapps.join(format!("appmanifest_{}.acf", app_id));
    let manifest_content = format!(
        "\"AppState\"\n{{\n\t\"appid\"\t\"{}\"\n\t\"name\"\t\"Portal Prelude RTX\"\n\t\"installdir\"\t\"App 2410180\"\n}}",
        app_id
    );
    fs::write(&manifest_path, manifest_content).unwrap();

    let scanned = steamflow::library::scan_library_info(library_root)
        .await
        .unwrap();
    let info = scanned.get(&app_id).unwrap();

    assert_eq!(info.install_path, actual_dir);
    assert!(info.install_path.exists());
    assert!(info.install_path.join("steam_appid.txt").exists());

    let rewritten_manifest = fs::read_to_string(&manifest_path).unwrap();
    assert!(rewritten_manifest.contains("\"installdir\"\t\"Portal Prelude RTX\""));
}
