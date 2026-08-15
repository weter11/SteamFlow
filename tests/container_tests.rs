//! Phase 4.2 integration tests: Steam Linux Runtime provisioning end-to-end
//! plus the pressure-vessel/bwrap command builder via the public API.
//!
//! The provisioning cycle builds a REAL archive with the system `tar`
//! binary (the same binary `RuntimeManager::extract_archive` uses), so the
//! round-trip verifies actual extraction behavior, not just parsing.

use std::path::{Path, PathBuf};
use std::process::Command;

use tempfile::tempdir;

use steamflow::container::pressure_vessel::{CommandKind, PressureVesselBuilder};
use steamflow::container::runtime::{
    parse_versions_txt, ArchiveVerification, RuntimeManager, SteamRuntimeId,
};

/// Build an uncompressed tar archive of `source_dir` at `archive_path`.
/// Uses the system tar (project extraction convention).
fn make_tar(source_dir: &Path, archive_path: &Path) {
    let status = Command::new("tar")
        .arg("-cf")
        .arg(archive_path)
        .arg("-C")
        .arg(source_dir)
        .arg(".")
        .status()
        .expect("system tar must be available (used by runtime extraction)");
    assert!(status.success(), "failed creating fixture archive");
}

/// A minimal but structurally faithful steamrt4 runtime tree:
/// VERSIONS.txt, `run` entry point, and two component dirs with
/// manifest.json + a files/ payload.
fn write_runtime_fixture(root: &Path) {
    std::fs::create_dir_all(root.join("sniper_platform/files")).unwrap();
    std::fs::create_dir_all(root.join("sniper_tools/files")).unwrap();
    std::fs::write(
        root.join("VERSIONS.txt"),
        "VERSION sniper_platform 0.20240304.0\nVERSION sniper_tools 0.20240304.0\n",
    )
    .unwrap();
    std::fs::write(root.join("run"), "#!/bin/sh\nexec _v2-entry-point \"$@\"\n").unwrap();
    std::fs::write(
        root.join("sniper_platform/manifest.json"),
        r#"{"name":"sniper_platform","version":"0.20240304.0","architecture":"amd64","os":"linux"}"#,
    )
    .unwrap();
    std::fs::write(
        root.join("sniper_tools/manifest.json"),
        r#"{"name":"sniper_tools","version":"0.20240304.0"}"#,
    )
    .unwrap();
    std::fs::write(root.join("sniper_platform/files/hello"), "payload\n").unwrap();
}

#[tokio::test]
async fn test_runtime_provision_cycle_flat_archive() {
    let dir = tempdir().unwrap();
    let fixture = dir.path().join("fixture");
    write_runtime_fixture(&fixture);

    let archive = dir.path().join("steamrt4.tar");
    make_tar(&fixture, &archive);

    // Expected digest computed from the archive itself.
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(std::fs::read(&archive).unwrap());
    let expected_hex = hex::encode(hasher.finalize());

    let mgr = RuntimeManager::new(SteamRuntimeId::Steamrt4, dir.path().join("provisioned"));
    let verification = ArchiveVerification {
        expected_sha256: Some(expected_hex.clone()),
        ..Default::default()
    };
    let state = mgr
        .provision_from_archive(&archive, &verification, true)
        .await
        .unwrap();

    assert!(state.present, "state: {state:?}");
    assert!(state.complete, "state errors: {:?}", state.errors);
    assert!(state.is_usable());
    assert_eq!(state.revision.as_deref(), Some("0.20240304.0"));
    assert_eq!(state.versions.len(), 2);
    assert_eq!(state.manifests.len(), 2);
    assert!(state.entry_point.as_deref().unwrap().ends_with("run"));
    // Provisioned payload landed on disk.
    assert!(dir
        .path()
        .join("provisioned/sniper_platform/files/hello")
        .is_file());

    // Second provision with a WRONG digest must fail BEFORE extraction and
    // must NOT clobber the existing deployment. (The archive was kept above
    // so this exercises the digest path, not the missing-file path.)
    let bad = ArchiveVerification {
        expected_sha256: Some("0".repeat(64)),
        ..Default::default()
    };
    let err = mgr
        .provision_from_archive(&archive, &bad, false)
        .await
        .unwrap_err();
    assert!(format!("{err:#}").contains("SHA256 mismatch"));
    assert!(
        dir.path().join("provisioned/run").exists(),
        "existing deployment must survive"
    );
}

#[tokio::test]
async fn test_runtime_provision_cycle_nested_archive() {
    // Valve depot tarballs often wrap the runtime in a single top-level dir;
    // find_runtime_root must normalize that so the state still reads correct.
    let dir = tempdir().unwrap();
    let fixture = dir.path().join("fixture");
    write_runtime_fixture(&fixture);
    let wrapper = dir.path().join("wrapper/steamrt4");
    std::fs::create_dir_all(&wrapper).unwrap();
    // Move the fixture contents under a single top-level dir.
    for entry in std::fs::read_dir(&fixture).unwrap() {
        let entry = entry.unwrap();
        let dest = wrapper.join(entry.file_name());
        std::fs::rename(entry.path(), &dest).unwrap();
    }

    let archive = dir.path().join("steamrt4-nested.tar");
    make_tar(&dir.path().join("wrapper"), &archive);

    let mgr = RuntimeManager::new(SteamRuntimeId::Steamrt4, dir.path().join("provisioned"));
    let state = mgr
        .provision_from_archive(&archive, &ArchiveVerification::default(), false)
        .await
        .unwrap();
    assert!(state.complete, "state errors: {:?}", state.errors);
    assert_eq!(state.versions.len(), 2);
    assert_eq!(state.manifests.len(), 2);
    assert!(dir
        .path()
        .join("provisioned/steamrt4/sniper_platform/files/hello")
        .is_file());
}

#[test]
fn test_pressure_vessel_builder_public_api() {
    // Cross-module smoke test through the public API: full flags for
    // Vulkan/display/audio/prefix with a pressure-vessel wrap, plus the
    // bwrap flavor.
    let dir = tempdir().unwrap();
    let pfx = dir.path().join("steamapps/compatdata/620/pfx");
    let install = dir.path().join("steamapps/common/Portal 2");
    std::fs::create_dir_all(&pfx).unwrap();
    std::fs::create_dir_all(&install).unwrap();

    let mut builder = PressureVesselBuilder::new(CommandKind::PressureVesselWrap);
    builder
        .runtime(dir.path().join("runtimes/steamrt4"), "0.20240304.0")
        .filesystem(install.clone())
        .filesystem(pfx.clone())
        .device(PathBuf::from("/dev/dri"))
        .env_if_host("DISPLAY", ":0")
        .bind_mount(
            PathBuf::from("/run/user/1000/pulse/native"),
            PathBuf::from("/run/user/1000/pulse/native"),
        )
        .command(PathBuf::from("/usr/bin/true"), vec!["--flag".into()]);
    let argv = builder.build().unwrap();

    assert_eq!(argv[0], "pressure-vessel-wrap");
    assert!(argv.iter().any(|a| a.starts_with("--runtime-path=")));
    assert!(argv.iter().any(|a| a == "--device=/dev/dri"));
    assert!(argv
        .iter()
        .any(|a| a.starts_with("--bind-mount=") && a.contains("pulse/native")));
    assert!(argv.iter().any(|a| a == "--env-if-host=DISPLAY=:0"));
    let sep_count = argv.iter().filter(|a| a.as_str() == "--").count();
    assert_eq!(sep_count, 2, "pv-wrap needs two `--` separators: {argv:?}");
    assert_eq!(argv.last().unwrap(), "--flag");

    // Bwrap flavor: same semantic mounts, bubblewrap syntax.
    let mut bwrap = PressureVesselBuilder::new(CommandKind::Bwrap);
    bwrap
        .filesystem(install.clone())
        .filesystem(pfx)
        .device(PathBuf::from("/dev/dri"))
        .env("STEAM_APPID", "620")
        .command(PathBuf::from("/bin/true"), vec![]);
    let argv = bwrap.build().unwrap();
    assert_eq!(argv[0], "bwrap");
    assert!(argv.iter().any(|a| a == "--unshare-all"));
    let bind_idx = argv.iter().position(|a| a == "--bind").unwrap();
    assert_eq!(argv[bind_idx + 1], install.display().to_string());
    assert_eq!(argv[bind_idx + 2], install.display().to_string());
    let dev_idx = argv.iter().position(|a| a == "--dev-bind").unwrap();
    assert_eq!(argv[dev_idx + 1], "/dev/dri");
    assert!(argv
        .windows(3)
        .any(|w| w == ["--setenv", "STEAM_APPID", "620"]));
}

#[test]
fn test_versions_txt_public_parser() {
    let parsed = parse_versions_txt("VERSION steamrt4_platform 0.20250701.0\n");
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].name, "steamrt4_platform");
    assert_eq!(parsed[0].version, "0.20250701.0");
}
