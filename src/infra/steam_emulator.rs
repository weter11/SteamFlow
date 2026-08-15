//! Offline Steam API emulator provisioning (Phase 4.1 — clientless launcher).
//!
//! Implements the "OfflineEmulated" `SteamMode`: the game is launched
//! directly under its pure-PE runner with NO Windows (or Linux) Steam client
//! running. A local steam_api emulator (e.g. Goldberg SteamEmu, SmartSteamEmu)
//! answers Steamworks calls instead.
//!
//! The emulator DLL binaries themselves are USER-SUPPLIED external artifacts —
//! SteamFlow does not ship them. Drop `steam_api.dll` + `steam_api64.dll`
//! (pure-PE builds of your emulator of choice) into
//! `~/.config/SteamFlow/steam_emulator/` and this module stages them, writes
//! the emulator contract files (`steam_appid.txt`,
//! `steam_settings/force_account_name.txt`, `steam_settings/force_steamid.txt`)
//! and exposes the env fragments (`WINEDLLOVERRIDES` / `WINEDLLPATH`) that
//! make Wine prefer the emulator over the game's original steam_api DLL.
//!
//! Two deployment mechanisms, in order of reliability:
//!
//! 1. **In-place override** (the mechanism that actually works for every
//!    engine): the emulator DLL is copied over the game's own `steam_api*.dll`
//!    wherever the game keeps it (game root, `bin/`, …), with the original
//!    preserved as `<dll>.steamflow-orig` next to it. This is required for
//!    engines that load steam_api by a CONSTRUCTED path — the Source engine
//!    loads `%s/bin/steam_api.dll` via its tier0 module system (verified
//!    2026-08-15 on Portal 2: `vstdlib.dll` contains the format string
//!    `%s/bin/%s` + `steam_api.dll`), and Wine's WINEDLLPATH / DLL overrides
//!    are bypassed entirely for path-qualified loads.
//! 2. **WINEDLLPATH shadowing**: the staged copy in the prefix
//!    (`<prefix>/drive_c/SteamFlow/steam_emulator/<appid>/`) is placed FIRST
//!    in WINEDLLPATH and `steam_api=n,b;steam_api64=n,b` is appended to
//!    WINEDLLOVERRIDES. This covers engines that load by bare name.
//!
//! Layout inside the prefix (never touches the game's own files except the
//! deliberate in-place override above, which is backed up):
//! ```text
//! <prefix>/drive_c/SteamFlow/steam_emulator/<appid>/
//!   steam_api.dll            (staged copy, if supplied)
//!   steam_api64.dll          (staged copy, if supplied)
//!   steam_appid.txt
//!   steam_settings/
//!     force_account_name.txt
//!     force_steamid.txt
//! ```

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::models::{OfflineSettings, SteamMode, UserAppConfig};

/// Default emulator DLL source directory (`~/.config/SteamFlow/steam_emulator/`).
pub fn emulator_source_dir() -> PathBuf {
    crate::config::config_dir()
        .map(|d| d.join("steam_emulator"))
        .unwrap_or_else(|_| PathBuf::from("steam_emulator"))
}

/// Per-game staging directory INSIDE the game's Wine prefix.
pub fn staging_dir_for(wine_prefix: &Path, app_id: u32) -> PathBuf {
    wine_prefix
        .join("drive_c")
        .join("SteamFlow")
        .join("steam_emulator")
        .join(app_id.to_string())
}

/// WINEDLLOVERRIDES fragment that makes Wine prefer a native (emulator)
/// steam_api over builtins. `n,b` = try native first, then builtin.
pub const WINEDLL_OVERRIDES_FRAGMENT: &str = "steam_api=n,b;steam_api64=n,b";

/// Whether the game actually needs the Steam API: the per-game flag OR a
/// steam_api(64).dll present in the install directory (mirrors the UI badge).
pub fn game_requires_steam_api(
    user_config: Option<&UserAppConfig>,
    install_dir: Option<&Path>,
) -> bool {
    if user_config.map(|c| c.requires_steam_api).unwrap_or(false) {
        return true;
    }
    if let Some(dir) = install_dir {
        if dir.join("steam_api64.dll").exists() || dir.join("steam_api.dll").exists() {
            return true;
        }
    }
    false
}

/// Is a native Steam host session active? "Native host" = the Windows Steam
/// client in the master prefix (the two-runner architecture's client). Either
/// a persisted login session OR a running client process counts — a running
/// client can answer Steamworks queries, and a persisted session means the
/// one-time-login onboarding already happened.
pub fn native_steam_host_session_active() -> bool {
    let cfg = crate::utils::get_master_steam_config();
    crate::steam_client::SteamClient::windows_client_has_session(&cfg.wine_prefix)
        || crate::steam_client::SteamClient::is_steam_running_in_prefix(&cfg.wine_prefix)
}

/// PURE decision (unit-testable): resolve the EFFECTIVE steam mode.
///
/// `Auto` falls back to `OfflineEmulated` only when the game needs the Steam
/// API AND no native Steam host session is active. DRM-free games (no
/// steam_api) stay fully clientless-clean in Auto — injecting steam_appid.txt
/// / emulator env into them makes them try to init Steam and fail (the
/// Amnesia: The Dark Descent lesson, AppID 57300).
pub fn resolve_effective_steam_mode(
    user_config: Option<&UserAppConfig>,
    native_session_active: bool,
    game_requires_steam_api: bool,
) -> SteamMode {
    let configured = user_config.map(|c| c.steam_mode).unwrap_or_default();
    match configured {
        SteamMode::Auto => {
            if game_requires_steam_api && !native_session_active {
                SteamMode::OfflineEmulated
            } else {
                SteamMode::Auto
            }
        }
        other => other,
    }
}

/// Result of a provisioning run (also used for diagnostics/logging).
#[derive(Debug, Clone, Default)]
pub struct ProvisionReport {
    /// Staging dir inside the prefix where emulator files were written.
    pub staging_dir: PathBuf,
    /// Names of emulator DLLs actually staged (e.g. `["steam_api64.dll"]`).
    pub dlls_staged: Vec<String>,
    /// Names of emulator DLLs that were NOT found in the source dir.
    pub dlls_missing: Vec<String>,
    /// Emulator DLLs copied OVER the game's own copies (in-place override).
    pub dlls_deployed: Vec<PathBuf>,
    /// Game-owned steam_api DLLs preserved as `<dll>.steamflow-orig`.
    pub backed_up: Vec<PathBuf>,
    /// `steam_appid.txt` files written (game root / exe dir / staging dir).
    pub appid_files: Vec<PathBuf>,
    /// `steam_settings/*` files written.
    pub settings_files: Vec<PathBuf>,
}

/// Offline Steam API emulator provisioner.
pub struct SteamEmulatorManager;

impl SteamEmulatorManager {
    /// Provision the offline emulator contract for a clientless launch:
    ///
    /// 1. `steam_appid.txt` → game root, primary executable directory AND the
    ///    staging dir (Goldberg checks `steam_settings/` first, then the game
    ///    run path, then beside the DLL — covering all three).
    /// 2. Emulator DLLs (`steam_api.dll` / `steam_api64.dll`) copied from
    ///    `~/.config/SteamFlow/steam_emulator/` into the staging dir inside
    ///    the Wine prefix. Missing DLLs are non-fatal (logged + reported) —
    ///    the config files are still written so a partially-staged setup is
    ///    diagnosable.
    /// 3. `steam_settings/force_account_name.txt` + `force_steamid.txt` from
    ///    `OfflineSettings`, written beside the DLLs where the emulator reads
    ///    them.
    ///
    /// The game's own steam_api DLLs are NEVER overwritten — the staged copies
    /// shadow them via `WINEDLLPATH` (see [`Self::winedllpath_fragment`]).
    pub fn provision(
        game_root: &Path,
        exe_dir: &Path,
        app_id: u32,
        settings: &OfflineSettings,
        wine_prefix: &Path,
    ) -> anyhow::Result<ProvisionReport> {
        Self::provision_with_source(game_root, exe_dir, app_id, settings, wine_prefix, &emulator_source_dir())
    }

    /// Same as [`Self::provision`] with an explicit emulator source dir
    /// (test seam; the production entry point uses the config dir).
    pub fn provision_with_source(
        game_root: &Path,
        exe_dir: &Path,
        app_id: u32,
        settings: &OfflineSettings,
        wine_prefix: &Path,
        source_dir: &Path,
    ) -> anyhow::Result<ProvisionReport> {
        let staging = staging_dir_for(wine_prefix, app_id);
        std::fs::create_dir_all(&staging).map_err(|e| {
            anyhow::anyhow!(
                "failed creating emulator staging dir {}: {e}",
                staging.display()
            )
        })?;

        let mut report = ProvisionReport {
            staging_dir: staging.clone(),
            ..Default::default()
        };

        // 1. steam_appid.txt — every location the emulator / steam_api probes.
        let app_id_str = app_id.to_string();
        let mut appid_targets: BTreeSet<PathBuf> = BTreeSet::new();
        appid_targets.insert(game_root.to_path_buf());
        appid_targets.insert(exe_dir.to_path_buf());
        appid_targets.insert(staging.clone());
        for dir in appid_targets {
            if !dir.is_dir() {
                continue;
            }
            let target = dir.join("steam_appid.txt");
            match std::fs::write(&target, &app_id_str) {
                Ok(()) => report.appid_files.push(target),
                Err(e) => tracing::warn!(
                    "Failed writing steam_appid.txt to {}: {e}",
                    target.display()
                ),
            }
        }

        // 2. Emulator DLL staging (user-supplied binaries — never fabricated).
        // `source_dir` is the test seam; production uses the config dir
        // (`emulator_source_dir()`).
        for dll in ["steam_api.dll", "steam_api64.dll"] {
            let src = source_dir.join(dll);
            if !src.is_file() {
                report.dlls_missing.push(dll.to_string());
                continue;
            }
            let dst = staging.join(dll);
            match std::fs::copy(&src, &dst) {
                Ok(_) => report.dlls_staged.push(dll.to_string()),
                Err(e) => {
                    tracing::warn!("Failed staging emulator DLL {} → {}: {e}", src.display(), dst.display());
                    report.dlls_missing.push(dll.to_string());
                }
            }
        }
        if !report.dlls_staged.is_empty() {
            tracing::info!(
                "Staged offline Steam API emulator DLL(s) into {}: {}",
                staging.display(),
                report.dlls_staged.join(", ")
            );
        }
        if !report.dlls_missing.is_empty() {
            tracing::warn!(
                "OfflineEmulated: emulator DLL(s) missing from {} ({}). The game's own steam_api will be used and SteamAPI_Init will fail without a client. Drop steam_api.dll/steam_api64.dll (e.g. Goldberg SteamEmu) into {} to enable clientless Steamworks.",
                source_dir.display(),
                report.dlls_missing.join(", "),
                source_dir.display()
            );
        }

        // 2b. IN-PLACE OVERRIDE — deploy the emulator over the game's own
        //     steam_api*.dll wherever the game keeps it (game root, bin/, …).
        //     Engines that load steam_api by a CONSTRUCTED path (Source:
        //     `%s/bin/steam_api.dll` via its tier0 module system) bypass
        //     WINEDLLPATH and DLL overrides entirely, so the file the game
        //     actually loads must BE the emulator. Originals are preserved as
        //     `<dll>.steamflow-orig` next to the replacement.
        let mut deploy_targets: BTreeSet<PathBuf> = BTreeSet::new();
        for dir in [game_root, exe_dir] {
            for dll in ["steam_api.dll", "steam_api64.dll"] {
                if dir.join(dll).is_file() {
                    deploy_targets.insert(dir.to_path_buf());
                }
            }
        }
        if let Ok(entries) = std::fs::read_dir(game_root) {
            for entry in entries.flatten() {
                let p = entry.path();
                if p.is_dir()
                    && (p.join("steam_api.dll").is_file() || p.join("steam_api64.dll").is_file())
                {
                    deploy_targets.insert(p);
                }
            }
        }
        // No game-owned steam_api anywhere → fall back to the exe dir so a
        // constructed `%s/steam_api.dll` path still hits the emulator.
        if deploy_targets.is_empty() {
            deploy_targets.insert(exe_dir.to_path_buf());
        }
        for dir in &deploy_targets {
            for dll in ["steam_api.dll", "steam_api64.dll"] {
                let src = source_dir.join(dll);
                if !src.is_file() {
                    continue;
                }
                let dst = dir.join(dll);
                let backup = dir.join(format!("{dll}.steamflow-orig"));
                if dst.exists() && !backup.exists() {
                    match std::fs::rename(&dst, &backup) {
                        Ok(()) => report.backed_up.push(backup.clone()),
                        Err(e) => tracing::warn!(
                            "Failed backing up {} → {}: {e}",
                            dst.display(),
                            backup.display()
                        ),
                    }
                }
                match std::fs::copy(&src, &dst) {
                    Ok(_) => report.dlls_deployed.push(dst),
                    Err(e) => tracing::warn!(
                        "Failed deploying emulator DLL {} → {}: {e}",
                        src.display(),
                        dst.display()
                    ),
                }
            }
        }
        if !report.dlls_deployed.is_empty() {
            tracing::info!(
                "Deployed offline Steam API emulator DLL(s) in place of the game's own: {}",
                report
                    .dlls_deployed
                    .iter()
                    .map(|p| p.display().to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }

        // 3. steam_settings/ — the emulator reads these from the game dir,
        //    the working dir or beside its DLL, so write them everywhere the
        //    emulator can end up looking: game root, each deploy target and
        //    the staging dir.
        let mut settings_dirs: BTreeSet<PathBuf> = BTreeSet::new();
        settings_dirs.insert(game_root.to_path_buf());
        settings_dirs.insert(staging.clone());
        for dir in &deploy_targets {
            settings_dirs.insert(dir.clone());
        }
        for dir in &settings_dirs {
            let settings_dir = dir.join("steam_settings");
            std::fs::create_dir_all(&settings_dir).map_err(|e| {
                anyhow::anyhow!(
                    "failed creating emulator settings dir {}: {e}",
                    settings_dir.display()
                )
            })?;
            let account_file = settings_dir.join("force_account_name.txt");
            std::fs::write(&account_file, &settings.account_name).map_err(|e| {
                anyhow::anyhow!("failed writing {}: {e}", account_file.display())
            })?;
            report.settings_files.push(account_file);
            let steamid_file = settings_dir.join("force_steamid.txt");
            std::fs::write(&steamid_file, settings.steam_id.to_string()).map_err(|e| {
                anyhow::anyhow!("failed writing {}: {e}", steamid_file.display())
            })?;
            report.settings_files.push(steamid_file);
        }

        let dlls_label = if report.dlls_staged.is_empty() {
            "NONE".to_string()
        } else {
            report.dlls_staged.join(",")
        };
        tracing::info!(
            "OfflineEmulated provisioning complete for app {} (staging {}, account={}, steam_id={}, dlls={})",
            app_id,
            staging.display(),
            settings.account_name,
            settings.steam_id,
            dlls_label
        );
        Ok(report)
    }

    /// WINEDLLPATH entry (Unix path) for the per-game staging dir, so Wine
    /// resolves the staged emulator before the game's own steam_api DLLs.
    pub fn winedllpath_fragment(wine_prefix: &Path, app_id: u32) -> String {
        staging_dir_for(wine_prefix, app_id).to_string_lossy().to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn test_steam_mode_serde_defaults_and_overrides() {
        // Missing fields → defaults (backwards compatibility with old
        // user_apps.json files).
        let old_style = r#"{"launch_options":"","env_variables":{},"use_steam_runtime":false,"hidden":false,"favorite":false}"#;
        let cfg: UserAppConfig = serde_json::from_str(old_style).unwrap();
        assert_eq!(cfg.steam_mode, SteamMode::Auto);
        assert_eq!(cfg.offline_settings.account_name, "Slavik");
        assert_eq!(cfg.offline_settings.steam_id, 76561198000000000);

        // Explicit overrides round-trip.
        let explicit = r#"{"launch_options":"","env_variables":{},"use_steam_runtime":false,"hidden":false,"favorite":false,"steam_mode":"OfflineEmulated","offline_settings":{"account_name":"TestUser","steam_id":42}}"#;
        let cfg: UserAppConfig = serde_json::from_str(explicit).unwrap();
        assert_eq!(cfg.steam_mode, SteamMode::OfflineEmulated);
        assert_eq!(cfg.offline_settings.account_name, "TestUser");
        assert_eq!(cfg.offline_settings.steam_id, 42);

        // Serialization uses PascalCase variants (the schema contract).
        let json = serde_json::to_string(&SteamMode::OfflineEmulated).unwrap();
        assert_eq!(json, "\"OfflineEmulated\"");
        // Round-trip the whole config.
        let back: UserAppConfig = serde_json::from_str(&serde_json::to_string(&cfg).unwrap()).unwrap();
        assert_eq!(back.steam_mode, SteamMode::OfflineEmulated);
    }

    #[test]
    fn test_steam_mode_auto_fallback() {
        // Auto + game needs Steam API + no session → OfflineEmulated.
        let mut cfg = UserAppConfig::default();
        cfg.requires_steam_api = true;
        assert_eq!(
            resolve_effective_steam_mode(Some(&cfg), false, true),
            SteamMode::OfflineEmulated
        );
        // Auto + session active → stay Auto (classic client behavior).
        assert_eq!(
            resolve_effective_steam_mode(Some(&cfg), true, true),
            SteamMode::Auto
        );
        // Auto + DRM-free game (no steam_api) + no session → stay Auto, do
        // NOT inject the emulator (Amnesia lesson).
        cfg.requires_steam_api = false;
        assert_eq!(
            resolve_effective_steam_mode(Some(&cfg), false, false),
            SteamMode::Auto
        );
        // Explicit mode always wins.
        cfg.steam_mode = SteamMode::OfflineEmulated;
        assert_eq!(
            resolve_effective_steam_mode(Some(&cfg), true, false),
            SteamMode::OfflineEmulated
        );
        cfg.steam_mode = SteamMode::OnlineContainerized;
        assert_eq!(
            resolve_effective_steam_mode(Some(&cfg), false, true),
            SteamMode::OnlineContainerized
        );
        // No config at all → Auto semantics.
        assert_eq!(
            resolve_effective_steam_mode(None, false, true),
            SteamMode::OfflineEmulated
        );
    }

    #[test]
    fn test_steam_emulator_provisioning() {
        let tmp = tempdir().unwrap();
        let game_root = tmp.path().join("game");
        std::fs::create_dir_all(&game_root).unwrap();
        let exe_dir = game_root.join("bin");
        std::fs::create_dir_all(&exe_dir).unwrap();
        // The game ships its own steam_api64.dll — must stay untouched.
        std::fs::write(exe_dir.join("steam_api64.dll"), "ORIGINAL").unwrap();
        let wine_prefix = tmp.path().join("pfx");
        std::fs::create_dir_all(&wine_prefix).unwrap();

        // Without an emulator source dir: config files still written, DLLs
        // reported missing, game's own DLL untouched. Uses an explicit EMPTY
        // source dir (never the real config dir — a user-supplied emulator
        // there would turn this into a deployment test).
        let empty_src = tmp.path().join("empty_emu");
        std::fs::create_dir_all(&empty_src).unwrap();
        let settings = OfflineSettings::default();
        let report = SteamEmulatorManager::provision_with_source(
            &game_root,
            &exe_dir,
            620,
            &settings,
            &wine_prefix,
            &empty_src,
        )
        .expect("provision must succeed even without DLLs");
        assert_eq!(report.dlls_staged.len(), 0);
        assert_eq!(report.dlls_missing.len(), 2);
        assert_eq!(report.dlls_deployed.len(), 0); // no source DLLs → no in-place override
        assert_eq!(report.backed_up.len(), 0);
        assert_eq!(report.appid_files.len(), 3); // game root + exe dir + staging
        // steam_settings/ written to game root + deploy target (exe_dir, which
        // ships the game's steam_api64.dll) + staging = 3 dirs × 2 files.
        assert_eq!(report.settings_files.len(), 6);

        // steam_appid.txt present in game root and exe dir with the app id.
        assert_eq!(std::fs::read_to_string(game_root.join("steam_appid.txt")).unwrap(), "620");
        assert_eq!(std::fs::read_to_string(exe_dir.join("steam_appid.txt")).unwrap(), "620");
        // The game's original DLL is untouched (no emulator DLLs supplied).
        assert_eq!(std::fs::read_to_string(exe_dir.join("steam_api64.dll")).unwrap(), "ORIGINAL");
        // steam_settings beside the game's DLL too (where Goldberg looks).
        assert_eq!(
            std::fs::read_to_string(exe_dir.join("steam_settings/force_account_name.txt")).unwrap(),
            "Slavik"
        );

        // steam_settings beside the DLLs with the configured identity.
        let staging = report.staging_dir.clone();
        let account = staging.join("steam_settings/force_account_name.txt");
        let steamid = staging.join("steam_settings/force_steamid.txt");
        assert!(account.is_file() && steamid.is_file());
        assert_eq!(std::fs::read_to_string(&account).unwrap(), "Slavik");
        assert_eq!(std::fs::read_to_string(&steamid).unwrap(), "76561198000000000");
        // steam_appid.txt also in the staging dir (emulator-first location).
        assert_eq!(std::fs::read_to_string(staging.join("steam_appid.txt")).unwrap(), "620");
    }

    #[test]
    fn test_steam_emulator_provisioning_with_dlls() {
        let tmp = tempdir().unwrap();
        let game_root = tmp.path().join("game");
        std::fs::create_dir_all(&game_root).unwrap();
        let wine_prefix = tmp.path().join("pfx");
        std::fs::create_dir_all(&wine_prefix).unwrap();

        // Fake emulator source dir with both DLLs.
        let src = tmp.path().join("emulator_src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("steam_api.dll"), "EMU32").unwrap();
        std::fs::write(src.join("steam_api64.dll"), "EMU64").unwrap();

        // Redirect the source dir lookup for the test.
        let settings = OfflineSettings {
            account_name: "TestUser".into(),
            steam_id: 123456789,
        };
        let report = SteamEmulatorManager::provision_with_source(
            &game_root,
            &game_root,
            620,
            &settings,
            &wine_prefix,
            &src,
        )
        .expect("provision must succeed");

        assert_eq!(report.dlls_staged, vec!["steam_api.dll", "steam_api64.dll"]);
        assert!(report.dlls_missing.is_empty());
        let staging = report.staging_dir.clone();
        assert_eq!(std::fs::read_to_string(staging.join("steam_api64.dll")).unwrap(), "EMU64");
        // In-place override: no game-owned steam_api existed → fallback deploys
        // into the exe dir (== game root here); nothing to back up.
        assert_eq!(report.dlls_deployed.len(), 2);
        assert!(report.backed_up.is_empty());
        assert_eq!(std::fs::read_to_string(game_root.join("steam_api.dll")).unwrap(), "EMU32");
        assert_eq!(std::fs::read_to_string(game_root.join("steam_api64.dll")).unwrap(), "EMU64");
        assert_eq!(
            std::fs::read_to_string(staging.join("steam_settings/force_account_name.txt")).unwrap(),
            "TestUser"
        );
        assert_eq!(
            std::fs::read_to_string(staging.join("steam_settings/force_steamid.txt")).unwrap(),
            "123456789"
        );
        // steam_settings/ also in the game root (Goldberg reads it from there).
        assert_eq!(
            std::fs::read_to_string(game_root.join("steam_settings/force_account_name.txt")).unwrap(),
            "TestUser"
        );
        // WINEDLLPATH fragment points at the staging dir.
        assert_eq!(
            SteamEmulatorManager::winedllpath_fragment(&wine_prefix, 620),
            staging.to_string_lossy()
        );
    }

    #[test]
    fn test_steam_emulator_provisioning_backs_up_and_replaces_game_dll() {
        let tmp = tempdir().unwrap();
        let game_root = tmp.path().join("game");
        std::fs::create_dir_all(&game_root).unwrap();
        let wine_prefix = tmp.path().join("pfx");
        std::fs::create_dir_all(&wine_prefix).unwrap();

        // The game ships its own steam_api64.dll in bin/ (Source-engine layout:
        // Portal 2 loads `bin\steam_api.dll` by constructed path — the exact
        // case that bypasses WINEDLLPATH and needs the in-place override).
        let bin = game_root.join("bin");
        std::fs::create_dir_all(&bin).unwrap();
        std::fs::write(bin.join("steam_api64.dll"), "ORIGINAL").unwrap();

        let src = tmp.path().join("emulator_src");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(src.join("steam_api64.dll"), "EMU64").unwrap();

        let settings = OfflineSettings::default();
        let report = SteamEmulatorManager::provision_with_source(
            &game_root,
            &game_root,
            620,
            &settings,
            &wine_prefix,
            &src,
        )
        .expect("provision must succeed");

        // The emulator replaced the game's own DLL in bin/, original preserved.
        assert_eq!(
            report.dlls_deployed,
            vec![bin.join("steam_api64.dll")]
        );
        assert_eq!(
            report.backed_up,
            vec![bin.join("steam_api64.dll.steamflow-orig")]
        );
        assert_eq!(
            std::fs::read_to_string(bin.join("steam_api64.dll")).unwrap(),
            "EMU64"
        );
        assert_eq!(
            std::fs::read_to_string(bin.join("steam_api64.dll.steamflow-orig")).unwrap(),
            "ORIGINAL"
        );
        // steam_settings/ beside the deployed DLL + in the game root + staging.
        assert_eq!(
            std::fs::read_to_string(bin.join("steam_settings/force_account_name.txt")).unwrap(),
            "Slavik"
        );
        assert!(game_root.join("steam_settings/force_steamid.txt").is_file());

        // Idempotency: a second provision refreshes the emulator but never
        // clobbers the preserved original.
        let report2 = SteamEmulatorManager::provision_with_source(
            &game_root,
            &game_root,
            620,
            &settings,
            &wine_prefix,
            &src,
        )
        .expect("second provision must succeed");
        assert!(report2.backed_up.is_empty(), "original must not be re-backed-up");
        assert_eq!(report2.dlls_deployed.len(), 1);
        assert_eq!(
            std::fs::read_to_string(bin.join("steam_api64.dll")).unwrap(),
            "EMU64"
        );
        assert_eq!(
            std::fs::read_to_string(bin.join("steam_api64.dll.steamflow-orig")).unwrap(),
            "ORIGINAL"
        );
    }
}
