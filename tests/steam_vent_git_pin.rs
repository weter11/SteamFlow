//! Offline regression coverage for the pinned steam-vent Git dependency.
//!
//! The tuple-struct visibility assertion deliberately constructs
//! `SteamGuardToken` by field instead of calling `SteamGuardToken::new(...)`:
//! the public constructor already exists on upstream main, so only direct
//! tuple construction compiles if PR #19's `pub` field change is present.

use steam_vent::auth::SteamGuardToken;

const PINNED_STEAM_VENT_REV: &str = "54ecd10ebd385c6879a536725fd77cdb846fc9a3";

#[test]
fn test_steam_guard_token_tuple_field_is_public() {
    let token = SteamGuardToken("123456".to_string());
    assert_eq!(token.0, "123456");
}

#[test]
fn test_resolved_steam_vent_is_pinned_to_expected_git_revision() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let lock_path = manifest_dir.join("Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("failed reading {}: {e}", lock_path.display()));

    let expected_source =
        format!("git+https://codeberg.org/steam-vent/steam-vent.git?rev={PINNED_STEAM_VENT_REV}#");
    let mut steam_vent_packages: Vec<&str> = Vec::new();
    let mut current_name: Option<&str> = None;
    let mut current_source: Option<&str> = None;

    for line in lock.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            // Flush the previous package before starting the next one.
            if current_name == Some("steam-vent") {
                steam_vent_packages.push(current_source.unwrap_or("<no source>"));
            }
            current_name = None;
            current_source = None;
        } else if let Some(name) = trimmed.strip_prefix("name = \"") {
            current_name = name.strip_suffix('"');
        } else if let Some(source) = trimmed.strip_prefix("source = \"") {
            current_source = source.strip_suffix('"');
        }
    }
    if current_name == Some("steam-vent") {
        steam_vent_packages.push(current_source.unwrap_or("<no source>"));
    }

    assert_eq!(
        steam_vent_packages.len(),
        1,
        "expected exactly one steam-vent package, found {steam_vent_packages:?}"
    );
    assert!(
        steam_vent_packages[0].starts_with(&expected_source),
        "steam-vent source is not bound to pinned revision {PINNED_STEAM_VENT_REV}: {}",
        steam_vent_packages[0]
    );
}
