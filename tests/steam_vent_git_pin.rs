//! Offline regression coverage for the vendored steam-vent revision.
//!
//! steam-vent is vendored as a path dependency because Cargo cannot resolve an
//! unadvertised `refs/pull/NN/head` commit from a `rev = "<sha>"` git
//! dependency: its fetcher asks for `refs/heads/<sha>`, which does not exist
//! while the pull request is open. Vendoring the exact commit keeps CI and a
//! fresh clone deterministic without publishing a mirror.
//!
//! Two things must therefore be asserted offline instead of by package source:
//!   1. the recorded upstream revision, and
//!   2. the PR #19 structural change itself.
//!
//! The tuple-struct assertion deliberately constructs `SteamGuardToken` by field
//! rather than calling `SteamGuardToken::new(...)`: the public constructor
//! already exists upstream, so only direct tuple construction compiles if the
//! `pub` field change is present.

use steam_vent::auth::SteamGuardToken;

const PINNED_STEAM_VENT_REV: &str = "54ecd10ebd385c6879a536725fd77cdb846fc9a3";

fn vendored_root() -> std::path::PathBuf {
    std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("vendor")
        .join("steam-vent")
}

#[test]
fn test_steam_guard_token_tuple_field_is_public() {
    let token = SteamGuardToken("123456".to_string());
    assert_eq!(token.0, "123456");
}

#[test]
fn test_vendored_steam_vent_records_the_expected_upstream_revision() {
    let rev_path = vendored_root().join("STEAMVENT_REV");
    let recorded = std::fs::read_to_string(&rev_path)
        .unwrap_or_else(|e| panic!("failed reading {}: {e}", rev_path.display()));
    assert_eq!(
        recorded.trim(),
        PINNED_STEAM_VENT_REV,
        "vendor/steam-vent/STEAMVENT_REV does not match the pinned revision; \
         re-vendor with `git archive {PINNED_STEAM_VENT_REV}`"
    );
}

#[test]
fn test_vendored_steam_vent_source_contains_the_pr_19_change() {
    let auth_path = vendored_root().join("src").join("auth").join("mod.rs");
    let source = std::fs::read_to_string(&auth_path)
        .unwrap_or_else(|e| panic!("failed reading {}: {e}", auth_path.display()));
    assert!(
        source.contains("pub struct SteamGuardToken(pub String);"),
        "vendored steam-vent is missing PR #19's public tuple field; the recorded \
         revision and the actual source disagree"
    );
}

#[test]
fn test_resolved_steam_vent_is_the_vendored_path_package() {
    // The root lockfile must resolve steam-vent as a local path package, not as
    // a git or registry package: a git entry would reintroduce the unadvertised
    // refspec problem, and a registry entry would silently drop PR #19.
    let lock_path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    let lock = std::fs::read_to_string(&lock_path)
        .unwrap_or_else(|e| panic!("failed reading {}: {e}", lock_path.display()));

    let mut current_name: Option<&str> = None;
    let mut current_source: Option<&str> = None;
    let mut sources: Vec<&str> = Vec::new();
    for line in lock.lines() {
        let trimmed = line.trim();
        if trimmed == "[[package]]" {
            if current_name == Some("steam-vent") {
                sources.push(current_source.unwrap_or("<no source>"));
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
        sources.push(current_source.unwrap_or("<no source>"));
    }

    assert_eq!(
        sources.len(),
        1,
        "expected exactly one steam-vent package, found {sources:?}"
    );
    assert!(
        !sources[0].starts_with("git+") && !sources[0].starts_with("registry+"),
        "steam-vent must resolve to the vendored path package, found: {}",
        sources[0]
    );
}
