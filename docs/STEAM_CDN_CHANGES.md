# Steam-CDN Changes (`vendor/steam-cdn`)

## 1. Origin / Source

- Crate: `steam-cdn` (lib name `steam_cdn`), version `1.0.0`, license Apache-2.0, description "Steam CDN".
- Source: crates.io registry (`source = "registry+https://github.com/rust-lang/crates.io-index"` in `vendor/steam-cdn/Cargo.lock`). No `repository` or `authors` field is recorded in `Cargo.toml` / `Cargo.toml.orig`.
- Vendored in commit `0542112` (2026-02-16) as part of PR #8, with the note "Vendored and patched `steam-cdn` in `vendor/steam-cdn` to fix compilation errors and update it to `steam-vent` 0.4."
- Sources checked: `vendor/steam-cdn/Cargo.toml`, `Cargo.toml.orig`, `Cargo.lock`, `LICENSE`, `README.md` (only "# steam-cdn"), `.cargo_vcs_info.json` (absent), `THIRD-PARTY-NOTICES.md`, `AGENTS.md`, code comments/grep for crates.io/github repository URLs. No upstream repository URL or commit hash is recorded anywhere in the tree.

## 2. Complete Commit History

`git log --reverse --follow -- vendor/steam-cdn` and `git log --reverse -- vendor/steam-cdn` both return 29 commits. No path rename/move was detected, so `--follow` did not change the count. The previously reported count of 29 is confirmed (an earlier intermediate count of 27 was incomplete).

| # | SHA | Date | PR | Summary (files touched) | Type |
|---|-----|------|----|--------------------------|------|
| 1 | 0542112 | 2026-02-16 | #8 | Added the entire vendored crate (Cargo, LICENSE, src, examples) plus integration in `src/steam_client.rs`. | dependency vendoring |
| 2 | ee556fa | 2026-02-16 | #8 | `src/download_pipeline.rs`, `src/steam_client.rs`, `vendor/steam-cdn/src/cdn/manifest/file.rs`, `mod.rs`. | bug fix |
| 3 | d2fc329 | 2026-02-16 | #8 | `src/steam_api.rs`, `src/steam_client.rs`, `vendor/steam-cdn/src/cdn/mod.rs`. | bug fix |
| 4 | 6c18776 | 2026-02-17 | #8 | Reverted experimental CDN changes; touched `src/lib.rs`, `src/steam_api.rs`, `src/steam_client.rs`, `vendor/steam-cdn/src/cdn/inner.rs`, `manifest/file.rs`, `mod.rs`. | revert |
| 5 | 9a12690 | 2026-02-17 | #9 | `src/steam_client.rs`, `vendor/steam-cdn/src/cdn/inner.rs`, `mod.rs`, `lib.rs`, `web_api/content_service.rs`. | new functionality |
| 6 | 896bd29 | 2026-02-17 | #9 | `src/steam_client.rs`, `vendor/steam-cdn/src/cdn/inner.rs`, `mod.rs`. | new functionality |
| 7 | dfe20bb | 2026-02-17 | #9 | `vendor/steam-cdn/src/cdn/inner.rs`. | diagnostics |
| 8 | a2aaba0 | 2026-02-17 | #9 | `Cargo.lock`, `Cargo.toml`, `src/download_pipeline.rs`, `vendor/steam-cdn/src/cdn/inner.rs`, `manifest/mod.rs`. | bug fix |
| 9 | 4657f68 | 2026-02-17 | #9 | `src/download_pipeline.rs`, `vendor/steam-cdn/src/cdn/manifest/mod.rs`. | diagnostics |
| 10 | a038f5d | 2026-02-17 | #9 | `src/download_pipeline.rs`, `vendor/steam-cdn/src/cdn/manifest/mod.rs`, `mod.rs`. | bug fix |
| 11 | c8fb06c | 2026-02-17 | #9 | `src/download_pipeline.rs`, `vendor/steam-cdn/src/cdn/manifest/mod.rs`. | bug fix |
| 12 | a957d69 | 2026-02-17 | #9 | Large cleanup touching many files incl. `vendor/steam-cdn/src/cdn/inner.rs`, `manifest/mod.rs`. | cleanup |
| 13 | ede3c94 | 2026-02-17 | #10 | `src/*`, `vendor/steam-cdn/src/cdn/manifest/file.rs`, `mod.rs`. | adaptation |
| 14 | cf9dacf | 2026-02-17 | #10 | `Cargo.toml`, `src/*`, `vendor/steam-cdn/Cargo.toml`. | adaptation |
| 15 | f876dab | 2026-02-17 | #12 | `Cargo.lock`, `src/*`, `vendor/steam-cdn/Cargo.toml`, `manifest/file.rs`, `mod.rs`. | new functionality |
| 16 | 7ee8e9a | 2026-02-18 | #13 | `Cargo.lock`, `README.md`, `src/install.rs`, `src/lib.rs`, `src/steam_client.rs`, `vendor/steam-cdn/Cargo.toml`, `examples/download_manifest.rs`, `manifest/file.rs`, `mod.rs`. | new functionality |
| 17 | cb57329 | 2026-02-18 | #13 | `src/depot_browser.rs`, `src/models.rs`, `src/steam_client.rs`, `src/ui.rs`, `vendor/steam-cdn/examples/download_manifest.rs`, `manifest/file.rs`, `mod.rs`. | new functionality |
| 18 | fbe906a | 2026-08-05 | #72 | `vendor/steam-cdn/src/cdn/manifest/file.rs`. | bug fix |
| 19 | a3af687 | 2026-08-05 | #73 | `vendor/steam-cdn/src/cdn/manifest/file.rs`. | bug fix |
| 20 | e77ad16 | 2026-08-05 | #76 | `src/models.rs`, `src/steam_client.rs`, `src/ui.rs`, `vendor/steam-cdn/src/cdn/manifest/file.rs`, `mod.rs`. | new functionality |
| 21 | 983b921 | 2026-08-05 | #76 | `src/depot_browser.rs`, `src/models.rs`, `src/steam_client.rs`, `src/ui.rs`, `vendor/steam-cdn/src/lib.rs`. | new functionality |
| 22 | cab5ed9 | 2026-08-05 | #76 | `src/steam_client.rs`, `src/ui.rs`, `vendor/steam-cdn/src/cdn/manifest/file.rs`, `mod.rs`. | bug fix |
| 23 | 3429171 | 2026-08-05 | #77 | `src/infra/runners/wine_tkg.rs`, `src/models.rs`, `src/steam_client.rs`, `src/ui.rs`, `vendor/steam-cdn/src/cdn/mod.rs`. | new functionality |
| 24 | accf92a | 2026-08-06 | #80 | `vendor/steam-cdn/Cargo.lock`, `src/cdn/depot.rs`, `inner.rs`. | bug fix |
| 25 | d69501e | 2026-08-06 | #80 | `vendor/steam-cdn/src/cdn/depot.rs`. | bug fix |
| 26 | 579293e | 2026-08-11 | #82 | `Cargo.lock`, `docs/...`, `src/*`, `vendor/steam-cdn/Cargo.toml`, `src/cdn/depot_chunk/mod.rs`, `utils/mod.rs`, `utils/zstd.rs`. | new functionality |
| 27 | 7eaa018 | 2026-09-25 | #93 | `Cargo.lock`, `Cargo.toml`, `vendor/steam-cdn/Cargo.lock`, `Cargo.toml`. | dependency vendoring |
| 28 | 59715fa | 2026-09-25 | #93 | `src/cloud_sync.rs`, `src/depot_browser.rs`, `src/headless.rs`, `src/steam_client.rs`, `vendor/steam-cdn/src/cdn/inner.rs`, `manifest/mod.rs`, `mod.rs`. | adaptation |
| 29 | 290c5ab | 2026-09-29 | #93 | `Cargo.lock`, `Cargo.toml`, `vendor/steam-cdn/Cargo.lock`, `Cargo.toml`, plus the steam-vent re-vendor. | dependency vendoring |

## 3. Final Summary

The original crates.io `steam-cdn` 1.0.0 tarball could not be retrieved (no cargo registry cache present, no `.cargo_vcs_info.json`), so a `diff -ru` against the original could not be run. Substantive changes evident from the commit history:

- Vendored and patched for `steam-vent` 0.4 compatibility (commit 0542112).
- Added `CDNClient::download_depot`, `CDNAuthToken` handshake, and `ContentServerDirectory` service (PR #8, #9).
- Manifest parsing hardened (custom header offsets, exact segment sizes, robust fallbacks) (PR #9).
- Download pipeline unified with Verify Mode, Pause/Resume, smart updates (PR #12, #13).
- August: hash-check before resume-skip, chmod u+w before write, progress-bar/pause/cancel fixes, zstd utility added (PR #72, #73, #76, #77, #80).
- September: split steam protocol crates, re-vendor against steam-vent 0.6.0 (PR #93).

## 4. Unknowns

- Exact upstream repository URL and source revision: not recorded; verify via crates.io metadata or `cargo search steam-cdn`.
- Original tarball unavailable for a full `diff -ru`: fetch `steam-cdn 1.0.0` from the cargo registry or crates.io and compare.
- Per-commit PR mapping verified via the GitHub API for all 29 commits.

## Report

- Commits in list: 29.
- PRs referenced: 12 distinct (PR #8, #9, #10, #12, #13, #72, #73, #76, #77, #80, #82, #93).
- Original source: crates.io, `steam-cdn` 1.0.0 (repository URL not recorded).
- Verified: 29 out of 29 commits mapped to PRs via API; 29 out of 29 present in `git log`.
