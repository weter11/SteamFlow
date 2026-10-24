# Steam-CDN Changes (`vendor/steam-cdn`)

## 1. Origin / source

- Crate `steam-cdn` (lib name `steam_cdn`), version `1.0.0`, license Apache-2.0, description "Steam CDN".
- Artifact: `https://static.crates.io/crates/steam-cdn/steam-cdn-1.0.0.crate`, 34,512 bytes,
  SHA-256 `48a8311e77f9cae1aca69e296450608f9cb389279c183fd833d8a32c6ce71eca`. This hash is identical to the
  checksum crates.io records for 1.0.0, so the artifact is the published release.
- `.cargo_vcs_info.json` inside the `.crate` records the source revision:
  `git sha1 5506382590450a77e11c77026aa03cbd7a74cd3d`, `path_in_vcs` empty.
- crates.io metadata: default and maximum version 1.0.0, two published versions, crate created 2024-08-23,
  1.0.0 published 2025-01-12; `repository`, `homepage` and `documentation` are all null.
- `Cargo.toml.orig` (in the `.crate` and in the vendored tree) records no `repository` and no `authors`.
- Vendored in commit `0542112` (2026-02-16) as part of PR #8. The vendoring copied the crate contents but
  dropped `.cargo_vcs_info.json` and `.gitignore`, which is why the vendored tree on its own does not
  identify its source revision.
- Provenance is established from the `.crate` artifact, its SHA-256 and `Cargo.toml.orig`. The vendored
  `Cargo.lock` is not evidence of origin: its `source = "registry+https://github.com/rust-lang/crates.io-index"`
  lines describe the crate's dependencies, and a hand-vendored crate has no source entry there.

## 2. Complete commit history (29 commits)

`git log --reverse -- vendor/steam-cdn` and the same command with `--follow` both return 29 commits;
no path move is involved, so `--follow` changes nothing. Dates are author dates.

| # | SHA | Author date | PR | Change | Type | Paths (repo-relative) |
|---|-----|-------------|----|--------|------|-----------------------|
| 1 | 0542112 | 2026-02-16 | #8 | Switch to steam-cdn for hybrid download logic | dependency vendoring | `vendor/steam-cdn/Cargo.lock`, `vendor/steam-cdn/Cargo.toml`, `vendor/steam-cdn/Cargo.toml.orig`, `vendor/steam-cdn/LICENSE`, `vendor/steam-cdn/README.md`, `vendor/steam-cdn/examples/download_manifest.rs`, `vendor/steam-cdn/src/cdn/depot.rs`, `vendor/steam-cdn/src/cdn/depot_chunk/mod.rs`, `vendor/steam-cdn/src/cdn/inner.rs`, `vendor/steam-cdn/src/cdn/manifest/buf.rs`, `vendor/steam-cdn/src/cdn/manifest/error.rs`, `vendor/steam-cdn/src/cdn/manifest/file.rs`, `vendor/steam-cdn/src/cdn/manifest/mod.rs`, `vendor/steam-cdn/src/cdn/mod.rs`, `vendor/steam-cdn/src/crypto/aes256.rs`, `vendor/steam-cdn/src/crypto/mod.rs`, `vendor/steam-cdn/src/error.rs`, `vendor/steam-cdn/src/lib.rs`, `vendor/steam-cdn/src/utils/base64.rs`, `vendor/steam-cdn/src/utils/lzma.rs`, `vendor/steam-cdn/src/utils/mod.rs`, `vendor/steam-cdn/src/web_api/content_service.rs`, `vendor/steam-cdn/src/web_api/mod.rs`; `Cargo.lock`, `Cargo.toml`, `src/steam_client.rs` |
| 2 | ee556fa | 2026-02-16 | #8 | Fix CDN server resolution via Web API and improve steam-cdn integration | bug fix | `vendor/steam-cdn/src/cdn/manifest/file.rs`, `vendor/steam-cdn/src/cdn/mod.rs`; `src/download_pipeline.rs`, `src/lib.rs`, `src/steam_api.rs` (+1 more) |
| 3 | d2fc329 | 2026-02-16 | #8 | Fix CDN server resolution and implement hybrid download pipeline | bug fix | `vendor/steam-cdn/src/cdn/mod.rs`; `src/steam_api.rs`, `src/steam_client.rs` |
| 4 | 6c18776 | 2026-02-17 | #8 | Revert experimental CDN changes and stabilize baseline | revert | `vendor/steam-cdn/src/cdn/inner.rs`, `vendor/steam-cdn/src/cdn/manifest/file.rs`, `vendor/steam-cdn/src/cdn/mod.rs`; `src/lib.rs`, `src/steam_api.rs`, `src/steam_client.rs` |
| 5 | 9a12690 | 2026-02-17 | #9 | Implement ContentServerDirectory service and CDN auth tokens | new functionality | `vendor/steam-cdn/src/cdn/inner.rs`, `vendor/steam-cdn/src/cdn/mod.rs`, `vendor/steam-cdn/src/lib.rs`, `vendor/steam-cdn/src/web_api/content_service.rs`; `src/steam_client.rs` |
| 6 | 896bd29 | 2026-02-17 | #9 | Complete ContentServerDirectory implementation and CDN authorization | new functionality | `vendor/steam-cdn/src/cdn/inner.rs`, `vendor/steam-cdn/src/cdn/mod.rs`; `src/steam_client.rs` |
| 7 | dfe20bb | 2026-02-17 | #9 | Improve CDN authentication with headers and logging | diagnostics | `vendor/steam-cdn/src/cdn/inner.rs` |
| 8 | a2aaba0 | 2026-02-17 | #9 | Fix Steam Manifest decoding and improve CDN authorization | bug fix | `vendor/steam-cdn/src/cdn/inner.rs`, `vendor/steam-cdn/src/cdn/manifest/mod.rs`; `Cargo.lock`, `Cargo.toml`, `src/download_pipeline.rs` |
| 9 | 4657f68 | 2026-02-17 | #9 | Add deep manifest inspection and diagnostic logging | diagnostics | `vendor/steam-cdn/src/cdn/manifest/mod.rs`; `src/download_pipeline.rs` |
| 10 | a038f5d | 2026-02-17 | #9 | Fix manifest parsing with custom header offsets and robust metadata fallbacks | bug fix | `vendor/steam-cdn/src/cdn/manifest/mod.rs`, `vendor/steam-cdn/src/cdn/mod.rs`; `src/download_pipeline.rs` |
| 11 | c8fb06c | 2026-02-17 | #9 | Fix manifest parsing using exact segment sizes and robust segment parsing | bug fix | `vendor/steam-cdn/src/cdn/manifest/mod.rs`; `src/download_pipeline.rs` |
| 12 | a957d69 | 2026-02-17 | #9 | Perform project cleanup and update documentation for release | cleanup | `vendor/steam-cdn/src/cdn/inner.rs`, `vendor/steam-cdn/src/cdn/manifest/mod.rs`; `COMPARISON.md`, `OpenSteamClient/.vscode/extensions.json`, `OpenSteamClient/.vscode/launch.json` (+39 more) |
| 13 | ede3c94 | 2026-02-17 | #10 | Refactor for portability, fix metadata resolution, and implement shared-state progress bar | adaptation | `vendor/steam-cdn/src/cdn/manifest/file.rs`, `vendor/steam-cdn/src/cdn/mod.rs`; `src/config.rs`, `src/depot_browser.rs`, `src/download_pipeline.rs` (+5 more) |
| 14 | cf9dacf | 2026-02-17 | #10 | Implement robust lazy-fetching for metadata and images, and update zip crate | adaptation | `vendor/steam-cdn/Cargo.toml`; `Cargo.toml`, `ROADMAP.md`, `TODO.md` (+2 more) |
| 15 | f876dab | 2026-02-17 | #12 | Update logo, assets, and unify download pipeline with smart updates | new functionality | `vendor/steam-cdn/Cargo.toml`, `vendor/steam-cdn/src/cdn/manifest/file.rs`, `vendor/steam-cdn/src/cdn/mod.rs`; `Cargo.lock`, `src/depot_browser.rs`, `src/download_pipeline.rs` (+4 more) |
| 16 | 7ee8e9a | 2026-02-18 | #13 | Unify download pipeline and implement Verify Mode | new functionality | `vendor/steam-cdn/Cargo.toml`, `vendor/steam-cdn/examples/download_manifest.rs`, `vendor/steam-cdn/src/cdn/manifest/file.rs`, `vendor/steam-cdn/src/cdn/mod.rs`; `Cargo.lock`, `README.md`, `src/install.rs` (+2 more) |
| 17 | cb57329 | 2026-02-18 | #13 | Implement Pause/Resume and Unified Download Pipeline | new functionality | `vendor/steam-cdn/examples/download_manifest.rs`, `vendor/steam-cdn/src/cdn/manifest/file.rs`, `vendor/steam-cdn/src/cdn/mod.rs`; `src/depot_browser.rs`, `src/models.rs`, `src/steam_client.rs` (+1 more) |
| 18 | fbe906a | 2026-08-05 | #72 | fix(steam-cdn): chmod u+w before opening target for write | bug fix | `vendor/steam-cdn/src/cdn/manifest/file.rs` |
| 19 | a3af687 | 2026-08-05 | #73 | fix(steam-cdn): hash-check chunks before resume-skip in all modes | bug fix | `vendor/steam-cdn/src/cdn/manifest/file.rs` |
| 20 | e77ad16 | 2026-08-05 | #76 | Thread operation controller through downloads | new functionality | `vendor/steam-cdn/src/cdn/manifest/file.rs`, `vendor/steam-cdn/src/cdn/mod.rs`; `src/models.rs`, `src/steam_client.rs`, `src/ui.rs` |
| 21 | 983b921 | 2026-08-05 | #76 | Polish lifecycle and operation controls | new functionality | `vendor/steam-cdn/src/lib.rs`; `src/depot_browser.rs`, `src/models.rs`, `src/steam_client.rs` (+1 more) |
| 22 | cab5ed9 | 2026-08-05 | #76 | fix(ui,steam-cdn): progress bar, pause/cancel visibility, case-insensitive verify paths | bug fix | `vendor/steam-cdn/src/cdn/manifest/file.rs`, `vendor/steam-cdn/src/cdn/mod.rs`; `src/steam_client.rs`, `src/ui.rs` |
| 23 | 3429171 | 2026-08-05 | #77 | feat(ui): file-level progress, header wrap, settings cleanup, cover-art retry | new functionality | `vendor/steam-cdn/src/cdn/mod.rs`; `src/infra/runners/wine_tkg.rs`, `src/models.rs`, `src/steam_client.rs` (+1 more) |
| 24 | accf92a | 2026-08-06 | #80 | Fix steam-cdn compiler warnings | bug fix | `vendor/steam-cdn/Cargo.lock`, `vendor/steam-cdn/src/cdn/depot.rs`, `vendor/steam-cdn/src/cdn/inner.rs` |
| 25 | d69501e | 2026-08-06 | #80 | Correct VDF parser migration | bug fix | `vendor/steam-cdn/src/cdn/depot.rs` |
| 26 | 579293e | 2026-08-11 | #82 | feat(valve-stack): Phase 2 complete — native Rust Proton ABI, env-parity harness, VERSIONS.txt … | new functionality | `vendor/steam-cdn/Cargo.toml`, `vendor/steam-cdn/src/cdn/depot_chunk/mod.rs`, `vendor/steam-cdn/src/utils/mod.rs`, `vendor/steam-cdn/src/utils/zstd.rs`; `Cargo.lock`, `docs/architecture/valve-stack-replication.md`, `src/headless.rs` (+12 more) |
| 27 | 7eaa018 | 2026-09-25 | #93 † | build(deps): pin steam-vent git revision | dependency vendoring | `vendor/steam-cdn/Cargo.lock`, `vendor/steam-cdn/Cargo.toml`; `Cargo.lock`, `Cargo.toml` |
| 28 | 59715fa | 2026-09-25 | #93 † | refactor(deps): use split steam protocol crates | adaptation | `vendor/steam-cdn/src/cdn/inner.rs`, `vendor/steam-cdn/src/cdn/manifest/mod.rs`, `vendor/steam-cdn/src/cdn/mod.rs`; `src/cloud_sync.rs`, `src/depot_browser.rs`, `src/headless.rs` (+1 more) |
| 29 | 290c5ab | 2026-09-25 | #93 † | build(deps): vendor steam-vent to avoid unreachable PR ref | dependency vendoring | `vendor/steam-cdn/Cargo.lock`, `vendor/steam-cdn/Cargo.toml`; `Cargo.lock`, `Cargo.toml`, `tests/steam_vent_git_pin.rs` (+58 more) |

† PR #93 (`74c889a4`, 2026-09-29) was rebase-merged, so these three commits have no merge commit and cannot be
attributed by ancestry; their PR comes from `GET /repos/weter11/SteamFlow/commits/{sha}/pulls`.

## 3. Initial patch: 1.0.0 → `0542112`

`diff -u` of the published crate against the tree at `0542112`: 6 files, +117 / −6 — `Cargo.toml`
(steam-vent 0.3 → 0.4), `src/cdn/mod.rs` (+55/−2: `CDNClient::new(app_ticket)` and
`CDNClient::download_depot(app_id, …)`), `src/cdn/inner.rs` (+48/−2: `remote_cmd_with_auth`,
`GetCDNAuthToken` request, `x-steam-auth` header, `app_ticket` field, `get_chunk` app_id),
`src/cdn/manifest/error.rs` (+7: `From<TryGetError>`), `src/cdn/manifest/file.rs` (+2/−1: app_id passed to
`get_chunk`), `src/cdn/manifest/mod.rs` (+4: app_id field). The full patch is in the appendix.

## 4. Current tree vs 1.0.0 (`main` @ `488170b1`, 2026-10-22)

`diff -ru` of the published crate against `vendor/steam-cdn` as of `main`: 14 paths change — 13 modified,
1 added (`vendor/steam-cdn/src/utils/zstd.rs`, new, 62 lines), none removed; +2037 / −1098 lines in total,
of which `Cargo.lock` accounts for +1420 / −1010, leaving +617 / −88 in code and manifests.

| Path | Added | Removed |
|------|-------|---------|
| `vendor/steam-cdn/Cargo.lock` | +1420 | −1010 |
| `vendor/steam-cdn/Cargo.toml` | +17 | −2 |
| `vendor/steam-cdn/examples/download_manifest.rs` | +5 | −9 |
| `vendor/steam-cdn/src/cdn/depot.rs` | +1 | −1 |
| `vendor/steam-cdn/src/cdn/depot_chunk/mod.rs` | +3 | −1 |
| `vendor/steam-cdn/src/cdn/inner.rs` | +31 | −12 |
| `vendor/steam-cdn/src/cdn/manifest/error.rs` | +7 | −0 |
| `vendor/steam-cdn/src/cdn/manifest/file.rs` | +226 | −9 |
| `vendor/steam-cdn/src/cdn/manifest/mod.rs` | +77 | −41 |
| `vendor/steam-cdn/src/cdn/mod.rs` | +182 | −10 |
| `vendor/steam-cdn/src/lib.rs` | +2 | −2 |
| `vendor/steam-cdn/src/utils/mod.rs` | +1 | −0 |
| `vendor/steam-cdn/src/web_api/content_service.rs` | +3 | −1 |
| `vendor/steam-cdn/src/utils/zstd.rs` | +62 (new file) | — |

Significant changes:

- API. `CDNClient::new(connection)`, `CDNClient::with_server` / `with_servers`, `download_depot(app_id, depot_id,
  manifest_gid, key, target_dir)`, `ManifestFile::download(depot_key, target_path, verify_mode, on_progress,
  controller, …)`, and `OperationController` with `pause` / `resume` / `cancel` / `is_paused` / `is_cancelled`.
  `web_api` is now a public module, `lib.rs` re-exports `OperationController`, and `ManifestError` gains
  `From<TryGetError>`.
- Dependencies. `steam-vent` 0.3 → path `../steam-vent` (the vendored 0.6.0 plus PR #19), split into
  `steam-vent-proto-common` 0.5.1 and `steam-vent-proto-steam` 0.5.2; added `sha1` 0.10, `tracing` 0.1,
  `zstd` 0.13; `zip` 2.2 → 2.2.2.
- Behaviour. Downloads are pausable and cancellable, verify mode runs a per-chunk deep check, resume compares
  the length of an existing file, tool-replaced read-only targets are handled, on-disk casing is resolved before
  verification, and chunk decoding covers zip, LZMA (`VZa`) and Zstd (`VSZa`, new `utils/zstd.rs`, added in PR #82 / 579293e).
- Examples. `examples/download_manifest.rs` follows the new `get_manifest(app_id, …)` and
  `download(depot_key, target_path, verify_mode, …)` signatures.

Line endings: the `.crate` ships CRLF in `Cargo.toml.orig` and `LICENSE`, while the vendored tree is LF. Both
sides were normalised to LF (`sed 's/\r$//'`) before diffing, so line-ending-only differences are excluded, and
`.cargo_vcs_info.json` / `.gitignore` are excluded because the vendoring dropped them.

## 5. Unknowns

- Repository URL and project home of `steam-cdn`: not recorded (crates.io metadata null, no `repository` or
  `authors` field, no URL in `LICENSE`, `README.md` or `THIRD-PARTY-NOTICES.md`). The source revision itself is
  known: git `5506382590450a77e11c77026aa03cbd7a74cd3d`.

## Report

- Commits in list: 29; PRs referenced: 12 (PR #8, #9, #10, #12, #13, #72, #73, #76, #77, #80, #82, #93).
- Source: crates.io, `steam-cdn` 1.0.0, SHA-256 `48a8311e…ce71eca`, git `5506382590450a77e11c77026aa03cbd7a74cd3d`.
- Initial patch: 6 files, +117 / −6. Current tree: 14 paths, +2037 / −1098.
- Verified: 29 of 29 commits present and tabulated; 29 of 29 PR
  attributions correct (26 by merge ancestry, 3 via the commits/pulls API for the rebase-merged PR #93); 12 of 12
  cited PRs merged.

## Appendix: initial patch (diff -ru, 1.0.0 → `0542112`)

```diff
diff -ru a/Cargo.toml b/Cargo.toml
--- a/Cargo.toml
+++ b/Cargo.toml
@@ -74,7 +74,7 @@
 features = ["derive"]
 
 [dependencies.steam-vent]
-version = "0.3"
+version = "0.4"
 
 [dependencies.thiserror]
 version = "2.0"
diff -ru a/src/cdn/inner.rs b/src/cdn/inner.rs
--- a/src/cdn/inner.rs
+++ b/src/cdn/inner.rs
@@ -18,6 +18,7 @@
     pub connection: Arc<Connection>,
     web_client: Client,
     pub servers: Vec<CDNServer>,
+    pub app_ticket: Option<Vec<u8>>,
 }
 
 impl InnerClient {
@@ -26,6 +27,7 @@
             connection,
             web_client: Client::new(),
             servers: Vec::new(),
+            app_ticket: None,
         }
     }
 
@@ -85,6 +87,18 @@
         args: A,
         manifest_request_code: Option<u64>,
     ) -> Result<Response, Error> {
+        self.remote_cmd_with_auth(command, args, manifest_request_code, None, None)
+            .await
+    }
+
+    pub async fn remote_cmd_with_auth<C: AsRef<str>, A: AsRef<str>>(
+        &self,
+        command: C,
+        args: A,
+        manifest_request_code: Option<u64>,
+        app_id: Option<u32>,
+        depot_id: Option<u32>,
+    ) -> Result<Response, Error> {
         let server = self.get_server()?;
         let mut url = format!(
             "{}://{}:{}/{}/{}",
@@ -98,17 +112,49 @@
             url.push('/');
             url.push_str(manifest_request_code.to_string().as_str());
         }
-        Ok(self.web_client.get(url).send().await?)
+
+        let mut request = self.web_client.get(url);
+
+        if let (Some(app_id), Some(depot_id)) = (app_id, depot_id) {
+            use steam_vent::proto::steammessages_contentsystem_steamclient::{
+                CContentServerDirectory_GetCDNAuthToken_Request,
+                CContentServerDirectory_GetCDNAuthToken_Response,
+            };
+
+            let mut auth_req = CContentServerDirectory_GetCDNAuthToken_Request::new();
+            auth_req.set_app_id(app_id);
+            auth_req.set_depot_id(depot_id);
+            auth_req.set_host_name(server.host.clone());
+            // if let Some(ticket) = &self.app_ticket {
+            //     auth_req.set_app_ticket(ticket.clone());
+            // }
+
+            let response: CContentServerDirectory_GetCDNAuthToken_Response =
+                self.connection.service_method(auth_req).await?;
+
+            if let Some(token) = response.token {
+                request = request.header("x-steam-auth", token);
+            }
+        }
+
+        Ok(request.send().await?)
     }
 
     pub async fn get_chunk(
         &self,
+        app_id: u32,
         depot_id: u32,
         depot_key: [u8; 32],
         chunk_id: String,
     ) -> Result<Vec<u8>, Error> {
         let response = self
-            .remote_cmd("depot", format!("{depot_id}/chunk/{chunk_id}"), None)
+            .remote_cmd_with_auth(
+                "depot",
+                format!("{depot_id}/chunk/{chunk_id}"),
+                None,
+                Some(app_id),
+                Some(depot_id),
+            )
             .await?;
         if !response.status().is_success() {
             return Err(Error::HttpStatus(response.status()));
diff -ru a/src/cdn/manifest/error.rs b/src/cdn/manifest/error.rs
--- a/src/cdn/manifest/error.rs
+++ b/src/cdn/manifest/error.rs
@@ -1,4 +1,5 @@
 use aes::cipher::block_padding;
+use bytes::TryGetError;
 use std::{io, str};
 use zip::result::ZipError;
 
@@ -40,6 +41,12 @@
     }
 }
 
+impl From<TryGetError> for ManifestError {
+    fn from(err: TryGetError) -> Self {
+        Self::Eof(err.to_string())
+    }
+}
+
 impl From<block_padding::UnpadError> for ManifestError {
     fn from(err: block_padding::UnpadError) -> Self {
         Self::DecryptFilename(err.to_string())
diff -ru a/src/cdn/manifest/file.rs b/src/cdn/manifest/file.rs
--- a/src/cdn/manifest/file.rs
+++ b/src/cdn/manifest/file.rs
@@ -46,6 +46,7 @@
 #[derive(Debug)]
 pub struct ManifestFile {
     pub(super) inner: Arc<InnerClient>,
+    pub(super) app_id: u32,
     pub(super) depot_id: u32,
     pub(super) filename: String,
     pub(super) size: u64,
@@ -122,7 +123,7 @@
                     let permit = semaphore_owned.acquire_owned().await?;
                     let result = self
                         .inner
-                        .get_chunk(self.depot_id, depot_key, chunk_data.id())
+                        .get_chunk(self.app_id, self.depot_id, depot_key, chunk_data.id())
                         .await;
                     drop(permit);
                     result
diff -ru a/src/cdn/manifest/mod.rs b/src/cdn/manifest/mod.rs
--- a/src/cdn/manifest/mod.rs
+++ b/src/cdn/manifest/mod.rs
@@ -27,6 +27,7 @@
 
 #[derive(Debug)]
 pub struct DepotManifest {
+    app_id: u32,
     depot_id: u32,
     manifest_gid: u64,
     creatime_time: u32,
@@ -82,6 +83,7 @@
 
     pub(crate) fn deserialize(
         client: Arc<InnerClient>,
+        app_id: u32,
         data: &[u8],
     ) -> Result<Self, ManifestError> {
         let cursor = Cursor::new(data);
@@ -122,6 +124,7 @@
         }
 
         Ok(Self {
+            app_id,
             depot_id: metadata.depot_id(),
             manifest_gid: metadata.gid_manifest(),
             creatime_time: metadata.creation_time(),
@@ -133,6 +136,7 @@
                 .into_iter()
                 .map(|map| ManifestFile {
                     inner: client.clone(),
+                    app_id,
                     depot_id: metadata.depot_id(),
                     filename: map.filename().to_string(),
                     size: map.size(),
diff -ru a/src/cdn/mod.rs b/src/cdn/mod.rs
--- a/src/cdn/mod.rs
+++ b/src/cdn/mod.rs
@@ -27,6 +27,19 @@
 }
 
 impl CDNClient {
+    pub fn new(
+        _steam_id: u64,
+        _cell_id: u32,
+        connection: Arc<Connection>,
+        app_ticket: Option<Vec<u8>>,
+    ) -> Self {
+        let mut inner = InnerClient::new(connection);
+        inner.app_ticket = app_ticket;
+        Self {
+            inner: Arc::new(inner),
+        }
+    }
+
     pub async fn discover(connection: Arc<Connection>) -> Result<Self, Error> {
         let mut inner = InnerClient::new(connection);
         inner.servers =
@@ -101,8 +114,45 @@
             ))
     }
 
+    pub async fn download_depot(
+        &self,
+        app_id: u32,
+        depot_id: u32,
+        manifest_id: u64,
+        depot_key: &[u8],
+        target_dir: impl AsRef<std::path::Path>,
+    ) -> Result<(), Error> {
+        let request_code = self
+            .get_manifest_request_code(app_id, depot_id, manifest_id)
+            .await
+            .ok();
+
+        let mut key_arr = [0u8; 32];
+        key_arr.copy_from_slice(&depot_key[..32]);
+
+        let manifest = self
+            .get_manifest(app_id, depot_id, manifest_id, request_code, Some(key_arr))
+            .await?;
+
+        for file in manifest.files() {
+            let full_path = target_dir.as_ref().join(file.full_path());
+            if let Some(parent) = full_path.parent() {
+                std::fs::create_dir_all(parent).map_err(|e| Error::Unexpected(e.to_string()))?;
+            }
+
+            if file.size() > 0 {
+                let mut out = tokio::fs::File::create(&full_path)
+                    .await
+                    .map_err(|e| Error::Unexpected(e.to_string()))?;
+                file.download(key_arr, &mut out, None).await?;
+            }
+        }
+        Ok(())
+    }
+
     pub async fn get_manifest(
         &self,
+        app_id: u32,
         depot_id: u32,
         manifest_id: u64,
         request_code: Option<u64>,
@@ -110,16 +160,19 @@
     ) -> Result<DepotManifest, Error> {
         let bytes = self
             .inner
-            .remote_cmd(
+            .remote_cmd_with_auth(
                 "depot",
                 format!("{depot_id}/manifest/{manifest_id}/{MANIFEST_VERSION}"),
                 request_code,
+                Some(app_id),
+                Some(depot_id),
             )
             .await?
             .bytes()
             .await?;
 
-        let mut manifest = DepotManifest::deserialize(self.inner.clone(), &bytes[..])?;
+        let mut manifest =
+            DepotManifest::deserialize(self.inner.clone(), app_id, &bytes[..])?;
         if manifest.filenames_encrypted() {
             if let Some(key) = depot_key {
                 manifest.decrypt_filenames(key)?;
```
