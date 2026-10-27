# Aurelia CDN/download layer: comparison with SteamFlow

Read-only comparison of the CDN and depot-download code in SteamFlow's `vendor/steam-cdn` (and the
SteamFlow wrapper that drives it) with the equivalent layer in Aurelia. No code was copied, built or
run; every statement below comes from reading the two trees at the commits named here.

## Sources

- SteamFlow: `https://github.com/weter11/SteamFlow`, commit `488170b` (2026-10-22), the same tree the
  history documents describe. Paths: `vendor/steam-cdn/`, `src/steam_client.rs`,
  `src/steam_client/…`.
- Aurelia: `https://github.com/Drackrath/Aurelia`, commit `78b7085` (2026-10-22), clone analysed at
  `/data/user/0/com.hermesagent.android/files/home/Aurelia` (`origin/main`). Its CDN paths are
  unchanged from `11dd427`; the three commits between those tips (`1f7a279`, `947ffe9`, `78b7085`)
  touch `src/steam_client.rs`, `src/steam_client/launch.rs`, `src/steam_client/process.rs` and a test
  file only.
- Aurelia licence file: `LICENSE`. It states that commits up to `065782b` are MIT, that commits up to
  `94e513e` derive from SteamFlow (up to SteamFlow `c0222b7`), and that later commits are under the
  GNU GPL v3 text that follows. `Cargo.toml` declares `license = "GPL 3.0"`. The vendored
  `vendor/steam-cdn/LICENSE` in Aurelia is still the Apache License 2.0 of the upstream crate.
  SteamFlow is MIT (`LICENSE`, `Cargo.toml`).

Because Aurelia records derivation from SteamFlow up to `c0222b7`, parts of the two trees share
lineage. Similar shapes below are therefore partly inherited, not independently designed.

## Comparison table

Line numbers are from the two commits above. "code" means read directly from the source; "inferred"
means the statement depends on an argument from absence or on behaviour not exercised.

| Feature | SteamFlow `488170b` | Aurelia `78b7085` | In | Difference | Confidence |
|---|---|---|---|---|---|
| Content-server discovery | `src/steam_client.rs::get_content_servers` (2863), inside `with_healthy_connection` | `src/steam_client/content.rs::get_content_servers` (8), direct call | Both | Same request: `GetServersForSteamPipe`, `max_servers = 20`, filtered to `SteamCache`/`CDN`. Neither orders by `load`/`weighted_load`; Aurelia has no reconnect wrapper. | code |
| CDN client per host | `src/steam_client.rs` 2585–2634: host loop; re-lease at 2606, `CDNServer` at 2613, `CDNClient::with_server` at 2625 | `src/steam_client/install.rs` 601–615: build `CDNServer` from the stored connection, `CDNClient::with_server` | Both | Same struct fields (`https` from port 443, host/vhost, cell id, auth token). SteamFlow re-leases a connection per host; Aurelia reuses the daemon-held one. | code |
| CDN auth token | `src/steam_client.rs::get_cdn_auth_token` (2913): `CMsgClientGetCDNAuthToken` job; empty token is an error | `src/steam_client/content.rs::get_cdn_auth_token` (65): `CContentServerDirectory_GetCDNAuthToken` service call; empty token is an error | Both | Different RPC. SteamFlow's comment (2926–2929) says the service variant fails server-side and the real client uses the job. Both callers warn on failure and continue without a token. | code |
| Depot key | `src/steam_client.rs::get_depot_key` (3047), `CMsgClientGetDepotDecryptionKey`, wrapped for one transport retry | `src/steam_client/content.rs::get_depot_key` (425), same job, direct | Both | Same message and `eresult` check; SteamFlow retries once after a transport failure, Aurelia does not. | code |
| Manifest request code | `src/steam_client.rs::get_manifest_request_code` (2891), returns the code as-is | `src/steam_client/content.rs::get_manifest_request_code` (33), warns when the code is 0 | Both | Aurelia logs the 0 case; SteamFlow returns it silently. Both pass it to the manifest fetch. | code |
| Manifest fetch and parse | crate `get_manifest`; `manifest/mod.rs` 89–140: zip sniffing (`PK`), magic-wrapped protobuf, raw fallback | same sniffing and fallback in `manifest/mod.rs` 99–145 | Both | Aurelia's `decrypt_filenames` also decrypts a non-empty `linktarget` with AES (77–79); SteamFlow decrypts filenames only and keeps `linktarget` raw (`decrypt_filenames` 66–78). | code |
| Chunk fetch | `inner.rs::get_chunk` via `remote_cmd_with_auth`: `?token=` plus `x-cdn-auth-token` header | same, with the same token query and header (`inner.rs`) | Both | SteamFlow passes `app_id` into `get_chunk`; Aurelia does too. No retry inside either fetch. | code |
| Decrypt | `crypto/aes256.rs::decrypt_cbc_with_iv_extraction` (AES-256-CBC, PKCS7, IV from the first block) | same function | Both | Identical algorithm and API. | code |
| Decompress | `depot_chunk::decrypt_and_decompress` → zip / `VZa` LZMA (CRC32 of decompressed data, `utils/lzma.rs` 74–75) / `VSZa` zstd (`utils/zstd.rs`, header-footer CRC32, decoded CRC32 and size, 43–59) | zip / `VZa` LZMA with the same CRC32 check / `VSZ` zstd in `utils/lzma.rs::decompress_vsz` (35) via `ruzstd`, checking only the magic and footer | Both | SteamFlow verifies CRC32 and size on zstd chunks. Aurelia's VSZ path reads the frame but does not verify the header CRC32, footer CRC32 or size. | code |
| Chunk integrity vs manifest | `manifest/file.rs` 214–243 hashes existing on-disk bytes before a skip; fetched bytes are written at 276–283 with no hash | `manifest/file.rs` 200–225 hashes existing on-disk bytes; fetched bytes written at 245–260 with no hash; `download_to_memory` (126–140) returns fetched bytes unhashed | Both | Neither compares a downloaded chunk with `chunk_data.sha` (issue #96). Aurelia's zstd path additionally skips the container CRC, so a corrupted fetched VSZ chunk has no check at all. | code |
| Resume/skip policy | skip only on SHA-1 match; `verify_mode` reaches the log line only | skip only on SHA-1 match; `verify_mode` explicitly unused (`let _ = (verify_mode, current_len_before)`) | Both | Same behaviour after SteamFlow PR #73; Aurelia reaches it with an unused parameter. | code |
| Verify/repair | `verify_game` (3659) → `start_manifest_download(appid, true, …)` (3668) re-uses local manifest ids and hashes installed chunks | `verify_game` (launch.rs 432) → `start_manifest_download(appid, true, …)` | Both | Same design: verify is a download pass over the installed manifests that skips matching chunks. | code |
| Retry/backoff at CDN level | none per chunk or per host; hosts tried once each; CM calls get one reconnect retry via `with_healthy_connection` (1685) | none per chunk or per host; hosts tried once each; no CM reconnect wrapper; daemon session restore has a 30 s backoff (`daemon/mod.rs` 116) unrelated to CDN | Both | Neither retries a failed chunk or waits between host attempts. SteamFlow's retry is at the CM job layer, not the CDN HTTP layer. | code |
| Host fallback and depot failure | per-host error logged, next host tried; after the last host the depot fails and the run stops (`src/steam_client.rs` 2730–2760) | same loop shape, `bail!("Failed to download depot … from all available servers")` (`install.rs` 681–686); a failed depot ends the loop | Both | Equivalent. Neither distinguishes auth failure, 404 and timeout when deciding the next step. | code |
| Cancellation and pause | `OperationController` (pause/resume/cancel) plus `abort_signal`, exposed in the UI | `abort_signal` only (`install.rs` 642–645, `file.rs` 178–184) | SteamFlow only | Aurelia can abort a download but not pause and resume it. | code |
| Progress reporting | aggregate `on_progress(done,total)`, `on_manifest(total)` and per-file `on_file_progress(path,done,total)` | aggregate `on_progress(bytes)`, `on_manifest(total)`; CLI adds speed and ETA (`commands/common.rs`) | SteamFlow only (per-file) | Aurelia reports depot-level bytes only; SteamFlow carries the active file path and offsets into the UI. | code |
| Parallelism / rate limiting | `Semaphore` in `ManifestFile::download`, `max_tasks` default 4, `download_depot` passes `None` | same semaphore, same default, `None` passed | Both | Fixed 4 concurrent chunk requests in both; no rate limit, no configurable task count through the public API. | code |
| Depot delta / patching | no binary delta; resume is chunk-level hash skip | no binary delta; resume is chunk-level hash skip; manifest pinning exists for `downgrade` (`install.rs` `InstallOptions::manifest_overrides`) | Both | Neither implements Steam's delta patching; Aurelia's extra is choosing an older manifest, not patching. | code |
| Cache handling | image cache (`src/config.rs::opensteam_image_cache_dir`, 211) and `library_cache.json`; no chunk or manifest cache | image cache (`core/config.rs::opensteam_image_cache_dir`, 298) and per-app info JSON (`info_cache_dir`); no chunk or manifest cache | Both | Equivalent in scope: neither caches CDN payloads or manifests. | code |
| Directory, symlink and executable entries | not handled in the vendored crate: no `FLAG_DIRECTORY`/`FLAG_SYMLINK`/executable handling | `FLAG_DIRECTORY`/`FLAG_SYMLINK` in `cdn/mod.rs` 161–190, symlink materialisation with target decryption, and `apply_unix_mode` (file.rs 269) for the executable bit | Aurelia only | Aurelia creates directories, zero-byte files and symlinks and marks ELF/shebang files executable; SteamFlow writes file content only. | code |
| HTTP timeouts | none: `inner.rs` builds `Client::new()`; no timeout in the vendored crate | none: same | Both | A stalled CDN response holds a chunk slot indefinitely in both implementations. | code |

## Issue #96 in Aurelia

Aurelia has the same gap: it does not compare fetched chunk bytes with the manifest.

- `ManifestFile::download` (Aurelia `vendor/steam-cdn/src/cdn/manifest/file.rs` 142) hashes only an
  existing on-disk chunk (200–225) and then writes the fetched payload at its offset (245–260) with no
  SHA-1 check.
- `download_to_memory` (126–140), used for symlink entries whose target is chunk data, returns the
  fetched bytes without a hash as well.
- The only manifest-hash comparison is the pre-skip one. On a mismatch there, Aurelia logs
  `Corruption detected in chunk` (223) and fetches that chunk again from the same host; there is no
  per-chunk retry count and no switch to another server for a single chunk. A failed fetch or
  decompression propagates out of `download_depot`, and `download_depot_to_with_hosts` then tries the
  next host for the whole depot (`install.rs` 676–688).
- Aurelia's `VSZ` decompressor (`utils/lzma.rs::decompress_vsz`, 35) checks the magic and the `zsv`
  footer only, so a corrupted fetched zstd chunk can be decompressed and written without any error.
  SteamFlow's `VSZa` path verifies header/footer CRC32, the decoded CRC32 and the decompressed size,
  which catches that class of corruption but is still not the manifest SHA-1.

So the answer to #96 for Aurelia is: no verification of downloaded chunks; mismatch handling exists
only for bytes already on disk, where it means "re-fetch this chunk from the same host".

## Candidate explanations for "the CDN is not fully polished"

These are observations in Aurelia's layer, listed as candidates. None of them is evidence of a
SteamFlow defect.

1. CDN auth token uses the `ContentServerDirectory.GetCDNAuthToken` service call, while SteamFlow's
   code comments that this variant fails server-side and the real client uses the
   `CMsgClientGetCDNAuthToken` job. A token-less request can still work on cache servers that do not
   require one, so this would not fail every download.
2. Token-fetch failure is only a warning: the host is still tried without a token (`install.rs` 583–592).
3. No HTTP timeouts in either crate; a slow CDN host can hold a chunk slot indefinitely.
4. No retry or backoff: each host is attempted once per depot, in the order the directory returned,
   with no distinction between a 403, a 404 and a connection reset.
5. Server list is not ordered by load or distance (`content.rs` 11–30); the first responsive host is
   not necessarily the best one.
6. Concurrency is fixed at four chunk requests and cannot be tuned through `download_depot`.
7. Cancellation is abort-only: a transient failure or a user abort ends the depot run, and a resumed
   run starts a fresh pass rather than continuing from a paused state.
8. `verify_mode` is inert in the vendored crate, so a verify pass and an install pass use the same
   skip logic; the only difference is where the manifest list comes from.
9. zstd chunks are not CRC-checked, so a corrupted chunk is written and later read by the game.

## Licence and reuse

- SteamFlow is MIT. Aurelia as of `78b7085` is GPL-3.0 for commits after `065782b`, with the earlier
  commits (including the initial import `94e513e`) MIT; `Cargo.toml` says `GPL 3.0`. The vendored
  `steam-cdn` retains Apache-2.0.
- MIT code can be taken into a GPL-3.0 work; the reverse is not true. Copying any post-`065782b`
  Aurelia code — which includes the CDN patches `554e2d1` (VSZ), `8a5542f` (directories, zero-byte
  files, symlinks), `16d789d` (skip only on SHA match), `20988df` (symlink materialisation) and
  `c82ff4c` (executable bits) — into SteamFlow would make the combined work subject to GPL-3.0, and
  SteamFlow's MIT-only distribution terms could not be kept for it.
- GPL-3.0 also requires keeping copyright and licence notices, marking modified files and making the
  corresponding source available; Apache-2.0 requires keeping its `LICENSE`/`NOTICE`. The
  MIT-licensed early Aurelia commits and the SteamFlow-derived parts carry the SteamFlow MIT notice
  and can be used under MIT.
- Nothing in this document is legal advice, and no file-by-file provenance audit of Aurelia was done.

## Not checked statically

- No build, test, or run of either project: no `cargo check`, no `cargo test`, no live download. The
  laptop is unavailable.
- Behaviour that needs a CDN in front of it: host ordering, token acceptance, timeout effects, retry
  counts, real server errors.
- Which decompressor real depots exercise (zip, `VZa` or `VSZ`/`VSZa`); no depot payload was sampled.
- Whether `GetCDNAuthToken` through the service variant really fails, as SteamFlow's comment claims.
  Only the comment and the two call sites were read.
- Aurelia's daemon and its commands were read only where the download path needs them; the CLI/daemon
  interaction was not exercised.
- SteamFlow's pause/resume UI path and the `OperationController` behaviour under load were not run.
- The three commits between `11dd427` and `78b7085` were read as a diff and touch process/launch only;
  that they leave the CDN code untouched is a code reading, not a test.
- Licence statements come from `LICENSE` and `Cargo.toml` only, not from a legal review.

## What to test on the laptop

1. Download the same depot/manifest with both projects and compare file hashes, sizes, permissions
   and symlinks.
2. Serve one chunk with corrupted bytes (local stub or proxy) and see whether either client rejects,
   retries or silently writes it; repeat for a `VSZ`/`VSZa` chunk to check the CRC difference.
3. Kill or delay a CDN host mid-depot to observe host fallback and the absence of timeouts.
4. Force `GetCDNAuthToken` to fail and confirm both clients continue without a token.
5. Verify a depot that contains directories, symlinks and executables, and compare the resulting tree.
6. Measure concurrent chunk requests and confirm the fixed limit of four.
7. Pause and resume a download in SteamFlow with the UI control; confirm Aurelia's abort-only
   behaviour.
8. Run a verify pass on a deliberately corrupted install in both projects and compare what each
   reports.
